//// WebAuthn registration ceremony: generate options and verify responses.
////
//// ## Example
////
//// ```gleam
//// import glasslock/registration
////
//// // Generate options for browser
//// let #(request_json, challenge) =
////   registration.new(
////     relying_party: registration.RelyingParty(id: "example.com", name: "My App"),
////     user: registration.User(id: user_id, name: "john", display_name: "John"),
////     origin: "https://example.com",
////   )
////   |> registration.build()
////
//// // Send request_json to browser, receive response_json back. Keep
//// // `challenge` in memory for a single-node deploy; to span processes
//// // or nodes, serialize with `registration.encode_challenge` and hydrate
//// // it back with `registration.parse_challenge`.
////
//// // Verify the response
//// case registration.verify_json(response_json:, challenge:) {
////   Ok(credential) -> todo as "store credential"
////   Error(e) -> todo as "handle error"
//// }
//// ```

import glasslock
import glasslock/internal
import glasslock/internal/cbor
import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/set
import gleam/time/duration.{type Duration}
import gose
import kryptos/crypto

/// Supported cryptographic algorithms.
pub type Algorithm {
  /// ECDSA with P-256 curve and SHA-256 hash (COSE algorithm -7).
  Es256
  /// EdDSA with Ed25519 curve (COSE algorithm -8).
  Ed25519
  /// RSASSA-PKCS1-v1_5 with SHA-256 (COSE algorithm -257).
  Rs256
}

/// Authenticator attachment preference.
pub type AuthenticatorAttachment {
  /// Platform authenticator (e.g., Touch ID, Windows Hello).
  Platform
  /// Roaming authenticator (e.g., USB security key, Bluetooth).
  CrossPlatform
}

/// Resident key (discoverable credential) requirement.
pub type ResidentKey {
  /// The authenticator should not create a discoverable credential.
  ResidentKeyDiscouraged
  /// The authenticator should create a discoverable credential if possible.
  ResidentKeyPreferred
  /// The authenticator must create a discoverable credential.
  ResidentKeyRequired
}

/// The Relying Party: the service using WebAuthn to register or authenticate
/// users (i.e. your application).
pub type RelyingParty {
  RelyingParty(
    /// A valid domain string identifying the Relying Party, e.g.
    /// `"example.com"`. The browser binds credentials to this value, so it
    /// must match the effective domain of the page calling WebAuthn.
    id: String,
    /// A human-readable name shown to the user by the authenticator during
    /// registration, e.g. `"My App"`.
    name: String,
  )
}

/// User information for registration.
pub type User {
  User(
    /// An opaque user handle (max 64 bytes) that uniquely identifies the
    /// user to the authenticator. The WebAuthn spec requires this be random
    /// bytes that are not derived from personal information (email,
    /// username, etc.), so authenticators cannot correlate the user across
    /// relying parties. Generate once per user (e.g.
    /// `crypto.strong_random_bytes(16)`) and persist alongside the account.
    id: BitArray,
    /// A human-palatable identifier for the account, typically the login
    /// the user enters (username or email). Shown by the authenticator
    /// during account selection.
    name: String,
    /// A human-palatable name for the user (e.g. `"Jane Doe"`), intended
    /// only for display.
    display_name: String,
  )
}

/// Errors that can occur during registration verification.
pub type Error {
  /// A verification field does not match the expected value.
  VerificationMismatch(field: glasslock.VerificationField)
  /// The key format, algorithm, or curve is not supported.
  UnsupportedKey(reason: String)
  /// Failed to parse data (CBOR, JSON, or authenticator data).
  ParseError(message: String)
  /// The attestation format or statement is invalid.
  InvalidAttestation(reason: String)
  /// The cryptographic signature verification failed.
  InvalidSignature
  /// User presence was required but not asserted by the authenticator.
  UserPresenceFailed
  /// User verification was required but not performed by the authenticator.
  UserVerificationFailed
}

/// Configuration for a registration request, built up via `new` and the
/// setter functions, then handed to `build` to produce browser options
/// and a challenge verifier.
pub opaque type Builder {
  Builder(
    relying_party: RelyingParty,
    user: User,
    origins: List(String),
    timeout: Duration,
    authenticator_attachment: Option(AuthenticatorAttachment),
    resident_key: Option(ResidentKey),
    user_verification: Option(glasslock.UserVerification),
    allow_cross_origin: Bool,
    algorithms: List(Algorithm),
    exclude_credentials: List(#(BitArray, List(glasslock.Transport))),
    allowed_top_origins: List(String),
  )
}

/// A finalized registration challenge ready for verification or
/// out-of-process serialization (see `encode_challenge`).
pub opaque type Challenge {
  Challenge(data: internal.ChallengeData, algorithms: List(Algorithm))
}

/// A parsed registration response. Construct via `response_decoder()`
/// (when the response arrives nested in a larger JSON envelope) or
/// `parse_response_json` (when you have a raw response string). Pass to
/// [`verify`](#verify).
pub opaque type Response {
  Response(parsed: ParsedResponse)
}

type ParsedResponse {
  ParsedResponse(
    raw_id: String,
    credential_id: String,
    credential_type: String,
    client_data_json: String,
    attestation_object: String,
    transports: List(String),
  )
}

/// Start a new registration request builder with the required fields.
///
/// Defaults: 1-minute timeout, ECDSA P-256 algorithm, no excluded credentials,
/// cross-origin disallowed. Layer on optional configuration with the setter
/// functions before calling `build`.
pub fn new(
  relying_party relying_party: RelyingParty,
  user user: User,
  origin origin: String,
) -> Builder {
  Builder(
    relying_party:,
    user:,
    origins: [origin],
    timeout: duration.minutes(1),
    authenticator_attachment: option.None,
    resident_key: option.None,
    user_verification: option.None,
    allow_cross_origin: False,
    algorithms: [Es256],
    exclude_credentials: [],
    allowed_top_origins: [],
  )
}

/// Add an additional accepted origin. The origin passed to `new` is always
/// included; this function appends further origins. The signed
/// `clientDataJSON.origin` returned by the authenticator must match one of
/// them.
pub fn origin(builder: Builder, origin: String) -> Builder {
  Builder(..builder, origins: [origin, ..builder.origins])
}

/// Set the ceremony timeout. Defaults to 1 minute.
pub fn timeout(builder: Builder, timeout: Duration) -> Builder {
  Builder(..builder, timeout:)
}

/// Restrict authenticator type. Omitted by default (any authenticator).
pub fn authenticator_attachment(
  builder: Builder,
  attachment: AuthenticatorAttachment,
) -> Builder {
  Builder(..builder, authenticator_attachment: option.Some(attachment))
}

/// Set the discoverable credential requirement. When unset the field is
/// omitted from the JSON sent to the browser, and the browser applies the
/// spec default of `discouraged`.
pub fn resident_key(builder: Builder, resident_key: ResidentKey) -> Builder {
  Builder(..builder, resident_key: option.Some(resident_key))
}

/// Set the user verification requirement. When unset the field is omitted
/// from the JSON sent to the browser; the browser applies the spec default
/// of `preferred`, and verify treats the policy as `preferred`.
pub fn user_verification(
  builder: Builder,
  user_verification: glasslock.UserVerification,
) -> Builder {
  Builder(..builder, user_verification: option.Some(user_verification))
}

/// Allow cross-origin requests. Defaults to disallowed.
pub fn allow_cross_origin(builder: Builder, allow: Bool) -> Builder {
  Builder(..builder, allow_cross_origin: allow)
}

/// Replace the list of accepted signing algorithms, in preference order
/// (the authenticator picks the first it supports). Must be non-empty.
/// Defaults to `[Es256]` because it is the one algorithm every mainstream
/// authenticator handles; opt in to `Ed25519` or `Rs256` when broader
/// coverage is desired.
pub fn algorithms(builder: Builder, algorithms: List(Algorithm)) -> Builder {
  Builder(..builder, algorithms:)
}

/// Add a credential to the `excludeCredentials` list (prevent
/// re-registration on this authenticator). Pass the stored credential's
/// `id` and `transports` so the browser can route the request.
pub fn exclude_credential(
  builder: Builder,
  id id: BitArray,
  transports transports: List(glasslock.Transport),
) -> Builder {
  Builder(..builder, exclude_credentials: [
    #(id, transports),
    ..builder.exclude_credentials
  ])
}

/// Add a top-level origin to the cross-origin iframe allowlist. The
/// allowlist is consulted only when the browser supplies a `topOrigin`
/// field; older browsers omit the field even for cross-origin requests,
/// in which case top-origin verification is skipped.
pub fn allowed_top_origin(builder: Builder, origin: String) -> Builder {
  Builder(..builder, allowed_top_origins: [
    origin,
    ..builder.allowed_top_origins
  ])
}

/// Serialize a registration challenge for out-of-process storage between the
/// `request` and `verify` steps (signed cookie, Redis, database row). Pair
/// with `parse_challenge` to rehydrate.
///
/// # Security
///
/// The returned string is *not* authenticated. If an attacker can tamper with
/// the stored blob they can redirect verification by forging `rp_id` or
/// `origins`. Store it somewhere the caller controls (server-side session, a
/// signed cookie, or authenticated encryption). Wisp's `wisp.Signed` cookie
/// security is a common fit.
pub fn encode_challenge(challenge: Challenge) -> String {
  let algorithms =
    json.array(challenge.algorithms, fn(alg) {
      json.int(algorithm_to_cose(alg))
    })

  [
    #("v", json.int(1)),
    #("kind", json.string("registration")),
    #("algorithms", algorithms),
    ..internal.encode_challenge_data_fields(challenge.data)
  ]
  |> json.object
  |> json.to_string
}

@internal
pub fn challenge_data(challenge: Challenge) -> internal.ChallengeData {
  challenge.data
}

@internal
pub fn challenge_algorithms(challenge: Challenge) -> List(Algorithm) {
  challenge.algorithms
}

/// Decode a previously-encoded registration challenge. Returns a
/// `ParseError` if the blob is malformed, encodes an authentication
/// challenge, or uses an unsupported format version.
pub fn parse_challenge(encoded: String) -> Result(Challenge, Error) {
  let decoder = {
    use algs <- decode.field("algorithms", decode.list(decode.int))
    decode.success(algs)
  }

  use #(data, cose_algs) <- result.try(
    wrap_error(internal.parse_challenge_shared(
      encoded,
      expected_kind: "registration",
      rest_decoder: decoder,
    )),
  )
  use algorithms <- result.try(list.try_map(cose_algs, algorithm_from_cose))
  Ok(Challenge(data:, algorithms:))
}

/// Generate registration options and a challenge verifier from a builder.
///
/// The first element is a `PublicKeyCredentialCreationOptionsJSON` value
/// ready to serialize with `gleam/json.to_string` or embed inside a
/// response envelope. The second is the verifier to pass to `verify`.
pub fn build(builder: Builder) -> #(Json, Challenge) {
  let challenge_bytes = crypto.random_bytes(32)
  let challenge_b64 = bit_array.base64_url_encode(challenge_bytes, False)

  let user_id_b64 = bit_array.base64_url_encode(builder.user.id, False)

  let pub_key_params =
    list.map(builder.algorithms, fn(alg) {
      json.object([
        #("type", json.string("public-key")),
        #("alg", json.int(algorithm_to_cose(alg))),
      ])
    })

  let authenticator_selection_fields =
    []
    |> maybe_add_attachment(builder.authenticator_attachment)
    |> maybe_add_user_verification(builder.user_verification)
    |> maybe_add_resident_key(builder.resident_key)

  let options_json =
    json.object(
      [
        #("challenge", json.string(challenge_b64)),
        #(
          "rp",
          json.object([
            #("id", json.string(builder.relying_party.id)),
            #("name", json.string(builder.relying_party.name)),
          ]),
        ),
        #(
          "user",
          json.object([
            #("id", json.string(user_id_b64)),
            #("name", json.string(builder.user.name)),
            #("displayName", json.string(builder.user.display_name)),
          ]),
        ),
        #("pubKeyCredParams", json.preprocessed_array(pub_key_params)),
        #("timeout", json.int(duration.to_milliseconds(builder.timeout))),
      ]
      |> maybe_add_authenticator_selection(authenticator_selection_fields)
      |> internal.maybe_add_credential_descriptors(
        key: "excludeCredentials",
        credentials: builder.exclude_credentials,
      ),
    )

  let challenge =
    Challenge(
      data: internal.ChallengeData(
        bytes: challenge_bytes,
        origins: set.from_list(builder.origins),
        rp_id: builder.relying_party.id,
        user_verification: option.unwrap(
          builder.user_verification,
          glasslock.VerificationPreferred,
        ),
        allow_cross_origin: builder.allow_cross_origin,
        allowed_top_origins: builder.allowed_top_origins,
      ),
      algorithms: builder.algorithms,
    )

  #(options_json, challenge)
}

fn algorithm_to_cose(alg: Algorithm) -> Int {
  case alg {
    Es256 -> -7
    Ed25519 -> -8
    Rs256 -> -257
  }
}

fn algorithm_from_cose(cose_alg: Int) -> Result(Algorithm, Error) {
  case cose_alg {
    -7 -> Ok(Es256)
    -8 -> Ok(Ed25519)
    -257 -> Ok(Rs256)
    _ -> Error(ParseError("Unsupported algorithm: " <> int.to_string(cose_alg)))
  }
}

fn algorithm_to_signature_alg(alg: Algorithm) -> gose.DigitalSignatureAlg {
  case alg {
    Es256 -> gose.Ecdsa(gose.EcdsaP256)
    Ed25519 -> gose.Eddsa
    Rs256 -> gose.RsaPkcs1(gose.RsaPkcs1Sha256)
  }
}

fn attachment_to_string(attachment: AuthenticatorAttachment) -> String {
  case attachment {
    Platform -> "platform"
    CrossPlatform -> "cross-platform"
  }
}

fn maybe_add_attachment(
  fields: List(#(String, Json)),
  attachment: Option(AuthenticatorAttachment),
) -> List(#(String, Json)) {
  case attachment {
    option.None -> fields
    option.Some(attachment_value) -> [
      #(
        "authenticatorAttachment",
        json.string(attachment_to_string(attachment_value)),
      ),
      ..fields
    ]
  }
}

fn maybe_add_resident_key(
  fields: List(#(String, Json)),
  resident_key: Option(ResidentKey),
) -> List(#(String, Json)) {
  case resident_key {
    option.None -> fields
    option.Some(value) -> [
      #("residentKey", json.string(resident_key_to_string(value))),
      ..fields
    ]
  }
}

fn maybe_add_user_verification(
  fields: List(#(String, Json)),
  user_verification: Option(glasslock.UserVerification),
) -> List(#(String, Json)) {
  case user_verification {
    option.None -> fields
    option.Some(value) -> [
      #(
        "userVerification",
        json.string(internal.user_verification_to_string(value)),
      ),
      ..fields
    ]
  }
}

fn maybe_add_authenticator_selection(
  fields: List(#(String, Json)),
  selection_fields: List(#(String, Json)),
) -> List(#(String, Json)) {
  case selection_fields {
    [] -> fields
    _ -> [#("authenticatorSelection", json.object(selection_fields)), ..fields]
  }
}

fn resident_key_to_string(resident_key: ResidentKey) -> String {
  case resident_key {
    ResidentKeyDiscouraged -> "discouraged"
    ResidentKeyPreferred -> "preferred"
    ResidentKeyRequired -> "required"
  }
}

/// Decoder for a registration response. Use when the response arrives
/// nested in a larger JSON envelope (e.g. `{"response": <PublicKeyCredentialJSON>}`).
/// Combine with `gleam/dynamic/decode` to extract the response and pass to
/// [`verify`](#verify).
pub fn response_decoder() -> decode.Decoder(Response) {
  use credential_id <- decode.field("id", decode.string)
  use raw_id <- decode.field("rawId", decode.string)
  use credential_type <- decode.field("type", decode.string)
  use client_data_json <- decode.subfield(
    ["response", "clientDataJSON"],
    decode.string,
  )
  use attestation_object <- decode.subfield(
    ["response", "attestationObject"],
    decode.string,
  )
  use transports <- decode.then(decode.optionally_at(
    ["response", "transports"],
    [],
    decode.list(decode.string),
  ))
  decode.success(
    Response(ParsedResponse(
      raw_id:,
      credential_id:,
      credential_type:,
      client_data_json:,
      attestation_object:,
      transports:,
    )),
  )
}

/// Parse a raw response JSON string into a `Response`. Use when the
/// response is the entire request body. For envelope shapes use
/// [`response_decoder`](#response_decoder) inside your own decoder.
pub fn parse_response_json(response_json: String) -> Result(Response, Error) {
  json.parse(response_json, response_decoder())
  |> result.replace_error(ParseError("Invalid registration response JSON"))
}

/// Verify a response from the browser.
///
/// Takes a parsed `Response` (from [`response_decoder`](#response_decoder) or
/// [`parse_response_json`](#parse_response_json)) and the challenge from
/// `build()`. Returns the verified credential on success.
pub fn verify(
  response response: Response,
  challenge challenge: Challenge,
) -> Result(glasslock.Credential, Error) {
  let response = response.parsed

  use #(raw_id, client_data_json, attestation_object) <- result.try(
    decode_response_credential(response),
  )

  use client_data <- result.try(
    wrap_error(internal.parse_client_data(client_data_json)),
  )
  use _ <- result.try(
    wrap_error(internal.verify_client_data(
      client_data,
      expected_type: "webauthn.create",
      expected_challenge: challenge.data.bytes,
      expected_origins: challenge.data.origins,
      allow_cross_origin: challenge.data.allow_cross_origin,
      allowed_top_origins: challenge.data.allowed_top_origins,
    )),
  )

  use #(attested, public_key, sign_count) <- result.try(verify_attestation(
    challenge,
    raw_id,
    attestation_object,
  ))

  Ok(glasslock.Credential(
    id: attested.credential_id,
    public_key:,
    sign_count: sign_count,
    transports: list.filter_map(
      response.transports,
      internal.transport_from_string,
    ),
  ))
}

fn decode_response_credential(
  response: ParsedResponse,
) -> Result(#(BitArray, BitArray, BitArray), Error) {
  use raw_id <- result.try(
    wrap_error(internal.decode_base64url(response.raw_id, "rawId")),
  )
  use credential_id_bytes <- result.try(
    wrap_error(internal.decode_base64url(response.credential_id, "id")),
  )
  use <- bool.guard(
    when: credential_id_bytes != raw_id,
    return: Error(VerificationMismatch(glasslock.CredentialIdField)),
  )

  use client_data_json <- result.try(
    wrap_error(internal.decode_base64url(
      response.client_data_json,
      "clientDataJSON",
    )),
  )
  use attestation_object <- result.try(
    wrap_error(internal.decode_base64url(
      response.attestation_object,
      "attestationObject",
    )),
  )

  use <- bool.guard(
    when: response.credential_type != "public-key",
    return: Error(VerificationMismatch(glasslock.CredentialTypeField)),
  )

  Ok(#(raw_id, client_data_json, attestation_object))
}

fn verify_attestation(
  challenge: Challenge,
  raw_id: BitArray,
  attestation_object: BitArray,
) -> Result(#(internal.AttestedCredential, glasslock.PublicKey, Int), Error) {
  use attestation_obj <- result.try(
    wrap_error(internal.parse_attestation_object(attestation_object)),
  )
  use #(auth_data_bytes, att_stmt, fmt_string) <- result.try(
    wrap_error(internal.extract_attestation_fields(attestation_obj)),
  )
  use <- bool.guard(
    when: fmt_string != "none",
    return: Error(InvalidAttestation("unsupported format: " <> fmt_string)),
  )
  use auth_data <- result.try(
    wrap_error(internal.parse_registration_auth_data(auth_data_bytes)),
  )

  let attested = auth_data.attested_credential

  use <- bool.guard(
    when: raw_id != attested.credential_id,
    return: Error(VerificationMismatch(glasslock.CredentialIdField)),
  )

  use _ <- result.try(
    wrap_error(internal.verify_rp_id(auth_data.rp_id_hash, challenge.data.rp_id)),
  )
  use _ <- result.try(
    wrap_error(internal.verify_user_policies(
      auth_data.user_present,
      auth_data.user_verified,
      challenge.data.user_verification,
    )),
  )

  use public_key <- result.try(
    glasslock.parse_public_key(attested.public_key_cbor)
    |> result.map_error(public_key_error),
  )
  use <- bool.guard(
    when: !list.any(challenge.algorithms, fn(a) {
      algorithm_to_signature_alg(a) == glasslock.public_key_alg(public_key)
    }),
    return: Error(UnsupportedKey(
      "credential algorithm does not match requested algorithms",
    )),
  )

  use <- bool.guard(
    when: att_stmt != cbor.Map([]),
    return: Error(InvalidAttestation(
      "none attestation with non-empty statement",
    )),
  )

  Ok(#(attested, public_key, auth_data.sign_count))
}

/// Convenience wrapper around [`verify`](#verify) for callers whose response
/// arrives as a raw JSON string: parses with `parse_response_json` then
/// verifies.
pub fn verify_json(
  response_json response_json: String,
  challenge challenge: Challenge,
) -> Result(glasslock.Credential, Error) {
  use response <- result.try(parse_response_json(response_json))
  verify(response:, challenge:)
}

fn wrap_error(result: Result(a, internal.Error)) -> Result(a, Error) {
  result.map_error(result, fn(error) {
    case error {
      internal.VerificationMismatch(field) -> VerificationMismatch(field)
      internal.UnsupportedKey(reason) -> UnsupportedKey(reason)
      internal.ParseError(message) -> ParseError(message)
      internal.UserPresenceFailed -> UserPresenceFailed
      internal.UserVerificationFailed -> UserVerificationFailed
      internal.SignatureVerificationFailed -> InvalidSignature
    }
  })
}

fn public_key_error(error: glasslock.PublicKeyError) -> Error {
  case error {
    glasslock.InvalidPublicKey(reason) -> ParseError(reason)
    glasslock.UnsupportedPublicKey(reason) -> UnsupportedKey(reason)
  }
}
