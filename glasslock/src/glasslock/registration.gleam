//// WebAuthn registration ceremony: generate options and verify responses.
////
//// ## Example
////
//// ```gleam
//// import glasslock/registration
////
//// // Generate options for browser
//// let assert Ok(#(request_json, challenge)) =
////   registration.request(
////     relying_party: registration.RelyingParty(id: "example.com", name: "My App"),
////     user: registration.User(id: user_id, name: "john", display_name: "John"),
////     origins: ["https://example.com"],
////     options: registration.default_options(),
////   )
////
//// // Send request_json to browser, receive response_json back. Keep
//// // `challenge` in memory for a single-node deploy; to span processes
//// // or nodes, serialize with `registration.encode_challenge` and hydrate
//// // it back with `registration.parse_challenge`.
////
//// // Verify the response
//// case registration.verify(response_json:, challenge:) {
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

/// Optional knobs for registration challenge generation. The required
/// `relying_party`, `user`, and `origins` values are passed directly to
/// `request`.
pub type Options {
  Options(
    /// Timeout for the ceremony. Defaults to 1 minute.
    timeout: Duration,
    /// Restrict authenticator type. `option.None` allows any.
    authenticator_attachment: Option(AuthenticatorAttachment),
    /// Discoverable credential requirement. `option.None` omits the field
    /// from the JSON sent to the browser; the browser then applies the spec
    /// default of `discouraged`.
    resident_key: Option(ResidentKey),
    /// User verification requirement. `option.None` omits the field from
    /// the JSON sent to the browser; the browser applies the spec default
    /// of `preferred` and verify treats the policy as `preferred`.
    user_verification: Option(glasslock.UserVerification),
    /// Whether to allow cross-origin requests. Defaults to `False`.
    allow_cross_origin: Bool,
    /// Accepted signing algorithms, in preference order (the authenticator
    /// picks the first it supports). Must be non-empty. Defaults to `[Es256]`
    /// because it is the one algorithm every mainstream authenticator handles;
    /// opt in to `Ed25519` or `Rs256` when broader coverage is desired.
    algorithms: List(Algorithm),
    /// Credentials to exclude (prevent re-registration). Build each entry
    /// from a stored `glasslock.Credential` with
    /// `glasslock.CredentialDescriptor(id:, transports:)` so transport hints
    /// are preserved.
    exclude_credentials: List(glasslock.CredentialDescriptor),
    /// Allowed top-level origins for cross-origin iframe verification. The
    /// allowlist is consulted only when the browser supplies a `topOrigin`
    /// field; older browsers omit the field even for cross-origin requests,
    /// in which case top-origin verification is skipped.
    /// Defaults to `[]`.
    allowed_top_origins: List(String),
  )
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
///
/// - `id`: a valid domain string identifying the Relying Party, e.g.
///   `"example.com"`. The browser binds credentials to this value, so it must
///   match the effective domain of the page calling WebAuthn.
/// - `name`: a human-readable name shown to the user by the authenticator
///   during registration, e.g. `"My App"`.
pub type RelyingParty {
  RelyingParty(id: String, name: String)
}

/// User information for registration.
pub type User {
  User(id: BitArray, name: String, display_name: String)
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

/// A finalized registration challenge ready for verification.
pub opaque type Challenge {
  Challenge(data: internal.ChallengeData, algorithms: List(Algorithm))
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

/// Returns an `Options` record with default values.
pub fn default_options() -> Options {
  Options(
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

/// Generate registration options and a challenge verifier.
///
/// The first element is a `PublicKeyCredentialCreationOptionsJSON` value
/// ready to serialize with `gleam/json.to_string` or embed inside a
/// response envelope. The second is the verifier to pass to `verify`.
pub fn request(
  relying_party relying_party: RelyingParty,
  user user: User,
  origins origins: List(String),
  options options: Options,
) -> Result(#(Json, Challenge), Error) {
  use <- bool.guard(
    when: list.is_empty(origins),
    return: Error(ParseError(
      "no allowed origins configured; pass a non-empty origins list to request",
    )),
  )
  use <- bool.guard(
    when: list.is_empty(options.algorithms),
    return: Error(ParseError(
      "no algorithms configured; pass a non-empty algorithms list to request",
    )),
  )

  let challenge_bytes = crypto.random_bytes(32)
  let challenge_b64 = bit_array.base64_url_encode(challenge_bytes, False)

  let user_id_b64 = bit_array.base64_url_encode(user.id, False)

  let pub_key_params =
    list.map(options.algorithms, fn(alg) {
      json.object([
        #("type", json.string("public-key")),
        #("alg", json.int(algorithm_to_cose(alg))),
      ])
    })

  let authenticator_selection_fields =
    []
    |> maybe_add_attachment(options.authenticator_attachment)
    |> maybe_add_user_verification(options.user_verification)
    |> maybe_add_resident_key(options.resident_key)

  let options_json =
    json.object(
      [
        #("challenge", json.string(challenge_b64)),
        #(
          "rp",
          json.object([
            #("id", json.string(relying_party.id)),
            #("name", json.string(relying_party.name)),
          ]),
        ),
        #(
          "user",
          json.object([
            #("id", json.string(user_id_b64)),
            #("name", json.string(user.name)),
            #("displayName", json.string(user.display_name)),
          ]),
        ),
        #("pubKeyCredParams", json.preprocessed_array(pub_key_params)),
        #("timeout", json.int(duration.to_milliseconds(options.timeout))),
      ]
      |> maybe_add_authenticator_selection(authenticator_selection_fields)
      |> internal.maybe_add_credential_descriptors(
        key: "excludeCredentials",
        credentials: options.exclude_credentials,
      ),
    )

  let challenge =
    Challenge(
      data: internal.ChallengeData(
        bytes: challenge_bytes,
        origins: set.from_list(origins),
        rp_id: relying_party.id,
        user_verification: option.unwrap(
          options.user_verification,
          glasslock.VerificationPreferred,
        ),
        allow_cross_origin: options.allow_cross_origin,
        allowed_top_origins: options.allowed_top_origins,
      ),
      algorithms: options.algorithms,
    )

  Ok(#(options_json, challenge))
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

/// Verify a response JSON from the browser.
///
/// Takes the JSON response string from the browser and the challenge from `request()`.
/// Returns the verified credential on success.
pub fn verify(
  response_json response_json: String,
  challenge challenge: Challenge,
) -> Result(glasslock.Credential, Error) {
  use response <- result.try(parse_response_json(response_json))

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

  use #(_, alg) <- result.try(
    wrap_error(internal.parse_public_key(attested.public_key_cbor)),
  )
  use <- bool.guard(
    when: !list.any(challenge.algorithms, fn(a) {
      algorithm_to_signature_alg(a) == alg
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

  Ok(glasslock.Credential(
    id: glasslock.CredentialId(attested.credential_id),
    public_key: glasslock.PublicKey(attested.public_key_cbor),
    sign_count: auth_data.sign_count,
    transports: list.filter_map(
      response.transports,
      internal.transport_from_string,
    ),
  ))
}

fn parse_response_json(json_string: String) -> Result(ParsedResponse, Error) {
  let decoder = {
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
    decode.success(ParsedResponse(
      raw_id:,
      credential_id:,
      credential_type:,
      client_data_json:,
      attestation_object:,
      transports:,
    ))
  }

  json.parse(json_string, decoder)
  |> result.replace_error(ParseError("Invalid registration response JSON"))
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
