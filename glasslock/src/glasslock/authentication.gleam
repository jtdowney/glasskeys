//// WebAuthn authentication ceremony: generate options and verify responses.
////
//// ## Example (known credential)
////
//// ```gleam
//// import glasslock/authentication
////
//// // Generate options for browser
//// let #(request_json, challenge) =
////   authentication.new(
////     relying_party_id: "example.com",
////     origin: "https://example.com",
////   )
////   |> authentication.allow_credential(
////     id: stored_credential.id,
////     transports: stored_credential.transports,
////   )
////   |> authentication.build()
////
//// // Send request_json to browser, receive response_json back. Keep
//// // `challenge` in memory for a single-node deploy; to span processes
//// // or nodes, serialize with `authentication.encode_challenge` and
//// // hydrate it back with `authentication.parse_challenge`.
////
//// // Verify the response
//// case authentication.verify_json(response_json:, challenge:, stored: stored_credential) {
////   Ok(updated_credential) -> todo as "update stored sign_count"
////   Error(e) -> todo as "handle error"
//// }
//// ```
////
//// ## Example (discoverable/passkey)
////
//// ```gleam
//// // No allow_credential calls = discoverable flow
//// let #(request_json, challenge) =
////   authentication.new(
////     relying_party_id: "example.com",
////     origin: "https://example.com",
////   )
////   |> authentication.build()
////
//// // Parse response to get credential_id for lookup. As above, keep
//// // `challenge` in memory for a single node, or round-trip through
//// // `authentication.encode_challenge` / `authentication.parse_challenge`
//// // to span processes.
//// case authentication.parse_response(response_json) {
////   Ok(info) ->
////     case lookup_credential(info.credential_id) {
////       Ok(stored) ->
////         case authentication.verify_json(response_json:, challenge:, stored:) {
////           Ok(updated) -> todo as "update stored sign_count"
////           Error(e) -> todo as "handle verification error"
////         }
////       Error(e) -> todo as "handle lookup error"
////     }
////   Error(e) -> todo as "handle parse error"
//// }
//// ```

import glasslock
import glasslock/internal
import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/set
import gleam/time/duration.{type Duration}
import kryptos/crypto
import kryptos/hash

/// Parsed credential lookup info from an authentication response. Use in
/// the discoverable (usernameless) flow to find the stored credential
/// before calling `verify`.
pub type ResponseInfo {
  ResponseInfo(
    /// The credential ID the authenticator asserted. Look this up against
    /// your stored credentials to find the matching record.
    credential_id: BitArray,
    /// The user handle the authenticator returned: the same opaque bytes
    /// originally registered as `User.id`. `None` when the authenticator
    /// did not return one. Required for discoverable credentials, optional
    /// otherwise.
    user_handle: Option(BitArray),
  )
}

/// Errors that can occur during authentication verification.
pub type Error {
  /// A verification field does not match the expected value.
  VerificationMismatch(field: glasslock.VerificationField)
  /// The key format, algorithm, or curve is not supported.
  UnsupportedKey(reason: String)
  /// Failed to parse data (CBOR, JSON, or authenticator data).
  ParseError(message: String)
  /// The cryptographic signature verification failed.
  InvalidSignature
  /// The credential ID is not in the allowed credentials list or does not match the stored credential.
  CredentialNotAllowed
  /// The sign count did not strictly increase from a nonzero stored count,
  /// indicating a possible cloned authenticator.
  SignCountRegression
  /// User presence was required but not asserted by the authenticator.
  UserPresenceFailed
  /// User verification was required but not performed by the authenticator.
  UserVerificationFailed
}

/// Configuration for an authentication request, built up via `new` and the
/// setter functions, then handed to `build` to produce browser options
/// and a challenge verifier.
pub opaque type Builder {
  Builder(
    relying_party_id: String,
    origins: List(String),
    timeout: Duration,
    user_verification: Option(glasslock.UserVerification),
    allow_cross_origin: Bool,
    allow_credentials: List(#(BitArray, List(glasslock.Transport))),
    allowed_top_origins: List(String),
  )
}

/// A finalized authentication challenge ready for verification.
pub opaque type Challenge {
  Challenge(
    data: internal.ChallengeData,
    allowed_credentials: List(#(BitArray, List(glasslock.Transport))),
  )
}

/// A parsed authentication response. Construct via `response_decoder()`
/// (when the response arrives nested in a larger JSON envelope) or
/// `parse_response_json` (when you have a raw response string). Pass to
/// [`verify`](#verify) or [`response_info`](#response_info).
pub opaque type Response {
  Response(parsed: ParsedResponse)
}

type ParsedResponse {
  ParsedResponse(
    raw_id: String,
    credential_id: String,
    credential_type: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option(String),
  )
}

/// Start a new authentication request builder with the required fields.
///
/// Defaults: 1-minute timeout, no allowed credentials (discoverable/passkey
/// flow), cross-origin disallowed. Layer on optional configuration with the
/// setter functions before calling `build`.
pub fn new(
  relying_party_id relying_party_id: String,
  origin origin: String,
) -> Builder {
  Builder(
    relying_party_id:,
    origins: [origin],
    timeout: duration.minutes(1),
    user_verification: option.None,
    allow_cross_origin: False,
    allow_credentials: [],
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

/// Set the user verification requirement. When unset the field is omitted
/// from the JSON sent to the browser; the browser applies the spec default
/// of `preferred`.
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

/// Add a credential to the `allowCredentials` list. Pass the stored
/// credential's `id` and `transports` so the browser can route the request.
/// With no calls the request is a discoverable (passkey) flow where the
/// authenticator selects a credential.
pub fn allow_credential(
  builder: Builder,
  id id: BitArray,
  transports transports: List(glasslock.Transport),
) -> Builder {
  Builder(..builder, allow_credentials: [
    #(id, transports),
    ..builder.allow_credentials
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

/// Serialize an authentication challenge for out-of-process storage between
/// the `request` and `verify` steps (signed cookie, Redis, database row).
/// Pair with `parse_challenge` to rehydrate.
///
/// # Security
///
/// The returned string is *not* authenticated. If an attacker can tamper with
/// the stored blob they can redirect verification by forging `rp_id` or
/// `origins`. Store it somewhere the caller controls (server-side session, a
/// signed cookie, or authenticated encryption). Wisp's `wisp.Signed` cookie
/// security is a common fit.
pub fn encode_challenge(challenge: Challenge) -> String {
  let allow_credentials =
    json.array(challenge.allowed_credentials, fn(entry) {
      let #(raw, transports) = entry
      json.object([
        #("id", json.string(bit_array.base64_url_encode(raw, False))),
        #(
          "transports",
          json.array(transports, fn(t) {
            json.string(internal.transport_to_string(t))
          }),
        ),
      ])
    })

  [
    #("v", json.int(1)),
    #("kind", json.string("authentication")),
    #("allow_credentials", allow_credentials),
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
pub fn challenge_allowed_credentials(
  challenge: Challenge,
) -> List(#(BitArray, List(glasslock.Transport))) {
  challenge.allowed_credentials
}

/// Decode a previously-encoded authentication challenge. Returns a
/// `ParseError` if the blob is malformed, encodes a registration challenge,
/// or uses an unsupported format version.
pub fn parse_challenge(encoded: String) -> Result(Challenge, Error) {
  let descriptor_decoder = {
    use id_b64 <- decode.field("id", decode.string)
    use transports <- decode.optional_field(
      "transports",
      [],
      decode.list(decode.string),
    )
    decode.success(#(id_b64, transports))
  }

  let decoder = {
    use entries <- decode.field(
      "allow_credentials",
      decode.list(descriptor_decoder),
    )
    decode.success(entries)
  }

  use #(data, entries) <- result.try(
    wrap_error(internal.parse_challenge_shared(
      encoded,
      expected_kind: "authentication",
      rest_decoder: decoder,
    )),
  )
  use allowed_credentials <- result.try(parse_allow_credentials(entries))
  Ok(Challenge(data:, allowed_credentials:))
}

fn parse_allow_credentials(
  entries: List(#(String, List(String))),
) -> Result(List(#(BitArray, List(glasslock.Transport))), Error) {
  list.try_map(entries, fn(entry) {
    let #(id_b64, transport_strings) = entry
    use raw <- result.try(
      wrap_error(internal.decode_base64url(id_b64, "allow_credentials")),
    )
    Ok(#(
      raw,
      list.filter_map(transport_strings, internal.transport_from_string),
    ))
  })
}

/// Generate authentication options and a challenge verifier from a builder.
///
/// The first element is a `PublicKeyCredentialRequestOptionsJSON` value
/// ready to serialize with `gleam/json.to_string` or embed inside a
/// response envelope. The second is the verifier to pass to `verify`.
pub fn build(builder: Builder) -> #(Json, Challenge) {
  let challenge_bytes = crypto.random_bytes(32)
  let challenge_b64 = bit_array.base64_url_encode(challenge_bytes, False)

  let options_json =
    json.object(
      [
        #("challenge", json.string(challenge_b64)),
        #("rpId", json.string(builder.relying_party_id)),
        #("timeout", json.int(duration.to_milliseconds(builder.timeout))),
      ]
      |> maybe_add_user_verification(builder.user_verification)
      |> internal.maybe_add_credential_descriptors(
        key: "allowCredentials",
        credentials: builder.allow_credentials,
      ),
    )

  let challenge =
    Challenge(
      data: internal.ChallengeData(
        bytes: challenge_bytes,
        origins: set.from_list(builder.origins),
        rp_id: builder.relying_party_id,
        user_verification: option.unwrap(
          builder.user_verification,
          glasslock.VerificationPreferred,
        ),
        allow_cross_origin: builder.allow_cross_origin,
        allowed_top_origins: builder.allowed_top_origins,
      ),
      allowed_credentials: builder.allow_credentials,
    )

  #(options_json, challenge)
}

fn maybe_add_user_verification(
  fields: List(#(String, json.Json)),
  user_verification: Option(glasslock.UserVerification),
) -> List(#(String, json.Json)) {
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

/// Decoder for an authentication response. Use when the response arrives
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
  use authenticator_data <- decode.subfield(
    ["response", "authenticatorData"],
    decode.string,
  )
  use signature <- decode.subfield(["response", "signature"], decode.string)
  use user_handle <- decode.then(decode.optionally_at(
    ["response", "userHandle"],
    option.None,
    decode.optional(decode.string),
  ))
  decode.success(
    Response(ParsedResponse(
      raw_id:,
      credential_id:,
      credential_type:,
      client_data_json:,
      authenticator_data:,
      signature:,
      user_handle:,
    )),
  )
}

/// Parse a raw response JSON string into a `Response`. Use when the
/// response is the entire request body. For envelope shapes use
/// [`response_decoder`](#response_decoder) inside your own decoder.
pub fn parse_response_json(response_json: String) -> Result(Response, Error) {
  json.parse(response_json, response_decoder())
  |> result.replace_error(ParseError("Invalid authentication response JSON"))
}

/// Extract the credential id and optional user handle for lookup (discoverable flow).
///
/// Once you have a parsed `Response`, call this to look up the stored
/// credential before passing the same `Response` to [`verify`](#verify).
pub fn response_info(response: Response) -> Result(ResponseInfo, Error) {
  let parsed = response.parsed
  use raw_id <- result.try(
    wrap_error(internal.decode_base64url(parsed.raw_id, "rawId")),
  )
  use credential_id_bytes <- result.try(
    wrap_error(internal.decode_base64url(parsed.credential_id, "id")),
  )
  use <- bool.guard(
    when: credential_id_bytes != raw_id,
    return: Error(VerificationMismatch(glasslock.CredentialIdField)),
  )

  internal.decode_optional_base64url(parsed.user_handle, "userHandle")
  |> result.map(ResponseInfo(raw_id, _))
  |> wrap_error
}

/// Convenience wrapper around `parse_response_json` +
/// [`response_info`](#response_info) for callers whose response arrives as a
/// raw string. Use during the discoverable flow to look up the stored
/// credential before calling [`verify_json`](#verify_json).
pub fn parse_response(response_json: String) -> Result(ResponseInfo, Error) {
  parse_response_json(response_json) |> result.try(response_info)
}

/// Verify a challenge response from the browser.
///
/// Takes a parsed `Response` (from [`response_decoder`](#response_decoder) or
/// [`parse_response_json`](#parse_response_json)), the challenge from
/// `build()`, and the stored credential to verify against.
///
/// For discoverable flow: call [`response_info`](#response_info) first to get
/// credential_id for lookup.
///
/// Returns an updated credential with the new sign count on success.
pub fn verify(
  response response: Response,
  challenge challenge: Challenge,
  stored stored: glasslock.Credential,
) -> Result(glasslock.Credential, Error) {
  let response = response.parsed

  use #(raw_id, client_data_json, authenticator_data, signature) <- result.try(
    decode_response_credential(response),
  )
  use _ <- result.try(check_credential_allowed(challenge, stored, raw_id))

  use client_data <- result.try(
    wrap_error(internal.parse_client_data(client_data_json)),
  )
  use _ <- result.try(
    wrap_error(internal.verify_client_data(
      client_data,
      expected_type: "webauthn.get",
      expected_challenge: challenge.data.bytes,
      expected_origins: challenge.data.origins,
      allow_cross_origin: challenge.data.allow_cross_origin,
      allowed_top_origins: challenge.data.allowed_top_origins,
    )),
  )

  use client_data_hash <- result.try(
    crypto.hash(hash.Sha256, client_data_json)
    |> result.replace_error(ParseError("Failed to hash client data")),
  )

  use auth_data <- result.try(
    wrap_error(internal.parse_authentication_auth_data(authenticator_data)),
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

  let signed_data = bit_array.concat([authenticator_data, client_data_hash])
  use _ <- result.try(
    wrap_error(internal.verify_signature(
      glasslock.public_key_cose(stored.public_key),
      alg: glasslock.public_key_alg(stored.public_key),
      message: signed_data,
      signature:,
    )),
  )

  use _ <- result.try(check_sign_count(stored.sign_count, auth_data.sign_count))

  Ok(glasslock.Credential(..stored, sign_count: auth_data.sign_count))
}

fn decode_response_credential(
  response: ParsedResponse,
) -> Result(#(BitArray, BitArray, BitArray, BitArray), Error) {
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
  use authenticator_data <- result.try(
    wrap_error(internal.decode_base64url(
      response.authenticator_data,
      "authenticatorData",
    )),
  )
  use signature <- result.try(
    wrap_error(internal.decode_base64url(response.signature, "signature")),
  )

  use <- bool.guard(
    when: response.credential_type != "public-key",
    return: Error(VerificationMismatch(glasslock.CredentialTypeField)),
  )

  Ok(#(raw_id, client_data_json, authenticator_data, signature))
}

fn check_credential_allowed(
  challenge: Challenge,
  stored: glasslock.Credential,
  raw_id: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: !list.is_empty(challenge.allowed_credentials)
      && !list.any(challenge.allowed_credentials, fn(entry) {
      entry.0 == raw_id
    }),
    return: Error(CredentialNotAllowed),
  )
  use <- bool.guard(
    when: raw_id != stored.id,
    return: Error(CredentialNotAllowed),
  )
  Ok(Nil)
}

// Sign count 0 means the authenticator does not track signature counts. Accept
// any new value when stored is 0. Reject when new drops to 0 but stored was
// non-zero (possible cloned key).
fn check_sign_count(stored: Int, new: Int) -> Result(Nil, Error) {
  let ok = case stored, new {
    0, _ -> True
    _, 0 -> False
    _, _ -> new > stored
  }
  case ok {
    True -> Ok(Nil)
    False -> Error(SignCountRegression)
  }
}

/// Convenience wrapper around [`verify`](#verify) for callers whose response
/// arrives as a raw JSON string: parses with `parse_response_json` then
/// verifies.
pub fn verify_json(
  response_json response_json: String,
  challenge challenge: Challenge,
  stored stored: glasslock.Credential,
) -> Result(glasslock.Credential, Error) {
  use response <- result.try(parse_response_json(response_json))
  verify(response:, challenge:, stored:)
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
