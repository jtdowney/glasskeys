//// WebAuthn authentication ceremony: generate options and verify responses.
////
//// ## Example (known credential)
////
//// ```gleam
//// import glasslock/authentication
////
//// // Generate options for browser
//// let assert Ok(#(request_json, challenge)) =
////   authentication.request(
////     relying_party_id: "example.com",
////     origins: ["https://example.com"],
////     options: authentication.Options(
////       ..authentication.default_options(),
////       allow_credentials: [
////         glasslock.CredentialDescriptor(
////           id: stored_credential.id,
////           transports: stored_credential.transports,
////         ),
////       ],
////     ),
////   )
////
//// // Send request_json to browser, receive response_json back. Keep
//// // `challenge` in memory for a single-node deploy; to span processes
//// // or nodes, serialize with `authentication.encode_challenge` and
//// // hydrate it back with `authentication.parse_challenge`.
////
//// // Verify the response
//// case authentication.verify(response_json:, challenge:, stored: stored_credential) {
////   Ok(updated_credential) -> todo as "update stored sign_count"
////   Error(e) -> todo as "handle error"
//// }
//// ```
////
//// ## Example (discoverable/passkey)
////
//// ```gleam
//// // Empty allow_credentials is the default (discoverable flow)
//// let assert Ok(#(request_json, challenge)) =
////   authentication.request(
////     relying_party_id: "example.com",
////     origins: ["https://example.com"],
////     options: authentication.default_options(),
////   )
////
//// // Parse response to get credential_id for lookup. As above, keep
//// // `challenge` in memory for a single node, or round-trip through
//// // `authentication.encode_challenge` / `authentication.parse_challenge`
//// // to span processes.
//// case authentication.parse_response(response_json) {
////   Ok(info) ->
////     case lookup_credential(info.credential_id) {
////       Ok(stored) ->
////         case authentication.verify(response_json:, challenge:, stored:) {
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

/// Optional knobs for authentication challenge generation.
pub type Options {
  Options(
    /// Timeout for the ceremony. Defaults to 1 minute.
    timeout: Duration,
    /// User verification requirement. `None` omits the field from
    /// the JSON sent to the browser; the browser applies the spec default
    /// of `preferred`.
    user_verification: Option(glasslock.UserVerification),
    /// Whether to allow cross-origin requests. Defaults to `False`.
    allow_cross_origin: Bool,
    /// Credentials the user may authenticate with. Empty for discoverable flow.
    /// Build each entry from a stored `glasslock.Credential` with
    /// `glasslock.CredentialDescriptor(id:, transports:)` so transport hints
    /// are preserved; pass an empty `transports` list if not stored.
    allow_credentials: List(glasslock.CredentialDescriptor),
    /// Allowed top-level origins for cross-origin iframe verification. The
    /// allowlist is consulted only when the browser supplies a `topOrigin`
    /// field; older browsers omit the field even for cross-origin requests,
    /// in which case top-origin verification is skipped.
    /// Defaults to `[]`.
    allowed_top_origins: List(String),
  )
}

/// Parsed credential lookup info from response (for discoverable flow).
pub type ResponseInfo {
  ResponseInfo(
    credential_id: glasslock.CredentialId,
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

/// A finalized authentication challenge ready for verification.
pub opaque type Challenge {
  Challenge(
    data: internal.ChallengeData,
    allowed_credentials: List(glasslock.CredentialDescriptor),
  )
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
    json.array(challenge.allowed_credentials, fn(descriptor) {
      let glasslock.CredentialDescriptor(id:, transports:) = descriptor
      let glasslock.CredentialId(raw) = id
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
) -> List(glasslock.CredentialDescriptor) {
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
) -> Result(List(glasslock.CredentialDescriptor), Error) {
  list.try_map(entries, fn(entry) {
    let #(id_b64, transport_strings) = entry
    use raw <- result.try(
      wrap_error(internal.decode_base64url(id_b64, "allow_credentials")),
    )
    Ok(glasslock.CredentialDescriptor(
      id: glasslock.CredentialId(raw),
      transports: list.filter_map(
        transport_strings,
        internal.transport_from_string,
      ),
    ))
  })
}

/// Returns an `Options` record with default values. With the empty
/// `allow_credentials` default, this configures the discoverable (passkey)
/// flow where the authenticator selects a credential.
pub fn default_options() -> Options {
  Options(
    timeout: duration.minutes(1),
    user_verification: option.None,
    allow_cross_origin: False,
    allow_credentials: [],
    allowed_top_origins: [],
  )
}

/// Generate authentication options and a challenge verifier.
///
/// The first element is a `PublicKeyCredentialRequestOptionsJSON` value
/// ready to serialize with `gleam/json.to_string` or embed inside a
/// response envelope. The second is the verifier to pass to `verify`.
pub fn request(
  relying_party_id relying_party_id: String,
  origins origins: List(String),
  options options: Options,
) -> Result(#(Json, Challenge), Error) {
  use <- bool.guard(
    when: list.is_empty(origins),
    return: Error(ParseError(
      "no allowed origins configured; pass a non-empty origins list to request",
    )),
  )

  let challenge_bytes = crypto.random_bytes(32)
  let challenge_b64 = bit_array.base64_url_encode(challenge_bytes, False)

  let options_json =
    json.object(
      [
        #("challenge", json.string(challenge_b64)),
        #("rpId", json.string(relying_party_id)),
        #("timeout", json.int(duration.to_milliseconds(options.timeout))),
      ]
      |> maybe_add_user_verification(options.user_verification)
      |> internal.maybe_add_credential_descriptors(
        key: "allowCredentials",
        credentials: options.allow_credentials,
      ),
    )

  let challenge =
    Challenge(
      data: internal.ChallengeData(
        bytes: challenge_bytes,
        origins: set.from_list(origins),
        rp_id: relying_party_id,
        user_verification: option.unwrap(
          options.user_verification,
          glasslock.VerificationPreferred,
        ),
        allow_cross_origin: options.allow_cross_origin,
        allowed_top_origins: options.allowed_top_origins,
      ),
      allowed_credentials: options.allow_credentials,
    )

  Ok(#(options_json, challenge))
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

/// Parse response JSON to get credential_id/user_handle for lookup (discoverable flow).
///
/// Call this first, look up the stored credential, then call verify().
pub fn parse_response(response_json: String) -> Result(ResponseInfo, Error) {
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

  internal.decode_optional_base64url(response.user_handle, "userHandle")
  |> result.map(ResponseInfo(glasslock.CredentialId(raw_id), _))
  |> wrap_error
}

/// Verify a challenge response from the browser.
///
/// Takes the JSON response string from the browser, the challenge from `request()`,
/// and the stored credential to verify against.
///
/// For discoverable flow: call `parse_response()` first to get credential_id for lookup.
///
/// Returns an updated credential with the new sign count on success.
pub fn verify(
  response_json response_json: String,
  challenge challenge: Challenge,
  stored stored: glasslock.Credential,
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

  // When `allow_credentials` is non-empty the presented ID must appear
  // in it; separately, the presented ID must match the stored credential
  // the caller looked up. Both are required: the allow-list enforces the
  // RP's policy, and the stored-ID match prevents using one credential's
  // response to authenticate as another.
  let presented_id = glasslock.CredentialId(raw_id)
  use <- bool.guard(
    when: !list.is_empty(challenge.allowed_credentials)
      && !list.any(challenge.allowed_credentials, fn(d) { d.id == presented_id }),
    return: Error(CredentialNotAllowed),
  )
  use <- bool.guard(
    when: glasslock.CredentialId(raw_id) != stored.id,
    return: Error(CredentialNotAllowed),
  )

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
  let glasslock.PublicKey(public_key_cbor) = stored.public_key
  use #(parsed_key, alg) <- result.try(
    wrap_error(internal.parse_public_key(public_key_cbor)),
  )
  use _ <- result.try(
    wrap_error(internal.verify_signature(
      parsed_key,
      alg:,
      message: signed_data,
      signature:,
    )),
  )

  // Sign count 0 means the authenticator does not track signature counts.
  // Accept any new value when stored is 0. Reject when new drops to 0 but
  // stored was non-zero (possible cloned key).
  let sign_count_ok = case stored.sign_count, auth_data.sign_count {
    0, _ -> True
    _, 0 -> False
    _, _ -> auth_data.sign_count > stored.sign_count
  }
  use <- bool.guard(when: !sign_count_ok, return: Error(SignCountRegression))

  Ok(glasslock.Credential(..stored, sign_count: auth_data.sign_count))
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
    decode.success(ParsedResponse(
      raw_id:,
      credential_id:,
      credential_type:,
      client_data_json:,
      authenticator_data:,
      signature:,
      user_handle:,
    ))
  }

  json.parse(json_string, decoder)
  |> result.replace_error(ParseError("Invalid authentication response JSON"))
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
