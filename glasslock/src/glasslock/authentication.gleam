//// WebAuthn authentication ceremony: generate options and verify responses.
////
//// ## Example (known credential)
////
//// ```gleam
//// import glasslock/authentication
////
//// // Generate options for browser
//// let #(options_json, challenge) = authentication.generate_options(
////   authentication.Options(
////     rp_id: "example.com",
////     origins: ["https://example.com"],
////     allow_credentials: [stored_credential.id],
////     ..authentication.default_options()
////   ),
//// )
////
//// // Send options_json to browser, receive response_json back
////
//// // Verify the response
//// case authentication.verify(response_json:, challenge:, stored: stored_credential) {
////   Ok(updated_credential) -> // Update stored sign_count
////   Error(e) -> // Handle error
//// }
//// ```
////
//// ## Example (discoverable/passkey)
////
//// ```gleam
//// // Generate options with empty allow_credentials
//// let #(options_json, challenge) = authentication.generate_options(
////   authentication.Options(
////     rp_id: "example.com",
////     origins: ["https://example.com"],
////     allow_credentials: [],
////     ..authentication.default_options()
////   ),
//// )
////
//// // Parse response to get credential_id for lookup
//// case authentication.parse_response(response_json) {
////   Ok(info) -> {
////     // Look up stored credential by info.credential_id
////     case lookup_credential(info.credential_id) {
////       Ok(stored) ->
////         case authentication.verify(response_json:, challenge:, stored:) {
////           Ok(updated) -> // Update stored sign_count
////           Error(e) -> // Handle verification error
////         }
////       Error(e) -> // Handle lookup error
////     }
////   }
////   Error(e) -> // Handle parse error
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
import kryptos/crypto
import kryptos/hash

/// Options for authentication challenge generation.
pub type Options {
  Options(
    /// Relying party identifier (e.g., `"example.com"`).
    rp_id: String,
    /// Allow-list of acceptable origins (e.g., `["https://example.com"]`).
    /// The authenticator-signed `clientDataJSON.origin` must match one entry.
    origins: List(String),
    /// Timeout in milliseconds for the ceremony. Defaults to 60000.
    timeout: Int,
    /// User verification requirement. Defaults to preferred.
    user_verification: glasslock.UserVerification,
    /// User presence requirement. Defaults to required.
    user_presence: glasslock.UserPresence,
    /// Whether to allow cross-origin requests. Defaults to `False`.
    allow_cross_origin: Bool,
    /// Credential IDs the user may authenticate with. Empty for discoverable flow.
    allow_credentials: List(glasslock.CredentialId),
    /// Allowed top-level origins for cross-origin iframe verification. Defaults to `[]`.
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

/// A finalized authentication challenge ready for verification.
pub opaque type Challenge {
  AuthenticationChallenge(
    data: internal.ChallengeData,
    allowed_credentials: List(glasslock.CredentialId),
  )
}

type ParsedResponse {
  ParsedResponse(
    raw_id: String,
    credential_type: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option(String),
  )
}

/// Get the challenge bytes from the challenge.
pub fn challenge_bytes(challenge: Challenge) -> BitArray {
  challenge.data.bytes
}

/// Get the list of expected origins from the challenge.
pub fn challenge_origins(challenge: Challenge) -> List(String) {
  set.to_list(challenge.data.origins)
}

/// Get the RP ID from the challenge.
pub fn challenge_rp_id(challenge: Challenge) -> String {
  challenge.data.rp_id
}

/// Returns default options with empty `rp_id` and `origins` values
/// that must be overridden before use.
pub fn default_options() -> Options {
  Options(
    rp_id: "",
    origins: [],
    timeout: 60_000,
    user_verification: glasslock.VerificationPreferred,
    user_presence: glasslock.PresenceRequired,
    allow_cross_origin: False,
    allow_credentials: [],
    allowed_top_origins: [],
  )
}

/// Generate authentication options and a challenge verifier.
///
/// The first element is a `PublicKeyCredentialRequestOptionsJSON` value
/// ready to serialise with `gleam/json.to_string` or embed inside a
/// response envelope. The second is the verifier to pass to `verify`.
pub fn generate_options(options: Options) -> #(Json, Challenge) {
  let challenge_bytes = crypto.random_bytes(32)
  let challenge_b64 = bit_array.base64_url_encode(challenge_bytes, False)

  let options_json =
    json.object(
      [
        #("challenge", json.string(challenge_b64)),
        #("rpId", json.string(options.rp_id)),
        #("timeout", json.int(options.timeout)),
        #(
          "userVerification",
          json.string(internal.user_verification_to_string(
            options.user_verification,
          )),
        ),
      ]
      |> internal.maybe_add_credential_descriptors(
        key: "allowCredentials",
        credentials: options.allow_credentials,
      ),
    )

  let challenge =
    AuthenticationChallenge(
      data: internal.ChallengeData(
        bytes: challenge_bytes,
        origins: set.from_list(options.origins),
        rp_id: options.rp_id,
        user_verification: options.user_verification,
        user_presence: options.user_presence,
        allow_cross_origin: options.allow_cross_origin,
        allowed_top_origins: options.allowed_top_origins,
      ),
      allowed_credentials: options.allow_credentials,
    )

  #(options_json, challenge)
}

/// Parse response JSON to get credential_id/user_handle for lookup (discoverable flow).
///
/// Call this first, look up the stored credential, then call verify().
pub fn parse_response(
  response_json: String,
) -> Result(ResponseInfo, glasslock.Error) {
  use response <- result.try(parse_response_json(response_json))
  use credential_id <- result.try(internal.decode_base64url(
    response.raw_id,
    "rawId",
  ))

  internal.decode_optional_base64url(response.user_handle, "userHandle")
  |> result.map(ResponseInfo(glasslock.CredentialId(credential_id), _))
}

/// Verify a challenge response from the browser.
///
/// Takes the JSON response string from the browser, the challenge from `generate_options()`,
/// and the stored credential to verify against.
///
/// For discoverable flow: call `parse_response()` first to get credential_id for lookup.
///
/// Returns an updated credential with the new sign count on success.
pub fn verify(
  response_json response_json: String,
  challenge challenge: Challenge,
  stored stored: glasslock.Credential,
) -> Result(glasslock.Credential, glasslock.Error) {
  use response <- result.try(parse_response_json(response_json))

  use credential_id <- result.try(internal.decode_base64url(
    response.raw_id,
    "rawId",
  ))
  use client_data_json <- result.try(internal.decode_base64url(
    response.client_data_json,
    "clientDataJSON",
  ))
  use authenticator_data <- result.try(internal.decode_base64url(
    response.authenticator_data,
    "authenticatorData",
  ))
  use signature <- result.try(internal.decode_base64url(
    response.signature,
    "signature",
  ))

  use <- bool.guard(
    when: response.credential_type != "public-key",
    return: Error(glasslock.VerificationMismatch(glasslock.CredentialTypeField)),
  )

  // When `allow_credentials` is non-empty the presented ID must appear
  // in it; separately, the presented ID must match the stored credential
  // the caller looked up. Both are required: the allow-list enforces the
  // RP's policy, and the stored-ID match prevents using one credential's
  // response to authenticate as another.
  use <- bool.guard(
    when: !list.is_empty(challenge.allowed_credentials)
      && !list.contains(
      challenge.allowed_credentials,
      glasslock.CredentialId(credential_id),
    ),
    return: Error(glasslock.CredentialNotAllowed),
  )
  use <- bool.guard(
    when: glasslock.CredentialId(credential_id) != stored.id,
    return: Error(glasslock.CredentialNotAllowed),
  )

  use client_data <- result.try(internal.parse_client_data(client_data_json))
  use _ <- result.try(internal.verify_client_data(
    client_data:,
    expected_type: "webauthn.get",
    expected_challenge: challenge.data.bytes,
    expected_origins: challenge.data.origins,
    allow_cross_origin: challenge.data.allow_cross_origin,
    allowed_top_origins: challenge.data.allowed_top_origins,
  ))

  use client_data_hash <- result.try(
    crypto.hash(hash.Sha256, client_data_json)
    |> result.replace_error(glasslock.ParseError("Failed to hash client data")),
  )

  use auth_data <- result.try(internal.parse_authentication_auth_data(
    authenticator_data,
  ))

  use _ <- result.try(internal.verify_rp_id(
    auth_data.rp_id_hash,
    challenge.data.rp_id,
  ))
  use _ <- result.try(internal.verify_user_policies(
    auth_data.user_present,
    auth_data.user_verified,
    challenge.data.user_presence,
    challenge.data.user_verification,
  ))

  let signed_data = bit_array.concat([authenticator_data, client_data_hash])
  let glasslock.PublicKey(public_key_cbor) = stored.public_key
  use #(parsed_key, alg) <- result.try(internal.parse_public_key(
    public_key_cbor,
  ))
  use _ <- result.try(internal.verify_signature(
    key: parsed_key,
    alg:,
    message: signed_data,
    signature:,
  ))

  // Sign count 0 means the authenticator does not track signature counts.
  // Accept any new value when stored is 0. Reject when new drops to 0 but
  // stored was non-zero (possible cloned key).
  let sign_count_ok = case stored.sign_count, auth_data.sign_count {
    0, _ -> True
    _, 0 -> False
    _, _ -> auth_data.sign_count > stored.sign_count
  }
  use <- bool.guard(
    when: !sign_count_ok,
    return: Error(glasslock.SignCountRegression),
  )

  Ok(glasslock.Credential(..stored, sign_count: auth_data.sign_count))
}

fn parse_response_json(
  json_string: String,
) -> Result(ParsedResponse, glasslock.Error) {
  let response_decoder = {
    use client_data_json <- decode.field("clientDataJSON", decode.string)
    use authenticator_data <- decode.field("authenticatorData", decode.string)
    use signature <- decode.field("signature", decode.string)
    use user_handle <- decode.optional_field(
      "userHandle",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(#(
      client_data_json,
      authenticator_data,
      signature,
      user_handle,
    ))
  }

  let decoder = {
    use raw_id <- decode.field("rawId", decode.string)
    use credential_type <- decode.field("type", decode.string)
    use #(client_data_json, authenticator_data, signature, user_handle) <- decode.field(
      "response",
      response_decoder,
    )
    decode.success(ParsedResponse(
      raw_id:,
      credential_type:,
      client_data_json:,
      authenticator_data:,
      signature:,
      user_handle:,
    ))
  }

  json.parse(json_string, decoder)
  |> result.replace_error(glasslock.ParseError(
    "Invalid authentication response JSON",
  ))
}
