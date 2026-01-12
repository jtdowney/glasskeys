//// Builder and verification API for WebAuthn authentication.
////
//// ## Example
////
//// ```gleam
//// import glasskeys
//// import glasskeys/authentication
////
//// // Build a challenge
//// let #(challenge_b64, verifier) =
////   authentication.new()
////   |> authentication.origin("https://example.com")
////   |> authentication.rp_id("example.com")
////   |> authentication.allowed_credentials([stored_credential_id])
////   |> authentication.build()
////
//// // Later, verify the response
//// case authentication.verify(
////   authenticator_data: authenticator_data,
////   client_data_json: client_data_json,
////   signature: signature,
////   credential_id: credential_id,
////   challenge: verifier,
////   stored: stored_credential,
//// ) {
////   Ok(updated_credential) -> // Update stored sign_count
////   Error(e) -> // Handle error
//// }
//// ```

import glasskeys.{
  type Credential, type CredentialId, type GlasskeysError, type Has,
  type Missing, type UserPresence, type UserVerification, Credential,
  CredentialNotAllowed, ParseError, PresenceRequired, SignCountRegression,
  UserPresenceFailed, UserVerificationFailed, VerificationMismatch,
  VerificationPreferred, VerificationRequired,
}
import glasskeys/internal
import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/option
import gleam/result
import kryptos/crypto
import kryptos/hash

/// Builder for configuring a WebAuthn authentication challenge.
///
/// The type parameters track which required fields have been set:
/// - First parameter: whether `origin` has been set
/// - Second parameter: whether `rp_id` has been set
///
/// Use `new()` to create, configure with builder functions, and call `build()`
/// when both origin and rp_id are configured.
pub opaque type Builder(origin, rp_id) {
  Builder(
    bytes: BitArray,
    origin: String,
    rp_id: String,
    allowed_credentials: List(CredentialId),
    user_verification: UserVerification,
    user_presence: UserPresence,
    allow_cross_origin: Bool,
  )
}

/// A finalized authentication challenge ready for verification.
///
/// This is the type passed to `verify()` after calling `build()`.
pub type Challenge {
  Challenge(
    bytes: BitArray,
    origin: String,
    rp_id: String,
    allowed_credentials: List(CredentialId),
    user_verification: UserVerification,
    user_presence: UserPresence,
    allow_cross_origin: Bool,
  )
}

/// Create a new authentication challenge builder with a random 32-byte challenge.
/// Origin and rp_id must be set before calling build().
pub fn new() -> Builder(Missing, Missing) {
  Builder(
    bytes: crypto.random_bytes(32),
    origin: "",
    rp_id: "",
    allowed_credentials: [],
    user_verification: VerificationPreferred,
    user_presence: PresenceRequired,
    allow_cross_origin: False,
  )
}

/// Finalize the challenge and return a tuple of (base64url-encoded challenge, verifier).
/// Send the base64url string to the browser; keep the verifier for verification.
///
/// This function only accepts a Builder where both origin and rp_id are set.
/// Attempting to call build() without setting both fields is a compile-time error.
pub fn build(builder: Builder(Has, Has)) -> #(String, Challenge) {
  let Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
  ) = builder

  let encoded = bit_array.base64_url_encode(bytes, False)
  let challenge =
    Challenge(
      bytes: bytes,
      origin: origin,
      rp_id: rp_id,
      allowed_credentials: allowed_credentials,
      user_verification: user_verification,
      user_presence: user_presence,
      allow_cross_origin: allow_cross_origin,
    )
  #(encoded, challenge)
}

/// Set the expected origin (e.g., "https://example.com").
pub fn origin(builder: Builder(o, r), origin: String) -> Builder(Has, r) {
  let Builder(
    bytes: bytes,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
  )
}

/// Set the relying party ID (e.g., "example.com").
pub fn rp_id(builder: Builder(o, r), rp_id: String) -> Builder(o, Has) {
  let Builder(
    bytes: bytes,
    origin: origin,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
  )
}

/// Set the list of allowed credential IDs.
/// Can be called at any point in the builder chain.
pub fn allowed_credentials(
  builder: Builder(o, r),
  creds: List(CredentialId),
) -> Builder(o, r) {
  let Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: creds,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
  )
}

/// Set the user verification requirement.
/// Can be called at any point in the builder chain.
pub fn user_verification(
  builder: Builder(o, r),
  uv: UserVerification,
) -> Builder(o, r) {
  let Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: uv,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
  )
}

/// Set the user presence requirement.
/// Can be called at any point in the builder chain.
pub fn user_presence(builder: Builder(o, r), up: UserPresence) -> Builder(o, r) {
  let Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    user_presence: up,
    allow_cross_origin: allow_cross_origin,
  )
}

/// Allow or disallow cross-origin requests.
/// Defaults to False (reject cross-origin requests).
/// Can be called at any point in the builder chain.
pub fn allow_cross_origin(builder: Builder(o, r), allow: Bool) -> Builder(o, r) {
  let Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    user_presence: user_presence,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    allowed_credentials: allowed_credentials,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow,
  )
}

/// Verify a WebAuthn authentication response.
///
/// Takes the authenticator data, client data JSON, and signature from the browser,
/// along with the credential ID, challenge verifier from `build()`, and the
/// stored credential.
///
/// Returns an updated credential with the new sign count on success.
pub fn verify(
  authenticator_data authenticator_data: BitArray,
  client_data_json client_data_json: BitArray,
  signature signature: BitArray,
  credential_id credential_id: BitArray,
  challenge challenge: Challenge,
  stored stored: Credential,
) -> Result(Credential, GlasskeysError) {
  use <- bool.guard(
    when: !list.is_empty(challenge.allowed_credentials)
      && !list.contains(challenge.allowed_credentials, credential_id),
    return: Error(CredentialNotAllowed),
  )
  use <- bool.guard(
    when: credential_id != stored.id,
    return: Error(CredentialNotAllowed),
  )

  use cd <- result.try(internal.parse_client_data(client_data_json))
  use <- bool.guard(
    when: cd.typ != "webauthn.get",
    return: Error(VerificationMismatch("type")),
  )
  use <- bool.guard(
    when: cd.challenge != challenge.bytes,
    return: Error(VerificationMismatch("challenge")),
  )
  use <- bool.guard(
    when: cd.origin != challenge.origin,
    return: Error(VerificationMismatch("origin")),
  )
  use <- bool.guard(
    when: cd.cross_origin && !challenge.allow_cross_origin,
    return: Error(VerificationMismatch("cross_origin")),
  )

  let assert Ok(client_data_hash) = crypto.hash(hash.Sha256, client_data_json)

  use auth_data <- result.try(internal.parse_authenticator_data(
    authenticator_data,
  ))

  use <- bool.guard(
    when: option.is_some(auth_data.attested_credential),
    return: Error(ParseError("AT flag should not be set in authentication")),
  )

  let assert Ok(expected_rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string(challenge.rp_id))
  use <- bool.guard(
    when: auth_data.rp_id_hash != expected_rp_id_hash,
    return: Error(VerificationMismatch("rp_id")),
  )

  let verification_ok = case challenge.user_verification {
    VerificationRequired -> auth_data.user_verified
    _ -> True
  }
  use <- bool.guard(
    when: !verification_ok,
    return: Error(UserVerificationFailed),
  )

  let presence_ok = case challenge.user_presence {
    PresenceRequired -> auth_data.user_present
    _ -> True
  }
  use <- bool.guard(when: !presence_ok, return: Error(UserPresenceFailed))

  let signed_data = bit_array.concat([authenticator_data, client_data_hash])
  use _ <- result.try(internal.verify_es256(
    stored.public_key,
    signed_data,
    signature,
  ))

  let sign_count_ok = case stored.sign_count, auth_data.sign_count {
    0, 0 -> True
    0, _ -> True
    _, 0 -> False
    _, _ -> auth_data.sign_count > stored.sign_count
  }
  use <- bool.guard(when: !sign_count_ok, return: Error(SignCountRegression))

  Ok(
    Credential(
      ..stored,
      sign_count: auth_data.sign_count,
      user_verified: auth_data.user_verified,
    ),
  )
}
