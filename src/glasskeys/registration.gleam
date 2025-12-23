//// Builder and verification API for WebAuthn registration.
////
//// ## Example
////
//// ```gleam
//// import glasskeys
//// import glasskeys/registration
////
//// // Build a challenge
//// let #(challenge_b64, verifier) =
////   registration.new()
////   |> registration.origin("https://example.com")
////   |> registration.rp_id("example.com")
////   |> registration.user_verification(glasskeys.VerificationRequired)
////   |> registration.build()
////
//// // Later, verify the response
//// case registration.verify(
////   attestation_object: attestation_object,
////   client_data_json: client_data_json,
////   challenge: verifier,
//// ) {
////   Ok(credential) -> // Store credential
////   Error(e) -> // Handle error
//// }
//// ```

import glasskeys.{
  type Credential, type GlasskeysError, type Has, type Missing,
  type UserPresence, type UserVerification, Credential, ParseError,
  PresenceRequired, UserPresenceFailed, UserVerificationFailed,
  VerificationMismatch, VerificationPreferred, VerificationRequired,
}
import glasskeys/internal
import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/option.{None, Some}
import gleam/result

/// Builder for configuring a WebAuthn registration challenge.
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
    user_verification: UserVerification,
    user_presence: UserPresence,
    allow_cross_origin: Bool,
  )
}

/// A finalized registration challenge ready for verification.
///
/// This is the type passed to `verify()` after calling `build()`.
pub type Challenge {
  Challenge(
    bytes: BitArray,
    origin: String,
    rp_id: String,
    user_verification: UserVerification,
    user_presence: UserPresence,
    allow_cross_origin: Bool,
  )
}

/// Create a new registration challenge builder with a random 32-byte challenge.
/// Origin and rp_id must be set before calling build().
pub fn new() -> Builder(Missing, Missing) {
  Builder(
    bytes: crypto.strong_random_bytes(32),
    origin: "",
    rp_id: "",
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
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
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
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
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
    user_presence: user_presence,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
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
    user_verification: user_verification,
    allow_cross_origin: allow_cross_origin,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
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
    user_verification: user_verification,
    user_presence: user_presence,
    ..,
  ) = builder
  Builder(
    bytes: bytes,
    origin: origin,
    rp_id: rp_id,
    user_verification: user_verification,
    user_presence: user_presence,
    allow_cross_origin: allow,
  )
}

/// Verify a WebAuthn registration response.
///
/// Takes the attestation object and client data JSON from the browser,
/// along with the challenge verifier from `build()`.
///
/// Returns the verified credential on success, which should be stored
/// for future authentication.
pub fn verify(
  attestation_object attestation_object: BitArray,
  client_data_json client_data_json: BitArray,
  challenge challenge: Challenge,
) -> Result(Credential, GlasskeysError) {
  use cd <- result.try(internal.parse_client_data(client_data_json))
  use <- bool.guard(
    when: cd.typ != "webauthn.create",
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

  use attestation_obj <- result.try(internal.parse_attestation_object(
    attestation_object,
  ))
  use #(auth_data_bytes, att_stmt, fmt) <- result.try(
    internal.extract_attestation_fields(attestation_obj),
  )
  use auth_data <- result.try(internal.parse_authenticator_data(auth_data_bytes))

  let expected_rp_id_hash =
    crypto.hash(crypto.Sha256, bit_array.from_string(challenge.rp_id))
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

  use attested <- result.try(case auth_data.attested_credential {
    Some(cred) -> Ok(cred)
    None -> Error(ParseError("No attested credential in registration"))
  })

  use cose_key <- result.try(internal.parse_public_key(attested.public_key_cbor))
  let public_key = internal.cose_to_uncompressed_point(cose_key)

  use _ <- result.try(internal.verify_attestation(fmt, att_stmt))

  Ok(Credential(
    id: attested.credential_id,
    public_key: public_key,
    sign_count: auth_data.sign_count,
    user_verified: auth_data.user_verified,
  ))
}
