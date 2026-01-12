//// Test utilities for WebAuthn/FIDO2 credential verification.
////
//// This module provides helpers for generating test data in unit and
//// integration tests. It exposes both high-level builders for common
//// scenarios and low-level building blocks for edge cases.
////
//// **This module is for testing only.** It should not be used in
//// production code.
////
//// ## Quick Start
////
//// For a simple registration test:
////
//// ```gleam
//// import glasskeys/registration
//// import glasskeys/testing
////
//// pub fn registration_test() {
////   let #(_, challenge) = registration.new()
////     |> registration.origin("https://example.com")
////     |> registration.rp_id("example.com")
////     |> registration.build()
////
////   let response = testing.build_registration_response(challenge: challenge)
////
////   let assert Ok(credential) = registration.verify(
////     attestation_object: response.attestation_object,
////     client_data_json: response.client_data_json,
////     challenge: challenge,
////   )
//// }
//// ```

import gbor.{CBBinary, CBInt, CBMap, CBString}
import gbor/encode as cbor_encode
import glasskeys.{type Credential, type CredentialId, type PublicKey}
import glasskeys/authentication
import glasskeys/registration
import gleam/bit_array
import gleam/json
import kryptos/crypto
import kryptos/ec
import kryptos/ecdsa
import kryptos/hash

// ============================================================================
// Types
// ============================================================================

/// An ES256 (P-256) key pair for testing WebAuthn flows.
pub type KeyPair {
  KeyPair(
    /// DER-encoded private key (PKCS#8)
    private_key: BitArray,
    /// 32-byte X coordinate of public point
    x: BitArray,
    /// 32-byte Y coordinate of public point
    y: BitArray,
  )
}

/// Authenticator flags for building authenticator data.
pub type AuthenticatorFlags {
  AuthenticatorFlags(
    /// User presence (UP) flag - user touched/interacted with authenticator
    user_present: Bool,
    /// User verified (UV) flag - biometric/PIN verification performed
    user_verified: Bool,
  )
}

/// Complete response data for a registration ceremony.
pub type RegistrationResponse {
  RegistrationResponse(
    /// CBOR-encoded attestation object
    attestation_object: BitArray,
    /// UTF-8 encoded client data JSON
    client_data_json: BitArray,
    /// The credential ID generated for this registration
    credential_id: CredentialId,
    /// The key pair used (needed for subsequent authentication tests)
    keypair: KeyPair,
  )
}

/// Complete response data for an authentication ceremony.
pub type AuthenticationResponse {
  AuthenticationResponse(
    /// Binary authenticator data
    authenticator_data: BitArray,
    /// UTF-8 encoded client data JSON
    client_data_json: BitArray,
    /// ES256 signature over authenticator data + client data hash
    signature: BitArray,
  )
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a new random ES256 (P-256) key pair.
pub fn generate_keypair() -> KeyPair {
  let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
  let assert <<4, x:bytes-size(32), y:bytes-size(32)>> =
    ec.public_key_to_raw_point(public_key)
  let assert Ok(der) = ec.to_der(private_key)
  KeyPair(private_key: der, x: x, y: y)
}

/// Get the public key in uncompressed point format (0x04 || X || Y).
/// This is the format stored in `Credential.public_key`.
pub fn public_key(keypair: KeyPair) -> PublicKey {
  bit_array.concat([<<4>>, keypair.x, keypair.y])
}

/// Get the public key in COSE EC2 CBOR format.
/// This is the format embedded in authenticator data during registration.
pub fn cose_key(keypair: KeyPair) -> BitArray {
  let cose_map =
    CBMap([
      #(CBInt(1), CBInt(2)),
      #(CBInt(3), CBInt(-7)),
      #(CBInt(-1), CBInt(1)),
      #(CBInt(-2), CBBinary(keypair.x)),
      #(CBInt(-3), CBBinary(keypair.y)),
    ])
  let assert Ok(bytes) = cbor_encode.to_bit_array(cose_map)
  bytes
}

// ============================================================================
// Signing
// ============================================================================

/// Sign a message using ES256 (ECDSA with P-256 and SHA-256).
/// Returns signature in raw R||S format (64 bytes).
pub fn sign(keypair: KeyPair, message: BitArray) -> BitArray {
  let assert Ok(#(private_key, _)) = ec.from_der(keypair.private_key)
  let der_sig = ecdsa.sign(private_key, message, hash.Sha256)
  der_to_raw(der_sig)
}

fn der_to_raw(der: BitArray) -> BitArray {
  let assert <<0x30, _len, 0x02, r_len, rest:bytes>> = der
  let assert <<r:bytes-size(r_len), 0x02, s_len, s:bytes-size(s_len)>> = rest
  bit_array.concat([pad_to_32(r), pad_to_32(s)])
}

fn pad_to_32(bytes: BitArray) -> BitArray {
  let size = bit_array.byte_size(bytes)
  case size {
    s if s > 32 -> {
      let assert <<0, trimmed:bytes-size(32)>> = bytes
      trimmed
    }
    s if s < 32 -> {
      let padding = <<0:size({ { 32 - s } * 8 })>>
      bit_array.concat([padding, bytes])
    }
    _ -> bytes
  }
}

// ============================================================================
// Flags
// ============================================================================

/// Create default authenticator flags (user_present: True, user_verified: False).
pub fn default_flags() -> AuthenticatorFlags {
  AuthenticatorFlags(user_present: True, user_verified: False)
}

// ============================================================================
// High-Level Builders
// ============================================================================

/// Build a complete registration response for the given challenge.
///
/// This generates a fresh keypair and credential ID, building all the
/// binary structures needed for `registration.verify()`.
pub fn build_registration_response(
  challenge challenge: registration.Challenge,
) -> RegistrationResponse {
  let keypair = generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let cose = cose_key(keypair)
  let flags = default_flags()

  let auth_data =
    build_registration_authenticator_data(
      rp_id: challenge.rp_id,
      credential_id: credential_id,
      cose_key: cose,
      flags: flags,
      sign_count: 0,
    )

  let attestation_object = build_attestation_object(auth_data)
  let client_data_json =
    build_client_data_create(
      challenge: challenge.bytes,
      origin: challenge.origin,
      cross_origin: False,
    )

  RegistrationResponse(
    attestation_object: attestation_object,
    client_data_json: client_data_json,
    credential_id: credential_id,
    keypair: keypair,
  )
}

/// Build a complete authentication response for the given challenge and credential.
///
/// Uses the keypair to generate a valid signature.
pub fn build_authentication_response(
  challenge challenge: authentication.Challenge,
  credential credential: Credential,
  keypair keypair: KeyPair,
  sign_count sign_count: Int,
) -> AuthenticationResponse {
  let flags = default_flags()

  let auth_data =
    build_authentication_authenticator_data(
      rp_id: challenge.rp_id,
      flags: flags,
      sign_count: sign_count,
    )

  let client_data_json =
    build_client_data_get(
      challenge: challenge.bytes,
      origin: challenge.origin,
      cross_origin: False,
    )

  let assert Ok(client_data_hash) = crypto.hash(hash.Sha256, client_data_json)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = sign(keypair, signed_data)

  let _ = credential

  AuthenticationResponse(
    authenticator_data: auth_data,
    client_data_json: client_data_json,
    signature: signature,
  )
}

// ============================================================================
// Low-Level Building Blocks
// ============================================================================

/// Build client data JSON for registration.
///
/// Parameters allow constructing invalid data for error testing:
/// - Use a different `origin` to test origin mismatch
/// - Use a different `challenge` to test challenge mismatch
/// - Set `cross_origin: True` with a challenge that disallows it
pub fn build_client_data_create(
  challenge challenge: BitArray,
  origin origin: String,
  cross_origin cross_origin: Bool,
) -> BitArray {
  build_client_data(
    typ: "webauthn.create",
    challenge: challenge,
    origin: origin,
    cross_origin: cross_origin,
  )
}

/// Build client data JSON for authentication.
pub fn build_client_data_get(
  challenge challenge: BitArray,
  origin origin: String,
  cross_origin cross_origin: Bool,
) -> BitArray {
  build_client_data(
    typ: "webauthn.get",
    challenge: challenge,
    origin: origin,
    cross_origin: cross_origin,
  )
}

/// Build client data JSON with a custom type field.
/// Useful for testing type mismatch errors.
pub fn build_client_data(
  typ typ: String,
  challenge challenge: BitArray,
  origin origin: String,
  cross_origin cross_origin: Bool,
) -> BitArray {
  let challenge_b64 = bit_array.base64_url_encode(challenge, False)
  json.object([
    #("type", json.string(typ)),
    #("challenge", json.string(challenge_b64)),
    #("origin", json.string(origin)),
    #("crossOrigin", json.bool(cross_origin)),
  ])
  |> json.to_string
  |> bit_array.from_string
}

/// Build authenticator data for registration (includes attested credential).
///
/// Parameters:
/// - `rp_id`: The relying party ID (used to compute rp_id_hash)
/// - `credential_id`: Arbitrary bytes for the credential ID
/// - `cose_key`: Public key in COSE format (use `cose_key(keypair)`)
/// - `flags`: User presence and verification flags
/// - `sign_count`: The signature counter value
pub fn build_registration_authenticator_data(
  rp_id rp_id: String,
  credential_id credential_id: CredentialId,
  cose_key cose_key: BitArray,
  flags flags: AuthenticatorFlags,
  sign_count sign_count: Int,
) -> BitArray {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string(rp_id))
  let flags_byte = encode_flags(flags, True)
  let aaguid = <<0:128>>
  let cred_id_len = bit_array.byte_size(credential_id)

  bit_array.concat([
    rp_id_hash,
    <<flags_byte>>,
    <<sign_count:size(32)>>,
    aaguid,
    <<cred_id_len:size(16)>>,
    credential_id,
    cose_key,
  ])
}

/// Build authenticator data for authentication (no attested credential).
pub fn build_authentication_authenticator_data(
  rp_id rp_id: String,
  flags flags: AuthenticatorFlags,
  sign_count sign_count: Int,
) -> BitArray {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string(rp_id))
  let flags_byte = encode_flags(flags, False)

  bit_array.concat([rp_id_hash, <<flags_byte>>, <<sign_count:size(32)>>])
}

/// Build an attestation object with "none" attestation format.
///
/// This is the only attestation format currently supported by glasskeys.
pub fn build_attestation_object(auth_data: BitArray) -> BitArray {
  let attestation_obj =
    CBMap([
      #(CBString("fmt"), CBString("none")),
      #(CBString("authData"), CBBinary(auth_data)),
      #(CBString("attStmt"), CBMap([])),
    ])
  let assert Ok(bytes) = cbor_encode.to_bit_array(attestation_obj)
  bytes
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn encode_flags(flags: AuthenticatorFlags, has_attested_credential: Bool) -> Int {
  let up = case flags.user_present {
    True -> 0x01
    False -> 0
  }
  let uv = case flags.user_verified {
    True -> 0x04
    False -> 0
  }
  let at = case has_attested_credential {
    True -> 0x40
    False -> 0
  }
  up + uv + at
}
