//// Test helpers for generating valid WebAuthn data structures.

import gbor.{CBBinary, CBInt, CBMap, CBString}
import gbor/encode as cbor_encode
import gleam/bit_array
import gleam/crypto
import gleam/json

/// Build a minimal client data JSON for testing
pub fn make_client_data_json(
  typ: String,
  challenge_b64: String,
  origin: String,
  cross_origin: Bool,
) -> BitArray {
  json.object([
    #("type", json.string(typ)),
    #("challenge", json.string(challenge_b64)),
    #("origin", json.string(origin)),
    #("crossOrigin", json.bool(cross_origin)),
  ])
  |> json.to_string
  |> bit_array.from_string
}

/// A test key pair for WebAuthn testing
pub type TestKeyPair {
  TestKeyPair(private_key: BitArray, x: BitArray, y: BitArray)
}

/// Generate a new ES256 (P-256) key pair for testing
pub fn generate_keypair() -> TestKeyPair {
  let #(private_key, x, y) = do_generate_keypair()
  TestKeyPair(private_key: private_key, x: x, y: y)
}

@external(erlang, "test_crypto_ffi", "generate_keypair")
fn do_generate_keypair() -> #(BitArray, BitArray, BitArray)

/// Load the fixed ES256 (P-256) test key pair from the fixture file
pub fn load_test_keypair() -> TestKeyPair {
  let #(private_key, x, y) =
    do_load_keypair_from_pem("test/fixtures/test-key.pem")
  TestKeyPair(private_key: private_key, x: x, y: y)
}

@external(erlang, "test_crypto_ffi", "load_keypair_from_pem")
fn do_load_keypair_from_pem(path: String) -> #(BitArray, BitArray, BitArray)

/// Sign a message using ES256 (ECDSA with P-256 and SHA-256)
/// Returns the signature in raw R||S format (64 bytes)
pub fn sign_es256(message: BitArray, private_key: BitArray) -> BitArray {
  do_sign_ecdsa_p256(message, private_key)
}

@external(erlang, "test_crypto_ffi", "sign_ecdsa_p256")
fn do_sign_ecdsa_p256(message: BitArray, private_key: BitArray) -> BitArray

/// Encode a public key in COSE EC2 format for ES256
pub fn encode_cose_key(x: BitArray, y: BitArray) -> BitArray {
  let cose_map =
    CBMap([
      #(CBInt(1), CBInt(2)),
      #(CBInt(3), CBInt(-7)),
      #(CBInt(-1), CBInt(1)),
      #(CBInt(-2), CBBinary(x)),
      #(CBInt(-3), CBBinary(y)),
    ])
  let assert Ok(bytes) = cbor_encode.to_bit_array(cose_map)
  bytes
}

/// Build authenticator data for registration (with attested credential)
pub fn build_registration_auth_data(
  rp_id: String,
  credential_id: BitArray,
  public_key_cbor: BitArray,
  sign_count: Int,
  user_present: Bool,
  user_verified: Bool,
) -> BitArray {
  let rp_id_hash = crypto.hash(crypto.Sha256, bit_array.from_string(rp_id))

  let up_flag = case user_present {
    True -> 1
    False -> 0
  }
  let uv_flag = case user_verified {
    True -> 4
    False -> 0
  }
  let at_flag = 64
  let flags = up_flag + uv_flag + at_flag

  let aaguid = <<0:128>>
  let cred_id_len = bit_array.byte_size(credential_id)

  bit_array.concat([
    rp_id_hash,
    <<flags>>,
    <<sign_count:size(32)>>,
    aaguid,
    <<cred_id_len:size(16)>>,
    credential_id,
    public_key_cbor,
  ])
}

/// Build authenticator data for authentication (no attested credential)
pub fn build_authentication_auth_data(
  rp_id: String,
  sign_count: Int,
  user_present: Bool,
  user_verified: Bool,
) -> BitArray {
  let rp_id_hash = crypto.hash(crypto.Sha256, bit_array.from_string(rp_id))

  let up_flag = case user_present {
    True -> 1
    False -> 0
  }
  let uv_flag = case user_verified {
    True -> 4
    False -> 0
  }
  let flags = up_flag + uv_flag

  bit_array.concat([rp_id_hash, <<flags>>, <<sign_count:size(32)>>])
}

/// Build attestation object with "none" attestation format
pub fn build_attestation_object_none(auth_data: BitArray) -> BitArray {
  let attestation_obj =
    CBMap([
      #(CBString("fmt"), CBString("none")),
      #(CBString("authData"), CBBinary(auth_data)),
      #(CBString("attStmt"), CBMap([])),
    ])
  let assert Ok(bytes) = cbor_encode.to_bit_array(attestation_obj)
  bytes
}

/// Build client data JSON for registration
pub fn build_client_data_json_create(
  challenge: BitArray,
  origin: String,
  cross_origin: Bool,
) -> BitArray {
  let challenge_b64 = bit_array.base64_url_encode(challenge, False)
  json.object([
    #("type", json.string("webauthn.create")),
    #("challenge", json.string(challenge_b64)),
    #("origin", json.string(origin)),
    #("crossOrigin", json.bool(cross_origin)),
  ])
  |> json.to_string
  |> bit_array.from_string
}

/// Build client data JSON for authentication
pub fn build_client_data_json_get(
  challenge: BitArray,
  origin: String,
) -> BitArray {
  let challenge_b64 = bit_array.base64_url_encode(challenge, False)
  json.object([
    #("type", json.string("webauthn.get")),
    #("challenge", json.string(challenge_b64)),
    #("origin", json.string(origin)),
  ])
  |> json.to_string
  |> bit_array.from_string
}
