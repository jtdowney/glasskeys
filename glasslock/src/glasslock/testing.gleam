//// Helpers for generating WebAuthn/FIDO2 test data in unit and
//// integration tests. Exposes high-level builders for common
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
//// import glasslock/registration
//// import glasslock/testing
////
//// pub fn registration_test() {
////   let #(_, challenge) =
////     registration.new(
////       relying_party: registration.RelyingParty(id: "example.com", name: "Test"),
////       user: registration.User(id: <<1, 2, 3>>, name: "test", display_name: "Test"),
////       origin: "https://example.com",
////     )
////     |> registration.build()
////
////   let response = testing.build_registration_response(challenge: challenge)
////   let response_json = testing.to_registration_json(response)
////
////   let assert Ok(credential) = registration.verify_json(response_json:, challenge:)
//// }
//// ```

import glasslock
import glasslock/authentication
import glasslock/internal
import glasslock/internal/cbor
import glasslock/registration
import gleam/bit_array
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/set
import gose
import gose/cose
import kryptos/crypto
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash
import kryptos/rsa

/// Complete response data for an authentication ceremony.
pub type AuthenticationResponse {
  AuthenticationResponse(
    authenticator_data: BitArray,
    /// UTF-8 encoded client data JSON.
    client_data_json: BitArray,
    /// Signature over `authenticator_data || SHA-256(client_data_json)`.
    signature: BitArray,
  )
}

/// Authenticator flags for building authenticator data.
pub type AuthenticatorFlags {
  AuthenticatorFlags(
    /// WebAuthn UP (user presence) flag: the user touched or interacted
    /// with the authenticator.
    user_present: Bool,
    /// WebAuthn UV (user verification) flag: the authenticator performed
    /// biometric or PIN verification.
    user_verified: Bool,
  )
}

/// A COSE key pair for testing WebAuthn flows.
pub type KeyPair {
  KeyPair(key: cose.Key, alg: gose.DigitalSignatureAlg)
}

/// Complete response data for a registration ceremony.
pub type RegistrationResponse {
  RegistrationResponse(
    /// CBOR-encoded attestation object.
    attestation_object: BitArray,
    /// UTF-8 encoded client data JSON.
    client_data_json: BitArray,
    credential_id: BitArray,
    /// Retained on the response so downstream authentication tests can
    /// reuse the same key for signing.
    keypair: KeyPair,
  )
}

/// Build authenticator data for authentication (no attested credential).
pub fn build_authentication_authenticator_data(
  relying_party_id relying_party_id: String,
  flags flags: AuthenticatorFlags,
  sign_count sign_count: Int,
) -> BitArray {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string(relying_party_id))
  let flags_byte = encode_flags(flags, has_attested_credential: False)

  bit_array.concat([rp_id_hash, <<flags_byte>>, <<sign_count:size(32)>>])
}

/// Build a complete authentication response for the given challenge.
///
/// Uses the keypair to generate a valid signature.
pub fn build_authentication_response(
  challenge challenge: authentication.Challenge,
  keypair keypair: KeyPair,
  sign_count sign_count: Int,
) -> AuthenticationResponse {
  let data = authentication.challenge_data(challenge)
  let assert Ok(origin) = list.first(set.to_list(data.origins))
  let authenticator_data =
    build_authentication_authenticator_data(
      relying_party_id: data.rp_id,
      flags: default_flags(),
      sign_count: sign_count,
    )

  let client_data_json =
    build_client_data_get(challenge: data.bytes, origin:, cross_origin: False)

  let signature =
    sign_authentication_message(
      keypair:,
      authenticator_data:,
      client_data_json:,
    )

  AuthenticationResponse(authenticator_data:, client_data_json:, signature:)
}

/// Sign an authentication message the same way a real authenticator would:
/// ECDSA/EdDSA/RSA over `authenticator_data || SHA-256(client_data_json)`.
pub fn sign_authentication_message(
  keypair keypair: KeyPair,
  authenticator_data authenticator_data: BitArray,
  client_data_json client_data_json: BitArray,
) -> BitArray {
  let assert Ok(client_data_hash) = crypto.hash(hash.Sha256, client_data_json)
  sign(
    keypair:,
    message: bit_array.concat([authenticator_data, client_data_hash]),
  )
}

/// Convert an authentication response to an AuthenticationResponseJSON string.
pub fn to_authentication_json(
  response: AuthenticationResponse,
  credential_id credential_id: BitArray,
  user_handle user_handle: Option(BitArray),
) -> String {
  to_authentication_json_with(
    credential_id:,
    authenticator_data: response.authenticator_data,
    client_data_json: response.client_data_json,
    signature: response.signature,
    user_handle:,
    credential_type: "public-key",
    id_override: option.None,
  )
}

/// Build an `AuthenticationResponseJSON` envelope from raw components.
///
/// Exposed so tests can exercise malformed inputs (wrong `type`, mismatched
/// signature, swapped credential_id) without hand-rolling the JSON wrapper.
///
/// Pass `id_override: Some(s)` to set the top-level `id` field independently
/// from `rawId` (used by mismatch tests). `None` keeps both derived from
/// `credential_id`.
pub fn to_authentication_json_with(
  credential_id credential_id: BitArray,
  authenticator_data authenticator_data: BitArray,
  client_data_json client_data_json: BitArray,
  signature signature: BitArray,
  user_handle user_handle: Option(BitArray),
  credential_type credential_type: String,
  id_override id_override: Option(String),
) -> String {
  let user_handle_json = case user_handle {
    option.Some(handle) ->
      json.string(bit_array.base64_url_encode(handle, False))
    option.None -> json.null()
  }

  let credential_id_b64 = bit_array.base64_url_encode(credential_id, False)
  let id_json = case id_override {
    option.Some(s) -> json.string(s)
    option.None -> json.string(credential_id_b64)
  }
  json.object([
    #("id", id_json),
    #("rawId", json.string(credential_id_b64)),
    #("type", json.string(credential_type)),
    #(
      "response",
      json.object([
        #(
          "clientDataJSON",
          json.string(bit_array.base64_url_encode(client_data_json, False)),
        ),
        #(
          "authenticatorData",
          json.string(bit_array.base64_url_encode(authenticator_data, False)),
        ),
        #(
          "signature",
          json.string(bit_array.base64_url_encode(signature, False)),
        ),
        #("userHandle", user_handle_json),
      ]),
    ),
    #("clientExtensionResults", json.object([])),
  ])
  |> json.to_string
}

/// Build client data JSON with a custom type field.
/// Useful for testing type mismatch errors.
pub fn build_client_data(
  type_ type_: String,
  challenge challenge: BitArray,
  origin origin: String,
  cross_origin cross_origin: Bool,
  top_origin top_origin: Option(String),
) -> BitArray {
  let challenge_b64 = bit_array.base64_url_encode(challenge, False)
  let base_fields = [
    #("type", json.string(type_)),
    #("challenge", json.string(challenge_b64)),
    #("origin", json.string(origin)),
    #("crossOrigin", json.bool(cross_origin)),
  ]
  let fields = case top_origin {
    option.Some(top) -> [#("topOrigin", json.string(top)), ..base_fields]
    option.None -> base_fields
  }
  json.object(fields)
  |> json.to_string
  |> bit_array.from_string
}

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
    type_: "webauthn.create",
    challenge:,
    origin:,
    cross_origin:,
    top_origin: option.None,
  )
}

/// Build client data JSON for authentication.
///
/// Parameters allow constructing invalid data for error testing:
/// - Use a different `origin` to test origin mismatch
/// - Use a different `challenge` to test challenge mismatch
/// - Set `cross_origin: True` with a challenge that disallows it
pub fn build_client_data_get(
  challenge challenge: BitArray,
  origin origin: String,
  cross_origin cross_origin: Bool,
) -> BitArray {
  build_client_data(
    type_: "webauthn.get",
    challenge:,
    origin:,
    cross_origin:,
    top_origin: option.None,
  )
}

/// Create default authenticator flags (user_present: True, user_verified: False).
pub fn default_flags() -> AuthenticatorFlags {
  AuthenticatorFlags(user_present: True, user_verified: False)
}

fn encode_flags(
  flags: AuthenticatorFlags,
  has_attested_credential has_attested_credential: Bool,
) -> Int {
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
  int.bitwise_or(up, int.bitwise_or(uv, at))
}

/// Get the public key in COSE EC2 CBOR format.
/// This is the format embedded in authenticator data during registration.
pub fn cose_key(keypair: KeyPair) -> BitArray {
  let assert Ok(pub_key) = gose.public_key(keypair.key)
  let assert Ok(cbor_bytes) = cose.key_to_cbor(pub_key)
  cbor_bytes
}

/// Generate a new random ES256 (P-256) key pair.
pub fn generate_es256_keypair() -> KeyPair {
  let alg = gose.Ecdsa(gose.EcdsaP256)
  let key =
    gose.generate_ec(ec.P256)
    |> gose.with_alg(gose.SigningAlg(gose.DigitalSignature(alg)))
  KeyPair(key:, alg:)
}

/// Generate a new random Ed25519 key pair.
pub fn generate_ed25519_keypair() -> KeyPair {
  let alg = gose.Eddsa
  let key =
    gose.generate_eddsa(eddsa.Ed25519)
    |> gose.with_alg(gose.SigningAlg(gose.DigitalSignature(alg)))
  KeyPair(key:, alg:)
}

/// Generate a new random RS256 (RSA 2048-bit) key pair.
pub fn generate_rs256_keypair() -> KeyPair {
  let alg = gose.RsaPkcs1(gose.RsaPkcs1Sha256)
  let assert Ok(raw_key) = gose.generate_rsa(2048)
  let key = gose.with_alg(raw_key, gose.SigningAlg(gose.DigitalSignature(alg)))
  KeyPair(key:, alg:)
}

/// Get the public key as a parsed `glasslock.PublicKey`.
/// Use to construct a stored `Credential` in tests.
pub fn public_key(keypair: KeyPair) -> glasslock.PublicKey {
  let assert Ok(public_key) = glasslock.parse_public_key(cose_key(keypair))
  public_key
}

/// Sign a message using the algorithm stamped on the keypair.
///
/// Dispatches to ECDSA, EdDSA, RSA PKCS#1 v1.5, or RSA PSS based on the COSE
/// alg label assigned when the keypair was generated. Returns the wire-format
/// signature bytes a real WebAuthn authenticator would produce: ASN.1 DER for
/// ECDSA, raw for EdDSA, and raw PKCS#1 v1.5 or PSS bytes for RSA.
pub fn sign(keypair keypair: KeyPair, message message: BitArray) -> BitArray {
  let assert Ok(private_der) = gose.to_der(keypair.key)
  case keypair.alg {
    gose.Ecdsa(_) -> {
      let assert Ok(#(private, _)) = ec.from_der(private_der)
      ecdsa.sign(private, message, hash.Sha256)
    }
    gose.Eddsa -> {
      let assert Ok(#(private, _)) = eddsa.from_der(private_der)
      eddsa.sign(private, message)
    }
    gose.RsaPkcs1(_) -> {
      let assert Ok(#(private, _)) = rsa.from_der(private_der, rsa.Pkcs8)
      rsa.sign(private, message, hash.Sha256, rsa.Pkcs1v15)
    }
    gose.RsaPss(_) -> {
      let assert Ok(#(private, _)) = rsa.from_der(private_der, rsa.Pkcs8)
      rsa.sign(private, message, hash.Sha256, rsa.Pss(rsa.SaltLengthHashLen))
    }
  }
}

/// Build an attestation object with "none" attestation format.
///
/// This is the only attestation format currently supported by glasslock.
pub fn build_attestation_object(auth_data: BitArray) -> BitArray {
  build_attestation_object_with_fmt(fmt: "none", auth_data:)
}

/// Build an attestation object with a caller-supplied attestation format
/// and an empty `attStmt`. Use to exercise unsupported-format rejection paths.
pub fn build_attestation_object_with_fmt(
  fmt fmt: String,
  auth_data auth_data: BitArray,
) -> BitArray {
  cbor.encode(
    cbor.Map([
      #(cbor.String("fmt"), cbor.String(fmt)),
      #(cbor.String("authData"), cbor.Bytes(auth_data)),
      #(cbor.String("attStmt"), cbor.Map([])),
    ]),
  )
}

/// Build a `fmt: "none"` attestation object with a non-empty `attStmt`. Use
/// to exercise the "none attestation with non-empty statement" rejection.
pub fn build_attestation_object_with_non_empty_attstmt(
  auth_data auth_data: BitArray,
) -> BitArray {
  cbor.encode(
    cbor.Map([
      #(cbor.String("fmt"), cbor.String("none")),
      #(cbor.String("authData"), cbor.Bytes(auth_data)),
      #(cbor.String("attStmt"), cbor.Map([#(cbor.String("alg"), cbor.Int(-7))])),
    ]),
  )
}

/// Build authenticator data for registration (includes attested credential).
/// Pass `cose_key(keypair)` for the `cose_key_cbor` parameter.
pub fn build_registration_authenticator_data(
  relying_party_id relying_party_id: String,
  credential_id credential_id: BitArray,
  cose_key_cbor cose_key_cbor: BitArray,
  flags flags: AuthenticatorFlags,
  sign_count sign_count: Int,
) -> BitArray {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string(relying_party_id))
  let flags_byte = encode_flags(flags, has_attested_credential: True)
  let aaguid = <<0:128>>
  let cred_id_len = bit_array.byte_size(credential_id)

  bit_array.concat([
    rp_id_hash,
    <<flags_byte>>,
    <<sign_count:size(32)>>,
    aaguid,
    <<cred_id_len:size(16)>>,
    credential_id,
    cose_key_cbor,
  ])
}

/// Build a complete registration response for the given challenge.
///
/// Generates a fresh ES256 keypair and credential ID. Use
/// `build_registration_response_with_keypair` to supply a keypair of a
/// different algorithm.
pub fn build_registration_response(
  challenge challenge: registration.Challenge,
) -> RegistrationResponse {
  build_registration_response_with_keypair(
    challenge:,
    keypair: generate_es256_keypair(),
  )
}

/// Build a complete registration response using a caller-supplied keypair.
///
/// Useful when the test needs to exercise an algorithm other than ES256. The
/// keypair determines the COSE algorithm embedded in the attested credential.
pub fn build_registration_response_with_keypair(
  challenge challenge: registration.Challenge,
  keypair keypair: KeyPair,
) -> RegistrationResponse {
  let data = registration.challenge_data(challenge)
  let assert Ok(origin) = list.first(set.to_list(data.origins))
  let credential_id = crypto.random_bytes(16)
  let auth_data =
    build_registration_authenticator_data(
      relying_party_id: data.rp_id,
      credential_id:,
      cose_key_cbor: cose_key(keypair),
      flags: default_flags(),
      sign_count: 0,
    )
  let client_data_json =
    build_client_data_create(
      challenge: data.bytes,
      origin:,
      cross_origin: False,
    )
  RegistrationResponse(
    attestation_object: build_attestation_object(auth_data),
    client_data_json:,
    credential_id:,
    keypair:,
  )
}

/// Convert a registration response to a RegistrationResponseJSON string.
pub fn to_registration_json(response: RegistrationResponse) -> String {
  to_registration_json_with(
    credential_id: response.credential_id,
    client_data_json: response.client_data_json,
    attestation_object: response.attestation_object,
    credential_type: "public-key",
    transports: [],
    id_override: option.None,
  )
}

/// Build a `RegistrationResponseJSON` envelope from raw components.
///
/// Exposed so tests can exercise malformed inputs (wrong `type`, swapped
/// credential_id, mismatched attestation) without hand-rolling the JSON
/// wrapper.
///
/// Pass `id_override: Some(s)` to set the top-level `id` field independently
/// from `rawId` (used by mismatch tests). `None` keeps both derived from
/// `credential_id`.
pub fn to_registration_json_with(
  credential_id credential_id: BitArray,
  client_data_json client_data_json: BitArray,
  attestation_object attestation_object: BitArray,
  credential_type credential_type: String,
  transports transports: List(glasslock.Transport),
  id_override id_override: Option(String),
) -> String {
  let response_fields = [
    #(
      "clientDataJSON",
      json.string(bit_array.base64_url_encode(client_data_json, False)),
    ),
    #(
      "attestationObject",
      json.string(bit_array.base64_url_encode(attestation_object, False)),
    ),
  ]
  let response_fields = case transports {
    [] -> response_fields
    _ -> [
      #(
        "transports",
        json.array(transports, fn(transport) {
          transport
          |> internal.transport_to_string
          |> json.string
        }),
      ),
      ..response_fields
    ]
  }
  let credential_id_b64 = bit_array.base64_url_encode(credential_id, False)
  let id_json = case id_override {
    option.Some(s) -> json.string(s)
    option.None -> json.string(credential_id_b64)
  }
  json.object([
    #("id", id_json),
    #("rawId", json.string(credential_id_b64)),
    #("type", json.string(credential_type)),
    #("response", json.object(response_fields)),
    #("clientExtensionResults", json.object([])),
  ])
  |> json.to_string
}

/// Extract the random challenge bytes from a registration challenge.
/// Exposed for tests that need to construct matching client data.
pub fn registration_challenge_bytes(
  challenge: registration.Challenge,
) -> BitArray {
  registration.challenge_data(challenge).bytes
}

/// Extract the Relying Party ID from a registration challenge.
pub fn registration_challenge_rp_id(
  challenge: registration.Challenge,
) -> String {
  registration.challenge_data(challenge).rp_id
}

/// Extract the expected origins list from a registration challenge.
pub fn registration_challenge_origins(
  challenge: registration.Challenge,
) -> List(String) {
  set.to_list(registration.challenge_data(challenge).origins)
}

/// Extract the random challenge bytes from an authentication challenge.
pub fn authentication_challenge_bytes(
  challenge: authentication.Challenge,
) -> BitArray {
  authentication.challenge_data(challenge).bytes
}

/// Extract the Relying Party ID from an authentication challenge.
pub fn authentication_challenge_rp_id(
  challenge: authentication.Challenge,
) -> String {
  authentication.challenge_data(challenge).rp_id
}

/// Extract the expected origins list from an authentication challenge.
pub fn authentication_challenge_origins(
  challenge: authentication.Challenge,
) -> List(String) {
  set.to_list(authentication.challenge_data(challenge).origins)
}
