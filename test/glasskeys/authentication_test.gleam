import birdie
import glasskeys.{
  Credential, CredentialNotAllowed, InvalidSignature, ParseError,
  PresenceRequired, SignCountRegression, VerificationMismatch,
  VerificationPreferred,
}
import glasskeys/authentication.{Challenge}
import glasskeys/test_helpers.{make_client_data_json}
import gleam/bit_array
import gleam/crypto
import pprint

pub fn authentication_builder_test() {
  let cred_ids = [<<1, 2, 3>>, <<4, 5, 6>>]
  let #(challenge_b64, verifier) =
    authentication.new()
    |> authentication.origin("https://example.com")
    |> authentication.rp_id("example.com")
    |> authentication.allowed_credentials(cred_ids)
    |> authentication.user_verification(VerificationPreferred)
    |> authentication.build()

  assert verifier.origin == "https://example.com"
  assert verifier.allowed_credentials == [<<1, 2, 3>>, <<4, 5, 6>>]
  assert verifier.user_presence == PresenceRequired
  assert bit_array.byte_size(verifier.bytes) == 32

  let assert Ok(challenge) = bit_array.base64_url_decode(challenge_b64)
  assert verifier.bytes == challenge
}

pub fn verify_rejects_credential_not_allowed_test() {
  let challenge =
    Challenge(
      bytes: <<"test":utf8>>,
      origin: "https://example.com",
      rp_id: "example.com",
      allowed_credentials: [<<7, 8, 9>>, <<10, 11, 12>>],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let stored =
    Credential(
      id: <<1, 2, 3>>,
      public_key: <<4, 5, 6>>,
      sign_count: 0,
      user_verified: False,
    )

  let result =
    authentication.verify(
      authenticator_data: <<>>,
      client_data_json: <<>>,
      signature: <<>>,
      credential_id: <<1, 2, 3>>,
      challenge: challenge,
      stored: stored,
    )

  assert result == Error(CredentialNotAllowed)
}

pub fn verify_rejects_credential_id_mismatch_test() {
  let challenge =
    Challenge(
      bytes: <<"test":utf8>>,
      origin: "https://example.com",
      rp_id: "example.com",
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let stored =
    Credential(
      id: <<1, 2, 3>>,
      public_key: <<4, 5, 6>>,
      sign_count: 0,
      user_verified: False,
    )

  let result =
    authentication.verify(
      authenticator_data: <<>>,
      client_data_json: <<>>,
      signature: <<>>,
      credential_id: <<7, 8, 9>>,
      challenge: challenge,
      stored: stored,
    )

  assert result == Error(CredentialNotAllowed)
}

pub fn verify_rejects_invalid_client_data_json_test() {
  let challenge =
    Challenge(
      bytes: <<"test":utf8>>,
      origin: "https://example.com",
      rp_id: "example.com",
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let stored =
    Credential(
      id: <<1, 2, 3>>,
      public_key: <<4, 5, 6>>,
      sign_count: 0,
      user_verified: False,
    )

  let invalid_json = <<"not valid json":utf8>>

  let result =
    authentication.verify(
      authenticator_data: <<>>,
      client_data_json: invalid_json,
      signature: <<>>,
      credential_id: <<1, 2, 3>>,
      challenge: challenge,
      stored: stored,
    )

  assert result == Error(ParseError("Invalid JSON structure"))
}

pub fn verify_rejects_wrong_type_test() {
  let challenge =
    Challenge(
      bytes: <<"test":utf8>>,
      origin: "https://example.com",
      rp_id: "example.com",
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let stored =
    Credential(
      id: <<1, 2, 3>>,
      public_key: <<4, 5, 6>>,
      sign_count: 0,
      user_verified: False,
    )

  let client_data_json =
    make_client_data_json(
      "webauthn.create",
      "dGVzdA",
      "https://example.com",
      False,
    )

  let result =
    authentication.verify(
      authenticator_data: <<>>,
      client_data_json: client_data_json,
      signature: <<>>,
      credential_id: <<1, 2, 3>>,
      challenge: challenge,
      stored: stored,
    )

  assert result == Error(VerificationMismatch("type"))
}

pub fn verify_rejects_challenge_mismatch_test() {
  let challenge =
    Challenge(
      bytes: <<"test":utf8>>,
      origin: "https://example.com",
      rp_id: "example.com",
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let stored =
    Credential(
      id: <<1, 2, 3>>,
      public_key: <<4, 5, 6>>,
      sign_count: 0,
      user_verified: False,
    )

  let client_data_json =
    make_client_data_json(
      "webauthn.get",
      "d3Jvbmc",
      "https://example.com",
      False,
    )

  let result =
    authentication.verify(
      authenticator_data: <<>>,
      client_data_json: client_data_json,
      signature: <<>>,
      credential_id: <<1, 2, 3>>,
      challenge: challenge,
      stored: stored,
    )

  assert result == Error(VerificationMismatch("challenge"))
}

pub fn verify_rejects_origin_mismatch_test() {
  let challenge =
    Challenge(
      bytes: <<"test":utf8>>,
      origin: "https://example.com",
      rp_id: "example.com",
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let stored =
    Credential(
      id: <<1, 2, 3>>,
      public_key: <<4, 5, 6>>,
      sign_count: 0,
      user_verified: False,
    )

  let client_data_json =
    make_client_data_json("webauthn.get", "dGVzdA", "https://evil.com", False)

  let result =
    authentication.verify(
      authenticator_data: <<>>,
      client_data_json: client_data_json,
      signature: <<>>,
      credential_id: <<1, 2, 3>>,
      challenge: challenge,
      stored: stored,
    )

  assert result == Error(VerificationMismatch("origin"))
}

pub fn verify_valid_authentication_test() {
  let keypair = test_helpers.load_test_keypair()

  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>

  let public_key = bit_array.concat([<<4>>, keypair.x, keypair.y])

  let stored_credential =
    Credential(
      id: credential_id,
      public_key: public_key,
      sign_count: 0,
      user_verified: False,
    )

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let auth_data =
    test_helpers.build_authentication_auth_data(rp_id, 1, True, False)

  let client_data_json =
    test_helpers.build_client_data_json_get(challenge_bytes, origin)

  let client_data_hash = crypto.hash(crypto.Sha256, client_data_json)
  let signed_data = bit_array.concat([auth_data, client_data_hash])

  let signature = test_helpers.sign_es256(signed_data, keypair.private_key)

  let result =
    authentication.verify(
      authenticator_data: auth_data,
      client_data_json: client_data_json,
      signature: signature,
      credential_id: credential_id,
      challenge: challenge,
      stored: stored_credential,
    )

  let assert Ok(cred) = result

  cred
  |> pprint.format
  |> birdie.snap(title: "valid authentication")
}

pub fn verify_rejects_invalid_signature_test() {
  let keypair = test_helpers.load_test_keypair()
  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>
  let public_key = bit_array.concat([<<4>>, keypair.x, keypair.y])

  let stored_credential =
    Credential(
      id: credential_id,
      public_key: public_key,
      sign_count: 0,
      user_verified: False,
    )

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let auth_data =
    test_helpers.build_authentication_auth_data(rp_id, 1, True, False)
  let client_data_json =
    test_helpers.build_client_data_json_get(challenge_bytes, origin)

  let invalid_signature = <<0:512>>

  let result =
    authentication.verify(
      authenticator_data: auth_data,
      client_data_json: client_data_json,
      signature: invalid_signature,
      credential_id: credential_id,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(InvalidSignature)
}

pub fn verify_rejects_sign_count_regression_test() {
  let keypair = test_helpers.load_test_keypair()
  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>
  let public_key = bit_array.concat([<<4>>, keypair.x, keypair.y])

  let stored_credential =
    Credential(
      id: credential_id,
      public_key: public_key,
      sign_count: 10,
      user_verified: False,
    )

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let auth_data =
    test_helpers.build_authentication_auth_data(rp_id, 5, True, False)
  let client_data_json =
    test_helpers.build_client_data_json_get(challenge_bytes, origin)
  let client_data_hash = crypto.hash(crypto.Sha256, client_data_json)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = test_helpers.sign_es256(signed_data, keypair.private_key)

  let result =
    authentication.verify(
      authenticator_data: auth_data,
      client_data_json: client_data_json,
      signature: signature,
      credential_id: credential_id,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(SignCountRegression)
}

pub fn verify_rejects_sign_count_reset_to_zero_test() {
  let keypair = test_helpers.load_test_keypair()
  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>
  let public_key = bit_array.concat([<<4>>, keypair.x, keypair.y])

  let stored_credential =
    Credential(
      id: credential_id,
      public_key: public_key,
      sign_count: 10,
      user_verified: False,
    )

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      allowed_credentials: [],
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let auth_data =
    test_helpers.build_authentication_auth_data(rp_id, 0, True, False)
  let client_data_json =
    test_helpers.build_client_data_json_get(challenge_bytes, origin)
  let client_data_hash = crypto.hash(crypto.Sha256, client_data_json)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = test_helpers.sign_es256(signed_data, keypair.private_key)

  let result =
    authentication.verify(
      authenticator_data: auth_data,
      client_data_json: client_data_json,
      signature: signature,
      credential_id: credential_id,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(SignCountRegression)
}
