import birdie
import glasskeys.{
  ParseError, PresenceRequired, UserVerificationFailed, VerificationMismatch,
  VerificationPreferred, VerificationRequired,
}
import glasskeys/registration.{Challenge}
import glasskeys/test_helpers.{make_client_data_json}
import gleam/bit_array
import pprint

pub fn registration_builder_test() {
  let #(challenge_b64, verifier) =
    registration.new()
    |> registration.origin("https://example.com")
    |> registration.rp_id("example.com")
    |> registration.user_verification(VerificationRequired)
    |> registration.build()

  assert verifier.origin == "https://example.com"
  assert verifier.rp_id == "example.com"
  assert verifier.user_verification == VerificationRequired
  assert verifier.user_presence == PresenceRequired
  assert bit_array.byte_size(verifier.bytes) == 32

  let assert Ok(challenge) = bit_array.base64_url_decode(challenge_b64)
  assert verifier.bytes == challenge
}

pub fn verify_rejects_invalid_client_data_json_test() {
  let challenge =
    Challenge(
      bytes: <<1, 2, 3, 4>>,
      origin: "https://example.com",
      rp_id: "example.com",
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let invalid_json = bit_array.from_string("{not valid json")
  let result =
    registration.verify(
      attestation_object: <<>>,
      client_data_json: invalid_json,
      challenge: challenge,
    )

  assert result == Error(ParseError("Invalid JSON structure"))
}

pub fn verify_rejects_wrong_type_test() {
  let challenge =
    Challenge(
      bytes: <<1, 2, 3, 4>>,
      origin: "https://example.com",
      rp_id: "example.com",
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let client_data_json =
    make_client_data_json(
      "webauthn.get",
      "AQIDBA",
      "https://example.com",
      False,
    )
  let result =
    registration.verify(
      attestation_object: <<>>,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  assert result == Error(VerificationMismatch("type"))
}

pub fn verify_rejects_challenge_mismatch_test() {
  let challenge =
    Challenge(
      bytes: <<1, 2, 3, 4>>,
      origin: "https://example.com",
      rp_id: "example.com",
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let client_data_json =
    make_client_data_json(
      "webauthn.create",
      "WRONGCHALLENGE",
      "https://example.com",
      False,
    )
  let result =
    registration.verify(
      attestation_object: <<>>,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  assert result == Error(VerificationMismatch("challenge"))
}

pub fn verify_rejects_origin_mismatch_test() {
  let challenge =
    Challenge(
      bytes: <<1, 2, 3, 4>>,
      origin: "https://example.com",
      rp_id: "example.com",
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let client_data_json =
    make_client_data_json(
      "webauthn.create",
      "AQIDBA",
      "https://evil.com",
      False,
    )
  let result =
    registration.verify(
      attestation_object: <<>>,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  assert result == Error(VerificationMismatch("origin"))
}

pub fn verify_valid_registration_none_attestation_test() {
  let keypair = test_helpers.load_test_keypair()
  let public_key_cbor = test_helpers.encode_cose_key(keypair.x, keypair.y)

  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let auth_data =
    test_helpers.build_registration_auth_data(
      rp_id,
      credential_id,
      public_key_cbor,
      0,
      True,
      False,
    )

  let attestation_object = test_helpers.build_attestation_object_none(auth_data)

  let client_data_json =
    test_helpers.build_client_data_json_create(challenge_bytes, origin, False)

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  let assert Ok(cred) = result

  cred
  |> pprint.format
  |> birdie.snap(title: "valid registration with none attestation")
}

pub fn verify_rejects_when_verification_required_but_not_performed_test() {
  let keypair = test_helpers.load_test_keypair()
  let public_key_cbor = test_helpers.encode_cose_key(keypair.x, keypair.y)
  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      user_verification: VerificationRequired,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let auth_data =
    test_helpers.build_registration_auth_data(
      rp_id,
      credential_id,
      public_key_cbor,
      0,
      True,
      False,
    )

  let attestation_object = test_helpers.build_attestation_object_none(auth_data)
  let client_data_json =
    test_helpers.build_client_data_json_create(challenge_bytes, origin, False)

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  assert result == Error(UserVerificationFailed)
}

/// Test that verification succeeds when user verification is required and performed
pub fn verify_succeeds_when_verification_required_and_performed_test() {
  let keypair = test_helpers.load_test_keypair()
  let public_key_cbor = test_helpers.encode_cose_key(keypair.x, keypair.y)
  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      user_verification: VerificationRequired,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let auth_data =
    test_helpers.build_registration_auth_data(
      rp_id,
      credential_id,
      public_key_cbor,
      0,
      True,
      True,
    )

  let attestation_object = test_helpers.build_attestation_object_none(auth_data)
  let client_data_json =
    test_helpers.build_client_data_json_create(challenge_bytes, origin, False)

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  let assert Ok(cred) = result

  cred
  |> pprint.format
  |> birdie.snap(title: "valid registration with user verification")
}

pub fn verify_allows_cross_origin_when_enabled_test() {
  let keypair = test_helpers.load_test_keypair()
  let public_key_cbor = test_helpers.encode_cose_key(keypair.x, keypair.y)
  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: True,
    )

  let auth_data =
    test_helpers.build_registration_auth_data(
      rp_id,
      credential_id,
      public_key_cbor,
      0,
      True,
      False,
    )

  let attestation_object = test_helpers.build_attestation_object_none(auth_data)
  let client_data_json =
    test_helpers.build_client_data_json_create(challenge_bytes, origin, True)

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  let assert Ok(_) = result
}

pub fn verify_rejects_cross_origin_when_disabled_test() {
  let keypair = test_helpers.load_test_keypair()
  let public_key_cbor = test_helpers.encode_cose_key(keypair.x, keypair.y)
  let assert Ok(challenge_bytes) =
    bit_array.base16_decode("0102030405060708090a0b0c0d0e0f10")
  let origin = "https://example.com"
  let rp_id = "example.com"
  let credential_id = <<"test-credential-id":utf8>>

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: origin,
      rp_id: rp_id,
      user_verification: VerificationPreferred,
      user_presence: PresenceRequired,
      allow_cross_origin: False,
    )

  let auth_data =
    test_helpers.build_registration_auth_data(
      rp_id,
      credential_id,
      public_key_cbor,
      0,
      True,
      False,
    )

  let attestation_object = test_helpers.build_attestation_object_none(auth_data)
  let client_data_json =
    test_helpers.build_client_data_json_create(challenge_bytes, origin, True)

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  assert result == Error(VerificationMismatch("cross_origin"))
}
