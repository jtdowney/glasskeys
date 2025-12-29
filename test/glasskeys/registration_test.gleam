import glasskeys.{
  ParseError, PresenceRequired, UserVerificationFailed, VerificationMismatch,
  VerificationPreferred, VerificationRequired,
}
import glasskeys/registration.{Challenge}
import glasskeys/testing.{AuthenticatorFlags}
import gleam/bit_array

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
    testing.build_client_data(
      typ: "webauthn.get",
      challenge: <<1, 2, 3, 4>>,
      origin: "https://example.com",
      cross_origin: False,
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
    testing.build_client_data(
      typ: "webauthn.create",
      challenge: <<9, 9, 9, 9>>,
      origin: "https://example.com",
      cross_origin: False,
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
    testing.build_client_data(
      typ: "webauthn.create",
      challenge: <<1, 2, 3, 4>>,
      origin: "https://evil.com",
      cross_origin: False,
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
  let keypair = testing.generate_keypair()
  let cose_key = testing.cose_key(keypair)

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

  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: rp_id,
      credential_id: credential_id,
      cose_key: cose_key,
      flags: flags,
      sign_count: 0,
    )

  let attestation_object = testing.build_attestation_object(auth_data)

  let client_data_json =
    testing.build_client_data_create(
      challenge: challenge_bytes,
      origin: origin,
      cross_origin: False,
    )

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  let assert Ok(cred) = result
  assert cred.id == credential_id
  assert cred.sign_count == 0
  assert cred.user_verified == False
  assert bit_array.byte_size(cred.public_key) == 65
}

pub fn verify_rejects_when_verification_required_but_not_performed_test() {
  let keypair = testing.generate_keypair()
  let cose_key = testing.cose_key(keypair)
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

  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: rp_id,
      credential_id: credential_id,
      cose_key: cose_key,
      flags: flags,
      sign_count: 0,
    )

  let attestation_object = testing.build_attestation_object(auth_data)
  let client_data_json =
    testing.build_client_data_create(
      challenge: challenge_bytes,
      origin: origin,
      cross_origin: False,
    )

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
  let keypair = testing.generate_keypair()
  let cose_key = testing.cose_key(keypair)
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

  let flags = AuthenticatorFlags(user_present: True, user_verified: True)
  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: rp_id,
      credential_id: credential_id,
      cose_key: cose_key,
      flags: flags,
      sign_count: 0,
    )

  let attestation_object = testing.build_attestation_object(auth_data)
  let client_data_json =
    testing.build_client_data_create(
      challenge: challenge_bytes,
      origin: origin,
      cross_origin: False,
    )

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  let assert Ok(cred) = result
  assert cred.id == credential_id
  assert cred.sign_count == 0
  assert cred.user_verified == True
  assert bit_array.byte_size(cred.public_key) == 65
}

pub fn verify_allows_cross_origin_when_enabled_test() {
  let keypair = testing.generate_keypair()
  let cose_key = testing.cose_key(keypair)
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

  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: rp_id,
      credential_id: credential_id,
      cose_key: cose_key,
      flags: flags,
      sign_count: 0,
    )

  let attestation_object = testing.build_attestation_object(auth_data)
  let client_data_json =
    testing.build_client_data_create(
      challenge: challenge_bytes,
      origin: origin,
      cross_origin: True,
    )

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  let assert Ok(_) = result
}

pub fn verify_rejects_cross_origin_when_disabled_test() {
  let keypair = testing.generate_keypair()
  let cose_key = testing.cose_key(keypair)
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

  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: rp_id,
      credential_id: credential_id,
      cose_key: cose_key,
      flags: flags,
      sign_count: 0,
    )

  let attestation_object = testing.build_attestation_object(auth_data)
  let client_data_json =
    testing.build_client_data_create(
      challenge: challenge_bytes,
      origin: origin,
      cross_origin: True,
    )

  let result =
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: challenge,
    )

  assert result == Error(VerificationMismatch("cross_origin"))
}
