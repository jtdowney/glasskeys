import glasslock
import glasslock/registration
import glasslock/testing
import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option

pub fn generate_options_emits_core_fields_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let options =
    registration.Options(
      ..registration.default_options(),
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: ["https://example.com"],
    )

  let #(options_json, challenge) = registration.generate_options(options)

  let decoder = {
    use rp_id <- decode.subfield(["rp", "id"], decode.string)
    use rp_name <- decode.subfield(["rp", "name"], decode.string)
    use user_name <- decode.subfield(["user", "name"], decode.string)
    use attestation <- decode.field("attestation", decode.string)
    use timeout <- decode.field("timeout", decode.int)
    decode.success(#(rp_id, rp_name, user_name, attestation, timeout))
  }

  let assert Ok(#(rp_id, rp_name, user_name, attestation, timeout)) =
    json.parse(json.to_string(options_json), decoder)
  assert rp_id == "example.com"
  assert rp_name == "Test App"
  assert user_name == "testuser"
  assert attestation == "none"
  assert timeout == 60_000

  assert registration.challenge_origins(challenge) == ["https://example.com"]
  assert registration.challenge_rp_id(challenge) == "example.com"
  assert bit_array.byte_size(registration.challenge_bytes(challenge)) == 32
}

pub fn generate_options_produces_unique_challenges_test() {
  let options = setup_options(glasslock.VerificationPreferred)
  let #(_, challenge1) = registration.generate_options(options)
  let #(_, challenge2) = registration.generate_options(options)
  assert registration.challenge_bytes(challenge1)
    != registration.challenge_bytes(challenge2)
}

pub fn generate_options_with_exclude_credentials_test() {
  let cred1 = <<1, 2, 3, 4>>
  let cred2 = <<5, 6, 7, 8>>
  let options =
    registration.Options(
      ..setup_options(glasslock.VerificationPreferred),
      exclude_credentials: [
        glasslock.CredentialId(cred1),
        glasslock.CredentialId(cred2),
      ],
    )

  let #(options_json, _) = registration.generate_options(options)

  let id_decoder = {
    use id <- decode.field("id", decode.string)
    decode.success(id)
  }
  let decoder = {
    use ids <- decode.field("excludeCredentials", decode.list(id_decoder))
    decode.success(ids)
  }
  let assert Ok(ids) = json.parse(json.to_string(options_json), decoder)
  assert ids
    == [
      bit_array.base64_url_encode(cred1, False),
      bit_array.base64_url_encode(cred2, False),
    ]
}

pub fn generate_options_with_platform_attachment_test() {
  let options =
    registration.Options(
      ..setup_options(glasslock.VerificationPreferred),
      authenticator_attachment: option.Some(registration.Platform),
    )
  let #(options_json, _) = registration.generate_options(options)
  let decoder = {
    use att <- decode.subfield(
      ["authenticatorSelection", "authenticatorAttachment"],
      decode.string,
    )
    decode.success(att)
  }
  let assert Ok(att) = json.parse(json.to_string(options_json), decoder)
  assert att == "platform"
}

pub fn generate_options_with_cross_platform_attachment_test() {
  let options =
    registration.Options(
      ..setup_options(glasslock.VerificationPreferred),
      authenticator_attachment: option.Some(registration.CrossPlatform),
    )
  let #(options_json, _) = registration.generate_options(options)
  let decoder = {
    use att <- decode.subfield(
      ["authenticatorSelection", "authenticatorAttachment"],
      decode.string,
    )
    decode.success(att)
  }
  let assert Ok(att) = json.parse(json.to_string(options_json), decoder)
  assert att == "cross-platform"
}

pub fn generate_options_resident_key_variants_test() {
  let variants = [
    #(registration.ResidentKeyDiscouraged, "discouraged"),
    #(registration.ResidentKeyPreferred, "preferred"),
    #(registration.ResidentKeyRequired, "required"),
  ]

  let decoder = {
    use rk <- decode.subfield(
      ["authenticatorSelection", "residentKey"],
      decode.string,
    )
    decode.success(rk)
  }

  list.each(variants, fn(pair) {
    let #(variant, expected_string) = pair
    let options =
      registration.Options(
        ..setup_options(glasslock.VerificationPreferred),
        resident_key: variant,
      )
    let #(options_json, _) = registration.generate_options(options)
    let assert Ok(rk) = json.parse(json.to_string(options_json), decoder)
    assert rk == expected_string
  })
}

pub fn generate_options_attestation_variants_test() {
  let variants = [
    #(registration.AttestationNone, "none"),
    #(registration.AttestationIndirect, "indirect"),
    #(registration.AttestationDirect, "direct"),
    #(registration.AttestationEnterprise, "enterprise"),
  ]

  let decoder = {
    use att <- decode.field("attestation", decode.string)
    decode.success(att)
  }

  list.each(variants, fn(pair) {
    let #(variant, expected_string) = pair
    let options =
      registration.Options(
        ..setup_options(glasslock.VerificationPreferred),
        attestation: variant,
      )
    let #(options_json, _) = registration.generate_options(options)
    let assert Ok(att) = json.parse(json.to_string(options_json), decoder)
    assert att == expected_string
  })
}

pub fn verify_valid_registration_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)
  let response_json = testing.to_registration_json(response)

  let assert Ok(cred) = registration.verify(response_json:, challenge:)
  assert cred.id == response.credential_id
  assert cred.sign_count == 0
  let glasslock.PublicKey(raw_public_key) = cred.public_key
  assert bit_array.byte_size(raw_public_key) > 0
}

pub fn verify_rejects_invalid_json_test() {
  let challenge = setup_challenge()
  let result = registration.verify(response_json: "{not valid json", challenge:)
  assert result
    == Error(glasslock.ParseError("Invalid registration response JSON"))
}

pub fn verify_rejects_wrong_type_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)

  let wrong_type_client_data =
    testing.build_client_data(
      type_: "webauthn.get",
      challenge: registration.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
      top_origin: option.None,
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(
        ..response,
        client_data_json: wrong_type_client_data,
      ),
    )

  let result = registration.verify(response_json:, challenge:)
  assert result == Error(glasslock.VerificationMismatch(glasslock.TypeField))
}

pub fn verify_rejects_challenge_mismatch_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)

  let wrong_challenge_client_data =
    testing.build_client_data_create(
      challenge: <<9, 9, 9, 9>>,
      origin: "https://example.com",
      cross_origin: False,
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(
        ..response,
        client_data_json: wrong_challenge_client_data,
      ),
    )

  let result = registration.verify(response_json:, challenge:)
  assert result
    == Error(glasslock.VerificationMismatch(glasslock.ChallengeField))
}

pub fn verify_rejects_origin_mismatch_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)

  let wrong_origin_client_data =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: "https://evil.com",
      cross_origin: False,
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(
        ..response,
        client_data_json: wrong_origin_client_data,
      ),
    )

  let result = registration.verify(response_json:, challenge:)
  assert result == Error(glasslock.VerificationMismatch(glasslock.OriginField))
}

pub fn verify_rejects_when_verification_required_but_not_performed_test() {
  let challenge =
    setup_challenge_with_verification(glasslock.VerificationRequired)
  let response_json =
    manually_built_response(
      challenge:,
      flags: testing.AuthenticatorFlags(
        user_present: True,
        user_verified: False,
      ),
    )
  let result = registration.verify(response_json:, challenge:)
  assert result == Error(glasslock.UserVerificationFailed)
}

pub fn verify_succeeds_when_verification_required_and_performed_test() {
  let challenge =
    setup_challenge_with_verification(glasslock.VerificationRequired)
  let response_json =
    manually_built_response(
      challenge:,
      flags: testing.AuthenticatorFlags(user_present: True, user_verified: True),
    )
  let assert Ok(cred) = registration.verify(response_json:, challenge:)
  assert cred.sign_count == 0
}

pub fn verify_rejects_user_presence_not_asserted_test() {
  let challenge = setup_challenge()
  let response_json =
    manually_built_response(
      challenge:,
      flags: testing.AuthenticatorFlags(
        user_present: False,
        user_verified: False,
      ),
    )
  let result = registration.verify(response_json:, challenge:)
  assert result == Error(glasslock.UserPresenceFailed)
}

pub fn verify_rejects_rp_id_mismatch_test() {
  let challenge = setup_challenge()
  let keypair = testing.generate_es256_keypair()
  let credential_id = glasslock.CredentialId(<<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>)

  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: "evil.com",
      credential_id:,
      cose_key: testing.cose_key(keypair),
      flags: testing.default_flags(),
      sign_count: 0,
    )
  let client_data_json =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
    )
  let response_json =
    testing.to_registration_json_with(
      credential_id:,
      client_data_json:,
      attestation_object: testing.build_attestation_object(auth_data),
      credential_type: "public-key",
    )

  let result = registration.verify(response_json:, challenge:)
  assert result == Error(glasslock.VerificationMismatch(glasslock.RpIdField))
}

pub fn verify_rejects_cross_origin_when_disabled_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)

  let cross_origin_client_data =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(
        ..response,
        client_data_json: cross_origin_client_data,
      ),
    )

  let result = registration.verify(response_json:, challenge:)
  assert result
    == Error(glasslock.VerificationMismatch(glasslock.CrossOriginField))
}

pub fn verify_succeeds_with_cross_origin_allowed_test() {
  let #(_, challenge) =
    registration.generate_options(
      registration.Options(
        ..setup_options(glasslock.VerificationPreferred),
        allow_cross_origin: True,
      ),
    )
  let response = testing.build_registration_response(challenge:)

  let cross_origin_client_data =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(
        ..response,
        client_data_json: cross_origin_client_data,
      ),
    )

  let assert Ok(_cred) = registration.verify(response_json:, challenge:)
}

pub fn verify_rejects_invalid_credential_type_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)
  let response_json =
    testing.to_registration_json_with(
      credential_id: response.credential_id,
      client_data_json: response.client_data_json,
      attestation_object: response.attestation_object,
      credential_type: "invalid-type",
    )

  let result = registration.verify(response_json:, challenge:)
  assert result
    == Error(glasslock.VerificationMismatch(glasslock.CredentialTypeField))
}

fn setup_options(uv: glasslock.UserVerification) -> registration.Options {
  registration.Options(
    ..registration.default_options(),
    rp: registration.Rp(id: "example.com", name: "Test App"),
    user: registration.User(
      id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
      name: "testuser",
      display_name: "Test User",
    ),
    origins: ["https://example.com"],
    user_verification: uv,
  )
}

fn setup_challenge() -> registration.Challenge {
  setup_challenge_with_verification(glasslock.VerificationPreferred)
}

fn setup_challenge_with_verification(
  uv: glasslock.UserVerification,
) -> registration.Challenge {
  let #(_, challenge) = registration.generate_options(setup_options(uv))
  challenge
}

fn manually_built_response(
  challenge challenge: registration.Challenge,
  flags flags: testing.AuthenticatorFlags,
) -> String {
  let keypair = testing.generate_es256_keypair()
  let credential_id = glasslock.CredentialId(<<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>)
  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: registration.challenge_rp_id(challenge),
      credential_id:,
      cose_key: testing.cose_key(keypair),
      flags:,
      sign_count: 0,
    )
  let client_data_json =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
    )
  testing.to_registration_json_with(
    credential_id:,
    client_data_json:,
    attestation_object: testing.build_attestation_object(auth_data),
    credential_type: "public-key",
  )
}
