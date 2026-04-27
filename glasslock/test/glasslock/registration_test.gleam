import birdie
import glasslock
import glasslock/authentication
import glasslock/registration
import glasslock/testing
import gleam/bit_array
import gleam/dynamic/decode
import gleam/json.{type Json}
import gleam/list
import gleam/option
import gleam/set
import gleam/string
import gleam/time/duration
import qcheck

fn algorithm_generator() -> qcheck.Generator(registration.Algorithm) {
  qcheck.from_generators(qcheck.return(registration.Es256), [
    qcheck.return(registration.Ed25519),
    qcheck.return(registration.Rs256),
  ])
}

fn non_empty_list_from(
  element: qcheck.Generator(a),
) -> qcheck.Generator(List(a)) {
  qcheck.map2(element, qcheck.list_from(element), fn(x, xs) { [x, ..xs] })
}

fn user_verification_generator() -> qcheck.Generator(glasslock.UserVerification) {
  qcheck.from_generators(qcheck.return(glasslock.VerificationRequired), [
    qcheck.return(glasslock.VerificationPreferred),
    qcheck.return(glasslock.VerificationDiscouraged),
  ])
}

fn user_presence_generator() -> qcheck.Generator(glasslock.UserPresence) {
  qcheck.from_generators(qcheck.return(glasslock.PresenceRequired), [
    qcheck.return(glasslock.PresencePreferred),
    qcheck.return(glasslock.PresenceDiscouraged),
  ])
}

fn setup_options(uv: glasslock.UserVerification) -> registration.Options {
  registration.Options(..registration.default_options(), user_verification: uv)
}

fn make_request(
  options: registration.Options,
) -> #(Json, registration.Challenge) {
  let assert Ok(request) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: ["https://example.com"],
      options:,
    )
  request
}

fn setup_challenge() -> registration.Challenge {
  setup_challenge_with_verification(glasslock.VerificationPreferred)
}

fn setup_challenge_with_verification(
  uv: glasslock.UserVerification,
) -> registration.Challenge {
  let #(_, challenge) = make_request(setup_options(uv))
  challenge
}

fn build_response(
  challenge challenge: registration.Challenge,
  flags flags: testing.AuthenticatorFlags,
) -> String {
  let keypair = testing.generate_es256_keypair()
  let credential_id = glasslock.CredentialId(<<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>)
  let auth_data =
    testing.build_registration_authenticator_data(
      relying_party_id: testing.registration_challenge_rp_id(challenge),
      credential_id:,
      cose_key: testing.cose_key(keypair),
      flags:,
      sign_count: 0,
    )
  let client_data_json =
    testing.build_client_data_create(
      challenge: testing.registration_challenge_bytes(challenge),
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

pub fn request_emits_core_fields_test() {
  let #(options_json, challenge) = make_request(registration.default_options())

  let decoder = {
    use relying_party_id <- decode.subfield(["rp", "id"], decode.string)
    use relying_party_name <- decode.subfield(["rp", "name"], decode.string)
    use user_name <- decode.subfield(["user", "name"], decode.string)
    use attestation <- decode.field("attestation", decode.string)
    use timeout <- decode.field("timeout", decode.int)
    decode.success(#(
      relying_party_id,
      relying_party_name,
      user_name,
      attestation,
      timeout,
    ))
  }

  let assert Ok(#(
    relying_party_id,
    relying_party_name,
    user_name,
    attestation,
    timeout,
  )) = json.parse(json.to_string(options_json), decoder)
  assert relying_party_id == "example.com"
  assert relying_party_name == "Test App"
  assert user_name == "testuser"
  assert attestation == "none"
  assert timeout == 60_000

  assert testing.registration_challenge_origins(challenge)
    == ["https://example.com"]
  assert testing.registration_challenge_rp_id(challenge) == "example.com"
  assert bit_array.byte_size(testing.registration_challenge_bytes(challenge))
    == 32
}

pub fn request_produces_unique_challenges_test() {
  let options = setup_options(glasslock.VerificationPreferred)
  let #(_, challenge1) = make_request(options)
  let #(_, challenge2) = make_request(options)
  assert testing.registration_challenge_bytes(challenge1)
    != testing.registration_challenge_bytes(challenge2)
}

pub fn request_with_exclude_credentials_test() {
  let cred1 = <<1, 2, 3, 4>>
  let cred2 = <<5, 6, 7, 8>>
  let #(options_json, _) =
    make_request(
      registration.Options(
        ..setup_options(glasslock.VerificationPreferred),
        exclude_credentials: [
          glasslock.CredentialId(cred1),
          glasslock.CredentialId(cred2),
        ],
      ),
    )

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

pub fn request_with_platform_attachment_test() {
  let #(options_json, _) =
    make_request(
      registration.Options(
        ..setup_options(glasslock.VerificationPreferred),
        authenticator_attachment: option.Some(registration.Platform),
      ),
    )
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

pub fn request_with_cross_platform_attachment_test() {
  let #(options_json, _) =
    make_request(
      registration.Options(
        ..setup_options(glasslock.VerificationPreferred),
        authenticator_attachment: option.Some(registration.CrossPlatform),
      ),
    )
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

pub fn request_resident_key_variants_test() {
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
    let #(options_json, _) =
      make_request(
        registration.Options(
          ..setup_options(glasslock.VerificationPreferred),
          resident_key: variant,
        ),
      )
    let assert Ok(rk) = json.parse(json.to_string(options_json), decoder)
    assert rk == expected_string
  })
}

pub fn request_attestation_variants_test() {
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
    let #(options_json, _) =
      make_request(
        registration.Options(
          ..setup_options(glasslock.VerificationPreferred),
          attestation: variant,
        ),
      )
    let assert Ok(att) = json.parse(json.to_string(options_json), decoder)
    assert att == expected_string
  })
}

pub fn request_rejects_empty_origins_test() {
  let assert Error(registration.ParseError(message)) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: [],
      options: registration.default_options(),
    )
  assert message
    == "no allowed origins configured; pass a non-empty origins list to request"
}

pub fn request_rejects_empty_algorithms_test() {
  let assert Error(registration.ParseError(message)) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: ["https://example.com"],
      options: registration.Options(
        ..registration.default_options(),
        algorithms: [],
      ),
    )
  assert message
    == "no algorithms configured; pass a non-empty algorithms list to request"
}

pub fn request_accepts_valid_inputs_test() {
  let assert Ok(#(_, challenge)) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: ["https://example.com"],
      options: registration.default_options(),
    )

  assert testing.registration_challenge_origins(challenge)
    == ["https://example.com"]
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
    == Error(registration.ParseError("Invalid registration response JSON"))
}

pub fn verify_rejects_wrong_type_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)

  let wrong_type_client_data =
    testing.build_client_data(
      type_: "webauthn.get",
      challenge: testing.registration_challenge_bytes(challenge),
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
  assert result == Error(registration.VerificationMismatch(glasslock.TypeField))
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
    == Error(registration.VerificationMismatch(glasslock.ChallengeField))
}

pub fn verify_rejects_origin_mismatch_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)

  let wrong_origin_client_data =
    testing.build_client_data_create(
      challenge: testing.registration_challenge_bytes(challenge),
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
  assert result
    == Error(registration.VerificationMismatch(glasslock.OriginField))
}

pub fn verify_rejects_when_verification_required_but_not_performed_test() {
  let challenge =
    setup_challenge_with_verification(glasslock.VerificationRequired)
  let response_json =
    build_response(
      challenge:,
      flags: testing.AuthenticatorFlags(
        user_present: True,
        user_verified: False,
      ),
    )
  let result = registration.verify(response_json:, challenge:)
  assert result == Error(registration.UserVerificationFailed)
}

pub fn verify_succeeds_when_verification_required_and_performed_test() {
  let challenge =
    setup_challenge_with_verification(glasslock.VerificationRequired)
  let response_json =
    build_response(
      challenge:,
      flags: testing.AuthenticatorFlags(user_present: True, user_verified: True),
    )
  let assert Ok(cred) = registration.verify(response_json:, challenge:)
  assert cred.sign_count == 0
}

pub fn verify_rejects_user_presence_not_asserted_test() {
  let challenge = setup_challenge()
  let response_json =
    build_response(
      challenge:,
      flags: testing.AuthenticatorFlags(
        user_present: False,
        user_verified: False,
      ),
    )
  let result = registration.verify(response_json:, challenge:)
  assert result == Error(registration.UserPresenceFailed)
}

pub fn verify_rejects_rp_id_mismatch_test() {
  let challenge = setup_challenge()
  let keypair = testing.generate_es256_keypair()
  let credential_id = glasslock.CredentialId(<<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>)

  let auth_data =
    testing.build_registration_authenticator_data(
      relying_party_id: "evil.com",
      credential_id:,
      cose_key: testing.cose_key(keypair),
      flags: testing.default_flags(),
      sign_count: 0,
    )
  let client_data_json =
    testing.build_client_data_create(
      challenge: testing.registration_challenge_bytes(challenge),
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
  assert result
    == Error(registration.VerificationMismatch(glasslock.RelyingPartyIdField))
}

pub fn verify_rejects_cross_origin_when_disabled_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)

  let cross_origin_client_data =
    testing.build_client_data_create(
      challenge: testing.registration_challenge_bytes(challenge),
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
    == Error(registration.VerificationMismatch(glasslock.CrossOriginField))
}

pub fn verify_succeeds_with_cross_origin_allowed_test() {
  let #(_, challenge) =
    make_request(
      registration.Options(
        ..setup_options(glasslock.VerificationPreferred),
        allow_cross_origin: True,
      ),
    )
  let response = testing.build_registration_response(challenge:)

  let cross_origin_client_data =
    testing.build_client_data_create(
      challenge: testing.registration_challenge_bytes(challenge),
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

pub fn verify_accepts_allowed_top_origin_test() {
  let assert Ok(#(_, challenge)) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: ["https://example.com"],
      options: registration.Options(
        ..registration.default_options(),
        allow_cross_origin: True,
        allowed_top_origins: ["https://top.example.com"],
      ),
    )
  let response = testing.build_registration_response(challenge:)

  let client_data_json =
    testing.build_client_data(
      type_: "webauthn.create",
      challenge: testing.registration_challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
      top_origin: option.Some("https://top.example.com"),
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(..response, client_data_json:),
    )

  let assert Ok(_cred) = registration.verify(response_json:, challenge:)
}

pub fn verify_rejects_unknown_top_origin_test() {
  let assert Ok(#(_, challenge)) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: ["https://example.com"],
      options: registration.Options(
        ..registration.default_options(),
        allow_cross_origin: True,
        allowed_top_origins: ["https://top.example.com"],
      ),
    )
  let response = testing.build_registration_response(challenge:)

  let client_data_json =
    testing.build_client_data(
      type_: "webauthn.create",
      challenge: testing.registration_challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
      top_origin: option.Some("https://evil.com"),
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(..response, client_data_json:),
    )

  let result = registration.verify(response_json:, challenge:)
  assert result
    == Error(registration.VerificationMismatch(glasslock.TopOriginField))
}

pub fn verify_rejects_missing_top_origin_with_allowlist_test() {
  let assert Ok(#(_, challenge)) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: ["https://example.com"],
      options: registration.Options(
        ..registration.default_options(),
        allow_cross_origin: True,
        allowed_top_origins: ["https://top.example.com"],
      ),
    )
  let response = testing.build_registration_response(challenge:)

  let client_data_json =
    testing.build_client_data(
      type_: "webauthn.create",
      challenge: testing.registration_challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
      top_origin: option.None,
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(..response, client_data_json:),
    )

  let result = registration.verify(response_json:, challenge:)
  assert result
    == Error(registration.VerificationMismatch(glasslock.TopOriginField))
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
    == Error(registration.VerificationMismatch(glasslock.CredentialTypeField))
}

pub fn encode_decode_roundtrip_preserves_challenge_test() {
  use inputs <- qcheck.given(qcheck.tuple6(
    qcheck.non_empty_string(),
    non_empty_list_from(qcheck.non_empty_string()),
    non_empty_list_from(algorithm_generator()),
    qcheck.list_from(qcheck.non_empty_string()),
    qcheck.bool(),
    qcheck.tuple2(user_verification_generator(), user_presence_generator()),
  ))
  let #(
    rp_id,
    origins,
    algorithms,
    allowed_top_origins,
    allow_cross_origin,
    #(user_verification, user_presence),
  ) = inputs

  let options =
    registration.Options(
      ..registration.default_options(),
      algorithms:,
      allow_cross_origin:,
      allowed_top_origins:,
      user_verification:,
      user_presence:,
    )
  let assert Ok(#(_, challenge)) =
    registration.request(
      relying_party: registration.RelyingParty(id: rp_id, name: "Test App"),
      user: registration.User(
        id: <<1, 2, 3, 4>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins:,
      options:,
    )

  let encoded = registration.encode_challenge(challenge)
  let assert Ok(decoded) = registration.parse_challenge(encoded)

  let challenge_data = registration.challenge_data(challenge)
  let decoded_data = registration.challenge_data(decoded)
  let challenge_origins =
    challenge_data.origins |> set.to_list |> list.sort(string.compare)
  let decoded_origins =
    decoded_data.origins |> set.to_list |> list.sort(string.compare)

  assert decoded_origins == challenge_origins
  assert decoded_data.bytes == challenge_data.bytes
  assert decoded_data.rp_id == challenge_data.rp_id
  assert decoded_data.user_verification == challenge_data.user_verification
  assert decoded_data.user_presence == challenge_data.user_presence
  assert decoded_data.allow_cross_origin == challenge_data.allow_cross_origin
  assert decoded_data.allowed_top_origins == challenge_data.allowed_top_origins
  assert registration.challenge_algorithms(decoded)
    == registration.challenge_algorithms(challenge)
}

pub fn decoded_challenge_drives_verify_test() {
  let assert Ok(#(_, challenge)) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origins: ["https://example.com"],
      options: registration.default_options(),
    )

  let encoded = registration.encode_challenge(challenge)
  let assert Ok(decoded) = registration.parse_challenge(encoded)

  let response =
    testing.build_registration_response_with_keypair(
      challenge: decoded,
      keypair: testing.generate_es256_keypair(),
    )
  let response_json = testing.to_registration_json(response)
  let assert Ok(_) = registration.verify(response_json:, challenge: decoded)
}

pub fn decode_rejects_authentication_blob_test() {
  let assert Ok(#(_, auth_challenge)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com"],
      options: authentication.default_options(),
    )
  let encoded = authentication.encode_challenge(auth_challenge)

  let result = registration.parse_challenge(encoded)
  assert result
    == Error(registration.ParseError(
      "Expected registration challenge, got authentication",
    ))
}

pub fn decode_rejects_unknown_version_test() {
  let blob =
    json.object([
      #("v", json.int(99)),
      #("kind", json.string("registration")),
      #("bytes", json.string(bit_array.base64_url_encode(<<0:256>>, False))),
      #("rp_id", json.string("example.com")),
      #("origins", json.array(["https://example.com"], json.string)),
      #("user_verification", json.string("preferred")),
      #("user_presence", json.string("required")),
      #("allow_cross_origin", json.bool(False)),
      #("allowed_top_origins", json.array([], json.string)),
      #("algorithms", json.array([-7], json.int)),
    ])
    |> json.to_string

  let result = registration.parse_challenge(blob)
  assert result
    == Error(registration.ParseError("Unsupported challenge version: 99"))
}

pub fn request_emits_compat_json_test() {
  let assert Ok(#(options_json, challenge)) =
    registration.request(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Compat Test",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "alice",
        display_name: "Alice Example",
      ),
      origins: ["https://example.com"],
      options: registration.Options(
        timeout: duration.seconds(90),
        attestation: registration.AttestationDirect,
        authenticator_attachment: option.Some(registration.CrossPlatform),
        resident_key: registration.ResidentKeyRequired,
        user_verification: glasslock.VerificationRequired,
        user_presence: glasslock.PresenceRequired,
        allow_cross_origin: False,
        algorithms: [
          registration.Es256,
          registration.Ed25519,
          registration.Rs256,
        ],
        exclude_credentials: [
          glasslock.CredentialId(<<10, 11, 12>>),
          glasslock.CredentialId(<<20, 21, 22, 23>>),
        ],
        allowed_top_origins: [],
      ),
    )

  let challenge_b64 =
    bit_array.base64_url_encode(
      testing.registration_challenge_bytes(challenge),
      False,
    )

  options_json
  |> json.to_string
  |> string.replace(each: challenge_b64, with: "REDACTED_CHALLENGE_BASE64URL")
  |> birdie.snap("glasslock registration.request emits compat JSON")
}
