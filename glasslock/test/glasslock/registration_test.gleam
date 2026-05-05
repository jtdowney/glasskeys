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

fn default_builder() -> registration.Builder {
  registration.new(
    relying_party: registration.RelyingParty(
      id: "example.com",
      name: "Test App",
    ),
    user: registration.User(
      id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
      name: "testuser",
      display_name: "Test User",
    ),
    origin: "https://example.com",
  )
}

fn make_request(
  builder: registration.Builder,
) -> #(Json, registration.Challenge) {
  registration.build(builder)
}

fn setup_challenge() -> registration.Challenge {
  setup_challenge_with_verification(glasslock.VerificationPreferred)
}

fn setup_challenge_with_verification(
  uv: glasslock.UserVerification,
) -> registration.Challenge {
  let #(_, challenge) =
    default_builder()
    |> registration.user_verification(uv)
    |> make_request
  challenge
}

fn build_response(
  challenge challenge: registration.Challenge,
  flags flags: testing.AuthenticatorFlags,
) -> String {
  let keypair = testing.generate_es256_keypair()
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>
  let auth_data =
    testing.build_registration_authenticator_data(
      relying_party_id: testing.registration_challenge_rp_id(challenge),
      credential_id:,
      cose_key_cbor: testing.cose_key(keypair),
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
    transports: [],
    id_override: option.None,
  )
}

pub fn request_emits_core_fields_test() {
  let #(options_json, challenge) = make_request(default_builder())

  let decoder = {
    use relying_party_id <- decode.subfield(["rp", "id"], decode.string)
    use relying_party_name <- decode.subfield(["rp", "name"], decode.string)
    use user_name <- decode.subfield(["user", "name"], decode.string)
    use timeout <- decode.field("timeout", decode.int)
    decode.success(#(relying_party_id, relying_party_name, user_name, timeout))
  }

  let assert Ok(#(relying_party_id, relying_party_name, user_name, timeout)) =
    json.parse(json.to_string(options_json), decoder)
  assert relying_party_id == "example.com"
  assert relying_party_name == "Test App"
  assert user_name == "testuser"
  assert timeout == 60_000

  assert testing.registration_challenge_origins(challenge)
    == ["https://example.com"]
  assert testing.registration_challenge_rp_id(challenge) == "example.com"
  assert bit_array.byte_size(testing.registration_challenge_bytes(challenge))
    == 32
}

pub fn request_with_exclude_credentials_test() {
  let cred1 = <<1, 2, 3, 4>>
  let cred2 = <<5, 6, 7, 8>>
  let #(options_json, _) =
    default_builder()
    |> registration.user_verification(glasslock.VerificationPreferred)
    |> registration.exclude_credential(id: cred1, transports: [])
    |> registration.exclude_credential(id: cred2, transports: [
      glasslock.TransportUsb,
      glasslock.TransportInternal,
    ])
    |> make_request

  let entry_decoder = {
    use id <- decode.field("id", decode.string)
    use transports <- decode.optional_field(
      "transports",
      [],
      decode.list(decode.string),
    )
    decode.success(#(id, transports))
  }
  let decoder = {
    use entries <- decode.field(
      "excludeCredentials",
      decode.list(entry_decoder),
    )
    decode.success(entries)
  }
  let assert Ok(entries) = json.parse(json.to_string(options_json), decoder)
  assert entries
    == [
      #(bit_array.base64_url_encode(cred2, False), ["usb", "internal"]),
      #(bit_array.base64_url_encode(cred1, False), []),
    ]
}

pub fn build_succeeds_with_defaults_test() {
  let #(_, challenge) = registration.build(default_builder())

  assert testing.registration_challenge_origins(challenge)
    == ["https://example.com"]
}

pub fn verify_valid_registration_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)
  let response_json = testing.to_registration_json(response)

  let assert Ok(cred) = registration.verify_json(response_json:, challenge:)
  assert cred.id == response.credential_id
  assert cred.sign_count == 0
  let raw_public_key = glasslock.encode_public_key(cred.public_key)
  assert bit_array.byte_size(raw_public_key) > 0
}

pub fn verify_stores_reported_transports_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)
  let response_json =
    testing.to_registration_json_with(
      credential_id: response.credential_id,
      client_data_json: response.client_data_json,
      attestation_object: response.attestation_object,
      credential_type: "public-key",
      transports: [glasslock.TransportUsb, glasslock.TransportHybrid],
      id_override: option.None,
    )

  let assert Ok(cred) = registration.verify_json(response_json:, challenge:)
  assert cred.transports == [glasslock.TransportUsb, glasslock.TransportHybrid]
}

pub fn verify_defaults_transports_to_empty_when_field_missing_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)
  let response_json = testing.to_registration_json(response)

  let assert Ok(cred) = registration.verify_json(response_json:, challenge:)
  assert cred.transports == []
}

pub fn verify_drops_unknown_transport_strings_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)
  let raw_id_b64 = bit_array.base64_url_encode(response.credential_id, False)
  let response_json =
    json.object([
      #("id", json.string(raw_id_b64)),
      #("rawId", json.string(raw_id_b64)),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #(
            "clientDataJSON",
            json.string(bit_array.base64_url_encode(
              response.client_data_json,
              False,
            )),
          ),
          #(
            "attestationObject",
            json.string(bit_array.base64_url_encode(
              response.attestation_object,
              False,
            )),
          ),
          #(
            "transports",
            json.array(["usb", "future-thing", "hybrid"], json.string),
          ),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let assert Ok(cred) = registration.verify_json(response_json:, challenge:)
  assert cred.transports == [glasslock.TransportUsb, glasslock.TransportHybrid]
}

pub fn verify_rejects_invalid_json_test() {
  let challenge = setup_challenge()
  let result =
    registration.verify_json(response_json: "{not valid json", challenge:)
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

  let result = registration.verify_json(response_json:, challenge:)
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

  let result = registration.verify_json(response_json:, challenge:)
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

  let result = registration.verify_json(response_json:, challenge:)
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
  let result = registration.verify_json(response_json:, challenge:)
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
  let assert Ok(cred) = registration.verify_json(response_json:, challenge:)
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
  let result = registration.verify_json(response_json:, challenge:)
  assert result == Error(registration.UserPresenceFailed)
}

pub fn verify_rejects_rp_id_mismatch_test() {
  let challenge = setup_challenge()
  let keypair = testing.generate_es256_keypair()
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>

  let auth_data =
    testing.build_registration_authenticator_data(
      relying_party_id: "evil.com",
      credential_id:,
      cose_key_cbor: testing.cose_key(keypair),
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
      transports: [],
      id_override: option.None,
    )

  let result = registration.verify_json(response_json:, challenge:)
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

  let result = registration.verify_json(response_json:, challenge:)
  assert result
    == Error(registration.VerificationMismatch(glasslock.CrossOriginField))
}

pub fn verify_succeeds_with_cross_origin_allowed_test() {
  let #(_, challenge) =
    default_builder()
    |> registration.user_verification(glasslock.VerificationPreferred)
    |> registration.allow_cross_origin(True)
    |> make_request
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

  let assert Ok(_cred) = registration.verify_json(response_json:, challenge:)
}

pub fn verify_accepts_allowed_top_origin_test() {
  let #(_, challenge) =
    default_builder()
    |> registration.allow_cross_origin(True)
    |> registration.allowed_top_origin("https://top.example.com")
    |> registration.build()
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

  let assert Ok(_cred) = registration.verify_json(response_json:, challenge:)
}

pub fn verify_rejects_unknown_top_origin_test() {
  let #(_, challenge) =
    default_builder()
    |> registration.allow_cross_origin(True)
    |> registration.allowed_top_origin("https://top.example.com")
    |> registration.build()
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

  let result = registration.verify_json(response_json:, challenge:)
  assert result
    == Error(registration.VerificationMismatch(glasslock.TopOriginField))
}

pub fn verify_accepts_missing_top_origin_with_allowlist_test() {
  let #(_, challenge) =
    default_builder()
    |> registration.allow_cross_origin(True)
    |> registration.allowed_top_origin("https://top.example.com")
    |> registration.build()
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

  let assert Ok(_cred) = registration.verify_json(response_json:, challenge:)
}

pub fn verify_rejects_top_origin_without_cross_origin_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)

  let client_data_json =
    testing.build_client_data(
      type_: "webauthn.create",
      challenge: testing.registration_challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
      top_origin: option.Some("https://top.example.com"),
    )
  let response_json =
    testing.to_registration_json(
      testing.RegistrationResponse(..response, client_data_json:),
    )

  let result = registration.verify_json(response_json:, challenge:)
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
      transports: [],
      id_override: option.None,
    )

  let result = registration.verify_json(response_json:, challenge:)
  assert result
    == Error(registration.VerificationMismatch(glasslock.CredentialTypeField))
}

pub fn verify_rejects_top_level_id_mismatched_with_raw_id_test() {
  let challenge = setup_challenge()
  let response = testing.build_registration_response(challenge:)
  let mismatched_id_b64 =
    bit_array.base64_url_encode(<<99, 99, 99, 99, 99, 99, 99, 99>>, False)
  let response_json =
    testing.to_registration_json_with(
      credential_id: response.credential_id,
      client_data_json: response.client_data_json,
      attestation_object: response.attestation_object,
      credential_type: "public-key",
      transports: [],
      id_override: option.Some(mismatched_id_b64),
    )

  let result = registration.verify_json(response_json:, challenge:)
  assert result
    == Error(registration.VerificationMismatch(glasslock.CredentialIdField))
}

pub fn verify_rejects_non_empty_attestation_statement_test() {
  let challenge = setup_challenge()
  let keypair = testing.generate_es256_keypair()
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>
  let auth_data =
    testing.build_registration_authenticator_data(
      relying_party_id: testing.registration_challenge_rp_id(challenge),
      credential_id:,
      cose_key_cbor: testing.cose_key(keypair),
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
      attestation_object: testing.build_attestation_object_with_non_empty_attstmt(
        auth_data:,
      ),
      credential_type: "public-key",
      transports: [],
      id_override: option.None,
    )

  let result = registration.verify_json(response_json:, challenge:)
  assert result
    == Error(registration.InvalidAttestation(
      "none attestation with non-empty statement",
    ))
}

pub fn verify_rejects_unsupported_attestation_format_test() {
  let challenge = setup_challenge()
  let keypair = testing.generate_es256_keypair()
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>
  let auth_data =
    testing.build_registration_authenticator_data(
      relying_party_id: testing.registration_challenge_rp_id(challenge),
      credential_id:,
      cose_key_cbor: testing.cose_key(keypair),
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
      attestation_object: testing.build_attestation_object_with_fmt(
        fmt: "fido-u2f",
        auth_data:,
      ),
      credential_type: "public-key",
      transports: [],
      id_override: option.None,
    )

  let result = registration.verify_json(response_json:, challenge:)
  assert result
    == Error(registration.InvalidAttestation("unsupported format: fido-u2f"))
}

pub fn verify_rejects_credential_algorithm_not_requested_test() {
  let #(_, challenge) =
    default_builder()
    |> registration.algorithms([registration.Ed25519])
    |> make_request
  let response = testing.build_registration_response(challenge:)
  let response_json = testing.to_registration_json(response)

  let result = registration.verify_json(response_json:, challenge:)
  assert result
    == Error(registration.UnsupportedKey(
      "credential algorithm does not match requested algorithms",
    ))
}

pub fn encode_decode_roundtrip_preserves_challenge_test() {
  use inputs <- qcheck.given(qcheck.tuple6(
    qcheck.non_empty_string(),
    non_empty_list_from(qcheck.non_empty_string()),
    non_empty_list_from(algorithm_generator()),
    qcheck.list_from(qcheck.non_empty_string()),
    qcheck.bool(),
    user_verification_generator(),
  ))
  let #(
    rp_id,
    origins,
    algorithms,
    allowed_top_origins,
    allow_cross_origin,
    user_verification,
  ) = inputs
  let assert [first_origin, ..rest_origins] = origins

  let builder =
    registration.new(
      relying_party: registration.RelyingParty(id: rp_id, name: "Test App"),
      user: registration.User(
        id: <<1, 2, 3, 4>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: first_origin,
    )
    |> registration.algorithms(algorithms)
    |> registration.allow_cross_origin(allow_cross_origin)
    |> registration.user_verification(user_verification)
  let builder = list.fold(rest_origins, builder, registration.origin)
  let builder =
    list.fold(allowed_top_origins, builder, registration.allowed_top_origin)
  let #(_, challenge) = registration.build(builder)

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
  assert decoded_data.allow_cross_origin == challenge_data.allow_cross_origin
  assert decoded_data.allowed_top_origins == challenge_data.allowed_top_origins
  assert registration.challenge_algorithms(decoded)
    == registration.challenge_algorithms(challenge)
}

pub fn decoded_challenge_drives_verify_test() {
  let #(_, challenge) =
    registration.new(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Test App",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4>>,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
    )
    |> registration.build()

  let encoded = registration.encode_challenge(challenge)
  let assert Ok(decoded) = registration.parse_challenge(encoded)

  let response =
    testing.build_registration_response_with_keypair(
      challenge: decoded,
      keypair: testing.generate_es256_keypair(),
    )
  let response_json = testing.to_registration_json(response)
  let assert Ok(_) =
    registration.verify_json(response_json:, challenge: decoded)
}

pub fn decode_rejects_authentication_blob_test() {
  let #(_, auth_challenge) =
    authentication.new(
      relying_party_id: "example.com",
      origin: "https://example.com",
    )
    |> authentication.build()
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
      #("allow_cross_origin", json.bool(False)),
      #("allowed_top_origins", json.array([], json.string)),
      #("algorithms", json.array([-7], json.int)),
    ])
    |> json.to_string

  let result = registration.parse_challenge(blob)
  assert result
    == Error(registration.ParseError("Unsupported challenge version: 99"))
}

pub fn decode_rejects_missing_algorithms_test() {
  let blob =
    json.object([
      #("v", json.int(1)),
      #("kind", json.string("registration")),
      #("bytes", json.string(bit_array.base64_url_encode(<<0:256>>, False))),
      #("rp_id", json.string("example.com")),
      #("origins", json.array(["https://example.com"], json.string)),
      #("user_verification", json.string("preferred")),
      #("allow_cross_origin", json.bool(False)),
      #("allowed_top_origins", json.array([], json.string)),
    ])
    |> json.to_string

  let result = registration.parse_challenge(blob)
  assert result == Error(registration.ParseError("Invalid challenge encoding"))
}

pub fn request_emits_compat_json_test() {
  let #(options_json, challenge) =
    registration.new(
      relying_party: registration.RelyingParty(
        id: "example.com",
        name: "Compat Test",
      ),
      user: registration.User(
        id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "alice",
        display_name: "Alice Example",
      ),
      origin: "https://example.com",
    )
    |> registration.timeout(duration.seconds(90))
    |> registration.authenticator_attachment(registration.CrossPlatform)
    |> registration.resident_key(registration.ResidentKeyRequired)
    |> registration.user_verification(glasslock.VerificationRequired)
    |> registration.algorithms([
      registration.Es256,
      registration.Ed25519,
      registration.Rs256,
    ])
    |> registration.exclude_credential(id: <<10, 11, 12>>, transports: [])
    |> registration.exclude_credential(id: <<20, 21, 22, 23>>, transports: [
      glasslock.TransportUsb,
      glasslock.TransportNfc,
    ])
    |> registration.build()

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
