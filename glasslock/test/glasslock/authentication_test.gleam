import glasslock
import glasslock/authentication
import glasslock/testing
import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import kryptos/crypto
import kryptos/hash

pub fn generate_options_emits_core_fields_test() {
  let options =
    authentication.Options(
      ..authentication.default_options(),
      rp_id: "example.com",
      origins: ["https://example.com"],
    )

  let #(options_json, challenge) = authentication.generate_options(options)

  let decoder = {
    use rp_id <- decode.field("rpId", decode.string)
    use timeout <- decode.field("timeout", decode.int)
    use uv <- decode.field("userVerification", decode.string)
    decode.success(#(rp_id, timeout, uv))
  }

  let assert Ok(#(rp_id, timeout, uv)) =
    json.parse(json.to_string(options_json), decoder)
  assert rp_id == "example.com"
  assert timeout == 60_000
  assert uv == "preferred"

  assert authentication.challenge_origins(challenge) == ["https://example.com"]
  assert authentication.challenge_rp_id(challenge) == "example.com"
  assert bit_array.byte_size(authentication.challenge_bytes(challenge)) == 32
}

pub fn generate_options_produces_unique_challenges_test() {
  let options =
    authentication.Options(
      ..authentication.default_options(),
      rp_id: "example.com",
      origins: ["https://example.com"],
    )

  let #(_, challenge1) = authentication.generate_options(options)
  let #(_, challenge2) = authentication.generate_options(options)
  assert authentication.challenge_bytes(challenge1)
    != authentication.challenge_bytes(challenge2)
}

pub fn generate_options_with_allow_credentials_test() {
  let cred1 = <<1, 2, 3, 4>>
  let cred2 = <<5, 6, 7, 8>>
  let options =
    authentication.Options(
      ..authentication.default_options(),
      rp_id: "example.com",
      origins: ["https://example.com"],
      allow_credentials: [
        glasslock.CredentialId(cred1),
        glasslock.CredentialId(cred2),
      ],
    )

  let #(options_json, _) = authentication.generate_options(options)

  let id_decoder = {
    use id <- decode.field("id", decode.string)
    decode.success(id)
  }
  let decoder = {
    use ids <- decode.field("allowCredentials", decode.list(id_decoder))
    decode.success(ids)
  }
  let assert Ok(ids) = json.parse(json.to_string(options_json), decoder)
  assert ids
    == [
      bit_array.base64_url_encode(cred1, False),
      bit_array.base64_url_encode(cred2, False),
    ]
}

pub fn generate_options_user_verification_variants_test() {
  let variants = [
    #(glasslock.VerificationDiscouraged, "discouraged"),
    #(glasslock.VerificationPreferred, "preferred"),
    #(glasslock.VerificationRequired, "required"),
  ]

  let decoder = {
    use uv <- decode.field("userVerification", decode.string)
    decode.success(uv)
  }

  list.each(variants, fn(pair) {
    let #(variant, expected_string) = pair
    let options =
      authentication.Options(
        ..authentication.default_options(),
        rp_id: "example.com",
        origins: ["https://example.com"],
        user_verification: variant,
      )

    let #(options_json, _) = authentication.generate_options(options)
    let assert Ok(uv) = json.parse(json.to_string(options_json), decoder)
    assert uv == expected_string
  })
}

pub fn verify_valid_authentication_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.id == stored_credential.id
  assert cred.sign_count == 1
  assert cred.public_key == stored_credential.public_key
}

pub fn verify_valid_authentication_ed25519_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        generate_keypair: testing.generate_ed25519_keypair,
      ),
    )

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.sign_count == 1
}

pub fn verify_rejects_invalid_json_test() {
  let #(challenge, stored_credential, _keypair) = setup_authentication()

  let result =
    authentication.verify(
      response_json: "{not valid json",
      challenge:,
      stored: stored_credential,
    )

  assert result
    == Error(glasslock.ParseError("Invalid authentication response JSON"))
}

pub fn verify_rejects_wrong_type_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let wrong_type_client_data =
    testing.build_client_data(
      type_: "webauthn.create",
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
      top_origin: option.None,
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json: wrong_type_client_data,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.VerificationMismatch(glasslock.TypeField))
}

pub fn verify_rejects_challenge_mismatch_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let wrong_challenge_client_data =
    testing.build_client_data_get(
      challenge: <<9, 9, 9, 9>>,
      origin: "https://example.com",
      cross_origin: False,
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json: wrong_challenge_client_data,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(glasslock.VerificationMismatch(glasslock.ChallengeField))
}

pub fn verify_rejects_origin_mismatch_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let wrong_origin_client_data =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://evil.com",
      cross_origin: False,
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json: wrong_origin_client_data,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.VerificationMismatch(glasslock.OriginField))
}

pub fn verify_rejects_credential_not_allowed_test() {
  let other_credential_id = glasslock.CredentialId(crypto.random_bytes(32))
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        allow_credentials_override: option.Some([other_credential_id]),
      ),
    )

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.CredentialNotAllowed)
}

pub fn verify_rejects_credential_id_mismatch_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        allow_credentials_override: option.Some([]),
      ),
    )
  let different_credential_id = glasslock.CredentialId(crypto.random_bytes(32))

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: different_credential_id,
      user_handle: option.None,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.CredentialNotAllowed)
}

pub fn verify_rejects_invalid_signature_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let corrupted =
    testing.AuthenticationResponse(..response, signature: <<0:512>>)
  let response_json =
    testing.to_authentication_json(
      corrupted,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.InvalidSignature)
}

pub fn verify_rejects_sign_count_regression_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(..default_auth_setup(), stored_sign_count: 10),
    )

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 5)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.SignCountRegression)
}

pub fn verify_rejects_sign_count_reset_to_zero_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(..default_auth_setup(), stored_sign_count: 10),
    )

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 0)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.SignCountRegression)
}

pub fn verify_rejects_when_verification_required_but_not_performed_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        user_verification: glasslock.VerificationRequired,
      ),
    )

  let response_json =
    signed_response_with_flags(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      flags: testing.AuthenticatorFlags(
        user_present: True,
        user_verified: False,
      ),
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.UserVerificationFailed)
}

pub fn verify_succeeds_when_verification_required_and_performed_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        user_verification: glasslock.VerificationRequired,
      ),
    )

  let response_json =
    signed_response_with_flags(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      flags: testing.AuthenticatorFlags(user_present: True, user_verified: True),
    )

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.sign_count == 1
}

pub fn verify_rejects_user_presence_not_asserted_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let response_json =
    signed_response_with_flags(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      flags: testing.AuthenticatorFlags(
        user_present: False,
        user_verified: False,
      ),
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.UserPresenceFailed)
}

pub fn verify_rejects_rp_id_mismatch_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: "evil.com",
      flags: testing.default_flags(),
      sign_count: 1,
    )
  let client_data_json =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
    )
  let signature =
    testing.sign_authentication_message(
      keypair:,
      authenticator_data: auth_data,
      client_data_json:,
    )
  let response_json =
    testing.to_authentication_json_with(
      credential_id: stored_credential.id,
      authenticator_data: auth_data,
      client_data_json:,
      signature:,
      user_handle: option.None,
      credential_type: "public-key",
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result == Error(glasslock.VerificationMismatch(glasslock.RpIdField))
}

pub fn verify_rejects_at_flag_in_authentication_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  // Craft auth_data with AT (0x40) flag set manually: no testing helper
  // exposes this since it's illegal input for the authentication ceremony.
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("example.com"))
  let auth_data =
    bit_array.concat([rp_id_hash, <<0x41>>, <<0x00, 0x00, 0x00, 0x01>>])

  let client_data_json =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
    )
  let signature =
    testing.sign_authentication_message(
      keypair:,
      authenticator_data: auth_data,
      client_data_json:,
    )
  let response_json =
    testing.to_authentication_json_with(
      credential_id: stored_credential.id,
      authenticator_data: auth_data,
      client_data_json:,
      signature:,
      user_handle: option.None,
      credential_type: "public-key",
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(glasslock.ParseError("AT flag should not be set in authentication"))
}

pub fn verify_rejects_cross_origin_when_disabled_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let cross_origin_client_data =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json: cross_origin_client_data,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(glasslock.VerificationMismatch(glasslock.CrossOriginField))
}

pub fn verify_succeeds_with_cross_origin_allowed_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(..default_auth_setup(), allow_cross_origin: True),
    )

  let cross_origin_client_data =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json: cross_origin_client_data,
    )

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.sign_count == 1
}

pub fn verify_sign_count_zero_stored_allows_any_new_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let response =
    testing.build_authentication_response(
      challenge:,
      keypair:,
      sign_count: 999_999,
    )
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.sign_count == 999_999
}

pub fn verify_both_sign_counts_zero_succeeds_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 0)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.sign_count == 0
}

pub fn verify_rejects_invalid_credential_type_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let response_json =
    testing.to_authentication_json_with(
      credential_id: stored_credential.id,
      authenticator_data: response.authenticator_data,
      client_data_json: response.client_data_json,
      signature: response.signature,
      user_handle: option.None,
      credential_type: "invalid-type",
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(glasslock.VerificationMismatch(glasslock.CredentialTypeField))
}

pub fn verify_discoverable_flow_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        allow_credentials_override: option.Some([]),
      ),
    )

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let assert Ok(info) = authentication.parse_response(response_json)
  assert info.credential_id == stored_credential.id

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.sign_count == 1
}

pub fn parse_response_extracts_credential_info_test() {
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let user_handle = <<9, 10, 11, 12>>

  let response_json =
    response_envelope(
      credential_id:,
      credential_type: "public-key",
      user_handle: option.Some(
        json.string(bit_array.base64_url_encode(user_handle, False)),
      ),
    )

  let assert Ok(info) = authentication.parse_response(response_json)
  assert info.credential_id == glasslock.CredentialId(credential_id)
  assert info.user_handle == option.Some(user_handle)
}

pub fn parse_response_handles_missing_user_handle_test() {
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

  let response_json =
    response_envelope(
      credential_id:,
      credential_type: "public-key",
      user_handle: option.None,
    )

  let assert Ok(info) = authentication.parse_response(response_json)
  assert info.user_handle == option.None
}

pub fn parse_response_handles_null_user_handle_test() {
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

  let response_json =
    response_envelope(
      credential_id:,
      credential_type: "public-key",
      user_handle: option.Some(json.null()),
    )

  let assert Ok(info) = authentication.parse_response(response_json)
  assert info.user_handle == option.None
}

pub fn parse_response_errors_on_invalid_user_handle_base64_test() {
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

  let response_json =
    response_envelope(
      credential_id:,
      credential_type: "public-key",
      user_handle: option.Some(json.string("!!!invalid-base64!!!")),
    )

  assert authentication.parse_response(response_json)
    == Error(glasslock.ParseError("Invalid base64url in userHandle"))
}

pub fn parse_response_rejects_invalid_json_test() {
  assert authentication.parse_response("{bad")
    == Error(glasslock.ParseError("Invalid authentication response JSON"))
}

type AuthSetup {
  AuthSetup(
    stored_sign_count: Int,
    user_verification: glasslock.UserVerification,
    allow_cross_origin: Bool,
    allow_credentials_override: option.Option(List(glasslock.CredentialId)),
    generate_keypair: fn() -> testing.KeyPair,
  )
}

fn default_auth_setup() -> AuthSetup {
  AuthSetup(
    stored_sign_count: 0,
    user_verification: glasslock.VerificationPreferred,
    allow_cross_origin: False,
    allow_credentials_override: option.None,
    generate_keypair: testing.generate_es256_keypair,
  )
}

fn setup_authentication() -> #(
  authentication.Challenge,
  glasslock.Credential,
  testing.KeyPair,
) {
  setup_authentication_with(default_auth_setup())
}

fn setup_authentication_with(
  config: AuthSetup,
) -> #(authentication.Challenge, glasslock.Credential, testing.KeyPair) {
  let keypair = config.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let stored_credential =
    glasslock.Credential(
      id: glasslock.CredentialId(credential_id),
      public_key: testing.public_key(keypair),
      sign_count: config.stored_sign_count,
    )
  let allow_credentials = case config.allow_credentials_override {
    option.None -> [glasslock.CredentialId(credential_id)]
    option.Some(ids) -> ids
  }
  let options =
    authentication.Options(
      ..authentication.default_options(),
      rp_id: "example.com",
      origins: ["https://example.com"],
      allow_credentials:,
      user_verification: config.user_verification,
      allow_cross_origin: config.allow_cross_origin,
    )
  let #(_, challenge) = authentication.generate_options(options)
  #(challenge, stored_credential, keypair)
}

fn signed_response(
  challenge challenge: authentication.Challenge,
  stored stored: glasslock.Credential,
  keypair keypair: testing.KeyPair,
  sign_count sign_count: Int,
  client_data_json client_data_json: BitArray,
) -> String {
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags: testing.default_flags(),
      sign_count:,
    )
  let signature =
    testing.sign_authentication_message(
      keypair:,
      authenticator_data: auth_data,
      client_data_json:,
    )
  testing.to_authentication_json_with(
    credential_id: stored.id,
    authenticator_data: auth_data,
    client_data_json:,
    signature:,
    user_handle: option.None,
    credential_type: "public-key",
  )
}

fn signed_response_with_flags(
  challenge challenge: authentication.Challenge,
  stored stored: glasslock.Credential,
  keypair keypair: testing.KeyPair,
  sign_count sign_count: Int,
  flags flags: testing.AuthenticatorFlags,
) -> String {
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags:,
      sign_count:,
    )
  let client_data_json =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
    )
  let signature =
    testing.sign_authentication_message(
      keypair:,
      authenticator_data: auth_data,
      client_data_json:,
    )
  testing.to_authentication_json_with(
    credential_id: stored.id,
    authenticator_data: auth_data,
    client_data_json:,
    signature:,
    user_handle: option.None,
    credential_type: "public-key",
  )
}

fn response_envelope(
  credential_id credential_id: BitArray,
  credential_type credential_type: String,
  user_handle user_handle: option.Option(json.Json),
) -> String {
  let base_response_fields = [
    #("clientDataJSON", json.string("dGVzdA")),
    #("authenticatorData", json.string("dGVzdA")),
    #("signature", json.string("dGVzdA")),
  ]
  let response_fields = case user_handle {
    option.None -> base_response_fields
    option.Some(value) -> [#("userHandle", value), ..base_response_fields]
  }
  json.object([
    #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
    #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
    #("type", json.string(credential_type)),
    #("response", json.object(response_fields)),
    #("clientExtensionResults", json.object([])),
  ])
  |> json.to_string
}
