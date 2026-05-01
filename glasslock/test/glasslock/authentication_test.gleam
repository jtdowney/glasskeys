import birdie
import glasslock
import glasslock/authentication
import glasslock/internal/cbor
import glasslock/registration
import glasslock/testing
import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/set
import gleam/string
import gleam/time/duration
import kryptos/crypto
import kryptos/hash
import qcheck

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

fn credential_id_generator() -> qcheck.Generator(glasslock.CredentialId) {
  qcheck.byte_aligned_bit_array() |> qcheck.map(glasslock.CredentialId)
}

fn transport_generator() -> qcheck.Generator(glasslock.Transport) {
  qcheck.from_generators(qcheck.return(glasslock.TransportUsb), [
    qcheck.return(glasslock.TransportNfc),
    qcheck.return(glasslock.TransportBle),
    qcheck.return(glasslock.TransportSmartCard),
    qcheck.return(glasslock.TransportHybrid),
    qcheck.return(glasslock.TransportInternal),
  ])
}

fn credential_descriptor_generator() -> qcheck.Generator(
  glasslock.CredentialDescriptor,
) {
  qcheck.map2(
    credential_id_generator(),
    qcheck.list_from(transport_generator()),
    fn(id, transports) { glasslock.CredentialDescriptor(id:, transports:) },
  )
}

type AuthSetup {
  AuthSetup(
    stored_sign_count: Int,
    user_verification: glasslock.UserVerification,
    allow_cross_origin: Bool,
    allowed_top_origins: List(String),
    allow_credentials_override: option.Option(
      List(glasslock.CredentialDescriptor),
    ),
    generate_keypair: fn() -> testing.KeyPair,
  )
}

fn default_auth_setup() -> AuthSetup {
  AuthSetup(
    stored_sign_count: 0,
    user_verification: glasslock.VerificationPreferred,
    allow_cross_origin: False,
    allowed_top_origins: [],
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
  let credential_id = crypto.random_bytes(16)
  let stored_credential =
    glasslock.Credential(
      id: glasslock.CredentialId(credential_id),
      public_key: testing.public_key(keypair),
      sign_count: config.stored_sign_count,
      transports: [],
    )
  let allow_credentials = case config.allow_credentials_override {
    option.None -> [
      glasslock.CredentialDescriptor(
        id: stored_credential.id,
        transports: stored_credential.transports,
      ),
    ]
    option.Some(descriptors) -> descriptors
  }
  let assert Ok(#(_, challenge)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com"],
      options: authentication.Options(
        ..authentication.default_options(),
        allow_credentials:,
        user_verification: option.Some(config.user_verification),
        allow_cross_origin: config.allow_cross_origin,
        allowed_top_origins: config.allowed_top_origins,
      ),
    )
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
      relying_party_id: testing.authentication_challenge_rp_id(challenge),
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
    id_override: option.None,
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
      relying_party_id: testing.authentication_challenge_rp_id(challenge),
      flags:,
      sign_count:,
    )
  let client_data_json =
    testing.build_client_data_get(
      challenge: testing.authentication_challenge_bytes(challenge),
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
    id_override: option.None,
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

pub fn request_emits_core_fields_test() {
  let assert Ok(#(options_json, challenge)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com"],
      options: authentication.default_options(),
    )

  let decoder = {
    use relying_party_id <- decode.field("rpId", decode.string)
    use timeout <- decode.field("timeout", decode.int)
    use uv <- decode.optional_field(
      "userVerification",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(#(relying_party_id, timeout, uv))
  }

  let assert Ok(#(relying_party_id, timeout, uv)) =
    json.parse(json.to_string(options_json), decoder)
  assert relying_party_id == "example.com"
  assert timeout == 60_000
  assert uv == option.None

  assert testing.authentication_challenge_origins(challenge)
    == ["https://example.com"]
  assert testing.authentication_challenge_rp_id(challenge) == "example.com"
  assert bit_array.byte_size(testing.authentication_challenge_bytes(challenge))
    == 32
}

pub fn request_with_allow_credentials_test() {
  let cred1 = <<1, 2, 3, 4>>
  let cred2 = <<5, 6, 7, 8>>
  let assert Ok(#(options_json, _)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com"],
      options: authentication.Options(
        ..authentication.default_options(),
        allow_credentials: [
          glasslock.CredentialDescriptor(
            id: glasslock.CredentialId(cred1),
            transports: [],
          ),
          glasslock.CredentialDescriptor(
            id: glasslock.CredentialId(cred2),
            transports: [glasslock.TransportUsb, glasslock.TransportNfc],
          ),
        ],
      ),
    )

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
    use entries <- decode.field("allowCredentials", decode.list(entry_decoder))
    decode.success(entries)
  }
  let assert Ok(entries) = json.parse(json.to_string(options_json), decoder)
  assert entries
    == [
      #(bit_array.base64_url_encode(cred1, False), []),
      #(bit_array.base64_url_encode(cred2, False), ["usb", "nfc"]),
    ]
}

pub fn request_rejects_empty_origins_test() {
  let result =
    authentication.request(
      relying_party_id: "example.com",
      origins: [],
      options: authentication.default_options(),
    )

  assert result
    == Error(authentication.ParseError(
      "no allowed origins configured; pass a non-empty origins list to request",
    ))
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
    == Error(authentication.ParseError("Invalid authentication response JSON"))
}

pub fn verify_rejects_wrong_type_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let wrong_type_client_data =
    testing.build_client_data(
      type_: "webauthn.create",
      challenge: testing.authentication_challenge_bytes(challenge),
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
  assert result
    == Error(authentication.VerificationMismatch(glasslock.TypeField))
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
    == Error(authentication.VerificationMismatch(glasslock.ChallengeField))
}

pub fn verify_rejects_origin_mismatch_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let wrong_origin_client_data =
    testing.build_client_data_get(
      challenge: testing.authentication_challenge_bytes(challenge),
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
  assert result
    == Error(authentication.VerificationMismatch(glasslock.OriginField))
}

pub fn verify_rejects_credential_not_allowed_test() {
  let other_descriptor =
    glasslock.CredentialDescriptor(
      id: glasslock.CredentialId(crypto.random_bytes(16)),
      transports: [],
    )
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        allow_credentials_override: option.Some([other_descriptor]),
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
  assert result == Error(authentication.CredentialNotAllowed)
}

pub fn verify_rejects_credential_id_mismatch_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        allow_credentials_override: option.Some([]),
      ),
    )
  let different_credential_id = glasslock.CredentialId(crypto.random_bytes(16))

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
  assert result == Error(authentication.CredentialNotAllowed)
}

pub fn verify_rejects_top_level_id_mismatched_with_raw_id_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()
  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let glasslock.CredentialId(raw_id_bytes) = stored_credential.id
  let raw_id_b64 = bit_array.base64_url_encode(raw_id_bytes, False)
  let mismatched_id_b64 =
    bit_array.base64_url_encode(<<99, 99, 99, 99, 99, 99, 99, 99>>, False)
  let response_json =
    json.object([
      #("id", json.string(mismatched_id_b64)),
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
            "authenticatorData",
            json.string(bit_array.base64_url_encode(
              response.authenticator_data,
              False,
            )),
          ),
          #(
            "signature",
            json.string(bit_array.base64_url_encode(response.signature, False)),
          ),
        ]),
      ),
    ])
    |> json.to_string

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(authentication.VerificationMismatch(glasslock.CredentialIdField))
}

pub fn verify_rejects_unsupported_stored_public_key_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let response =
    testing.build_authentication_response(challenge:, keypair:, sign_count: 1)
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )

  let unsupported_key_cbor =
    cbor.encode(
      cbor.Map([
        #(cbor.Int(1), cbor.Int(4)),
        #(cbor.Int(-1), cbor.Bytes(<<0:256>>)),
      ]),
    )
  let stored_with_unsupported_key =
    glasslock.Credential(
      ..stored_credential,
      public_key: glasslock.PublicKey(unsupported_key_cbor),
    )

  let result =
    authentication.verify(
      response_json:,
      challenge:,
      stored: stored_with_unsupported_key,
    )
  assert result
    == Error(authentication.UnsupportedKey(
      "COSE key missing algorithm (label 3)",
    ))
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
  assert result == Error(authentication.InvalidSignature)
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
  assert result == Error(authentication.SignCountRegression)
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
  assert result == Error(authentication.SignCountRegression)
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
  assert result == Error(authentication.UserVerificationFailed)
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
  assert result == Error(authentication.UserPresenceFailed)
}

pub fn verify_rejects_rp_id_mismatch_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let auth_data =
    testing.build_authentication_authenticator_data(
      relying_party_id: "evil.com",
      flags: testing.default_flags(),
      sign_count: 1,
    )
  let client_data_json =
    testing.build_client_data_get(
      challenge: testing.authentication_challenge_bytes(challenge),
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
      id_override: option.None,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(authentication.VerificationMismatch(glasslock.RelyingPartyIdField))
}

pub fn verify_rejects_at_flag_in_authentication_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  // Craft auth_data with AT (0x40) flag set manually: no testing helper
  // exposes this since it's illegal input for the authentication ceremony.
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("example.com"))
  // 0x41 = UP (0x01) | AT (0x40)
  let auth_data =
    bit_array.concat([rp_id_hash, <<0x41>>, <<0x00, 0x00, 0x00, 0x01>>])

  let client_data_json =
    testing.build_client_data_get(
      challenge: testing.authentication_challenge_bytes(challenge),
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
      id_override: option.None,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(authentication.ParseError(
      "AT flag should not be set in authentication",
    ))
}

pub fn verify_rejects_cross_origin_when_disabled_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let cross_origin_client_data =
    testing.build_client_data_get(
      challenge: testing.authentication_challenge_bytes(challenge),
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
    == Error(authentication.VerificationMismatch(glasslock.CrossOriginField))
}

pub fn verify_succeeds_with_cross_origin_allowed_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(..default_auth_setup(), allow_cross_origin: True),
    )

  let cross_origin_client_data =
    testing.build_client_data_get(
      challenge: testing.authentication_challenge_bytes(challenge),
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

pub fn verify_accepts_allowed_top_origin_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        allow_cross_origin: True,
        allowed_top_origins: ["https://top.example.com"],
      ),
    )

  let client_data_json =
    testing.build_client_data(
      type_: "webauthn.get",
      challenge: testing.authentication_challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
      top_origin: option.Some("https://top.example.com"),
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json:,
    )

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.sign_count == 1
}

pub fn verify_rejects_unknown_top_origin_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        allow_cross_origin: True,
        allowed_top_origins: ["https://top.example.com"],
      ),
    )

  let client_data_json =
    testing.build_client_data(
      type_: "webauthn.get",
      challenge: testing.authentication_challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
      top_origin: option.Some("https://evil.com"),
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json:,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(authentication.VerificationMismatch(glasslock.TopOriginField))
}

pub fn verify_accepts_missing_top_origin_with_allowlist_test() {
  let #(challenge, stored_credential, keypair) =
    setup_authentication_with(
      AuthSetup(
        ..default_auth_setup(),
        allow_cross_origin: True,
        allowed_top_origins: ["https://top.example.com"],
      ),
    )

  let client_data_json =
    testing.build_client_data(
      type_: "webauthn.get",
      challenge: testing.authentication_challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: True,
      top_origin: option.None,
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json:,
    )

  let assert Ok(cred) =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert cred.sign_count == 1
}

pub fn verify_rejects_top_origin_without_cross_origin_test() {
  let #(challenge, stored_credential, keypair) = setup_authentication()

  let client_data_json =
    testing.build_client_data(
      type_: "webauthn.get",
      challenge: testing.authentication_challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
      top_origin: option.Some("https://top.example.com"),
    )
  let response_json =
    signed_response(
      challenge:,
      stored: stored_credential,
      keypair:,
      sign_count: 1,
      client_data_json:,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(authentication.VerificationMismatch(glasslock.TopOriginField))
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
      id_override: option.None,
    )

  let result =
    authentication.verify(response_json:, challenge:, stored: stored_credential)
  assert result
    == Error(authentication.VerificationMismatch(glasslock.CredentialTypeField))
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

pub fn parse_response_roundtrip_test() {
  use inputs <- qcheck.given(qcheck.tuple2(
    qcheck.byte_aligned_bit_array(),
    qcheck.option_from(qcheck.byte_aligned_bit_array()),
  ))
  let #(credential_id, user_handle) = inputs

  let user_handle_json =
    option.map(user_handle, fn(bytes) {
      json.string(bit_array.base64_url_encode(bytes, False))
    })

  let response_json =
    response_envelope(
      credential_id:,
      credential_type: "public-key",
      user_handle: user_handle_json,
    )

  let assert Ok(info) = authentication.parse_response(response_json)
  assert info.credential_id == glasslock.CredentialId(credential_id)
  assert info.user_handle == user_handle
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
    == Error(authentication.ParseError("Invalid base64url in userHandle"))
}

pub fn parse_response_rejects_invalid_json_test() {
  assert authentication.parse_response("{bad")
    == Error(authentication.ParseError("Invalid authentication response JSON"))
}

pub fn parse_response_rejects_id_raw_id_mismatch_test() {
  let mismatched_id_b64 =
    bit_array.base64_url_encode(<<99, 99, 99, 99, 99, 99, 99, 99>>, False)
  let response_json =
    testing.to_authentication_json_with(
      credential_id: glasslock.CredentialId(<<1, 2, 3, 4, 5, 6, 7, 8>>),
      authenticator_data: <<"test":utf8>>,
      client_data_json: <<"test":utf8>>,
      signature: <<"test":utf8>>,
      user_handle: option.None,
      credential_type: "public-key",
      id_override: option.Some(mismatched_id_b64),
    )

  assert authentication.parse_response(response_json)
    == Error(authentication.VerificationMismatch(glasslock.CredentialIdField))
}

pub fn sign_count_monotonicity_test() {
  let config = qcheck.default_config() |> qcheck.with_test_count(100)
  use inputs <- qcheck.run(
    config,
    qcheck.tuple2(
      qcheck.bounded_int(1, 1_000_000),
      qcheck.bounded_int(1, 1_000_000),
    ),
  )
  let #(stored, new) = inputs
  let keypair = testing.generate_es256_keypair()
  let credential_id = crypto.random_bytes(16)
  let public_key = testing.public_key(keypair)
  let stored_cred =
    glasslock.Credential(
      id: glasslock.CredentialId(credential_id),
      public_key: public_key,
      sign_count: stored,
      transports: [],
    )

  let assert Ok(#(_, challenge)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com"],
      options: authentication.Options(
        ..authentication.default_options(),
        allow_credentials: [
          glasslock.CredentialDescriptor(
            id: stored_cred.id,
            transports: stored_cred.transports,
          ),
        ],
      ),
    )
  let response =
    testing.build_authentication_response(
      challenge: challenge,
      keypair: keypair,
      sign_count: new,
    )
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: glasslock.CredentialId(credential_id),
      user_handle: option.None,
    )

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_cred,
    )

  case new > stored {
    True -> {
      let assert Ok(_) = result
      Nil
    }
    False -> {
      assert result == Error(authentication.SignCountRegression)
      Nil
    }
  }
}

pub fn encode_decode_roundtrip_preserves_challenge_test() {
  use inputs <- qcheck.given(qcheck.tuple6(
    qcheck.non_empty_string(),
    non_empty_list_from(qcheck.non_empty_string()),
    qcheck.list_from(credential_descriptor_generator()),
    qcheck.list_from(qcheck.non_empty_string()),
    qcheck.bool(),
    user_verification_generator(),
  ))
  let #(
    relying_party_id,
    origins,
    allow_credentials,
    allowed_top_origins,
    allow_cross_origin,
    user_verification,
  ) = inputs

  let assert Ok(#(_, challenge)) =
    authentication.request(
      relying_party_id:,
      origins:,
      options: authentication.Options(
        ..authentication.default_options(),
        allow_credentials:,
        allow_cross_origin:,
        allowed_top_origins:,
        user_verification: option.Some(user_verification),
      ),
    )

  let encoded = authentication.encode_challenge(challenge)
  let assert Ok(decoded) = authentication.parse_challenge(encoded)

  let challenge_data = authentication.challenge_data(challenge)
  let decoded_data = authentication.challenge_data(decoded)
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
  assert authentication.challenge_allowed_credentials(decoded)
    == authentication.challenge_allowed_credentials(challenge)
}

pub fn decoded_challenge_drives_verify_test() {
  let cred_a =
    glasslock.CredentialDescriptor(
      id: glasslock.CredentialId(<<1, 2, 3, 4>>),
      transports: [],
    )
  let cred_b =
    glasslock.CredentialDescriptor(
      id: glasslock.CredentialId(<<5, 6, 7, 8>>),
      transports: [glasslock.TransportInternal],
    )
  let assert Ok(#(_, challenge)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com", "https://alt.example.com"],
      options: authentication.Options(
        ..authentication.default_options(),
        allow_cross_origin: True,
        allow_credentials: [cred_a, cred_b],
        allowed_top_origins: ["https://top.example.com"],
      ),
    )

  let encoded = authentication.encode_challenge(challenge)
  let assert Ok(decoded) = authentication.parse_challenge(encoded)

  let keypair = testing.generate_es256_keypair()
  let stored_credential =
    glasslock.Credential(
      id: cred_a.id,
      public_key: testing.public_key(keypair),
      sign_count: 0,
      transports: cred_a.transports,
    )
  let response =
    testing.build_authentication_response(
      challenge: decoded,
      keypair:,
      sign_count: 1,
    )
  let response_json =
    testing.to_authentication_json(
      response,
      credential_id: stored_credential.id,
      user_handle: option.None,
    )
  let assert Ok(_) =
    authentication.verify(
      response_json:,
      challenge: decoded,
      stored: stored_credential,
    )
}

pub fn decode_rejects_registration_blob_test() {
  let assert Ok(#(_, reg_challenge)) =
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
  let encoded = registration.encode_challenge(reg_challenge)

  let result = authentication.parse_challenge(encoded)
  assert result
    == Error(authentication.ParseError(
      "Expected authentication challenge, got registration",
    ))
}

pub fn decode_rejects_unknown_version_test() {
  let blob =
    json.object([
      #("v", json.int(99)),
      #("kind", json.string("authentication")),
      #("bytes", json.string(bit_array.base64_url_encode(<<0:256>>, False))),
      #("rp_id", json.string("example.com")),
      #("origins", json.array(["https://example.com"], json.string)),
      #("user_verification", json.string("preferred")),
      #("allow_cross_origin", json.bool(False)),
      #("allowed_top_origins", json.array([], json.string)),
      #("allow_credentials", json.array([], json.string)),
    ])
    |> json.to_string

  let result = authentication.parse_challenge(blob)
  assert result
    == Error(authentication.ParseError("Unsupported challenge version: 99"))
}

pub fn decode_rejects_missing_allow_credentials_test() {
  let blob =
    json.object([
      #("v", json.int(1)),
      #("kind", json.string("authentication")),
      #("bytes", json.string(bit_array.base64_url_encode(<<0:256>>, False))),
      #("rp_id", json.string("example.com")),
      #("origins", json.array(["https://example.com"], json.string)),
      #("user_verification", json.string("preferred")),
      #("allow_cross_origin", json.bool(False)),
      #("allowed_top_origins", json.array([], json.string)),
    ])
    |> json.to_string

  let result = authentication.parse_challenge(blob)
  assert result
    == Error(authentication.ParseError("Invalid challenge encoding"))
}

pub fn request_emits_compat_json_test() {
  let assert Ok(#(options_json, challenge)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com"],
      options: authentication.Options(
        timeout: duration.seconds(45),
        user_verification: option.None,
        allow_cross_origin: False,
        allow_credentials: [
          glasslock.CredentialDescriptor(
            id: glasslock.CredentialId(<<30, 31, 32, 33>>),
            transports: [],
          ),
          glasslock.CredentialDescriptor(
            id: glasslock.CredentialId(<<40, 41, 42>>),
            transports: [glasslock.TransportHybrid, glasslock.TransportInternal],
          ),
        ],
        allowed_top_origins: [],
      ),
    )

  let challenge_b64 =
    bit_array.base64_url_encode(
      testing.authentication_challenge_bytes(challenge),
      False,
    )

  options_json
  |> json.to_string
  |> string.replace(each: challenge_b64, with: "REDACTED_CHALLENGE_BASE64URL")
  |> birdie.snap("glasslock authentication.request emits compat JSON")
}
