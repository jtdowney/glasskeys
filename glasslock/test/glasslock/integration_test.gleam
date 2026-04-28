import glasslock
import glasslock/authentication
import glasslock/registration
import glasslock/testing
import gleam/bit_array
import gleam/json
import gleam/option.{type Option}

fn glasskey_registration_json(
  response: testing.RegistrationResponse,
) -> String {
  let glasslock.CredentialId(raw_id) = response.credential_id
  let raw_id_b64 = bit_array.base64_url_encode(raw_id, False)
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
      ]),
    ),
  ])
  |> json.to_string
}

fn glasskey_authentication_json(
  response: testing.AuthenticationResponse,
  credential_id credential_id: glasslock.CredentialId,
  user_handle user_handle: Option(BitArray),
) -> String {
  let glasslock.CredentialId(raw_id) = credential_id
  let raw_id_b64 = bit_array.base64_url_encode(raw_id, False)
  let base = [
    #(
      "clientDataJSON",
      json.string(bit_array.base64_url_encode(response.client_data_json, False)),
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
  ]
  let response_fields = case user_handle {
    option.Some(handle) -> [
      #("userHandle", json.string(bit_array.base64_url_encode(handle, False))),
      ..base
    ]
    option.None -> base
  }
  json.object([
    #("id", json.string(raw_id_b64)),
    #("rawId", json.string(raw_id_b64)),
    #("type", json.string("public-key")),
    #("response", json.object(response_fields)),
  ])
  |> json.to_string
}

fn register_then_authenticate(
  algorithm: registration.Algorithm,
  keypair: testing.KeyPair,
) -> Nil {
  let relying_party =
    registration.RelyingParty(id: "example.com", name: "Test App")
  let user =
    registration.User(id: <<1, 2, 3, 4>>, name: "test", display_name: "Test")

  let assert Ok(#(_, reg_challenge)) =
    registration.request(
      relying_party:,
      user:,
      origins: ["https://example.com"],
      options: registration.Options(
        ..registration.default_options(),
        algorithms: [algorithm],
      ),
    )
  let reg_response =
    testing.build_registration_response_with_keypair(
      challenge: reg_challenge,
      keypair:,
    )
  let assert Ok(credential) =
    registration.verify(
      response_json: testing.to_registration_json(reg_response),
      challenge: reg_challenge,
    )
  assert credential.id == reg_response.credential_id
  assert credential.sign_count == 0

  let assert Ok(#(_, auth_challenge)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com"],
      options: authentication.Options(
        ..authentication.default_options(),
        allow_credentials: [credential.id],
      ),
    )
  let auth_response =
    testing.build_authentication_response(
      challenge: auth_challenge,
      keypair:,
      sign_count: 1,
    )
  let assert Ok(updated) =
    authentication.verify(
      response_json: testing.to_authentication_json(
        auth_response,
        credential_id: credential.id,
        user_handle: option.None,
      ),
      challenge: auth_challenge,
      stored: credential,
    )
  assert updated.sign_count == 1
}

fn register_then_authenticate_with_glasskey_shape(
  user_handle: Option(BitArray),
) -> Nil {
  let keypair = testing.generate_es256_keypair()
  let relying_party =
    registration.RelyingParty(id: "example.com", name: "Test App")
  let user =
    registration.User(id: <<1, 2, 3, 4>>, name: "test", display_name: "Test")

  let assert Ok(#(_, reg_challenge)) =
    registration.request(
      relying_party:,
      user:,
      origins: ["https://example.com"],
      options: registration.default_options(),
    )
  let reg_response =
    testing.build_registration_response_with_keypair(
      challenge: reg_challenge,
      keypair:,
    )
  let assert Ok(credential) =
    registration.verify(
      response_json: glasskey_registration_json(reg_response),
      challenge: reg_challenge,
    )
  assert credential.id == reg_response.credential_id
  assert credential.sign_count == 0

  let assert Ok(#(_, auth_challenge)) =
    authentication.request(
      relying_party_id: "example.com",
      origins: ["https://example.com"],
      options: authentication.Options(
        ..authentication.default_options(),
        allow_credentials: [credential.id],
      ),
    )
  let auth_response =
    testing.build_authentication_response(
      challenge: auth_challenge,
      keypair:,
      sign_count: 1,
    )
  let assert Ok(updated) =
    authentication.verify(
      response_json: glasskey_authentication_json(
        auth_response,
        credential_id: credential.id,
        user_handle:,
      ),
      challenge: auth_challenge,
      stored: credential,
    )
  assert updated.sign_count == 1
}

pub fn register_then_authenticate_es256_test() {
  register_then_authenticate(
    registration.Es256,
    testing.generate_es256_keypair(),
  )
}

pub fn register_then_authenticate_ed25519_test() {
  register_then_authenticate(
    registration.Ed25519,
    testing.generate_ed25519_keypair(),
  )
}

pub fn register_then_authenticate_rs256_test() {
  register_then_authenticate(
    registration.Rs256,
    testing.generate_rs256_keypair(),
  )
}

pub fn glasskey_shape_register_and_authenticate_with_user_handle_test() {
  register_then_authenticate_with_glasskey_shape(option.Some(<<1, 2, 3, 4>>))
}

pub fn glasskey_shape_register_and_authenticate_omitted_user_handle_test() {
  register_then_authenticate_with_glasskey_shape(option.None)
}
