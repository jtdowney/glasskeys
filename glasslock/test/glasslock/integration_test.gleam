import glasslock/authentication
import glasslock/registration
import glasslock/testing
import gleam/option

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

fn register_then_authenticate(
  algorithm: registration.Algorithm,
  keypair: testing.KeyPair,
) -> Nil {
  let rp = registration.Rp(id: "example.com", name: "Test App")
  let user =
    registration.User(id: <<1, 2, 3, 4>>, name: "test", display_name: "Test")

  let #(_, reg_challenge) =
    registration.generate_options(
      registration.Options(
        ..registration.default_options(),
        rp:,
        user:,
        origins: ["https://example.com"],
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

  let #(_, auth_challenge) =
    authentication.generate_options(
      authentication.Options(
        ..authentication.default_options(),
        rp_id: "example.com",
        origins: ["https://example.com"],
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
