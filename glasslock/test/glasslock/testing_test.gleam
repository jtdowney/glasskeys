import glasslock/internal
import glasslock/testing
import gleam/bit_array
import kryptos/crypto
import kryptos/hash

pub fn build_client_data_create_sets_type_test() {
  let client_data =
    testing.build_client_data_create(
      challenge: <<1, 2, 3>>,
      origin: "https://example.com",
      cross_origin: False,
    )
  let assert Ok(cd) = internal.parse_client_data(client_data)
  assert cd.type_ == "webauthn.create"
}

pub fn build_client_data_get_sets_type_test() {
  let client_data =
    testing.build_client_data_get(
      challenge: <<1, 2, 3>>,
      origin: "https://example.com",
      cross_origin: False,
    )
  let assert Ok(cd) = internal.parse_client_data(client_data)
  assert cd.type_ == "webauthn.get"
}

pub fn build_registration_auth_data_roundtrips_test() {
  let keypair = testing.generate_es256_keypair()
  let cose_key = testing.cose_key(keypair)
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let flags =
    testing.AuthenticatorFlags(user_present: True, user_verified: True)

  let auth_data =
    testing.build_registration_authenticator_data(
      relying_party_id: "example.com",
      credential_id:,
      cose_key: cose_key,
      flags: flags,
      sign_count: 42,
    )

  let assert Ok(ad) = internal.parse_registration_auth_data(auth_data)
  assert ad.user_present
  assert ad.user_verified
  assert ad.sign_count == 42
  assert ad.attested_credential.credential_id == credential_id

  let assert Ok(expected_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("example.com"))
  assert ad.rp_id_hash == expected_hash
}

pub fn build_authentication_auth_data_roundtrips_test() {
  let flags =
    testing.AuthenticatorFlags(user_present: True, user_verified: False)

  let auth_data =
    testing.build_authentication_authenticator_data(
      relying_party_id: "example.com",
      flags: flags,
      sign_count: 7,
    )

  let assert Ok(ad) = internal.parse_authentication_auth_data(auth_data)
  assert ad.user_present
  assert !ad.user_verified
  assert ad.sign_count == 7
}
