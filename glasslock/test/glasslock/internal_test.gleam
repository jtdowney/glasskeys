import glasslock
import glasslock/internal
import glasslock/internal/cbor
import glasslock/testing
import gleam/bit_array
import gleam/json
import gleam/list
import gleam/option
import gleam/set
import kryptos/crypto
import kryptos/hash
import qcheck

pub fn sign_verify_round_trip_test() {
  let generators = [
    testing.generate_es256_keypair,
    testing.generate_ed25519_keypair,
    testing.generate_rs256_keypair,
  ]
  let config = qcheck.default_config() |> qcheck.with_test_count(100)

  list.each(generators, fn(generate) {
    let keypair = generate()
    let glasslock.PublicKey(public_key_cbor) = testing.public_key(keypair)
    let assert Ok(#(parsed_key, alg)) =
      internal.parse_public_key(public_key_cbor)
    use message <- qcheck.run(
      config,
      qcheck.fixed_size_byte_aligned_bit_array(64),
    )
    let signature = testing.sign(keypair:, message:)
    assert internal.verify_signature(parsed_key, alg:, message:, signature:)
      == Ok(Nil)
    Nil
  })
}

pub fn parse_client_data_valid_test() {
  let challenge = <<1, 2, 3, 4>>
  let client_data =
    testing.build_client_data_get(
      challenge: challenge,
      origin: "https://example.com",
      cross_origin: False,
    )

  let assert Ok(cd) = internal.parse_client_data(client_data)
  assert cd.type_ == "webauthn.get"
  assert cd.challenge == challenge
  assert cd.origin == "https://example.com"
  assert cd.cross_origin == False
}

pub fn parse_client_data_invalid_utf8_test() {
  let invalid_utf8 = <<0xFF, 0xFE, 0x00>>
  assert internal.parse_client_data(invalid_utf8)
    == Error(internal.ParseError("Invalid UTF-8"))
}

pub fn parse_client_data_invalid_json_test() {
  let invalid_json = bit_array.from_string("{not valid json}")
  assert internal.parse_client_data(invalid_json)
    == Error(internal.ParseError("Invalid JSON structure"))
}

pub fn parse_client_data_invalid_challenge_encoding_test() {
  let bad_json =
    json.object([
      #("type", json.string("webauthn.get")),
      #("challenge", json.string("!!!invalid!!!")),
      #("origin", json.string("https://example.com")),
    ])
    |> json.to_string
    |> bit_array.from_string
  assert internal.parse_client_data(bad_json)
    == Error(internal.ParseError("Invalid challenge encoding"))
}

pub fn parse_authentication_auth_data_valid_test() {
  let auth_data =
    testing.build_authentication_authenticator_data(
      relying_party_id: "example.com",
      flags: testing.default_flags(),
      sign_count: 42,
    )

  let assert Ok(ad) = internal.parse_authentication_auth_data(auth_data)
  assert ad.user_present == True
  assert ad.user_verified == False
  assert ad.sign_count == 42
}

pub fn parse_registration_auth_data_missing_credential_test() {
  let auth_data =
    testing.build_authentication_authenticator_data(
      relying_party_id: "example.com",
      flags: testing.default_flags(),
      sign_count: 0,
    )

  assert internal.parse_registration_auth_data(auth_data)
    == Error(internal.ParseError("No attested credential in registration"))
}

pub fn cose_key_roundtrip_test() {
  let generators = [
    testing.generate_es256_keypair,
    testing.generate_ed25519_keypair,
    testing.generate_rs256_keypair,
  ]

  list.each(generators, fn(generate) {
    let keypair = generate()
    let cose_bytes = testing.cose_key(keypair)
    let assert Ok(_key) = internal.parse_public_key(cose_bytes)
    assert glasslock.PublicKey(cose_bytes) == testing.public_key(keypair)
  })
}

pub fn parse_public_key_rejects_invalid_cbor_test() {
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(<<0xFF, 0xFF, 0xFF>>)
}

pub fn parse_public_key_rejects_non_map_cbor_test() {
  let cbor_bytes = cbor.encode(cbor.String("not a map"))
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_unsupported_key_type_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(99)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_unsupported_curve_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(99)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_invalid_coordinates_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:128>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_missing_alg_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(4)),
      #(cbor.Int(-1), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  assert internal.parse_public_key(cbor_bytes)
    == Error(internal.UnsupportedKey("COSE key missing algorithm (label 3)"))
}

pub fn parse_authentication_auth_data_ignores_extensions_test() {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("example.com"))
  let flags_byte = 0x81
  let auth_data =
    bit_array.concat([
      rp_id_hash,
      <<flags_byte>>,
      <<0x00, 0x00, 0x00, 0x01>>,
      <<0xA0>>,
    ])
  let assert Ok(ad) = internal.parse_authentication_auth_data(auth_data)
  assert ad.user_present == True
  assert ad.sign_count == 1
}

pub fn parse_authentication_auth_data_rejects_trailing_bytes_test() {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("example.com"))
  let flags_byte = 0x01
  let auth_data =
    bit_array.concat([
      rp_id_hash,
      <<flags_byte>>,
      <<0x00, 0x00, 0x00, 0x01>>,
      <<0xDE, 0xAD>>,
    ])
  assert internal.parse_authentication_auth_data(auth_data)
    == Error(internal.ParseError(
      "Unexpected trailing bytes in authenticator data",
    ))
}

pub fn parse_registration_auth_data_ignores_extensions_test() {
  let keypair = testing.generate_es256_keypair()
  let cose_key = testing.cose_key(keypair)
  let credential_id = glasslock.CredentialId(<<1, 2, 3, 4>>)

  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("example.com"))
  let flags_byte = 0xC1
  let aaguid = <<0:128>>
  let glasslock.CredentialId(raw_cred_id) = credential_id
  let cred_id_len = bit_array.byte_size(raw_cred_id)
  let extension_data = <<0xA0>>
  let auth_data =
    bit_array.concat([
      rp_id_hash,
      <<flags_byte>>,
      <<0x00, 0x00, 0x00, 0x00>>,
      aaguid,
      <<cred_id_len:size(16)>>,
      raw_cred_id,
      cose_key,
      extension_data,
    ])

  let assert Ok(ad) = internal.parse_registration_auth_data(auth_data)
  assert ad.user_present == True
  assert ad.sign_count == 0
  assert ad.attested_credential.credential_id == raw_cred_id

  let assert Ok(_) =
    internal.parse_public_key(ad.attested_credential.public_key_cbor)
}

pub fn verify_client_data_accepts_valid_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://example.com",
      cross_origin: False,
      top_origin: option.None,
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://example.com"]),
      allow_cross_origin: False,
      allowed_top_origins: [],
    )
    == Ok(Nil)
}

pub fn verify_client_data_rejects_empty_origins_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://example.com",
      cross_origin: False,
      top_origin: option.None,
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list([]),
      allow_cross_origin: False,
      allowed_top_origins: [],
    )
    == Error(internal.ParseError(
      "no allowed origins configured; pass a non-empty origins list to request",
    ))
}

pub fn verify_client_data_rejects_wrong_type_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.get",
      challenge: challenge,
      origin: "https://example.com",
      cross_origin: False,
      top_origin: option.None,
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://example.com"]),
      allow_cross_origin: False,
      allowed_top_origins: [],
    )
    == Error(internal.VerificationMismatch(glasslock.TypeField))
}

pub fn verify_client_data_rejects_wrong_challenge_test() {
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: <<1, 2, 3, 4>>,
      origin: "https://example.com",
      cross_origin: False,
      top_origin: option.None,
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: <<9, 9, 9, 9>>,
      expected_origins: set.from_list(["https://example.com"]),
      allow_cross_origin: False,
      allowed_top_origins: [],
    )
    == Error(internal.VerificationMismatch(glasslock.ChallengeField))
}

pub fn verify_client_data_rejects_wrong_origin_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://evil.com",
      cross_origin: False,
      top_origin: option.None,
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://example.com"]),
      allow_cross_origin: False,
      allowed_top_origins: [],
    )
    == Error(internal.VerificationMismatch(glasslock.OriginField))
}

pub fn verify_client_data_rejects_cross_origin_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://example.com",
      cross_origin: True,
      top_origin: option.None,
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://example.com"]),
      allow_cross_origin: False,
      allowed_top_origins: [],
    )
    == Error(internal.VerificationMismatch(glasslock.CrossOriginField))
}

pub fn verify_client_data_allows_cross_origin_when_permitted_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://example.com",
      cross_origin: True,
      top_origin: option.None,
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://example.com"]),
      allow_cross_origin: True,
      allowed_top_origins: [],
    )
    == Ok(Nil)
}

pub fn verify_rp_id_accepts_matching_hash_test() {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("example.com"))
  assert internal.verify_rp_id(rp_id_hash, "example.com") == Ok(Nil)
}

pub fn verify_rp_id_rejects_mismatching_hash_test() {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("evil.com"))
  assert internal.verify_rp_id(rp_id_hash, "example.com")
    == Error(internal.VerificationMismatch(glasslock.RelyingPartyIdField))
}

pub fn verify_user_policies_required_present_test() {
  assert internal.verify_user_policies(
      True,
      True,
      glasslock.PresenceRequired,
      glasslock.VerificationRequired,
    )
    == Ok(Nil)
}

pub fn verify_user_policies_required_not_present_test() {
  assert internal.verify_user_policies(
      True,
      False,
      glasslock.PresenceRequired,
      glasslock.VerificationRequired,
    )
    == Error(internal.UserVerificationFailed)
}

pub fn verify_user_policies_preferred_always_passes_test() {
  assert internal.verify_user_policies(
      True,
      False,
      glasslock.PresencePreferred,
      glasslock.VerificationPreferred,
    )
    == Ok(Nil)
}

pub fn verify_user_policies_discouraged_always_passes_test() {
  assert internal.verify_user_policies(
      True,
      False,
      glasslock.PresenceDiscouraged,
      glasslock.VerificationDiscouraged,
    )
    == Ok(Nil)
}

pub fn verify_user_policies_presence_required_not_present_test() {
  assert internal.verify_user_policies(
      False,
      False,
      glasslock.PresenceRequired,
      glasslock.VerificationDiscouraged,
    )
    == Error(internal.UserPresenceFailed)
}

pub fn parse_public_key_rejects_missing_kty_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_missing_x_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_missing_y_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_non_integer_kty_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.String("EC")),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_non_bytes_x_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Int(42)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(internal.ParseError(_)) =
    internal.parse_public_key(cbor_bytes)
}

pub fn parse_authentication_auth_data_rejects_truncated_data_test() {
  let truncated = <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05>>
  assert internal.parse_authentication_auth_data(truncated)
    == Error(internal.ParseError("Authenticator data too short"))
}

pub fn parse_registration_auth_data_rejects_truncated_data_test() {
  let truncated = <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05>>
  assert internal.parse_registration_auth_data(truncated)
    == Error(internal.ParseError("Authenticator data too short"))
}

pub fn parse_registration_auth_data_rejects_truncated_credential_test() {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string("example.com"))
  let flags_byte = 0x41
  let auth_data =
    bit_array.concat([
      rp_id_hash,
      <<flags_byte>>,
      <<0x00, 0x00, 0x00, 0x00>>,
      <<0x00, 0x00>>,
    ])
  assert internal.parse_registration_auth_data(auth_data)
    == Error(internal.ParseError("Missing attested credential data"))
}

pub fn verify_attestation_rejects_non_empty_statement_test() {
  let non_empty = cbor.Map([#(cbor.String("alg"), cbor.Int(-7))])
  assert internal.verify_attestation(non_empty)
    == Error("none attestation with non-empty statement")
}

pub fn extract_attestation_fields_rejects_non_map_test() {
  assert internal.extract_attestation_fields(cbor.String("not a map"))
    == Error(internal.ParseError("Attestation object must be a map"))
}

pub fn extract_attestation_fields_rejects_missing_auth_data_test() {
  let cbor =
    cbor.Map([
      #(cbor.String("fmt"), cbor.String("none")),
      #(cbor.String("attStmt"), cbor.Map([])),
    ])
  assert internal.extract_attestation_fields(cbor)
    == Error(internal.ParseError("Missing field: authData"))
}

pub fn extract_attestation_fields_rejects_missing_fmt_test() {
  let cbor =
    cbor.Map([
      #(cbor.String("authData"), cbor.Bytes(<<0x00>>)),
      #(cbor.String("attStmt"), cbor.Map([])),
    ])
  assert internal.extract_attestation_fields(cbor)
    == Error(internal.ParseError("Missing field: fmt"))
}

pub fn parse_attestation_object_rejects_invalid_cbor_test() {
  assert internal.parse_attestation_object(<<0xFF, 0xFF, 0xFF>>)
    == Error(internal.ParseError("Unsupported CBOR additional info: 31"))
}

pub fn parse_client_data_with_missing_cross_origin_defaults_false_test() {
  let challenge = <<1, 2, 3, 4>>
  let challenge_b64 = bit_array.base64_url_encode(challenge, False)
  let client_data =
    json.object([
      #("type", json.string("webauthn.get")),
      #("challenge", json.string(challenge_b64)),
      #("origin", json.string("https://example.com")),
    ])
    |> json.to_string
    |> bit_array.from_string

  let assert Ok(cd) = internal.parse_client_data(client_data)
  assert cd.cross_origin == False
  assert cd.top_origin == option.None
}

pub fn decode_base64url_rejects_invalid_encoding_test() {
  assert internal.decode_base64url("!!!invalid!!!", "testField")
    == Error(internal.ParseError("Invalid base64url in testField"))
}

pub fn decode_optional_base64url_returns_none_for_none_test() {
  let assert Ok(option.None) =
    internal.decode_optional_base64url(option.None, "testField")
}

pub fn decode_optional_base64url_decodes_some_test() {
  let encoded = bit_array.base64_url_encode(<<1, 2, 3>>, False)
  let assert Ok(option.Some(<<1, 2, 3>>)) =
    internal.decode_optional_base64url(option.Some(encoded), "testField")
}

pub fn decode_optional_base64url_rejects_invalid_encoding_test() {
  assert internal.decode_optional_base64url(
      option.Some("!!!invalid!!!"),
      "testField",
    )
    == Error(internal.ParseError("Invalid base64url in testField"))
}

pub fn user_verification_to_string_test() {
  let variants = [
    #(glasslock.VerificationRequired, "required"),
    #(glasslock.VerificationPreferred, "preferred"),
    #(glasslock.VerificationDiscouraged, "discouraged"),
  ]

  list.each(variants, fn(pair) {
    let #(variant, expected) = pair
    assert internal.user_verification_to_string(variant) == expected
  })
}

pub fn parse_client_data_with_top_origin_test() {
  let challenge = <<1, 2, 3, 4>>
  let client_data =
    testing.build_client_data(
      type_: "webauthn.get",
      challenge:,
      origin: "https://sub.example.com",
      cross_origin: True,
      top_origin: option.Some("https://example.com"),
    )

  let assert Ok(cd) = internal.parse_client_data(client_data)
  assert cd.cross_origin == True
  assert cd.top_origin == option.Some("https://example.com")
}

pub fn parse_client_data_without_top_origin_defaults_none_test() {
  let challenge = <<1, 2, 3, 4>>
  let client_data =
    testing.build_client_data_get(
      challenge: challenge,
      origin: "https://example.com",
      cross_origin: False,
    )

  let assert Ok(cd) = internal.parse_client_data(client_data)
  assert cd.top_origin == option.None
}

pub fn verify_client_data_accepts_allowed_top_origin_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://sub.example.com",
      cross_origin: True,
      top_origin: option.Some("https://example.com"),
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://sub.example.com"]),
      allow_cross_origin: True,
      allowed_top_origins: ["https://example.com"],
    )
    == Ok(Nil)
}

pub fn verify_client_data_rejects_unknown_top_origin_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://sub.example.com",
      cross_origin: True,
      top_origin: option.Some("https://evil.com"),
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://sub.example.com"]),
      allow_cross_origin: True,
      allowed_top_origins: ["https://example.com"],
    )
    == Error(internal.VerificationMismatch(glasslock.TopOriginField))
}

pub fn verify_client_data_rejects_missing_top_origin_with_allowlist_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://sub.example.com",
      cross_origin: True,
      top_origin: option.None,
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://sub.example.com"]),
      allow_cross_origin: True,
      allowed_top_origins: ["https://example.com"],
    )
    == Error(internal.VerificationMismatch(glasslock.TopOriginField))
}

pub fn verify_client_data_rejects_top_origin_with_empty_allowlist_test() {
  let challenge = <<1, 2, 3, 4>>
  let cd =
    internal.ClientData(
      type_: "webauthn.create",
      challenge: challenge,
      origin: "https://sub.example.com",
      cross_origin: True,
      top_origin: option.Some("https://example.com"),
    )
  assert internal.verify_client_data(
      cd,
      expected_type: "webauthn.create",
      expected_challenge: challenge,
      expected_origins: set.from_list(["https://sub.example.com"]),
      allow_cross_origin: True,
      allowed_top_origins: [],
    )
    == Error(internal.VerificationMismatch(glasslock.TopOriginField))
}
