import glasskey
import glasskey_test_helpers as helpers
import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/javascript/promise.{type Promise}
import gleam/json
import gleam/list
import gleam/option
import qcheck
import unitest

pub fn main() {
  unitest.main()
}

type RegistrationFixture {
  RegistrationFixture(
    challenge: String,
    rp_id: String,
    rp_name: String,
    user_id: String,
    user_name: String,
    user_display_name: String,
    algorithms: List(Int),
    timeout: option.Option(Int),
    attestation: String,
    resident_key: String,
    user_verification: String,
    authenticator_attachment: option.Option(String),
    exclude_credentials: List(String),
  )
}

fn default_registration_fixture() -> RegistrationFixture {
  RegistrationFixture(
    challenge: "dGVzdA",
    rp_id: "example.com",
    rp_name: "App",
    user_id: "dQ",
    user_name: "u",
    user_display_name: "U",
    algorithms: [-7],
    timeout: option.None,
    attestation: "none",
    resident_key: "preferred",
    user_verification: "preferred",
    authenticator_attachment: option.None,
    exclude_credentials: [],
  )
}

fn default_registration_options() -> glasskey.RegistrationOptions {
  glasskey.RegistrationOptions(
    challenge: <<1, 2, 3, 4>>,
    rp_id: "example.com",
    rp_name: "Example",
    user_id: <<5, 6, 7, 8>>,
    user_name: "alice",
    user_display_name: "Alice",
    algorithms: [glasskey.Es256, glasskey.Ed25519, glasskey.Rs256],
    timeout: option.None,
    attestation: glasskey.AttestationNone,
    resident_key: glasskey.Required,
    user_verification: glasskey.Preferred,
    authenticator_attachment: option.None,
    exclude_credentials: [],
  )
}

fn default_authentication_options() -> glasskey.AuthenticationOptions {
  glasskey.AuthenticationOptions(
    challenge: <<9, 10, 11>>,
    rp_id: option.Some("example.com"),
    timeout: option.None,
    user_verification: glasskey.Required,
    allow_credentials: [],
  )
}

fn with_fake_navigator(body: fn() -> Promise(Nil)) -> Promise(Nil) {
  helpers.install_default_fake_navigator()
  use _ <- promise.await(body())
  helpers.uninstall_fake_navigator()
  promise.resolve(Nil)
}

fn build_registration_options(fixture: RegistrationFixture) -> Dynamic {
  let auth_selection_fields = [
    #(dynamic.string("residentKey"), dynamic.string(fixture.resident_key)),
    #(
      dynamic.string("userVerification"),
      dynamic.string(fixture.user_verification),
    ),
  ]
  let auth_selection_fields = case fixture.authenticator_attachment {
    option.Some(value) -> [
      #(dynamic.string("authenticatorAttachment"), dynamic.string(value)),
      ..auth_selection_fields
    ]
    option.None -> auth_selection_fields
  }

  let pub_key_cred_params =
    dynamic.array(
      list.map(fixture.algorithms, fn(alg) {
        dynamic.properties([
          #(dynamic.string("type"), dynamic.string("public-key")),
          #(dynamic.string("alg"), dynamic.int(alg)),
        ])
      }),
    )

  let fields = [
    #(dynamic.string("challenge"), dynamic.string(fixture.challenge)),
    #(
      dynamic.string("rp"),
      dynamic.properties([
        #(dynamic.string("id"), dynamic.string(fixture.rp_id)),
        #(dynamic.string("name"), dynamic.string(fixture.rp_name)),
      ]),
    ),
    #(
      dynamic.string("user"),
      dynamic.properties([
        #(dynamic.string("id"), dynamic.string(fixture.user_id)),
        #(dynamic.string("name"), dynamic.string(fixture.user_name)),
        #(
          dynamic.string("displayName"),
          dynamic.string(fixture.user_display_name),
        ),
      ]),
    ),
    #(dynamic.string("pubKeyCredParams"), pub_key_cred_params),
    #(dynamic.string("attestation"), dynamic.string(fixture.attestation)),
    #(
      dynamic.string("authenticatorSelection"),
      dynamic.properties(auth_selection_fields),
    ),
  ]

  let fields = case fixture.timeout {
    option.Some(t) -> [#(dynamic.string("timeout"), dynamic.int(t)), ..fields]
    option.None -> fields
  }

  let fields = case fixture.exclude_credentials {
    [] -> fields
    ids -> [
      #(
        dynamic.string("excludeCredentials"),
        dynamic.array(
          list.map(ids, fn(id) {
            dynamic.properties([
              #(dynamic.string("id"), dynamic.string(id)),
              #(dynamic.string("type"), dynamic.string("public-key")),
            ])
          }),
        ),
      ),
      ..fields
    ]
  }

  dynamic.properties(fields)
}

pub fn decode_registration_options_test() {
  let dyn =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        challenge: "dGVzdC1jaGFsbGVuZ2U",
        rp_name: "My App",
        user_id: "dXNlci0x",
        user_name: "john",
        user_display_name: "John",
        timeout: option.Some(60_000),
      ),
    )

  let assert Ok(opt) = decode.run(dyn, glasskey.registration_options_decoder())

  assert opt.challenge == <<"test-challenge":utf8>>
  assert opt.rp_id == "example.com"
  assert opt.rp_name == "My App"
  assert opt.user_id == <<"user-1":utf8>>
  assert opt.user_name == "john"
  assert opt.user_display_name == "John"
  assert opt.algorithms == [glasskey.Es256]
  assert opt.timeout == option.Some(60_000)
  assert opt.attestation == glasskey.AttestationNone
  assert opt.resident_key == glasskey.Preferred
  assert opt.user_verification == glasskey.Preferred
  assert opt.authenticator_attachment == option.None
  assert opt.exclude_credentials == []
}

pub fn decode_registration_options_algorithm_variants_test() {
  let variants = [
    #(-7, glasskey.Es256),
    #(-8, glasskey.Ed25519),
    #(-257, glasskey.Rs256),
  ]

  list.each(variants, fn(pair) {
    let #(int, expected) = pair
    let dyn =
      build_registration_options(
        RegistrationFixture(..default_registration_fixture(), algorithms: [
          int,
        ]),
      )
    let assert Ok(opt) =
      decode.run(dyn, glasskey.registration_options_decoder())
    assert opt.algorithms == [expected]
  })
}

pub fn decode_registration_options_with_exclude_credentials_test() {
  let dyn =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        exclude_credentials: ["AQID"],
      ),
    )

  let assert Ok(opt) = decode.run(dyn, glasskey.registration_options_decoder())

  assert opt.exclude_credentials == [<<1, 2, 3>>]
}

pub fn decode_registration_options_resident_key_variants_test() {
  let variants = [
    #("required", glasskey.Required),
    #("preferred", glasskey.Preferred),
    #("discouraged", glasskey.Discouraged),
  ]

  list.each(variants, fn(pair) {
    let #(string, expected) = pair
    let dyn =
      build_registration_options(
        RegistrationFixture(
          ..default_registration_fixture(),
          resident_key: string,
        ),
      )
    let assert Ok(opt) =
      decode.run(dyn, glasskey.registration_options_decoder())
    assert opt.resident_key == expected
  })
}

pub fn decode_registration_options_user_verification_variants_test() {
  let variants = [
    #("required", glasskey.Required),
    #("preferred", glasskey.Preferred),
    #("discouraged", glasskey.Discouraged),
  ]

  list.each(variants, fn(pair) {
    let #(string, expected) = pair
    let dyn =
      build_registration_options(
        RegistrationFixture(
          ..default_registration_fixture(),
          user_verification: string,
        ),
      )
    let assert Ok(opt) =
      decode.run(dyn, glasskey.registration_options_decoder())
    assert opt.user_verification == expected
  })
}

pub fn decode_registration_options_attestation_variants_test() {
  let variants = [
    #("none", glasskey.AttestationNone),
    #("indirect", glasskey.AttestationIndirect),
    #("direct", glasskey.AttestationDirect),
    #("enterprise", glasskey.AttestationEnterprise),
  ]

  list.each(variants, fn(pair) {
    let #(string, expected) = pair
    let dyn =
      build_registration_options(
        RegistrationFixture(
          ..default_registration_fixture(),
          attestation: string,
        ),
      )
    let assert Ok(opt) =
      decode.run(dyn, glasskey.registration_options_decoder())
    assert opt.attestation == expected
  })
}

pub fn decode_registration_options_authenticator_attachment_variants_test() {
  let variants = [
    #("platform", option.Some(glasskey.Platform)),
    #("cross-platform", option.Some(glasskey.CrossPlatform)),
  ]

  list.each(variants, fn(pair) {
    let #(string, expected) = pair
    let dyn =
      build_registration_options(
        RegistrationFixture(
          ..default_registration_fixture(),
          authenticator_attachment: option.Some(string),
        ),
      )
    let assert Ok(opt) =
      decode.run(dyn, glasskey.registration_options_decoder())
    assert opt.authenticator_attachment == expected
  })
}

pub fn decode_registration_options_missing_required_fields_test() {
  let assert Error(_) =
    decode.run(dynamic.properties([]), glasskey.registration_options_decoder())
}

pub fn decode_registration_options_unknown_requirement_test() {
  let dyn =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        resident_key: "typo-required",
      ),
    )

  let assert Error(_) = decode.run(dyn, glasskey.registration_options_decoder())
}

pub fn decode_registration_options_unknown_algorithm_test() {
  let dyn =
    build_registration_options(
      RegistrationFixture(..default_registration_fixture(), algorithms: [-999]),
    )

  let assert Error(_) = decode.run(dyn, glasskey.registration_options_decoder())
}

pub fn decode_registration_options_invalid_pub_key_cred_param_type_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
      #(
        dynamic.string("rp"),
        dynamic.properties([
          #(dynamic.string("id"), dynamic.string("example.com")),
          #(dynamic.string("name"), dynamic.string("App")),
        ]),
      ),
      #(
        dynamic.string("user"),
        dynamic.properties([
          #(dynamic.string("id"), dynamic.string("dQ")),
          #(dynamic.string("name"), dynamic.string("u")),
          #(dynamic.string("displayName"), dynamic.string("U")),
        ]),
      ),
      #(
        dynamic.string("pubKeyCredParams"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("type"), dynamic.string("not-public-key")),
            #(dynamic.string("alg"), dynamic.int(-7)),
          ]),
        ]),
      ),
      #(
        dynamic.string("authenticatorSelection"),
        dynamic.properties([
          #(dynamic.string("residentKey"), dynamic.string("preferred")),
          #(dynamic.string("userVerification"), dynamic.string("preferred")),
        ]),
      ),
    ])

  let assert Error(_) = decode.run(dyn, glasskey.registration_options_decoder())
}

pub fn decode_registration_options_missing_pub_key_cred_param_type_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
      #(
        dynamic.string("rp"),
        dynamic.properties([
          #(dynamic.string("id"), dynamic.string("example.com")),
          #(dynamic.string("name"), dynamic.string("App")),
        ]),
      ),
      #(
        dynamic.string("user"),
        dynamic.properties([
          #(dynamic.string("id"), dynamic.string("dQ")),
          #(dynamic.string("name"), dynamic.string("u")),
          #(dynamic.string("displayName"), dynamic.string("U")),
        ]),
      ),
      #(
        dynamic.string("pubKeyCredParams"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("alg"), dynamic.int(-7)),
          ]),
        ]),
      ),
      #(
        dynamic.string("authenticatorSelection"),
        dynamic.properties([
          #(dynamic.string("residentKey"), dynamic.string("preferred")),
          #(dynamic.string("userVerification"), dynamic.string("preferred")),
        ]),
      ),
    ])

  let assert Error(_) = decode.run(dyn, glasskey.registration_options_decoder())
}

pub fn decode_registration_options_invalid_exclude_credentials_type_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
      #(
        dynamic.string("rp"),
        dynamic.properties([
          #(dynamic.string("id"), dynamic.string("example.com")),
          #(dynamic.string("name"), dynamic.string("App")),
        ]),
      ),
      #(
        dynamic.string("user"),
        dynamic.properties([
          #(dynamic.string("id"), dynamic.string("dQ")),
          #(dynamic.string("name"), dynamic.string("u")),
          #(dynamic.string("displayName"), dynamic.string("U")),
        ]),
      ),
      #(
        dynamic.string("pubKeyCredParams"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("type"), dynamic.string("public-key")),
            #(dynamic.string("alg"), dynamic.int(-7)),
          ]),
        ]),
      ),
      #(
        dynamic.string("authenticatorSelection"),
        dynamic.properties([
          #(dynamic.string("residentKey"), dynamic.string("preferred")),
          #(dynamic.string("userVerification"), dynamic.string("preferred")),
        ]),
      ),
      #(
        dynamic.string("excludeCredentials"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("id"), dynamic.string("AQID")),
            #(dynamic.string("type"), dynamic.string("not-public-key")),
          ]),
        ]),
      ),
    ])

  let assert Error(_) = decode.run(dyn, glasskey.registration_options_decoder())
}

pub fn decode_registration_options_missing_exclude_credentials_type_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
      #(
        dynamic.string("rp"),
        dynamic.properties([
          #(dynamic.string("id"), dynamic.string("example.com")),
          #(dynamic.string("name"), dynamic.string("App")),
        ]),
      ),
      #(
        dynamic.string("user"),
        dynamic.properties([
          #(dynamic.string("id"), dynamic.string("dQ")),
          #(dynamic.string("name"), dynamic.string("u")),
          #(dynamic.string("displayName"), dynamic.string("U")),
        ]),
      ),
      #(
        dynamic.string("pubKeyCredParams"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("type"), dynamic.string("public-key")),
            #(dynamic.string("alg"), dynamic.int(-7)),
          ]),
        ]),
      ),
      #(
        dynamic.string("authenticatorSelection"),
        dynamic.properties([
          #(dynamic.string("residentKey"), dynamic.string("preferred")),
          #(dynamic.string("userVerification"), dynamic.string("preferred")),
        ]),
      ),
      #(
        dynamic.string("excludeCredentials"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("id"), dynamic.string("AQID")),
          ]),
        ]),
      ),
    ])

  let assert Error(_) = decode.run(dyn, glasskey.registration_options_decoder())
}

pub fn decode_registration_options_unknown_attestation_test() {
  let dyn =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        attestation: "bogus-format",
      ),
    )

  let assert Error(_) = decode.run(dyn, glasskey.registration_options_decoder())
}

pub fn decode_registration_options_unknown_authenticator_attachment_test() {
  let dyn =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        authenticator_attachment: option.Some("bogus-attachment"),
      ),
    )

  let assert Error(_) = decode.run(dyn, glasskey.registration_options_decoder())
}

pub fn decode_authentication_options_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdC1jaGFsbGVuZ2U")),
      #(dynamic.string("rpId"), dynamic.string("example.com")),
      #(dynamic.string("timeout"), dynamic.int(60_000)),
      #(dynamic.string("userVerification"), dynamic.string("preferred")),
    ])

  let assert Ok(opt) =
    decode.run(dyn, glasskey.authentication_options_decoder())

  assert opt.challenge == <<"test-challenge":utf8>>
  assert opt.rp_id == option.Some("example.com")
  assert opt.timeout == option.Some(60_000)
  assert opt.user_verification == glasskey.Preferred
  assert opt.allow_credentials == []
}

pub fn decode_authentication_options_with_allow_credentials_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
      #(dynamic.string("rpId"), dynamic.string("example.com")),
      #(dynamic.string("timeout"), dynamic.int(60_000)),
      #(dynamic.string("userVerification"), dynamic.string("required")),
      #(
        dynamic.string("allowCredentials"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("id"), dynamic.string("AQID")),
            #(dynamic.string("type"), dynamic.string("public-key")),
          ]),
        ]),
      ),
    ])

  let assert Ok(opt) =
    decode.run(dyn, glasskey.authentication_options_decoder())

  assert opt.allow_credentials == [<<1, 2, 3>>]
  assert opt.user_verification == glasskey.Required
}

pub fn decode_authentication_options_minimal_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
    ])

  let assert Ok(opt) =
    decode.run(dyn, glasskey.authentication_options_decoder())

  assert opt.challenge == <<"test":utf8>>
  assert opt.rp_id == option.None
  assert opt.timeout == option.None
  assert opt.user_verification == glasskey.Preferred
  assert opt.allow_credentials == []
}

pub fn decode_authentication_options_invalid_allow_credentials_type_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
      #(
        dynamic.string("allowCredentials"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("id"), dynamic.string("AQID")),
            #(dynamic.string("type"), dynamic.string("not-public-key")),
          ]),
        ]),
      ),
    ])

  let assert Error(_) =
    decode.run(dyn, glasskey.authentication_options_decoder())
}

pub fn decode_authentication_options_missing_allow_credentials_type_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
      #(
        dynamic.string("allowCredentials"),
        dynamic.array([
          dynamic.properties([
            #(dynamic.string("id"), dynamic.string("AQID")),
          ]),
        ]),
      ),
    ])

  let assert Error(_) =
    decode.run(dyn, glasskey.authentication_options_decoder())
}

pub fn decode_authentication_options_missing_required_fields_test() {
  let assert Error(_) =
    decode.run(
      dynamic.properties([]),
      glasskey.authentication_options_decoder(),
    )
}

pub fn decode_authentication_options_unknown_user_verification_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("dGVzdA")),
      #(dynamic.string("userVerification"), dynamic.string("bogus-value")),
    ])
  let assert Error(_) =
    decode.run(dyn, glasskey.authentication_options_decoder())
}

pub fn decode_authentication_options_malformed_challenge_test() {
  let dyn =
    dynamic.properties([
      #(dynamic.string("challenge"), dynamic.string("not!valid$base64")),
    ])
  let assert Error(_) =
    decode.run(dyn, glasskey.authentication_options_decoder())
}

pub fn encode_registration_response_test() {
  let result =
    glasskey.encode_registration_response(
      glasskey.RegistrationCredential(
        id: "cred-123",
        raw_id: <<1, 2, 3>>,
        client_data_json: <<"{}":utf8>>,
        attestation_object: <<7, 8, 9>>,
      ),
    )

  let decoder = {
    use id <- decode.field("id", decode.string)
    use raw_id <- decode.field("rawId", decode.string)
    use credential_type <- decode.field("type", decode.string)
    use client_data_json <- decode.subfield(
      ["response", "clientDataJSON"],
      decode.string,
    )
    use attestation_object <- decode.subfield(
      ["response", "attestationObject"],
      decode.string,
    )
    decode.success(#(
      id,
      raw_id,
      credential_type,
      client_data_json,
      attestation_object,
    ))
  }

  let assert Ok(#(id, raw_id, credential_type, cdj, ao)) =
    json.parse(result, decoder)

  assert id == "cred-123"
  assert raw_id == "AQID"
  assert credential_type == "public-key"
  assert cdj == "e30"
  assert ao == "BwgJ"
}

pub fn encode_authentication_response_with_user_handle_test() {
  let result =
    glasskey.encode_authentication_response(glasskey.AuthenticationCredential(
      id: "cred-abc",
      raw_id: <<10, 20, 30>>,
      client_data_json: <<"{}":utf8>>,
      authenticator_data: <<70, 80, 90>>,
      signature: <<100, 110, 120>>,
      user_handle: option.Some(<<1, 2>>),
    ))

  let decoder = {
    use id <- decode.field("id", decode.string)
    use raw_id <- decode.field("rawId", decode.string)
    use credential_type <- decode.field("type", decode.string)
    use client_data_json <- decode.subfield(
      ["response", "clientDataJSON"],
      decode.string,
    )
    use authenticator_data <- decode.subfield(
      ["response", "authenticatorData"],
      decode.string,
    )
    use signature <- decode.subfield(["response", "signature"], decode.string)
    use user_handle <- decode.subfield(
      ["response", "userHandle"],
      decode.optional(decode.string),
    )
    decode.success(#(
      id,
      raw_id,
      credential_type,
      client_data_json,
      authenticator_data,
      signature,
      user_handle,
    ))
  }

  let assert Ok(#(id, raw_id, credential_type, cdj, ad, sig, uh)) =
    json.parse(result, decoder)

  assert id == "cred-abc"
  assert raw_id == "ChQe"
  assert credential_type == "public-key"
  assert cdj == "e30"
  assert ad == "RlBa"
  assert sig == "ZG54"
  assert uh == option.Some("AQI")
}

pub fn encode_authentication_response_null_user_handle_test() {
  let result =
    glasskey.encode_authentication_response(glasskey.AuthenticationCredential(
      id: "cred-x",
      raw_id: <<1>>,
      client_data_json: <<"{}":utf8>>,
      authenticator_data: <<3>>,
      signature: <<4>>,
      user_handle: option.None,
    ))

  let decoder = {
    use user_handle <- decode.subfield(
      ["response", "userHandle"],
      decode.optional(decode.string),
    )
    decode.success(user_handle)
  }

  let assert Ok(user_handle) = json.parse(result, decoder)
  assert user_handle == option.None
}

pub fn decode_registration_options_roundtrip_test() {
  use inputs <- qcheck.given(qcheck.tuple4(
    qcheck.byte_aligned_bit_array(),
    qcheck.byte_aligned_bit_array(),
    qcheck.string(),
    qcheck.string(),
  ))
  let #(challenge, user_id, rp_name, user_display_name) = inputs
  let dyn =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        challenge: bit_array.base64_url_encode(challenge, False),
        user_id: bit_array.base64_url_encode(user_id, False),
        rp_name:,
        user_display_name:,
      ),
    )
  let assert Ok(opt) = decode.run(dyn, glasskey.registration_options_decoder())
  assert opt.challenge == challenge
  assert opt.user_id == user_id
  assert opt.rp_name == rp_name
  assert opt.user_display_name == user_display_name
}

pub fn supports_webauthn_returns_false_without_globals_test() {
  helpers.uninstall_fake_navigator()
  assert !glasskey.supports_webauthn()
}

pub fn supports_webauthn_returns_true_with_fake_navigator_test() {
  helpers.install_default_fake_navigator()
  let result = glasskey.supports_webauthn()
  helpers.uninstall_fake_navigator()
  assert result
}

pub fn start_registration_returns_not_supported_when_globals_missing_test() {
  helpers.uninstall_fake_navigator()
  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )
  assert result == Error(glasskey.NotSupported)
  promise.resolve(Nil)
}

pub fn start_registration_succeeds_with_credential_test() {
  use <- with_fake_navigator
  helpers.set_create_credential(
    raw_id: <<1, 2, 3>>,
    client_data_json: <<"{}":utf8>>,
    attestation_object: <<7, 8, 9>>,
  )

  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )

  let assert Ok(json_string) = result
  let decoder = {
    use raw_id <- decode.field("rawId", decode.string)
    use client_data_json <- decode.subfield(
      ["response", "clientDataJSON"],
      decode.string,
    )
    use attestation_object <- decode.subfield(
      ["response", "attestationObject"],
      decode.string,
    )
    decode.success(#(raw_id, client_data_json, attestation_object))
  }
  let assert Ok(#(raw_id, client_data_json, attestation_object)) =
    json.parse(json_string, decoder)
  assert raw_id == "AQID"
  assert client_data_json == "e30"
  assert attestation_object == "BwgJ"

  promise.resolve(Nil)
}

pub fn start_registration_returns_not_allowed_when_user_dismisses_test() {
  use <- with_fake_navigator
  helpers.set_create_null()

  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )

  assert result == Error(glasskey.NotAllowed)
  promise.resolve(Nil)
}

pub fn start_registration_classifies_not_supported_error_test() {
  use <- with_fake_navigator
  helpers.set_create_dom_exception(name: "NotSupportedError", message: "boom")

  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )

  assert result == Error(glasskey.NotSupported)
  promise.resolve(Nil)
}

pub fn start_registration_classifies_not_allowed_error_test() {
  use <- with_fake_navigator
  helpers.set_create_dom_exception(name: "NotAllowedError", message: "boom")

  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )

  assert result == Error(glasskey.NotAllowed)
  promise.resolve(Nil)
}

pub fn start_registration_classifies_abort_error_test() {
  use <- with_fake_navigator
  helpers.set_create_dom_exception(name: "AbortError", message: "boom")

  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )

  assert result == Error(glasskey.Aborted)
  promise.resolve(Nil)
}

pub fn start_registration_classifies_security_error_test() {
  use <- with_fake_navigator
  helpers.set_create_dom_exception(name: "SecurityError", message: "boom")

  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )

  assert result == Error(glasskey.SecurityError)
  promise.resolve(Nil)
}

pub fn start_registration_unknown_dom_exception_includes_name_and_message_test() {
  use <- with_fake_navigator
  helpers.set_create_dom_exception(name: "WeirdError", message: "oops")

  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )

  assert result == Error(glasskey.UnknownError("WeirdError: oops"))
  promise.resolve(Nil)
}

pub fn start_registration_plain_error_becomes_unknown_error_test() {
  use <- with_fake_navigator
  helpers.set_create_plain_error("network down")

  use result <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )

  assert result == Error(glasskey.UnknownError("network down"))
  promise.resolve(Nil)
}

pub fn start_registration_passes_options_to_navigator_test() {
  use <- with_fake_navigator
  helpers.set_create_credential(
    raw_id: <<>>,
    client_data_json: <<>>,
    attestation_object: <<>>,
  )

  let opts =
    glasskey.RegistrationOptions(
      ..default_registration_options(),
      challenge: <<99, 100, 101, 102>>,
      rp_id: "passes.example",
      timeout: option.Some(60_000),
      authenticator_attachment: option.Some(glasskey.Platform),
      exclude_credentials: [<<11, 12>>, <<13, 14>>],
    )

  use _ <- promise.await(glasskey.start_registration(opts))
  let assert Ok(snapshot) = helpers.last_create_snapshot()

  assert snapshot.challenge == <<99, 100, 101, 102>>
  assert snapshot.rp_id == "passes.example"
  assert snapshot.timeout == option.Some(60_000)
  assert snapshot.authenticator_attachment == option.Some("platform")
  assert snapshot.exclude_credential_count == 2
  assert snapshot.resident_key == "required"
  assert snapshot.user_verification == "preferred"
  assert snapshot.attestation == "none"
  assert snapshot.algs == [-7, -8, -257]

  promise.resolve(Nil)
}

pub fn start_registration_omits_optional_fields_when_none_test() {
  use <- with_fake_navigator
  helpers.set_create_credential(
    raw_id: <<>>,
    client_data_json: <<>>,
    attestation_object: <<>>,
  )

  use _ <- promise.await(
    glasskey.start_registration(default_registration_options()),
  )
  let assert Ok(snapshot) = helpers.last_create_snapshot()

  assert snapshot.timeout == option.None
  assert snapshot.authenticator_attachment == option.None
  assert snapshot.exclude_credential_count == 0

  promise.resolve(Nil)
}

pub fn start_authentication_returns_not_supported_when_globals_missing_test() {
  helpers.uninstall_fake_navigator()
  use result <- promise.await(
    glasskey.start_authentication(default_authentication_options()),
  )
  assert result == Error(glasskey.NotSupported)
  promise.resolve(Nil)
}

pub fn start_authentication_succeeds_with_user_handle_test() {
  use <- with_fake_navigator
  helpers.set_get_credential(
    raw_id: <<10, 20, 30>>,
    client_data_json: <<"{}":utf8>>,
    authenticator_data: <<70, 80, 90>>,
    signature: <<100, 110, 120>>,
    user_handle: option.Some(<<1, 2>>),
  )

  use result <- promise.await(
    glasskey.start_authentication(default_authentication_options()),
  )

  let assert Ok(json_string) = result
  let decoder = {
    use raw_id <- decode.field("rawId", decode.string)
    use signature <- decode.subfield(["response", "signature"], decode.string)
    use user_handle <- decode.subfield(
      ["response", "userHandle"],
      decode.optional(decode.string),
    )
    decode.success(#(raw_id, signature, user_handle))
  }
  let assert Ok(#(raw_id, signature, user_handle)) =
    json.parse(json_string, decoder)
  assert raw_id == "ChQe"
  assert signature == "ZG54"
  assert user_handle == option.Some("AQI")

  promise.resolve(Nil)
}

pub fn start_authentication_omits_user_handle_when_missing_test() {
  use <- with_fake_navigator
  helpers.set_get_credential(
    raw_id: <<1>>,
    client_data_json: <<"{}":utf8>>,
    authenticator_data: <<3>>,
    signature: <<4>>,
    user_handle: option.None,
  )

  use result <- promise.await(
    glasskey.start_authentication(default_authentication_options()),
  )

  let assert Ok(json_string) = result
  let decoder = {
    use user_handle <- decode.subfield(
      ["response", "userHandle"],
      decode.optional(decode.string),
    )
    decode.success(user_handle)
  }
  let assert Ok(user_handle) = json.parse(json_string, decoder)
  assert user_handle == option.None

  promise.resolve(Nil)
}

pub fn start_authentication_returns_not_allowed_when_user_dismisses_test() {
  use <- with_fake_navigator
  helpers.set_get_null()

  use result <- promise.await(
    glasskey.start_authentication(default_authentication_options()),
  )

  assert result == Error(glasskey.NotAllowed)
  promise.resolve(Nil)
}

pub fn start_authentication_classifies_security_error_test() {
  use <- with_fake_navigator
  helpers.set_get_dom_exception(name: "SecurityError", message: "bad rp")

  use result <- promise.await(
    glasskey.start_authentication(default_authentication_options()),
  )

  assert result == Error(glasskey.SecurityError)
  promise.resolve(Nil)
}

pub fn start_authentication_passes_options_to_navigator_test() {
  use <- with_fake_navigator
  helpers.set_get_credential(
    raw_id: <<>>,
    client_data_json: <<>>,
    authenticator_data: <<>>,
    signature: <<>>,
    user_handle: option.None,
  )

  let opts =
    glasskey.AuthenticationOptions(
      ..default_authentication_options(),
      timeout: option.Some(45_000),
      allow_credentials: [<<21, 22>>, <<23, 24>>, <<25, 26>>],
    )

  use _ <- promise.await(glasskey.start_authentication(opts))
  let assert Ok(snapshot) = helpers.last_get_snapshot()

  assert snapshot.rp_id == option.Some("example.com")
  assert snapshot.timeout == option.Some(45_000)
  assert snapshot.user_verification == "required"
  assert snapshot.allow_credential_count == 3

  promise.resolve(Nil)
}

pub fn start_conditional_authentication_returns_not_supported_when_globals_missing_test() {
  helpers.uninstall_fake_navigator()
  let result =
    glasskey.start_conditional_authentication(default_authentication_options())
  assert result == Error(glasskey.NotSupported)
}

pub fn start_conditional_authentication_resolves_to_assertion_test() {
  use <- with_fake_navigator
  helpers.set_get_credential(
    raw_id: <<1>>,
    client_data_json: <<"{}":utf8>>,
    authenticator_data: <<3>>,
    signature: <<4>>,
    user_handle: option.None,
  )

  let assert Ok(handle) =
    glasskey.start_conditional_authentication(default_authentication_options())
  use result <- promise.await(handle.result)

  let assert Ok(_) = result
  promise.resolve(Nil)
}

pub fn start_conditional_authentication_abort_signals_navigator_test() {
  use <- with_fake_navigator
  helpers.set_get_credential(
    raw_id: <<>>,
    client_data_json: <<>>,
    authenticator_data: <<>>,
    signature: <<>>,
    user_handle: option.None,
  )

  let assert Ok(handle) =
    glasskey.start_conditional_authentication(default_authentication_options())
  handle.abort()
  use _ <- promise.await(handle.result)

  assert helpers.last_get_signal_aborted() == Ok(True)
  promise.resolve(Nil)
}
