//// Frozen JSON fixtures mirroring what `glasslock/registration.request` and
//// `glasslock/authentication.request` emit (per
//// `glasslock/birdie_snapshots/glasslock_*_request_emits_compat_json.accepted`,
//// with the redacted challenge swapped for a deterministic base64url value
//// so the decoders run). If those glasslock snapshots change, update these
//// builders and re-accept the matching glasskey snapshots.

import gleam/json

pub fn registration_options_json() -> String {
  json.object([
    #(
      "excludeCredentials",
      json.preprocessed_array([
        credential_descriptor("CgsM"),
        credential_descriptor("FBUWFw"),
      ]),
    ),
    #("challenge", json.string("dGVzdC1jaGFsbGVuZ2U")),
    #(
      "rp",
      json.object([
        #("id", json.string("example.com")),
        #("name", json.string("Compat Test")),
      ]),
    ),
    #(
      "user",
      json.object([
        #("id", json.string("AQIDBAUGBwg")),
        #("name", json.string("alice")),
        #("displayName", json.string("Alice Example")),
      ]),
    ),
    #(
      "pubKeyCredParams",
      json.preprocessed_array([
        pub_key_cred_param(-7),
        pub_key_cred_param(-8),
        pub_key_cred_param(-257),
      ]),
    ),
    #("timeout", json.int(90_000)),
    #(
      "authenticatorSelection",
      json.object([
        #("authenticatorAttachment", json.string("cross-platform")),
        #("residentKey", json.string("required")),
        #("userVerification", json.string("required")),
      ]),
    ),
  ])
  |> json.to_string
}

pub fn authentication_options_json() -> String {
  json.object([
    #(
      "allowCredentials",
      json.preprocessed_array([
        credential_descriptor("Hh8gIQ"),
        credential_descriptor("KCkq"),
      ]),
    ),
    #("challenge", json.string("dGVzdC1jaGFsbGVuZ2U")),
    #("rpId", json.string("example.com")),
    #("timeout", json.int(45_000)),
    #("userVerification", json.string("preferred")),
  ])
  |> json.to_string
}

fn credential_descriptor(id_b64: String) -> json.Json {
  json.object([
    #("id", json.string(id_b64)),
    #("type", json.string("public-key")),
  ])
}

fn pub_key_cred_param(alg: Int) -> json.Json {
  json.object([
    #("type", json.string("public-key")),
    #("alg", json.int(alg)),
  ])
}
