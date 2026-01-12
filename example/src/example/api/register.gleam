import example/api/helpers
import example/store/credentials
import example/store/sessions.{RegistrationSession}
import example/web.{type Context}
import given
import glasskeys/registration
import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import wisp.{type Request, type Response}

pub fn begin(req: Request, ctx: Context) -> Response {
  use json_body <- wisp.require_json(req)

  let decoder = {
    use username <- decode.field("username", decode.string)
    decode.success(username)
  }

  use username <- given.ok(
    in: decode.run(json_body, decoder),
    else_return: fn(_) {
      helpers.json_error("Invalid request: missing username", 400)
    },
  )

  use username <- given.ok(
    in: helpers.validate_username(username),
    else_return: fn(_) { helpers.json_error("Invalid username", 400) },
  )

  case credentials.user_exists(ctx.credential_store, username) {
    True -> helpers.json_error("User already exists", 400)
    False -> {
      let #(challenge_b64, verifier) =
        registration.new()
        |> registration.origin(ctx.origin)
        |> registration.rp_id(ctx.rp_id)
        |> registration.build()

      let user_id = crypto.strong_random_bytes(32)
      let user_id_b64 = bit_array.base64_url_encode(user_id, False)

      let session_id = helpers.generate_session_id()
      sessions.set(
        ctx.session_store,
        session_id,
        RegistrationSession(username, user_id, verifier),
      )

      let response_json =
        json.object([
          #("session_id", json.string(session_id)),
          #(
            "publicKey",
            json.object([
              #("challenge", json.string(challenge_b64)),
              #(
                "rp",
                json.object([
                  #("name", json.string("Glasskeys Demo")),
                  #("id", json.string(ctx.rp_id)),
                ]),
              ),
              #(
                "user",
                json.object([
                  #("id", json.string(user_id_b64)),
                  #("name", json.string(username)),
                  #("displayName", json.string(username)),
                ]),
              ),
              #(
                "pubKeyCredParams",
                json.preprocessed_array([
                  json.object([
                    #("type", json.string("public-key")),
                    #("alg", json.int(-7)),
                  ]),
                ]),
              ),
              #(
                "authenticatorSelection",
                json.object([
                  #("residentKey", json.string("required")),
                  #("requireResidentKey", json.bool(True)),
                  #("userVerification", json.string("preferred")),
                ]),
              ),
              #("timeout", json.int(60_000)),
              #("attestation", json.string("none")),
            ]),
          ),
        ])

      wisp.json_response(json.to_string(response_json), 200)
    }
  }
}

pub fn complete(req: Request, ctx: Context) -> Response {
  use json_body <- wisp.require_json(req)

  let decoder = {
    use session_id <- decode.field("session_id", decode.string)
    use attestation_object <- decode.subfield(
      ["credential", "response", "attestationObject"],
      decode.string,
    )
    use client_data_json <- decode.subfield(
      ["credential", "response", "clientDataJSON"],
      decode.string,
    )
    decode.success(#(session_id, attestation_object, client_data_json))
  }

  use #(session_id, attestation_obj_b64, client_data_b64) <- given.ok(
    in: decode.run(json_body, decoder),
    else_return: fn(_) { helpers.json_error("Invalid request", 400) },
  )

  use session <- given.ok(
    in: sessions.get(ctx.session_store, session_id),
    else_return: fn(_) { helpers.json_error("Session not found", 400) },
  )
  sessions.delete(ctx.session_store, session_id)

  use #(username, user_id, verifier) <- require_registration_session(session)

  use attestation_object <- given.ok(
    in: bit_array.base64_url_decode(attestation_obj_b64),
    else_return: fn(_) {
      helpers.json_error("Invalid attestationObject encoding", 400)
    },
  )
  use client_data_json <- given.ok(
    in: bit_array.base64_url_decode(client_data_b64),
    else_return: fn(_) {
      helpers.json_error("Invalid clientDataJSON encoding", 400)
    },
  )

  case
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: verifier,
    )
  {
    Ok(credential) -> {
      case
        credentials.save(ctx.credential_store, username, user_id, credential)
      {
        Ok(_) -> {
          let response_json =
            json.object([
              #("status", json.string("ok")),
              #(
                "credential_id",
                json.string(bit_array.base64_url_encode(credential.id, False)),
              ),
            ])
          wisp.json_response(json.to_string(response_json), 200)
        }
        Error(_) -> helpers.json_error("Failed to save credential", 500)
      }
    }
    Error(e) -> helpers.json_error(helpers.error_to_string(e), 400)
  }
}

fn require_registration_session(
  session: sessions.SessionData,
  next: fn(#(String, BitArray, registration.Challenge)) -> Response,
) -> Response {
  case session {
    sessions.RegistrationSession(username, user_id, verifier) ->
      next(#(username, user_id, verifier))
    _ -> helpers.json_error("Invalid session type", 400)
  }
}
