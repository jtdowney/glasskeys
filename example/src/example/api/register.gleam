import example/api/helpers
import example/store/credentials
import example/store/sessions.{RegistrationSession}
import example/web.{type Context}
import glasskeys/registration
import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/result
import wisp.{type Request, type Response}

pub fn begin(req: Request, ctx: Context) -> Response {
  use json_body <- wisp.require_json(req)

  let decoder = {
    use username <- decode.field("username", decode.string)
    decode.success(username)
  }

  let username_result = decode.run(json_body, decoder)
  use <- bool.guard(
    when: result.is_error(username_result),
    return: helpers.json_error("Invalid request: missing username", 400),
  )
  let assert Ok(username) = username_result

  let username_result = helpers.validate_username(username)
  use <- bool.guard(
    when: result.is_error(username_result),
    return: helpers.json_error("Invalid username", 400),
  )
  let assert Ok(username) = username_result

  use <- bool.guard(
    when: credentials.user_exists(ctx.credential_store, username),
    return: helpers.json_error("User already exists", 400),
  )

  let user_id = crypto.strong_random_bytes(32)

  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: ctx.rp_id, name: "Glasskeys Demo"),
      user: registration.User(
        id: user_id,
        name: username,
        display_name: username,
      ),
      origin: ctx.origin,
      resident_key: registration.ResidentKeyRequired,
    )

  let #(options_json, challenge) = registration.generate_options(options)

  let session_id = helpers.generate_session_id()
  sessions.set(
    ctx.session_store,
    session_id,
    RegistrationSession(username, user_id, challenge),
  )

  // Wrap the options JSON with session_id for the frontend
  let response_json =
    json.object([
      #("session_id", json.string(session_id)),
      #("options", json.string(options_json)),
    ])

  wisp.json_response(json.to_string(response_json), 200)
}

pub fn complete(req: Request, ctx: Context) -> Response {
  use json_body <- wisp.require_json(req)

  let decoder = {
    use session_id <- decode.field("session_id", decode.string)
    use response <- decode.field("response", decode.string)
    decode.success(#(session_id, response))
  }

  let decode_result = decode.run(json_body, decoder)
  use <- bool.guard(
    when: result.is_error(decode_result),
    return: helpers.json_error("Invalid request", 400),
  )
  let assert Ok(#(session_id, response_json)) = decode_result

  let session_result = sessions.get(ctx.session_store, session_id)
  use <- bool.guard(
    when: result.is_error(session_result),
    return: helpers.json_error("Session not found", 400),
  )
  let assert Ok(session) = session_result
  sessions.delete(ctx.session_store, session_id)

  let session_data_result = require_registration_session(session)
  use <- bool.guard(
    when: result.is_error(session_data_result),
    return: helpers.json_error("Invalid session type", 400),
  )
  let assert Ok(#(username, user_id, challenge)) = session_data_result

  let verify_result =
    registration.verify(response_json: response_json, challenge: challenge)
  use <- bool.lazy_guard(when: result.is_error(verify_result), return: fn() {
    let assert Error(e) = verify_result
    helpers.json_error(helpers.error_to_string(e), 400)
  })
  let assert Ok(credential) = verify_result

  let save_result =
    credentials.save(ctx.credential_store, username, user_id, credential)
  use <- bool.guard(
    when: result.is_error(save_result),
    return: helpers.json_error("Failed to save credential", 500),
  )

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

fn require_registration_session(
  session: sessions.SessionData,
) -> Result(#(String, BitArray, registration.Challenge), Nil) {
  case session {
    sessions.RegistrationSession(username, user_id, challenge) ->
      Ok(#(username, user_id, challenge))
    _ -> Error(Nil)
  }
}
