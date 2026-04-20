import backend/credentials
import backend/sessions
import backend/web
import glasslock/registration
import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/result
import wisp

pub fn begin(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use username <- decode.field("username", decode.string)
    decode.success(username)
  }

  case json.parse(body, decoder) {
    Error(_) ->
      json.object([#("error", json.string("invalid json"))])
      |> json.to_string
      |> wisp.json_response(400)
    Ok(username) -> begin_registration(username, ctx)
  }
}

pub fn complete(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use session_id <- decode.field("session_id", decode.string)
    use response <- decode.field("response", decode.string)
    decode.success(#(session_id, response))
  }

  case json.parse(body, decoder) {
    Error(_) ->
      json.object([#("error", json.string("invalid json"))])
      |> json.to_string
      |> wisp.json_response(400)
    Ok(#(session_id, response)) ->
      complete_registration(session_id, response, ctx)
  }
}

fn begin_registration(username: String, ctx: web.Context) -> wisp.Response {
  case credentials.get_user(ctx.credentials, username) {
    Ok(_) ->
      json.object([#("error", json.string("username already registered"))])
      |> json.to_string
      |> wisp.json_response(409)
    Error(_) -> {
      let user_id = crypto.strong_random_bytes(32)
      let options =
        registration.Options(
          ..registration.default_options(),
          rp: registration.Rp(id: ctx.rp_id, name: ctx.rp_name),
          user: registration.User(
            id: user_id,
            name: username,
            display_name: username,
          ),
          origins: ctx.origins,
          resident_key: registration.ResidentKeyRequired,
        )
      let #(options_json, challenge) = registration.generate_options(options)

      let session_id =
        crypto.strong_random_bytes(32)
        |> bit_array.base64_url_encode(False)

      sessions.set_registration(
        ctx.sessions,
        session_id,
        sessions.Registration(username: username, user_id: user_id, challenge:),
      )

      let response_json =
        json.object([
          #("session_id", json.string(session_id)),
          #("options", options_json),
        ])
        |> json.to_string

      wisp.json_response(response_json, 200)
    }
  }
}

fn complete_registration(
  session_id: String,
  response_json: String,
  ctx: web.Context,
) -> wisp.Response {
  let result = {
    use session <- result.try(
      sessions.get_and_delete_registration(ctx.sessions, session_id)
      |> result.map_error(fn(_) { #("session not found", 400) }),
    )
    use credential <- result.map(
      registration.verify(
        response_json: response_json,
        challenge: session.challenge,
      )
      |> result.map_error(fn(_) { #("verification failed", 400) }),
    )
    credentials.save(
      ctx.credentials,
      session.username,
      session.user_id,
      credential,
    )
  }

  case result {
    Ok(_) ->
      json.object([#("verified", json.bool(True))])
      |> json.to_string
      |> wisp.json_response(200)
    Error(#(message, status)) ->
      json.object([#("error", json.string(message))])
      |> json.to_string
      |> wisp.json_response(status)
  }
}
