import backend/credentials
import backend/web
import glasslock/registration
import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/result
import wisp

const session_cookie = "registration"

const session_max_age = 300

type PendingRegistration {
  PendingRegistration(
    username: String,
    user_id: BitArray,
    challenge: registration.Challenge,
  )
}

pub fn begin(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use username <- decode.field("username", decode.string)
    decode.success(username)
  }

  case json.parse(body, decoder) {
    Error(_) -> error_response("invalid json", 400)
    Ok(username) -> begin_registration(req, username, ctx)
  }
}

pub fn complete(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use response <- decode.field("response", decode.string)
    decode.success(response)
  }

  case json.parse(body, decoder) {
    Error(_) -> error_response("invalid json", 400)
    Ok(response) -> complete_registration(req, response, ctx)
  }
}

fn begin_registration(
  req: wisp.Request,
  username: String,
  ctx: web.Context,
) -> wisp.Response {
  case credentials.get_user(ctx.credentials, username) {
    Ok(_) -> error_response("username already registered", 409)
    Error(_) -> {
      let user_id = crypto.strong_random_bytes(32)

      let assert Ok(#(options_json, challenge)) =
        registration.request(
          relying_party: registration.RelyingParty(
            id: ctx.rp_id,
            name: ctx.rp_name,
          ),
          user: registration.User(
            id: user_id,
            name: username,
            display_name: username,
          ),
          origins: ctx.origins,
          options: registration.Options(
            ..registration.default_options(),
            resident_key: registration.ResidentKeyRequired,
          ),
        )

      let pending =
        encode_pending(PendingRegistration(username:, user_id:, challenge:))

      json.object([#("options", options_json)])
      |> json.to_string
      |> wisp.json_response(200)
      |> wisp.set_cookie(
        req,
        session_cookie,
        pending,
        wisp.Signed,
        session_max_age,
      )
    }
  }
}

fn complete_registration(
  req: wisp.Request,
  response_json: String,
  ctx: web.Context,
) -> wisp.Response {
  let result = {
    use raw <- result.try(
      wisp.get_cookie(req, session_cookie, wisp.Signed)
      |> result.map_error(fn(_) { #("session not found", 400) }),
    )
    use session <- result.try(
      decode_pending(raw)
      |> result.map_error(fn(_) { #("session not found", 400) }),
    )
    use credential <- result.try(
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
    Ok(Nil)
  }

  case result {
    Ok(_) ->
      json.object([#("verified", json.bool(True))])
      |> json.to_string
      |> wisp.json_response(200)
      |> clear_session(req)
    Error(#(message, status)) ->
      error_response(message, status)
      |> clear_session(req)
  }
}

fn error_response(message: String, status: Int) -> wisp.Response {
  json.object([#("error", json.string(message))])
  |> json.to_string
  |> wisp.json_response(status)
}

fn clear_session(response: wisp.Response, req: wisp.Request) -> wisp.Response {
  wisp.set_cookie(response, req, session_cookie, "", wisp.PlainText, 0)
}

fn encode_pending(pending: PendingRegistration) -> String {
  json.object([
    #("username", json.string(pending.username)),
    #(
      "user_id",
      json.string(bit_array.base64_url_encode(pending.user_id, False)),
    ),
    #(
      "challenge",
      json.string(registration.encode_challenge(pending.challenge)),
    ),
  ])
  |> json.to_string
}

fn decode_pending(raw: String) -> Result(PendingRegistration, Nil) {
  let decoder = {
    use username <- decode.field("username", decode.string)
    use user_id_b64 <- decode.field("user_id", decode.string)
    use challenge_encoded <- decode.field("challenge", decode.string)
    decode.success(#(username, user_id_b64, challenge_encoded))
  }

  use #(username, user_id_b64, challenge_encoded) <- result.try(
    json.parse(raw, decoder)
    |> result.replace_error(Nil),
  )
  use user_id <- result.try(bit_array.base64_url_decode(user_id_b64))
  use challenge <- result.try(
    registration.parse_challenge(challenge_encoded)
    |> result.replace_error(Nil),
  )
  Ok(PendingRegistration(username:, user_id:, challenge:))
}
