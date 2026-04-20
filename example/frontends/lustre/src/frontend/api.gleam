import frontend/model
import glasskey
import gleam/dynamic/decode
import gleam/http/response.{type Response}
import gleam/json
import gleam/result
import lustre/effect.{type Effect}
import rsvp

pub fn login_begin(
  handler: fn(
    Result(model.BeginResponse(glasskey.AuthenticationOptions), String),
  ) ->
    msg,
) -> Effect(msg) {
  let body = json.object([])

  let expect =
    rsvp.expect_ok_response(fn(result) { handler(decode_login_begin(result)) })

  rsvp.post("/api/login/begin", body, expect)
}

pub fn login_complete(
  session_id: String,
  response: String,
  handler: fn(Result(String, String)) -> msg,
) -> Effect(msg) {
  let body =
    json.object([
      #("session_id", json.string(session_id)),
      #("response", json.string(response)),
    ])

  let expect =
    rsvp.expect_ok_response(fn(result) { handler(decode_login_result(result)) })

  rsvp.post("/api/login/complete", body, expect)
}

pub fn register_begin(
  username: String,
  handler: fn(Result(model.BeginResponse(glasskey.RegistrationOptions), String)) ->
    msg,
) -> Effect(msg) {
  let body = json.object([#("username", json.string(username))])

  let expect =
    rsvp.expect_ok_response(fn(result) {
      handler(decode_register_begin(result))
    })

  rsvp.post("/api/register/begin", body, expect)
}

pub fn register_complete(
  session_id: String,
  response: String,
  handler: fn(Result(Nil, String)) -> msg,
) -> Effect(msg) {
  let body =
    json.object([
      #("session_id", json.string(session_id)),
      #("response", json.string(response)),
    ])

  let expect =
    rsvp.expect_ok_response(fn(result) { handler(decode_verified(result)) })

  rsvp.post("/api/register/complete", body, expect)
}

fn decode_login_result(
  result: Result(Response(String), rsvp.Error),
) -> Result(String, String) {
  let decoder = {
    use verified <- decode.field("verified", decode.bool)
    use username <- decode.field("username", decode.string)
    decode.success(#(verified, username))
  }
  case decode_response(result, decoder) {
    Ok(#(True, username)) -> Ok(username)
    Ok(#(False, _)) -> Error("Verification failed")
    Error(e) -> Error(e)
  }
}

fn decode_response(
  result: Result(Response(String), rsvp.Error),
  decoder: decode.Decoder(a),
) -> Result(a, String) {
  case result {
    Error(rsvp.HttpError(resp)) -> {
      let error_decoder = {
        use msg <- decode.field("error", decode.string)
        decode.success(msg)
      }
      case json.parse(resp.body, error_decoder) {
        Ok(msg) -> Error(msg)
        Error(_) -> Error("Server error")
      }
    }
    Error(_) -> Error("Network error")
    Ok(resp) ->
      json.parse(resp.body, decoder)
      |> result.replace_error("Invalid response from server")
  }
}

fn decode_register_begin(
  result: Result(Response(String), rsvp.Error),
) -> Result(model.BeginResponse(glasskey.RegistrationOptions), String) {
  let decoder = {
    use session_id <- decode.field("session_id", decode.string)
    use options <- decode.field(
      "options",
      glasskey.registration_options_decoder(),
    )
    decode.success(model.BeginResponse(session_id:, options:))
  }
  decode_response(result, decoder)
}

fn decode_login_begin(
  result: Result(Response(String), rsvp.Error),
) -> Result(model.BeginResponse(glasskey.AuthenticationOptions), String) {
  let decoder = {
    use session_id <- decode.field("session_id", decode.string)
    use options <- decode.field(
      "options",
      glasskey.authentication_options_decoder(),
    )
    decode.success(model.BeginResponse(session_id:, options:))
  }
  decode_response(result, decoder)
}

fn decode_verified(
  result: Result(Response(String), rsvp.Error),
) -> Result(Nil, String) {
  let decoder = {
    use verified <- decode.field("verified", decode.bool)
    decode.success(verified)
  }
  case decode_response(result, decoder) {
    Ok(True) -> Ok(Nil)
    Ok(False) -> Error("Verification failed")
    Error(e) -> Error(e)
  }
}
