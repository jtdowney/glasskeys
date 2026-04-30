import backend/credentials
import backend/web
import glasslock
import glasslock/authentication
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import wisp

const session_cookie = "authentication"

const session_max_age = 300

pub fn begin(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use username <- decode.optional_field("username", "", decode.string)
    decode.success(username)
  }

  let username = case json.parse(body, decoder) {
    Ok(value) -> string.trim(value)
    Error(_) -> ""
  }

  case allow_credentials_for_username(ctx, username) {
    Error(message) ->
      json.object([#("error", json.string(message))])
      |> json.to_string
      |> wisp.json_response(404)
    Ok(allow_credentials) -> {
      let assert Ok(#(options_json, challenge)) =
        authentication.request(
          relying_party_id: ctx.rp_id,
          origins: ctx.origins,
          options: authentication.Options(
            ..authentication.default_options(),
            allow_credentials:,
          ),
        )

      let encoded = authentication.encode_challenge(challenge)

      json.object([#("options", options_json)])
      |> json.to_string
      |> wisp.json_response(200)
      |> wisp.set_cookie(
        req,
        session_cookie,
        encoded,
        wisp.Signed,
        session_max_age,
      )
    }
  }
}

fn allow_credentials_for_username(
  ctx: web.Context,
  username: String,
) -> Result(List(glasslock.CredentialId), String) {
  case username {
    "" -> Ok([])
    name ->
      case credentials.get_user(ctx.credentials, name) {
        Ok(user) -> Ok(list.map(user.credentials, fn(cred) { cred.id }))
        Error(_) -> Error("user not found")
      }
  }
}

pub fn complete(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use response <- decode.field("response", decode.string)
    decode.success(response)
  }

  case json.parse(body, decoder) {
    Error(_) ->
      json.object([#("error", json.string("invalid json"))])
      |> json.to_string
      |> wisp.json_response(400)
    Ok(response) -> complete_authentication(req, response, ctx)
  }
}

fn complete_authentication(
  req: wisp.Request,
  response_json: String,
  ctx: web.Context,
) -> wisp.Response {
  let result = {
    use encoded <- result.try(
      wisp.get_cookie(req, session_cookie, wisp.Signed)
      |> result.map_error(fn(_) { #("session not found", 400) }),
    )
    use challenge <- result.try(
      authentication.parse_challenge(encoded)
      |> result.map_error(fn(_) { #("session not found", 400) }),
    )
    use info <- result.try(
      authentication.parse_response(response_json)
      |> result.map_error(fn(_) { #("invalid response", 400) }),
    )
    use user <- result.try(
      lookup_user(ctx, info)
      |> result.map_error(fn(_) { #("user not found", 400) }),
    )
    use stored_credential <- result.try(
      list.find(user.credentials, fn(cred) { cred.id == info.credential_id })
      |> result.map_error(fn(_) { #("credential not found", 400) }),
    )
    use updated_credential <- result.try(
      authentication.verify(
        response_json: response_json,
        challenge:,
        stored: stored_credential,
      )
      |> result.map_error(fn(err) {
        #("verification failed: " <> describe_error(err), 400)
      }),
    )
    credentials.update(ctx.credentials, user, updated_credential)
    Ok(user.username)
  }

  case result {
    Ok(username) ->
      json.object([
        #("verified", json.bool(True)),
        #("username", json.string(username)),
      ])
      |> json.to_string
      |> wisp.json_response(200)
      |> clear_session(req)
    Error(#(message, status)) ->
      json.object([#("error", json.string(message))])
      |> json.to_string
      |> wisp.json_response(status)
      |> clear_session(req)
  }
}

fn clear_session(response: wisp.Response, req: wisp.Request) -> wisp.Response {
  wisp.set_cookie(response, req, session_cookie, "", wisp.PlainText, 0)
}

fn describe_error(err: authentication.Error) -> String {
  case err {
    authentication.VerificationMismatch(glasslock.TypeField) -> "type mismatch"
    authentication.VerificationMismatch(glasslock.ChallengeField) ->
      "challenge mismatch"
    authentication.VerificationMismatch(glasslock.OriginField) ->
      "origin mismatch"
    authentication.VerificationMismatch(glasslock.RelyingPartyIdField) ->
      "relying party id mismatch"
    authentication.VerificationMismatch(glasslock.CrossOriginField) ->
      "cross origin not allowed"
    authentication.VerificationMismatch(glasslock.TopOriginField) ->
      "top origin not allowed"
    authentication.VerificationMismatch(glasslock.CredentialIdField) ->
      "credential id mismatch"
    authentication.VerificationMismatch(glasslock.CredentialTypeField) ->
      "credential type mismatch"
    authentication.UnsupportedKey(reason) -> "unsupported key: " <> reason
    authentication.ParseError(message) -> "parse error: " <> message
    authentication.InvalidSignature -> "invalid signature"
    authentication.CredentialNotAllowed -> "credential not allowed"
    authentication.SignCountRegression -> "sign count regression"
    authentication.UserPresenceFailed -> "user presence failed"
    authentication.UserVerificationFailed -> "user verification failed"
  }
}

fn lookup_user(
  ctx: web.Context,
  info: authentication.ResponseInfo,
) -> Result(credentials.User, Nil) {
  let glasslock.CredentialId(credential_id) = info.credential_id
  case credentials.get_user_by_credential_id(ctx.credentials, credential_id) {
    Ok(user) -> Ok(user)
    Error(_) ->
      case info.user_handle {
        option.Some(user_handle) ->
          credentials.get_user_by_user_id(ctx.credentials, user_handle)
        option.None -> Error(Nil)
      }
  }
}
