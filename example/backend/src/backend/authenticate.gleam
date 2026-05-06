//// `/api/login/begin` and `/api/login/complete` handlers. Mirrors `register`
//// for the authentication ceremony, persisting the challenge in a signed-
//// cookie session.

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
import non_empty_list
import wisp

const session_cookie = "authentication"

// Five-minute lifetime for the pending-ceremony cookie. Bounds how long a
// half-completed login can sit before the user must restart.
const session_max_age = 300

pub fn begin(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use username <- decode.optional_field(
      "username",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(username)
  }

  let username_result = case string.trim(body) {
    "" -> Ok(option.None)
    _ -> json.parse(body, decoder)
  }

  case username_result {
    Error(_) -> web.error_response("invalid json", 400)
    Ok(username) -> begin_for_username(req, ctx, username)
  }
}

fn begin_for_username(
  req: wisp.Request,
  ctx: web.Context,
  username: option.Option(String),
) -> wisp.Response {
  case allow_credentials_for_username(ctx, username) {
    Error(_) -> web.error_response("user not found", 404)
    Ok(allow_credentials) -> {
      // User verification is preferred (the WebAuthn default) so the demo
      // works on authenticators without UV capability while still requesting
      // it when supported. Tighten to `VerificationRequired` for a deployment
      // that mandates biometric/PIN.
      let builder =
        authentication.new(
          relying_party_id: ctx.rp_id,
          origin: non_empty_list.first(ctx.origins),
        )
        |> authentication.user_verification(glasslock.VerificationPreferred)
      let builder =
        list.fold(
          non_empty_list.rest(ctx.origins),
          builder,
          authentication.origin,
        )
      let builder =
        list.fold(allow_credentials, builder, fn(b, entry) {
          let #(id, transports) = entry
          authentication.allow_credential(b, id:, transports:)
        })
      let #(options_json, challenge) = authentication.build(builder)

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
  username: option.Option(String),
) -> Result(List(#(BitArray, List(glasslock.Transport))), Nil) {
  case option.map(username, string.trim) {
    option.None -> Ok([])
    option.Some("") -> Ok([])
    option.Some(name) ->
      credentials.get_user(ctx.credentials, name)
      |> result.map(fn(user) {
        list.map(user.credentials, fn(cred) { #(cred.id, cred.transports) })
      })
  }
}

pub fn complete(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use response <- decode.field("response", authentication.response_decoder())
    decode.success(response)
  }

  case json.parse(body, decoder) {
    Error(_) -> web.error_response("invalid json", 400)
    Ok(response) -> complete_authentication(req, response, ctx)
  }
}

fn complete_authentication(
  req: wisp.Request,
  response: authentication.Response,
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
      authentication.response_info(response)
      |> result.map_error(fn(err) {
        #("invalid response: " <> describe_error(err), 400)
      }),
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
      authentication.verify(response:, challenge:, stored: stored_credential)
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
      |> web.clear_session(req, session_cookie)
    Error(#(message, status)) ->
      web.error_response(message, status)
      |> web.clear_session(req, session_cookie)
  }
}

fn describe_error(err: authentication.Error) -> String {
  case err {
    authentication.VerificationMismatch(field) -> describe_field(field)
    authentication.UnsupportedKey(reason) -> "unsupported key: " <> reason
    authentication.ParseError(message) -> "parse error: " <> message
    authentication.InvalidSignature -> "invalid signature"
    authentication.CredentialNotAllowed -> "credential not allowed"
    authentication.SignCountRegression -> "sign count regression"
    authentication.UserPresenceFailed -> "user presence failed"
    authentication.UserVerificationFailed -> "user verification failed"
  }
}

fn describe_field(field: glasslock.VerificationField) -> String {
  case field {
    glasslock.TypeField -> "type mismatch"
    glasslock.ChallengeField -> "challenge mismatch"
    glasslock.OriginField -> "origin mismatch"
    glasslock.RelyingPartyIdField -> "relying party id mismatch"
    glasslock.CrossOriginField -> "cross origin not allowed"
    glasslock.TopOriginField -> "top origin not allowed"
    glasslock.CredentialIdField -> "credential id mismatch"
    glasslock.CredentialTypeField -> "credential type mismatch"
  }
}

fn lookup_user(
  ctx: web.Context,
  info: authentication.ResponseInfo,
) -> Result(credentials.User, Nil) {
  case
    credentials.get_user_by_credential_id(ctx.credentials, info.credential_id)
  {
    Ok(user) -> Ok(user)
    Error(_) ->
      case info.user_handle {
        option.Some(user_handle) ->
          credentials.get_user_by_user_id(ctx.credentials, user_handle)
        option.None -> Error(Nil)
      }
  }
}
