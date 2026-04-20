import backend/credentials
import backend/sessions
import backend/web
import glasslock
import glasslock/authentication
import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import wisp

pub fn begin(ctx: web.Context) -> wisp.Response {
  let options =
    authentication.Options(
      ..authentication.default_options(),
      rp_id: ctx.rp_id,
      origins: ctx.origins,
      allow_credentials: [],
    )
  let #(options_json, challenge) = authentication.generate_options(options)

  let session_id =
    crypto.strong_random_bytes(32)
    |> bit_array.base64_url_encode(False)

  sessions.set_authentication(
    ctx.sessions,
    session_id,
    sessions.Authentication(challenge:),
  )

  let response_json =
    json.object([
      #("session_id", json.string(session_id)),
      #("options", options_json),
    ])
    |> json.to_string

  wisp.json_response(response_json, 200)
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
      complete_authentication(session_id, response, ctx)
  }
}

fn complete_authentication(
  session_id: String,
  response_json: String,
  ctx: web.Context,
) -> wisp.Response {
  let result = {
    use session <- result.try(
      sessions.get_and_delete_authentication(ctx.sessions, session_id)
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
        challenge: session.challenge,
        stored: stored_credential,
      )
      |> result.map_error(fn(err) {
        #("verification failed: " <> describe_error(err), 400)
      }),
    )
    credentials.update(ctx.credentials, updated_credential)
    |> result.map(fn(_) { user.username })
    |> result.map_error(fn(_) { #("failed to update credential", 500) })
  }

  case result {
    Ok(username) ->
      json.object([
        #("verified", json.bool(True)),
        #("username", json.string(username)),
      ])
      |> json.to_string
      |> wisp.json_response(200)
    Error(#(message, status)) ->
      json.object([#("error", json.string(message))])
      |> json.to_string
      |> wisp.json_response(status)
  }
}

fn describe_error(err: glasslock.Error) -> String {
  case err {
    glasslock.VerificationMismatch(glasslock.TypeField) -> "type mismatch"
    glasslock.VerificationMismatch(glasslock.ChallengeField) ->
      "challenge mismatch"
    glasslock.VerificationMismatch(glasslock.OriginField) -> "origin mismatch"
    glasslock.VerificationMismatch(glasslock.RpIdField) -> "rp id mismatch"
    glasslock.VerificationMismatch(glasslock.CrossOriginField) ->
      "cross origin not allowed"
    glasslock.VerificationMismatch(glasslock.TopOriginField) ->
      "top origin not allowed"
    glasslock.VerificationMismatch(glasslock.CredentialIdField) ->
      "credential id mismatch"
    glasslock.VerificationMismatch(glasslock.CredentialTypeField) ->
      "credential type mismatch"
    glasslock.UnsupportedKey(reason) -> "unsupported key: " <> reason
    glasslock.UnsupportedFeature(reason) -> "unsupported feature: " <> reason
    glasslock.ParseError(message) -> "parse error: " <> message
    glasslock.InvalidAttestation(reason) -> "invalid attestation: " <> reason
    glasslock.InvalidSignature -> "invalid signature"
    glasslock.CredentialNotAllowed -> "credential not allowed"
    glasslock.SignCountRegression -> "sign count regression"
    glasslock.UserPresenceFailed -> "user presence failed"
    glasslock.UserVerificationFailed -> "user verification failed"
  }
}

fn lookup_user(
  ctx: web.Context,
  info: authentication.ResponseInfo,
) -> Result(credentials.User, credentials.Error) {
  let glasslock.CredentialId(credential_id) = info.credential_id
  case credentials.get_user_by_credential_id(ctx.credentials, credential_id) {
    Ok(user) -> Ok(user)
    Error(_) ->
      case info.user_handle {
        option.Some(user_handle) ->
          credentials.get_user_by_user_id(ctx.credentials, user_handle)
        option.None -> Error(credentials.NotFound)
      }
  }
}
