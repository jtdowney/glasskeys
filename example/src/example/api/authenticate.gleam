import example/api/helpers
import example/store/credentials
import example/store/sessions.{AuthenticationSession}
import example/web.{type Context}
import glasskeys/authentication
import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import wisp.{type Request, type Response}

pub fn begin(_req: Request, ctx: Context) -> Response {
  let #(challenge_b64, verifier) =
    authentication.new()
    |> authentication.origin(ctx.origin)
    |> authentication.rp_id(ctx.rp_id)
    |> authentication.build()

  let session_id = helpers.generate_session_id()
  sessions.set(ctx.session_store, session_id, AuthenticationSession(verifier))

  let response_json =
    json.object([
      #("session_id", json.string(session_id)),
      #(
        "publicKey",
        json.object([
          #("challenge", json.string(challenge_b64)),
          #("rpId", json.string(ctx.rp_id)),
          #("timeout", json.int(60_000)),
          #("userVerification", json.string("preferred")),
        ]),
      ),
    ])

  wisp.json_response(json.to_string(response_json), 200)
}

pub fn complete(req: Request, ctx: Context) -> Response {
  use json_body <- wisp.require_json(req)

  let decoder = {
    use session_id <- decode.field("session_id", decode.string)
    use credential_id <- decode.subfield(["credential", "id"], decode.string)
    use authenticator_data <- decode.subfield(
      ["credential", "response", "authenticatorData"],
      decode.string,
    )
    use client_data_json <- decode.subfield(
      ["credential", "response", "clientDataJSON"],
      decode.string,
    )
    use signature <- decode.subfield(
      ["credential", "response", "signature"],
      decode.string,
    )
    use user_handle <- decode.subfield(
      ["credential", "response", "userHandle"],
      decode.optional(decode.string),
    )
    decode.success(#(
      session_id,
      credential_id,
      authenticator_data,
      client_data_json,
      signature,
      user_handle,
    ))
  }

  let decode_result = decode.run(json_body, decoder)
  use <- bool.guard(
    when: result.is_error(decode_result),
    return: helpers.json_error("Invalid request", 400),
  )
  let assert Ok(#(
    session_id,
    cred_id_b64,
    auth_data_b64,
    client_data_b64,
    sig_b64,
    user_handle_b64,
  )) = decode_result

  let session_result = sessions.get(ctx.session_store, session_id)
  use <- bool.guard(
    when: result.is_error(session_result),
    return: helpers.json_error("Session not found", 400),
  )
  let assert Ok(session) = session_result
  sessions.delete(ctx.session_store, session_id)

  let verifier_result = require_auth_session(session)
  use <- bool.guard(
    when: result.is_error(verifier_result),
    return: helpers.json_error("Invalid session type", 400),
  )
  let assert Ok(verifier) = verifier_result

  let cred_id_result = bit_array.base64_url_decode(cred_id_b64)
  use <- bool.guard(
    when: result.is_error(cred_id_result),
    return: helpers.json_error("Invalid credential_id encoding", 400),
  )
  let assert Ok(credential_id) = cred_id_result

  let auth_data_result = bit_array.base64_url_decode(auth_data_b64)
  use <- bool.guard(
    when: result.is_error(auth_data_result),
    return: helpers.json_error("Invalid authenticatorData encoding", 400),
  )
  let assert Ok(authenticator_data) = auth_data_result

  let client_data_result = bit_array.base64_url_decode(client_data_b64)
  use <- bool.guard(
    when: result.is_error(client_data_result),
    return: helpers.json_error("Invalid clientDataJSON encoding", 400),
  )
  let assert Ok(client_data_json) = client_data_result

  let sig_result = bit_array.base64_url_decode(sig_b64)
  use <- bool.guard(
    when: result.is_error(sig_result),
    return: helpers.json_error("Invalid signature encoding", 400),
  )
  let assert Ok(signature) = sig_result

  let user_result = find_user(ctx, credential_id, user_handle_b64)
  use <- bool.guard(
    when: result.is_error(user_result),
    return: helpers.json_error("User not found", 400),
  )
  let assert Ok(user) = user_result

  let stored_cred_result =
    list.find(user.credentials, fn(c) { c.id == credential_id })
  use <- bool.guard(
    when: result.is_error(stored_cred_result),
    return: helpers.json_error("Credential not found", 400),
  )
  let assert Ok(stored_cred) = stored_cred_result

  let verify_result =
    authentication.verify(
      authenticator_data: authenticator_data,
      client_data_json: client_data_json,
      signature: signature,
      credential_id: credential_id,
      challenge: verifier,
      stored: stored_cred,
    )
  use <- bool.lazy_guard(when: result.is_error(verify_result), return: fn() {
    let assert Error(e) = verify_result
    helpers.json_error(helpers.error_to_string(e), 400)
  })
  let assert Ok(updated_credential) = verify_result

  let update_result =
    credentials.update(ctx.credential_store, user.username, updated_credential)
  use <- bool.guard(
    when: result.is_error(update_result),
    return: helpers.json_error("Failed to update credential", 500),
  )

  wisp.redirect("/welcome")
  |> web.set_session_cookie(req, user.username)
}

fn find_user(
  ctx: Context,
  credential_id: BitArray,
  user_handle_b64: option.Option(String),
) -> Result(credentials.User, Nil) {
  case user_handle_b64 {
    Some(handle_b64) -> {
      use user_id <- result.try(bit_array.base64_url_decode(handle_b64))
      use user <- result.try(credentials.get_user_by_user_id(
        ctx.credential_store,
        user_id,
      ))
      case list.find(user.credentials, fn(c) { c.id == credential_id }) {
        Ok(_) -> Ok(user)
        Error(_) -> Error(Nil)
      }
    }
    None ->
      credentials.get_user_by_credential_id(ctx.credential_store, credential_id)
  }
}

fn require_auth_session(
  session: sessions.SessionData,
) -> Result(authentication.Challenge, Nil) {
  case session {
    sessions.AuthenticationSession(verifier) -> Ok(verifier)
    _ -> Error(Nil)
  }
}
