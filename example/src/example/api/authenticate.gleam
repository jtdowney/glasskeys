import example/api/helpers
import example/store/credentials
import example/store/sessions.{AuthenticationSession}
import example/web.{type Context}
import given
import glasskeys/authentication
import gleam/bit_array
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

  use
    #(
      session_id,
      cred_id_b64,
      auth_data_b64,
      client_data_b64,
      sig_b64,
      user_handle_b64,
    )
  <- given.ok(in: decode.run(json_body, decoder), else_return: fn(_) {
    helpers.json_error("Invalid request", 400)
  })

  use session <- given.ok(
    in: sessions.get(ctx.session_store, session_id),
    else_return: fn(_) { helpers.json_error("Session not found", 400) },
  )
  sessions.delete(ctx.session_store, session_id)

  use verifier <- require_auth_session(session)

  use credential_id <- given.ok(
    in: bit_array.base64_url_decode(cred_id_b64),
    else_return: fn(_) {
      helpers.json_error("Invalid credential_id encoding", 400)
    },
  )
  use authenticator_data <- given.ok(
    in: bit_array.base64_url_decode(auth_data_b64),
    else_return: fn(_) {
      helpers.json_error("Invalid authenticatorData encoding", 400)
    },
  )
  use client_data_json <- given.ok(
    in: bit_array.base64_url_decode(client_data_b64),
    else_return: fn(_) {
      helpers.json_error("Invalid clientDataJSON encoding", 400)
    },
  )
  use signature <- given.ok(
    in: bit_array.base64_url_decode(sig_b64),
    else_return: fn(_) { helpers.json_error("Invalid signature encoding", 400) },
  )

  use user <- given.ok(
    in: find_user(ctx, credential_id, user_handle_b64),
    else_return: fn(_) { helpers.json_error("User not found", 400) },
  )

  use stored_cred <- given.ok(
    in: list.find(user.credentials, fn(c) { c.id == credential_id }),
    else_return: fn(_) { helpers.json_error("Credential not found", 400) },
  )

  case
    authentication.verify(
      authenticator_data: authenticator_data,
      client_data_json: client_data_json,
      signature: signature,
      credential_id: credential_id,
      challenge: verifier,
      stored: stored_cred,
    )
  {
    Ok(updated_credential) -> {
      case
        credentials.update(
          ctx.credential_store,
          user.username,
          updated_credential,
        )
      {
        Ok(_) -> {
          wisp.redirect("/welcome")
          |> web.set_session_cookie(req, user.username)
        }
        Error(_) -> helpers.json_error("Failed to update credential", 500)
      }
    }
    Error(e) -> helpers.json_error(helpers.error_to_string(e), 400)
  }
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
  next: fn(authentication.Challenge) -> Response,
) -> Response {
  case session {
    sessions.AuthenticationSession(verifier) -> next(verifier)
    _ -> helpers.json_error("Invalid session type", 400)
  }
}
