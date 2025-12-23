import example/store/credentials.{type CredentialStore}
import example/store/sessions.{type SessionStore}
import wisp.{type Request, type Response}

const session_cookie_name = "session"

const session_max_age = 86_400

pub type Context {
  Context(
    origin: String,
    rp_id: String,
    priv: String,
    credential_store: CredentialStore,
    session_store: SessionStore,
  )
}

pub fn middleware(
  req: Request,
  _ctx: Context,
  handler: fn(Request) -> Response,
) -> Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes

  handler(req)
}

pub fn set_session_cookie(
  response: Response,
  request: Request,
  username: String,
) -> Response {
  wisp.set_cookie(
    response,
    request,
    session_cookie_name,
    username,
    wisp.Signed,
    session_max_age,
  )
}

pub fn get_session_username(request: Request) -> Result(String, Nil) {
  wisp.get_cookie(request, session_cookie_name, wisp.Signed)
}

pub fn clear_session_cookie(response: Response, request: Request) -> Response {
  wisp.set_cookie(response, request, session_cookie_name, "", wisp.Signed, 0)
}
