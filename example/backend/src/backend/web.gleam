import backend/credentials
import backend/sessions
import wisp

pub type Context {
  Context(
    sessions: sessions.Store,
    credentials: credentials.Store,
    rp_id: String,
    rp_name: String,
    origins: List(String),
  )
}

pub fn middleware(
  req: wisp.Request,
  handler: fn(wisp.Request) -> wisp.Response,
) -> wisp.Response {
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes

  handler(req)
}
