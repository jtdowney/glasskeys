//// Shared `Context` (credential store, RP id/name, allowed origins) and the
//// request-logging plus crash-rescue middleware used by every handler.

import backend/credentials
import non_empty_list.{type NonEmptyList}
import wisp

pub type Context {
  Context(
    credentials: credentials.Store,
    rp_id: String,
    rp_name: String,
    origins: NonEmptyList(String),
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
