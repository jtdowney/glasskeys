//// Shared `Context` (credential store, RP id/name, allowed origins), the
//// request-logging plus crash-rescue middleware, and small response helpers
//// used by every handler.

import backend/credentials
import gleam/json
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
  // No CSRF check: WebAuthn endpoints take JSON over fetch and rely on
  // SameSite=Lax session cookies to block cross-site form posts.
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes

  handler(req)
}

pub fn error_response(message: String, status: Int) -> wisp.Response {
  json.object([#("error", json.string(message))])
  |> json.to_string
  |> wisp.json_response(status)
}

pub fn clear_session(
  response: wisp.Response,
  req: wisp.Request,
  cookie_name: String,
) -> wisp.Response {
  wisp.set_cookie(response, req, cookie_name, "", wisp.PlainText, 0)
}
