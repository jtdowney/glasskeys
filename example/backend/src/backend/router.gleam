import backend/authenticate
import backend/register
import backend/web
import gleam/http
import wisp

pub fn handle_request(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use req <- web.middleware(req)

  case req.method, wisp.path_segments(req) {
    http.Post, ["api", "register", "begin"] -> register.begin(req, ctx)
    http.Post, ["api", "register", "complete"] -> register.complete(req, ctx)
    http.Post, ["api", "login", "begin"] -> authenticate.begin(ctx)
    http.Post, ["api", "login", "complete"] -> authenticate.complete(req, ctx)
    _, _ -> wisp.not_found()
  }
}
