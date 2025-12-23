import example/api/authenticate
import example/api/register
import example/pages
import example/web.{type Context, middleware}
import gleam/http
import wisp.{type Request, type Response}

pub fn handle_request(req: Request, ctx: Context) -> Response {
  use req <- middleware(req, ctx)

  case wisp.path_segments(req) {
    [] -> html_response(pages.index())

    ["register"] -> html_response(pages.register())

    ["login"] -> html_response(pages.login())

    ["welcome"] -> {
      case web.get_session_username(req) {
        Ok(username) -> html_response(pages.welcome(username))
        Error(_) -> wisp.redirect("/login")
      }
    }

    ["logout"] -> {
      wisp.redirect("/")
      |> web.clear_session_cookie(req)
    }

    ["static", ..] -> {
      use <- wisp.serve_static(req, under: "/static", from: ctx.priv)
      wisp.not_found()
    }

    ["api", "register", "begin"] -> {
      use <- wisp.require_method(req, http.Post)
      register.begin(req, ctx)
    }
    ["api", "register", "complete"] -> {
      use <- wisp.require_method(req, http.Post)
      register.complete(req, ctx)
    }

    ["api", "login", "begin"] -> {
      use <- wisp.require_method(req, http.Post)
      authenticate.begin(req, ctx)
    }
    ["api", "login", "complete"] -> {
      use <- wisp.require_method(req, http.Post)
      authenticate.complete(req, ctx)
    }

    _ -> wisp.not_found()
  }
}

fn html_response(body: String) -> Response {
  wisp.ok()
  |> wisp.set_header("content-type", "text/html; charset=utf-8")
  |> wisp.string_body(body)
}
