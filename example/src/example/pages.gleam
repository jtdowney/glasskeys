import gleam/list
import nakai
import nakai/attr
import nakai/html

fn page(
  title: String,
  content: List(html.Node),
  scripts: List(html.Node),
) -> String {
  html.Html([attr.lang("en"), attr.data("theme", "light")], [
    base_head(title),
    html.Body(
      [],
      list.append([html.main([attr.class("container")], content)], scripts),
    ),
  ])
  |> nakai.to_string
}

fn base_head(title: String) -> html.Node {
  html.Head([
    html.meta([attr.charset("UTF-8")]),
    html.meta([
      attr.name("viewport"),
      attr.content("width=device-width, initial-scale=1.0"),
    ]),
    html.title(title),
    html.link([
      attr.rel("stylesheet"),
      attr.href(
        "https://cdn.jsdelivr.net/npm/@picocss/pico@2.1.1/css/pico.min.css",
      ),
      attr.Attr(
        "integrity",
        "sha384-L1dWfspMTHU/ApYnFiMz2QID/PlP1xCW9visvBdbEkOLkSSWsP6ZJWhPw6apiXxU",
      ),
      attr.Attr("crossorigin", "anonymous"),
    ]),
  ])
}

pub fn index() -> String {
  page(
    "Glasskeys WebAuthn Demo",
    [
      html.h1_text([], "Glasskeys WebAuthn Demo"),
      html.div([attr.class("grid")], [
        html.article([], [
          html.header([], [html.h2_text([], "New User?")]),
          html.p_text([], "Create a passkey to get started."),
          html.a([attr.href("/register"), attr.role("button")], [
            html.Text("Register"),
          ]),
        ]),
        html.article([], [
          html.header([], [html.h2_text([], "Existing User?")]),
          html.p_text([], "Sign in with your passkey."),
          html.a([attr.href("/login"), attr.role("button")], [
            html.Text("Login"),
          ]),
        ]),
      ]),
    ],
    [],
  )
}

pub fn register() -> String {
  page(
    "Register - Glasskeys Demo",
    [
      html.h1_text([], "Register"),
      html.article([], [
        html.form([attr.id("register-form")], [
          html.input([
            attr.type_("text"),
            attr.id("register-username"),
            attr.name("username"),
            attr.placeholder("Choose a username"),
            attr.required("true"),
            attr.autofocus(),
          ]),
          html.button([attr.type_("submit")], [html.Text("Create Passkey")]),
        ]),
        html.p([attr.id("status"), attr.role("status")], []),
      ]),
      html.p([], [
        html.Text("Already have an account? "),
        html.a([attr.href("/login")], [html.Text("Login")]),
      ]),
    ],
    [
      html.Script([attr.src("/static/utils.js")], ""),
      html.Script([attr.src("/static/register.js")], ""),
    ],
  )
}

pub fn login() -> String {
  page(
    "Login - Glasskeys Demo",
    [
      html.h1_text([], "Login"),
      html.article([], [
        html.button([attr.id("passkey-btn"), attr.class("contrast")], [
          html.Text("Sign in with Passkey"),
        ]),
        html.p([attr.id("status"), attr.role("status")], []),
      ]),
      html.p([], [
        html.Text("Don't have an account? "),
        html.a([attr.href("/register")], [html.Text("Register")]),
      ]),
    ],
    [
      html.Script([attr.src("/static/utils.js")], ""),
      html.Script([attr.src("/static/login.js")], ""),
    ],
  )
}

pub fn welcome(username: String) -> String {
  page(
    "Welcome - Glasskeys Demo",
    [
      html.article([], [
        html.header([], [html.h1_text([], "Welcome!")]),
        html.p([], [
          html.Text("Logged in as: "),
          html.strong_text([], username),
        ]),
        html.a([attr.href("/logout"), attr.role("button")], [
          html.Text("Logout"),
        ]),
      ]),
    ],
    [],
  )
}
