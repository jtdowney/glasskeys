import frontend/model
import frontend/router
import gleam/uri.{type Uri}
import lustre/attribute
import lustre/element.{type Element}
import lustre/element/html
import lustre/event

pub fn root(m: model.Model) -> Element(model.Msg) {
  html.main([attribute.class("app")], [
    case m {
      model.Unauthenticated(page: model.HomePage) -> home()
      model.Unauthenticated(page: model.LoginPage(state:)) -> login(state)
      model.Unauthenticated(page: model.NotFoundPage(uri:)) -> not_found(uri)
      model.Registering(state:) -> register(state)
      model.Authenticated(username:) -> welcome(username)
    },
  ])
}

fn back_link() -> Element(model.Msg) {
  html.p([], [html.a([router.href(router.Home)], [html.text("Back to home")])])
}

fn home() -> Element(model.Msg) {
  html.div([], [
    html.h1([], [html.text("Glasskey Demo")]),
    html.p([], [html.text("WebAuthn passkey authentication demo.")]),
    html.div([attribute.class("stack")], [
      html.a([attribute.class("button"), router.href(router.Register)], [
        html.text("Register a new passkey"),
      ]),
      html.a([attribute.class("button"), router.href(router.Login)], [
        html.text("Sign in with a passkey"),
      ]),
    ]),
  ])
}

fn login(state: model.LoginState) -> Element(model.Msg) {
  let loading = is_login_loading(state)
  html.div([], [
    html.h1([], [html.text("Sign In")]),
    html.div([attribute.class("stack")], [
      html.input([
        attribute.type_("text"),
        attribute.name("username"),
        attribute.placeholder("Username"),
        attribute.attribute("autocomplete", "username webauthn"),
      ]),
      html.button(
        [
          event.on_click(model.LoginMsg(model.UserClickedLogin)),
          attribute.disabled(loading),
        ],
        [html.text("Sign in with passkey")],
      ),
    ]),
    status(login_status(state)),
    back_link(),
  ])
}

fn is_login_loading(state: model.LoginState) -> Bool {
  case state {
    model.LoginSettingUpConditional -> False
    model.LoginConditional(..) -> False
    model.LoginReady(..) -> False
    model.LoginModalBeginning -> True
    model.LoginModalAwaiting -> True
    model.LoginVerifying -> True
  }
}

fn login_status(state: model.LoginState) -> String {
  case state {
    model.LoginReady(status:) -> status
    _ -> ""
  }
}

fn register(state: model.RegisterState) -> Element(model.Msg) {
  let loading = is_register_loading(state)
  let username = model.register_username(state)
  html.div([], [
    html.h1([], [html.text("Register")]),
    html.div([attribute.class("stack")], [
      html.input([
        attribute.type_("text"),
        attribute.placeholder("Username"),
        attribute.value(username),
        attribute.disabled(loading),
        event.on_input(fn(text) {
          model.RegisterMsg(model.UserTypedUsername(text))
        }),
      ]),
      html.button(
        [
          event.on_click(model.RegisterMsg(model.UserClickedRegister)),
          attribute.disabled(loading || username == ""),
        ],
        [html.text("Register")],
      ),
    ]),
    status(register_status(state)),
    back_link(),
  ])
}

fn is_register_loading(state: model.RegisterState) -> Bool {
  case state {
    model.RegisterIdle(..) -> False
    model.RegisterBeginning(..) -> True
    model.RegisterAwaitingAuthenticator(..) -> True
    model.RegisterVerifying(..) -> True
  }
}

fn register_status(state: model.RegisterState) -> String {
  case state {
    model.RegisterIdle(status:, ..) -> status
    _ -> ""
  }
}

fn status(text: String) -> Element(model.Msg) {
  case text {
    "" -> element.none()
    message -> html.p([attribute.class("status")], [html.text(message)])
  }
}

fn welcome(username: String) -> Element(model.Msg) {
  html.div([], [
    html.h1([], [html.text("Welcome, " <> username <> "!")]),
    html.p([], [html.text("You have successfully authenticated.")]),
    html.a([attribute.class("button"), router.href(router.Home)], [
      html.text("Log out"),
    ]),
  ])
}

fn not_found(uri: Uri) -> Element(model.Msg) {
  html.div([], [
    html.h1([], [html.text("Page not found")]),
    html.p([], [
      html.text("No page matches "),
      html.code([], [html.text(uri.path)]),
      html.text("."),
    ]),
    back_link(),
  ])
}
