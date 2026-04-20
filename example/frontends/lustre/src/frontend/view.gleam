import frontend/model
import lustre/attribute
import lustre/element.{type Element}
import lustre/element/html
import lustre/event

pub fn root(m: model.Model) -> Element(model.Msg) {
  html.div(
    [
      attribute.style("max-width", "400px"),
      attribute.style("margin", "2em auto"),
      attribute.style("font-family", "system-ui, sans-serif"),
    ],
    [
      case m.page {
        model.HomePage -> home()
        model.RegisterPage(stage:) -> register(m.username, stage, m.status)
        model.LoginPage(stage:) -> login(stage, m.status)
        model.WelcomePage(username) -> welcome(username)
      },
    ],
  )
}

fn back_link() -> Element(model.Msg) {
  html.p([], [
    html.button([event.on_click(model.NavigateTo(model.DestHome))], [
      html.text("Back to home"),
    ]),
  ])
}

fn home() -> Element(model.Msg) {
  html.div([], [
    html.h1([], [html.text("Glasskey Demo")]),
    html.p([], [html.text("WebAuthn passkey authentication demo.")]),
    html.div(
      [
        attribute.style("display", "flex"),
        attribute.style("flex-direction", "column"),
        attribute.style("gap", "0.5em"),
      ],
      [
        html.button([event.on_click(model.NavigateTo(model.DestRegister))], [
          html.text("Register a new passkey"),
        ]),
        html.button([event.on_click(model.NavigateTo(model.DestLogin))], [
          html.text("Sign in with a passkey"),
        ]),
      ],
    ),
  ])
}

fn login(stage: model.LoginStage, status_text: String) -> Element(model.Msg) {
  let loading = is_login_loading(stage)
  html.div([], [
    html.h1([], [html.text("Sign In")]),
    html.input([
      attribute.type_("text"),
      attribute.name("username"),
      attribute.placeholder("Username"),
      attribute.attribute("autocomplete", "username webauthn"),
    ]),
    html.button(
      [event.on_click(model.LoginClicked), attribute.disabled(loading)],
      [html.text("Sign in with passkey")],
    ),
    status(status_text),
    back_link(),
  ])
}

fn is_login_loading(stage: model.LoginStage) -> Bool {
  case stage {
    model.LoginSettingUpConditional -> False
    model.LoginConditional(..) -> False
    model.LoginReady -> False
    model.LoginModalBeginning -> True
    model.LoginModalAwaiting(..) -> True
    model.LoginVerifying(..) -> True
  }
}

fn register(
  username: String,
  stage: model.RegisterStage,
  status_text: String,
) -> Element(model.Msg) {
  let loading = is_register_loading(stage)
  html.div([], [
    html.h1([], [html.text("Register")]),
    html.div(
      [
        attribute.style("display", "flex"),
        attribute.style("flex-direction", "column"),
        attribute.style("gap", "0.5em"),
      ],
      [
        html.input([
          attribute.type_("text"),
          attribute.placeholder("Username"),
          attribute.value(username),
          attribute.disabled(loading),
          event.on_input(model.UsernameChanged),
        ]),
        html.button(
          [
            event.on_click(model.RegisterClicked),
            attribute.disabled(loading || username == ""),
          ],
          [html.text("Register")],
        ),
      ],
    ),
    status(status_text),
    back_link(),
  ])
}

fn is_register_loading(stage: model.RegisterStage) -> Bool {
  case stage {
    model.RegisterIdle -> False
    model.RegisterBeginning -> True
    model.RegisterAwaitingAuthenticator(..) -> True
    model.RegisterVerifying(..) -> True
  }
}

fn status(text: String) -> Element(model.Msg) {
  case text {
    "" -> element.none()
    message -> html.p([attribute.style("color", "#555")], [html.text(message)])
  }
}

fn welcome(username: String) -> Element(model.Msg) {
  html.div([], [
    html.h1([], [html.text("Welcome, " <> username <> "!")]),
    html.p([], [html.text("You have successfully authenticated.")]),
    html.button([event.on_click(model.NavigateTo(model.DestHome))], [
      html.text("Log out"),
    ]),
  ])
}
