import frontend/api
import frontend/model
import frontend/view
import glasskey
import gleam/javascript/promise.{type Promise}
import lustre
import lustre/effect.{type Effect}

pub fn main() {
  let app = lustre.application(init, update, view.root)
  let assert Ok(_) = lustre.start(app, "#app", Nil)
  Nil
}

fn init(_flags) -> #(model.Model, Effect(model.Msg)) {
  let m = model.Model(page: model.HomePage, username: "", status: "")
  #(m, effect.none())
}

fn update(m: model.Model, msg: model.Msg) -> #(model.Model, Effect(model.Msg)) {
  case msg {
    model.NavigateTo(destination) -> navigate(m, destination)
    model.UsernameChanged(username) -> #(
      model.Model(..m, username:),
      effect.none(),
    )
    model.RegisterClicked -> start_registration(m)
    model.GotRegisterBeginResponse(result) -> handle_register_begin(m, result)
    model.GotWebAuthnRegistrationResult(result) ->
      handle_registration_result(m, result)
    model.GotRegisterCompleteResponse(result) ->
      handle_register_complete(m, result)
    model.LoginClicked -> start_modal_login(m)
    model.GotLoginBeginResponse(result) -> handle_login_begin(m, result)
    model.GotModalLoginBeginResponse(result) ->
      handle_modal_login_begin(m, result)
    model.GotWebAuthnAuthenticationResult(result) ->
      handle_auth_result(m, result)
    model.GotConditionalAuthenticationResult(result) ->
      handle_conditional_result(m, result)
    model.GotLoginCompleteResponse(result) -> handle_login_complete(m, result)
  }
}

fn navigate(
  m: model.Model,
  destination: model.Destination,
) -> #(model.Model, Effect(model.Msg)) {
  abort_if_conditional(m.page)
  case destination {
    model.DestHome -> #(
      model.Model(..m, page: model.HomePage, status: ""),
      effect.none(),
    )
    model.DestRegister -> #(
      model.Model(
        ..m,
        page: model.RegisterPage(stage: model.RegisterIdle),
        status: "",
      ),
      effect.none(),
    )
    model.DestLogin -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginSettingUpConditional),
        status: "",
      ),
      api.login_begin(model.GotLoginBeginResponse),
    )
  }
}

fn abort_if_conditional(page: model.Page) -> Nil {
  case page {
    model.LoginPage(stage: model.LoginConditional(abort:, ..)) -> abort()
    _ -> Nil
  }
}

fn start_registration(m: model.Model) -> #(model.Model, Effect(model.Msg)) {
  case m.page {
    model.RegisterPage(stage: model.RegisterIdle) -> #(
      model.Model(
        ..m,
        page: model.RegisterPage(stage: model.RegisterBeginning),
        status: "Starting registration...",
      ),
      api.register_begin(m.username, model.GotRegisterBeginResponse),
    )
    _ -> #(m, effect.none())
  }
}

fn handle_register_begin(
  m: model.Model,
  result: Result(model.BeginResponse(glasskey.RegistrationOptions), String),
) -> #(model.Model, Effect(model.Msg)) {
  case m.page, result {
    model.RegisterPage(stage: model.RegisterBeginning),
      Ok(model.BeginResponse(session_id:, options:))
    -> #(
      model.Model(
        ..m,
        page: model.RegisterPage(stage: model.RegisterAwaitingAuthenticator(
          session_id:,
        )),
        status: "Waiting for authenticator...",
      ),
      registration_effect(options),
    )
    model.RegisterPage(stage: model.RegisterBeginning), Error(message) -> #(
      model.Model(
        ..m,
        page: model.RegisterPage(stage: model.RegisterIdle),
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_registration_result(
  m: model.Model,
  result: Result(String, glasskey.Error),
) -> #(model.Model, Effect(model.Msg)) {
  case m.page, result {
    model.RegisterPage(stage: model.RegisterAwaitingAuthenticator(session_id:)),
      Ok(response)
    -> #(
      model.Model(
        ..m,
        page: model.RegisterPage(stage: model.RegisterVerifying(session_id:)),
        status: "Verifying with server...",
      ),
      api.register_complete(
        session_id,
        response,
        model.GotRegisterCompleteResponse,
      ),
    )
    model.RegisterPage(stage: model.RegisterAwaitingAuthenticator(..)),
      Error(error)
    -> #(
      model.Model(
        ..m,
        page: model.RegisterPage(stage: model.RegisterIdle),
        status: "Error: " <> glasskey_error_to_string(error),
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_register_complete(
  m: model.Model,
  result: Result(Nil, String),
) -> #(model.Model, Effect(model.Msg)) {
  case m.page, result {
    model.RegisterPage(stage: model.RegisterVerifying(..)), Ok(Nil) -> #(
      model.Model(
        ..m,
        page: model.RegisterPage(stage: model.RegisterIdle),
        status: "Registration successful!",
      ),
      effect.none(),
    )
    model.RegisterPage(stage: model.RegisterVerifying(..)), Error(message) -> #(
      model.Model(
        ..m,
        page: model.RegisterPage(stage: model.RegisterIdle),
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn start_modal_login(m: model.Model) -> #(model.Model, Effect(model.Msg)) {
  abort_if_conditional(m.page)
  case m.page {
    model.LoginPage(_) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginModalBeginning),
        status: "Starting authentication...",
      ),
      api.login_begin(model.GotModalLoginBeginResponse),
    )
    _ -> #(m, effect.none())
  }
}

fn handle_login_begin(
  m: model.Model,
  result: Result(model.BeginResponse(glasskey.AuthenticationOptions), String),
) -> #(model.Model, Effect(model.Msg)) {
  case m.page, result {
    model.LoginPage(stage: model.LoginSettingUpConditional),
      Ok(model.BeginResponse(session_id:, options:))
    -> start_conditional(m, session_id, options)
    model.LoginPage(stage: model.LoginSettingUpConditional), Error(message) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn start_conditional(
  m: model.Model,
  session_id: String,
  options: glasskey.AuthenticationOptions,
) -> #(model.Model, Effect(model.Msg)) {
  case glasskey.start_conditional_authentication(options) {
    Ok(conditional) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginConditional(
          session_id:,
          abort: conditional.abort,
        )),
        status: "",
      ),
      await_conditional_authentication_effect(conditional.result),
    )
    Error(_) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginReady),
        status: "",
      ),
      effect.none(),
    )
  }
}

fn handle_modal_login_begin(
  m: model.Model,
  result: Result(model.BeginResponse(glasskey.AuthenticationOptions), String),
) -> #(model.Model, Effect(model.Msg)) {
  case m.page, result {
    model.LoginPage(stage: model.LoginModalBeginning),
      Ok(model.BeginResponse(session_id:, options:))
    -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginModalAwaiting(session_id:)),
        status: "Waiting for authenticator...",
      ),
      authentication_effect(options),
    )
    model.LoginPage(stage: model.LoginModalBeginning), Error(message) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_auth_result(
  m: model.Model,
  result: Result(String, glasskey.Error),
) -> #(model.Model, Effect(model.Msg)) {
  case m.page, result {
    model.LoginPage(stage: model.LoginModalAwaiting(session_id:)), Ok(response) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginVerifying(session_id:)),
        status: "Verifying with server...",
      ),
      api.login_complete(session_id, response, model.GotLoginCompleteResponse),
    )
    model.LoginPage(stage: model.LoginModalAwaiting(..)), Error(error) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> glasskey_error_to_string(error),
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_conditional_result(
  m: model.Model,
  result: Result(String, glasskey.Error),
) -> #(model.Model, Effect(model.Msg)) {
  case m.page, result {
    model.LoginPage(stage: model.LoginConditional(session_id:, ..)),
      Ok(response)
    -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginVerifying(session_id:)),
        status: "Verifying with server...",
      ),
      api.login_complete(session_id, response, model.GotLoginCompleteResponse),
    )
    model.LoginPage(stage: model.LoginConditional(..)), Error(glasskey.Aborted) -> #(
      model.Model(..m, page: model.LoginPage(stage: model.LoginReady)),
      effect.none(),
    )
    model.LoginPage(stage: model.LoginConditional(..)), Error(error) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> glasskey_error_to_string(error),
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_login_complete(
  m: model.Model,
  result: Result(String, String),
) -> #(model.Model, Effect(model.Msg)) {
  case m.page, result {
    model.LoginPage(stage: model.LoginVerifying(..)), Ok(username) -> #(
      model.Model(..m, page: model.WelcomePage(username:), status: ""),
      effect.none(),
    )
    model.LoginPage(stage: model.LoginVerifying(..)), Error(message) -> #(
      model.Model(
        ..m,
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn await_conditional_authentication_effect(
  result: Promise(Result(String, glasskey.Error)),
) -> Effect(model.Msg) {
  effect.from(fn(dispatch) {
    result
    |> promise.map(fn(r) {
      dispatch(model.GotConditionalAuthenticationResult(r))
    })
    Nil
  })
}

fn authentication_effect(
  options: glasskey.AuthenticationOptions,
) -> Effect(model.Msg) {
  effect.from(fn(dispatch) {
    glasskey.start_authentication(options)
    |> promise.map(fn(result) {
      dispatch(model.GotWebAuthnAuthenticationResult(result))
    })
    Nil
  })
}

fn registration_effect(
  options: glasskey.RegistrationOptions,
) -> Effect(model.Msg) {
  effect.from(fn(dispatch) {
    glasskey.start_registration(options)
    |> promise.map(fn(result) {
      dispatch(model.GotWebAuthnRegistrationResult(result))
    })
    Nil
  })
}

fn glasskey_error_to_string(error: glasskey.Error) -> String {
  case error {
    glasskey.NotSupported -> "WebAuthn is not supported in this browser"
    glasskey.NotAllowed -> "Operation was not allowed or was cancelled"
    glasskey.Aborted -> "Operation was aborted"
    glasskey.SecurityError -> "Security error occurred"
    glasskey.EncodingError(message) -> "Encoding error: " <> message
    glasskey.UnknownError(message) -> "Unknown error: " <> message
  }
}
