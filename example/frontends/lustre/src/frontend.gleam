import frontend/api
import frontend/model
import frontend/router
import frontend/view
import glasskey
import gleam/javascript/promise.{type Promise}
import gleam/option
import gleam/result
import gleam/uri.{type Uri}
import lustre
import lustre/effect.{type Effect}
import modem

pub fn main() {
  let app = lustre.application(init, update, view.root)
  let assert Ok(_) = lustre.start(app, "#app", Nil)
  Nil
}

fn init(_flags) -> #(model.Model, Effect(model.Msg)) {
  let starting_route = case modem.initial_uri() {
    Ok(uri) -> router.parse(uri)
    Error(_) -> router.Home
  }
  let #(m, route_effect) =
    apply_route(model.Unauthenticated(page: model.HomePage), starting_route)
  #(m, effect.batch([modem.init(on_url_change), route_effect]))
}

fn on_url_change(uri: Uri) -> model.Msg {
  model.UserNavigatedTo(router.parse(uri))
}

fn update(m: model.Model, msg: model.Msg) -> #(model.Model, Effect(model.Msg)) {
  case msg {
    model.UserNavigatedTo(route) -> apply_route(m, route)
    model.RegisterMsg(rm) -> dispatch_register(m, rm)
    model.LoginMsg(lm) -> dispatch_login(m, lm)
  }
}

fn dispatch_register(
  m: model.Model,
  msg: model.RegisterMsg,
) -> #(model.Model, Effect(model.Msg)) {
  case m {
    model.Registering(state:) -> {
      let #(next, eff) = update_register(state, msg)
      #(next, effect.map(eff, model.RegisterMsg))
    }
    _ -> #(m, effect.none())
  }
}

fn dispatch_login(
  m: model.Model,
  msg: model.LoginMsg,
) -> #(model.Model, Effect(model.Msg)) {
  case m {
    model.Unauthenticated(page: model.LoginPage(state:)) -> {
      let #(next, eff) = update_login(state, msg)
      #(next, effect.map(eff, model.LoginMsg))
    }
    _ -> #(m, effect.none())
  }
}

fn apply_route(
  m: model.Model,
  route: router.Route,
) -> #(model.Model, Effect(model.Msg)) {
  let m = abort_conditional(m)
  case route {
    router.Home -> #(model.Unauthenticated(page: model.HomePage), effect.none())
    router.Register -> #(
      model.Registering(state: model.RegisterIdle(
        username: previous_username(m) |> result.unwrap(""),
        status: "",
      )),
      effect.none(),
    )
    router.Login -> #(
      model.Unauthenticated(page: model.LoginPage(
        state: model.LoginSettingUpConditional,
      )),
      effect.map(api.login_begin(model.BackendBeganLogin), model.LoginMsg),
    )
    router.Welcome -> welcome_route(m)
    router.NotFound(uri:) -> #(
      model.Unauthenticated(page: model.NotFoundPage(uri:)),
      effect.none(),
    )
  }
}

fn welcome_route(m: model.Model) -> #(model.Model, Effect(model.Msg)) {
  case m {
    model.Authenticated(..) -> #(m, effect.none())
    model.Unauthenticated(..) | model.Registering(..) -> #(
      m,
      modem.push(router.to_path(router.Home), option.None, option.None),
    )
  }
}

fn previous_username(m: model.Model) -> Result(String, Nil) {
  case m {
    model.Registering(state:) -> Ok(model.register_username(state))
    _ -> Error(Nil)
  }
}

fn abort_conditional(m: model.Model) -> model.Model {
  case m {
    model.Unauthenticated(page: model.LoginPage(state: model.LoginConditional(
      abort:,
    ))) -> {
      abort()
      m
    }
    _ -> m
  }
}

fn update_register(
  state: model.RegisterState,
  msg: model.RegisterMsg,
) -> #(model.Model, Effect(model.RegisterMsg)) {
  case state, msg {
    model.RegisterIdle(..), model.UserTypedUsername(username) -> #(
      model.Registering(state: model.RegisterIdle(username:, status: "")),
      effect.none(),
    )
    model.RegisterIdle(username:, ..), model.UserClickedRegister -> #(
      model.Registering(state: model.RegisterBeginning(username:)),
      api.register_begin(username, model.BackendBeganRegistration),
    )
    model.RegisterBeginning(username:),
      model.BackendBeganRegistration(Ok(options))
    -> #(
      model.Registering(state: model.RegisterAwaitingAuthenticator(username:)),
      registration_effect(options),
    )
    model.RegisterBeginning(username:),
      model.BackendBeganRegistration(Error(message))
    -> #(
      model.Registering(state: model.RegisterIdle(
        username:,
        status: "Error: " <> message,
      )),
      effect.none(),
    )
    model.RegisterAwaitingAuthenticator(username:),
      model.AuthenticatorFinishedRegistration(Ok(response))
    -> #(
      model.Registering(state: model.RegisterVerifying(username:)),
      api.register_complete(response, model.BackendFinishedRegistration),
    )
    model.RegisterAwaitingAuthenticator(username:),
      model.AuthenticatorFinishedRegistration(Error(error))
    -> #(
      model.Registering(state: model.RegisterIdle(
        username:,
        status: "Error: " <> glasskey_error_to_string(error),
      )),
      effect.none(),
    )
    model.RegisterVerifying(username:),
      model.BackendFinishedRegistration(Ok(Nil))
    -> #(
      model.Registering(state: model.RegisterIdle(
        username:,
        status: "Registration successful!",
      )),
      effect.none(),
    )
    model.RegisterVerifying(username:),
      model.BackendFinishedRegistration(Error(message))
    -> #(
      model.Registering(state: model.RegisterIdle(
        username:,
        status: "Error: " <> message,
      )),
      effect.none(),
    )
    _, _ -> #(model.Registering(state:), effect.none())
  }
}

fn update_login(
  state: model.LoginState,
  msg: model.LoginMsg,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case state, msg {
    _, model.UserClickedLogin -> {
      case state {
        model.LoginConditional(abort:) -> abort()
        _ -> Nil
      }
      #(
        model.Unauthenticated(page: model.LoginPage(
          state: model.LoginModalBeginning,
        )),
        api.login_begin(model.BackendBeganModalLogin),
      )
    }
    model.LoginSettingUpConditional, model.BackendBeganLogin(Ok(options)) ->
      start_conditional(options)
    model.LoginSettingUpConditional, model.BackendBeganLogin(Error(message)) -> #(
      model.Unauthenticated(
        page: model.LoginPage(state: model.LoginReady(
          status: "Error: " <> message,
        )),
      ),
      effect.none(),
    )
    model.LoginModalBeginning, model.BackendBeganModalLogin(Ok(options)) -> #(
      model.Unauthenticated(page: model.LoginPage(
        state: model.LoginModalAwaiting,
      )),
      authentication_effect(options),
    )
    model.LoginModalBeginning, model.BackendBeganModalLogin(Error(message)) -> #(
      model.Unauthenticated(
        page: model.LoginPage(state: model.LoginReady(
          status: "Error: " <> message,
        )),
      ),
      effect.none(),
    )
    model.LoginModalAwaiting, model.AuthenticatorFinishedLogin(Ok(response)) -> #(
      model.Unauthenticated(page: model.LoginPage(state: model.LoginVerifying)),
      api.login_complete(response, model.BackendFinishedLogin),
    )
    model.LoginModalAwaiting, model.AuthenticatorFinishedLogin(Error(error)) -> #(
      model.Unauthenticated(
        page: model.LoginPage(state: model.LoginReady(
          status: "Error: " <> glasskey_error_to_string(error),
        )),
      ),
      effect.none(),
    )
    model.LoginConditional(..),
      model.AuthenticatorFinishedConditionalLogin(Ok(response))
    -> #(
      model.Unauthenticated(page: model.LoginPage(state: model.LoginVerifying)),
      api.login_complete(response, model.BackendFinishedLogin),
    )
    model.LoginConditional(..),
      model.AuthenticatorFinishedConditionalLogin(Error(glasskey.Aborted))
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(state: model.LoginReady(status: "")),
      ),
      effect.none(),
    )
    model.LoginConditional(..),
      model.AuthenticatorFinishedConditionalLogin(Error(error))
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(state: model.LoginReady(
          status: "Error: " <> glasskey_error_to_string(error),
        )),
      ),
      effect.none(),
    )
    model.LoginVerifying, model.BackendFinishedLogin(Ok(username)) -> #(
      model.Authenticated(username:),
      modem.push(router.to_path(router.Welcome), option.None, option.None),
    )
    model.LoginVerifying, model.BackendFinishedLogin(Error(message)) -> #(
      model.Unauthenticated(
        page: model.LoginPage(state: model.LoginReady(
          status: "Error: " <> message,
        )),
      ),
      effect.none(),
    )
    _, _ -> #(
      model.Unauthenticated(page: model.LoginPage(state:)),
      effect.none(),
    )
  }
}

fn start_conditional(
  options: glasskey.AuthenticationOptions,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case glasskey.start_conditional_authentication(options) {
    Ok(conditional) -> #(
      model.Unauthenticated(
        page: model.LoginPage(state: model.LoginConditional(
          abort: conditional.abort,
        )),
      ),
      await_conditional_authentication_effect(conditional.result),
    )
    Error(_) -> #(
      model.Unauthenticated(
        page: model.LoginPage(state: model.LoginReady(status: "")),
      ),
      effect.none(),
    )
  }
}

fn await_conditional_authentication_effect(
  result: Promise(Result(String, glasskey.Error)),
) -> Effect(model.LoginMsg) {
  effect.from(fn(dispatch) {
    result
    |> promise.map(fn(r) {
      dispatch(model.AuthenticatorFinishedConditionalLogin(r))
    })
    Nil
  })
}

fn authentication_effect(
  options: glasskey.AuthenticationOptions,
) -> Effect(model.LoginMsg) {
  effect.from(fn(dispatch) {
    glasskey.start_authentication(options)
    |> promise.map(fn(result) {
      dispatch(model.AuthenticatorFinishedLogin(result))
    })
    Nil
  })
}

fn registration_effect(
  options: glasskey.RegistrationOptions,
) -> Effect(model.RegisterMsg) {
  effect.from(fn(dispatch) {
    glasskey.start_registration(options)
    |> promise.map(fn(result) {
      dispatch(model.AuthenticatorFinishedRegistration(result))
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
    glasskey.UnknownError(message) -> "Unknown error: " <> message
  }
}
