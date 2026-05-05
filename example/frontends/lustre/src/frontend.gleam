import frontend/api
import frontend/model
import frontend/router
import frontend/view
import glasskey
import gleam/javascript/promise
import gleam/option
import gleam/uri.{type Uri}
import lustre
import lustre/effect.{type Effect}
import modem

@external(javascript, "./frontend_ffi.mjs", "setPendingAbort")
fn set_pending_abort(abort: fn() -> Nil) -> Nil

@external(javascript, "./frontend_ffi.mjs", "runPendingAbort")
fn run_pending_abort() -> Nil

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
  model.RouterChangedRoute(router.parse(uri))
}

fn update(m: model.Model, msg: model.Msg) -> #(model.Model, Effect(model.Msg)) {
  case msg {
    model.RouterChangedRoute(route) -> apply_route(m, route)
    _ -> dispatch_msg(m, msg)
  }
}

fn dispatch_msg(
  m: model.Model,
  msg: model.Msg,
) -> #(model.Model, Effect(model.Msg)) {
  case m {
    model.Registering(username:, phase:) ->
      update_register(username, phase, msg)
    model.Unauthenticated(page: model.LoginPage(state:, username:)) ->
      update_login(state, username, msg)
    _ -> #(m, effect.none())
  }
}

fn apply_route(
  m: model.Model,
  route: router.Route,
) -> #(model.Model, Effect(model.Msg)) {
  let abort_eff = abort_if_conditional(m)
  let #(next, route_eff) = case route {
    router.Home -> #(model.Unauthenticated(page: model.HomePage), effect.none())
    router.Register -> #(
      model.Registering(
        username: previous_username(m),
        phase: model.RegisterIdle(status: model.RegisterStart),
      ),
      effect.none(),
    )
    router.Login -> #(
      model.Unauthenticated(page: model.LoginPage(
        state: model.LoginCheckingAutofill,
        username: "",
      )),
      check_autofill_support_effect(),
    )
    router.Welcome -> welcome_route(m)
    router.NotFound(uri:) -> #(
      model.Unauthenticated(page: model.NotFoundPage(uri:)),
      effect.none(),
    )
  }
  #(next, effect.batch([abort_eff, route_eff]))
}

fn abort_if_conditional(m: model.Model) -> Effect(model.Msg) {
  case m {
    model.Unauthenticated(page: model.LoginPage(
      state: model.LoginConditional,
      ..,
    )) -> abort_conditional_effect()
    _ -> effect.none()
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

fn previous_username(m: model.Model) -> String {
  case m {
    model.Registering(username:, ..) -> username
    _ -> ""
  }
}

fn registering(username: String, phase: model.RegisterPhase) -> model.Model {
  model.Registering(username:, phase:)
}

fn login_model(state: model.LoginState, username: String) -> model.Model {
  model.Unauthenticated(page: model.LoginPage(state:, username:))
}

fn update_register(
  username: String,
  phase: model.RegisterPhase,
  msg: model.Msg,
) -> #(model.Model, Effect(model.Msg)) {
  case phase, msg {
    model.RegisterIdle(..), model.UserTypedRegisterUsername(typed) -> #(
      registering(typed, model.RegisterIdle(status: model.RegisterStart)),
      effect.none(),
    )
    model.RegisterIdle(..), model.UserClickedRegister -> #(
      registering(username, model.RegisterBeginning),
      api.register_begin(username, model.BackendBeganRegistration),
    )
    model.RegisterBeginning, model.BackendBeganRegistration(Ok(options)) -> #(
      registering(username, model.RegisterAwaitingAuthenticator),
      registration_effect(options),
    )
    model.RegisterBeginning, model.BackendBeganRegistration(Error(message)) -> #(
      registering(
        username,
        model.RegisterIdle(status: model.RegisterFailed(message)),
      ),
      effect.none(),
    )
    model.RegisterAwaitingAuthenticator,
      model.AuthenticatorFinishedRegistration(Ok(response))
    -> #(
      registering(username, model.RegisterVerifying),
      api.register_complete(response, model.BackendFinishedRegistration),
    )
    model.RegisterAwaitingAuthenticator,
      model.AuthenticatorFinishedRegistration(Error(error))
    -> #(
      registering(
        username,
        model.RegisterIdle(
          status: model.RegisterFailed(glasskey_error_to_string(error)),
        ),
      ),
      effect.none(),
    )
    model.RegisterVerifying, model.BackendFinishedRegistration(Ok(Nil)) -> #(
      registering(username, model.RegisterIdle(status: model.RegisterSucceeded)),
      effect.none(),
    )
    model.RegisterVerifying, model.BackendFinishedRegistration(Error(message))
    -> #(
      registering(
        username,
        model.RegisterIdle(status: model.RegisterFailed(message)),
      ),
      effect.none(),
    )
    _, _ -> #(registering(username, phase), effect.none())
  }
}

fn update_login(
  state: model.LoginState,
  username: String,
  msg: model.Msg,
) -> #(model.Model, Effect(model.Msg)) {
  case state, msg {
    _, model.UserTypedLoginUsername(typed) -> #(
      login_model(state, typed),
      effect.none(),
    )
    _, model.UserClickedLogin -> begin_modal_login(state, username)

    model.LoginCheckingAutofill, model.BrowserReportedAutofillSupport(True) -> #(
      login_model(model.LoginSettingUpConditional, username),
      api.login_begin("", model.BackendBeganLogin),
    )
    model.LoginCheckingAutofill, model.BrowserReportedAutofillSupport(False) -> #(
      login_model(model.LoginReady(status: ""), username),
      effect.none(),
    )

    model.LoginSettingUpConditional, model.BackendBeganLogin(Ok(options)) -> #(
      login_model(model.LoginSettingUpConditional, username),
      start_conditional_authentication_effect(options),
    )
    model.LoginSettingUpConditional, model.BackendBeganLogin(Error(message)) -> #(
      login_model(model.LoginReady(status: "Error: " <> message), username),
      effect.none(),
    )
    model.LoginSettingUpConditional, model.ConditionalAuthStarted(Ok(Nil)) -> #(
      login_model(model.LoginConditional, username),
      effect.none(),
    )
    model.LoginSettingUpConditional, model.ConditionalAuthStarted(Error(error))
    -> #(
      login_model(
        model.LoginReady(status: "Error: " <> glasskey_error_to_string(error)),
        username,
      ),
      effect.none(),
    )

    model.LoginModalBeginning, model.BackendBeganModalLogin(Ok(options)) -> #(
      login_model(model.LoginModalAwaiting, username),
      authentication_effect(options),
    )
    model.LoginModalBeginning, model.BackendBeganModalLogin(Error(message)) -> #(
      login_model(model.LoginReady(status: "Error: " <> message), username),
      effect.none(),
    )

    model.LoginModalAwaiting, model.AuthenticatorFinishedLogin(Ok(response)) -> #(
      login_model(model.LoginVerifying, username),
      api.login_complete(response, model.BackendFinishedLogin),
    )
    model.LoginModalAwaiting, model.AuthenticatorFinishedLogin(Error(error)) -> #(
      login_model(
        model.LoginReady(status: "Error: " <> glasskey_error_to_string(error)),
        username,
      ),
      effect.none(),
    )

    model.LoginConditional,
      model.AuthenticatorFinishedConditionalLogin(Ok(response))
    -> #(
      login_model(model.LoginVerifying, username),
      api.login_complete(response, model.BackendFinishedLogin),
    )
    model.LoginConditional,
      model.AuthenticatorFinishedConditionalLogin(Error(glasskey.Aborted))
    -> #(login_model(model.LoginReady(status: ""), username), effect.none())
    model.LoginConditional,
      model.AuthenticatorFinishedConditionalLogin(Error(error))
    -> #(
      login_model(
        model.LoginReady(status: "Error: " <> glasskey_error_to_string(error)),
        username,
      ),
      effect.none(),
    )

    model.LoginVerifying, model.BackendFinishedLogin(Ok(verified_username)) -> #(
      model.Authenticated(username: verified_username),
      modem.push(router.to_path(router.Welcome), option.None, option.None),
    )
    model.LoginVerifying, model.BackendFinishedLogin(Error(message)) -> #(
      login_model(model.LoginReady(status: "Error: " <> message), username),
      effect.none(),
    )

    _, _ -> #(login_model(state, username), effect.none())
  }
}

fn begin_modal_login(
  state: model.LoginState,
  username: String,
) -> #(model.Model, Effect(model.Msg)) {
  let abort_eff = case state {
    model.LoginConditional -> abort_conditional_effect()
    _ -> effect.none()
  }
  #(
    login_model(model.LoginModalBeginning, username),
    effect.batch([
      abort_eff,
      api.login_begin(username, model.BackendBeganModalLogin),
    ]),
  )
}

fn check_autofill_support_effect() -> Effect(model.Msg) {
  effect.from(fn(dispatch) {
    glasskey.supports_webauthn_autofill()
    |> promise.map(fn(supported) {
      dispatch(model.BrowserReportedAutofillSupport(supported))
    })
    Nil
  })
}

fn start_conditional_authentication_effect(
  options: glasskey.AuthenticationOptions,
) -> Effect(model.Msg) {
  effect.from(fn(dispatch) {
    case glasskey.start_conditional_authentication(options) {
      Ok(conditional) -> {
        set_pending_abort(conditional.abort)
        dispatch(model.ConditionalAuthStarted(Ok(Nil)))
        conditional.result
        |> promise.map(fn(r) {
          dispatch(model.AuthenticatorFinishedConditionalLogin(r))
        })
        Nil
      }
      Error(error) -> dispatch(model.ConditionalAuthStarted(Error(error)))
    }
  })
}

fn abort_conditional_effect() -> Effect(model.Msg) {
  effect.from(fn(_dispatch) { run_pending_abort() })
}

fn authentication_effect(
  options: glasskey.AuthenticationOptions,
) -> Effect(model.Msg) {
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
) -> Effect(model.Msg) {
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
    glasskey.InvalidState ->
      "Authenticator state conflict (credential may already be registered)"
    glasskey.UnknownError(message) -> "Unknown error: " <> message
  }
}
