import frontend/api
import frontend/model
import frontend/router
import frontend/view
import glasskey
import gleam/javascript/promise.{type Promise}
import gleam/json.{type Json}
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
    model.Unauthenticated(page: model.LoginPage(state:, username:)) -> {
      let #(next, eff) = update_login(state, username, msg)
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
        state: model.LoginCheckingAutofill,
        username: "",
      )),
      effect.map(check_autofill_support_effect(), model.LoginMsg),
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
    model.Unauthenticated(page: model.LoginPage(
      state: model.LoginConditional(abort:),
      ..,
    )) -> {
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
  let #(next_state, eff) = case state, msg {
    model.RegisterIdle(username:, ..), model.RegisterIdleAction(idle_msg) ->
      update_register_idle(username, idle_msg)
    model.RegisterBeginning(username:), model.RegisterBeginningAction(begin_msg)
    -> update_register_beginning(username, begin_msg)
    model.RegisterAwaitingAuthenticator(username:),
      model.RegisterAwaitingAction(await_msg)
    -> update_register_awaiting(username, await_msg)
    model.RegisterVerifying(username:),
      model.RegisterVerifyingAction(verify_msg)
    -> update_register_verifying(username, verify_msg)
    _, _ -> #(state, effect.none())
  }
  #(model.Registering(state: next_state), eff)
}

fn update_register_idle(
  username: String,
  msg: model.RegisterIdleMsg,
) -> #(model.RegisterState, Effect(model.RegisterMsg)) {
  case msg {
    model.UserTypedUsername(typed) -> #(
      model.RegisterIdle(username: typed, status: ""),
      effect.none(),
    )
    model.UserClickedRegister -> #(
      model.RegisterBeginning(username:),
      api.register_begin(username, fn(result) {
        model.RegisterBeginningAction(model.BackendBeganRegistration(result))
      }),
    )
  }
}

fn update_register_beginning(
  username: String,
  msg: model.RegisterBeginningMsg,
) -> #(model.RegisterState, Effect(model.RegisterMsg)) {
  case msg {
    model.BackendBeganRegistration(Ok(options)) -> #(
      model.RegisterAwaitingAuthenticator(username:),
      registration_effect(options),
    )
    model.BackendBeganRegistration(Error(message)) -> #(
      model.RegisterIdle(username:, status: "Error: " <> message),
      effect.none(),
    )
  }
}

fn update_register_awaiting(
  username: String,
  msg: model.RegisterAwaitingMsg,
) -> #(model.RegisterState, Effect(model.RegisterMsg)) {
  case msg {
    model.AuthenticatorFinishedRegistration(Ok(response)) -> #(
      model.RegisterVerifying(username:),
      api.register_complete(response, fn(result) {
        model.RegisterVerifyingAction(model.BackendFinishedRegistration(result))
      }),
    )
    model.AuthenticatorFinishedRegistration(Error(error)) -> #(
      model.RegisterIdle(
        username:,
        status: "Error: " <> glasskey_error_to_string(error),
      ),
      effect.none(),
    )
  }
}

fn update_register_verifying(
  username: String,
  msg: model.RegisterVerifyingMsg,
) -> #(model.RegisterState, Effect(model.RegisterMsg)) {
  case msg {
    model.BackendFinishedRegistration(Ok(Nil)) -> #(
      model.RegisterIdle(username:, status: "Registration successful!"),
      effect.none(),
    )
    model.BackendFinishedRegistration(Error(message)) -> #(
      model.RegisterIdle(username:, status: "Error: " <> message),
      effect.none(),
    )
  }
}

fn update_login(
  state: model.LoginState,
  username: String,
  msg: model.LoginMsg,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case state, msg {
    _, model.UserTypedLoginUsername(typed) -> #(
      login_model(state, typed),
      effect.none(),
    )
    _, model.UserClickedLogin -> begin_modal_login(state, username)
    model.LoginCheckingAutofill, model.LoginCheckingAutofillAction(autofill_msg)
    -> update_login_checking_autofill(username, autofill_msg)
    model.LoginSettingUpConditional,
      model.LoginSettingUpConditionalAction(setup_msg)
    -> update_login_setting_up_conditional(username, setup_msg)
    model.LoginModalBeginning, model.LoginModalBeginningAction(begin_msg) ->
      update_login_modal_beginning(username, begin_msg)
    model.LoginModalAwaiting, model.LoginModalAwaitingAction(await_msg) ->
      update_login_modal_awaiting(username, await_msg)
    model.LoginConditional(..), model.LoginConditionalAction(conditional_msg) ->
      update_login_conditional(username, conditional_msg)
    model.LoginVerifying, model.LoginVerifyingAction(verify_msg) ->
      update_login_verifying(username, verify_msg)
    _, _ -> #(login_model(state, username), effect.none())
  }
}

fn begin_modal_login(
  state: model.LoginState,
  username: String,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case state {
    model.LoginConditional(abort:) -> abort()
    _ -> Nil
  }
  #(
    login_model(model.LoginModalBeginning, username),
    api.login_begin(username, fn(result) {
      model.LoginModalBeginningAction(model.BackendBeganModalLogin(result))
    }),
  )
}

fn update_login_checking_autofill(
  username: String,
  msg: model.LoginCheckingAutofillMsg,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case msg {
    model.AutofillSupportChecked(True) -> #(
      login_model(model.LoginSettingUpConditional, username),
      api.login_begin("", fn(result) {
        model.LoginSettingUpConditionalAction(model.BackendBeganLogin(result))
      }),
    )
    model.AutofillSupportChecked(False) -> #(
      login_model(model.LoginReady(status: ""), username),
      effect.none(),
    )
  }
}

fn update_login_setting_up_conditional(
  username: String,
  msg: model.LoginSettingUpConditionalMsg,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case msg {
    model.BackendBeganLogin(Ok(options)) -> start_conditional(options, username)
    model.BackendBeganLogin(Error(message)) -> #(
      login_model(model.LoginReady(status: "Error: " <> message), username),
      effect.none(),
    )
  }
}

fn update_login_modal_beginning(
  username: String,
  msg: model.LoginModalBeginningMsg,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case msg {
    model.BackendBeganModalLogin(Ok(options)) -> #(
      login_model(model.LoginModalAwaiting, username),
      authentication_effect(options),
    )
    model.BackendBeganModalLogin(Error(message)) -> #(
      login_model(model.LoginReady(status: "Error: " <> message), username),
      effect.none(),
    )
  }
}

fn update_login_modal_awaiting(
  username: String,
  msg: model.LoginModalAwaitingMsg,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case msg {
    model.AuthenticatorFinishedLogin(Ok(response)) -> #(
      login_model(model.LoginVerifying, username),
      api.login_complete(response, fn(result) {
        model.LoginVerifyingAction(model.BackendFinishedLogin(result))
      }),
    )
    model.AuthenticatorFinishedLogin(Error(error)) -> #(
      login_model(
        model.LoginReady(status: "Error: " <> glasskey_error_to_string(error)),
        username,
      ),
      effect.none(),
    )
  }
}

fn update_login_conditional(
  username: String,
  msg: model.LoginConditionalMsg,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case msg {
    model.AuthenticatorFinishedConditionalLogin(Ok(response)) -> #(
      login_model(model.LoginVerifying, username),
      api.login_complete(response, fn(result) {
        model.LoginVerifyingAction(model.BackendFinishedLogin(result))
      }),
    )
    model.AuthenticatorFinishedConditionalLogin(Error(glasskey.Aborted)) -> #(
      login_model(model.LoginReady(status: ""), username),
      effect.none(),
    )
    model.AuthenticatorFinishedConditionalLogin(Error(error)) -> #(
      login_model(
        model.LoginReady(status: "Error: " <> glasskey_error_to_string(error)),
        username,
      ),
      effect.none(),
    )
  }
}

fn update_login_verifying(
  username: String,
  msg: model.LoginVerifyingMsg,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case msg {
    model.BackendFinishedLogin(Ok(verified_username)) -> #(
      model.Authenticated(username: verified_username),
      modem.push(router.to_path(router.Welcome), option.None, option.None),
    )
    model.BackendFinishedLogin(Error(message)) -> #(
      login_model(model.LoginReady(status: "Error: " <> message), username),
      effect.none(),
    )
  }
}

fn login_model(state: model.LoginState, username: String) -> model.Model {
  model.Unauthenticated(page: model.LoginPage(state:, username:))
}

fn start_conditional(
  options: glasskey.AuthenticationOptions,
  username: String,
) -> #(model.Model, Effect(model.LoginMsg)) {
  case glasskey.start_conditional_authentication(options) {
    Ok(conditional) -> #(
      login_model(model.LoginConditional(abort: conditional.abort), username),
      await_conditional_authentication_effect(conditional.result),
    )
    Error(_) -> #(
      login_model(model.LoginReady(status: ""), username),
      effect.none(),
    )
  }
}

fn await_conditional_authentication_effect(
  result: Promise(Result(Json, glasskey.Error)),
) -> Effect(model.LoginMsg) {
  effect.from(fn(dispatch) {
    result
    |> promise.map(fn(r) {
      dispatch(
        model.LoginConditionalAction(
          model.AuthenticatorFinishedConditionalLogin(r),
        ),
      )
    })
    Nil
  })
}

fn check_autofill_support_effect() -> Effect(model.LoginMsg) {
  effect.from(fn(dispatch) {
    glasskey.supports_webauthn_autofill()
    |> promise.map(fn(supported) {
      dispatch(
        model.LoginCheckingAutofillAction(model.AutofillSupportChecked(
          supported,
        )),
      )
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
      dispatch(
        model.LoginModalAwaitingAction(model.AuthenticatorFinishedLogin(result)),
      )
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
      dispatch(
        model.RegisterAwaitingAction(model.AuthenticatorFinishedRegistration(
          result,
        )),
      )
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
