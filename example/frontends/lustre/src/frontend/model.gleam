import frontend/router
import glasskey
import gleam/json.{type Json}
import gleam/uri.{type Uri}

pub type Model {
  Unauthenticated(page: UnauthenticatedPage)
  Registering(state: RegisterState)
  Authenticated(username: String)
}

pub type UnauthenticatedPage {
  HomePage
  LoginPage(state: LoginState, username: String)
  NotFoundPage(uri: Uri)
}

pub type RegisterState {
  RegisterIdle(username: String, status: String)
  RegisterBeginning(username: String)
  RegisterAwaitingAuthenticator(username: String)
  RegisterVerifying(username: String)
}

pub type LoginState {
  LoginCheckingAutofill
  LoginSettingUpConditional
  LoginConditional(abort: fn() -> Nil)
  LoginModalBeginning
  LoginModalAwaiting
  LoginVerifying
  LoginReady(status: String)
}

pub type Msg {
  UserNavigatedTo(router.Route)
  RegisterMsg(RegisterMsg)
  LoginMsg(LoginMsg)
}

pub type RegisterMsg {
  RegisterIdleAction(RegisterIdleMsg)
  RegisterBeginningAction(RegisterBeginningMsg)
  RegisterAwaitingAction(RegisterAwaitingMsg)
  RegisterVerifyingAction(RegisterVerifyingMsg)
}

pub type RegisterIdleMsg {
  UserTypedUsername(String)
  UserClickedRegister
}

pub type RegisterBeginningMsg {
  BackendBeganRegistration(Result(glasskey.RegistrationOptions, String))
}

pub type RegisterAwaitingMsg {
  AuthenticatorFinishedRegistration(Result(Json, glasskey.Error))
}

pub type RegisterVerifyingMsg {
  BackendFinishedRegistration(Result(Nil, String))
}

pub type LoginMsg {
  UserClickedLogin
  UserTypedLoginUsername(String)
  LoginCheckingAutofillAction(LoginCheckingAutofillMsg)
  LoginSettingUpConditionalAction(LoginSettingUpConditionalMsg)
  LoginModalBeginningAction(LoginModalBeginningMsg)
  LoginModalAwaitingAction(LoginModalAwaitingMsg)
  LoginConditionalAction(LoginConditionalMsg)
  LoginVerifyingAction(LoginVerifyingMsg)
}

pub type LoginCheckingAutofillMsg {
  AutofillSupportChecked(Bool)
}

pub type LoginSettingUpConditionalMsg {
  BackendBeganLogin(Result(glasskey.AuthenticationOptions, String))
}

pub type LoginModalBeginningMsg {
  BackendBeganModalLogin(Result(glasskey.AuthenticationOptions, String))
}

pub type LoginModalAwaitingMsg {
  AuthenticatorFinishedLogin(Result(Json, glasskey.Error))
}

pub type LoginConditionalMsg {
  AuthenticatorFinishedConditionalLogin(Result(Json, glasskey.Error))
}

pub type LoginVerifyingMsg {
  BackendFinishedLogin(Result(String, String))
}

pub fn register_username(state: RegisterState) -> String {
  case state {
    RegisterIdle(username:, ..) -> username
    RegisterBeginning(username:) -> username
    RegisterAwaitingAuthenticator(username:) -> username
    RegisterVerifying(username:) -> username
  }
}
