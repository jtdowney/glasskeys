import frontend/router
import glasskey
import gleam/json.{type Json}
import gleam/uri.{type Uri}

pub type Model {
  Unauthenticated(page: UnauthenticatedPage)
  Registering(username: String, phase: RegisterPhase)
  Authenticated(username: String)
}

pub type UnauthenticatedPage {
  HomePage
  LoginPage(state: LoginState, username: String)
  NotFoundPage(uri: Uri)
}

pub type RegisterPhase {
  RegisterIdle(status: RegisterStatus)
  RegisterBeginning
  RegisterAwaitingAuthenticator
  RegisterVerifying
}

pub type RegisterStatus {
  RegisterStart
  RegisterSucceeded
  RegisterFailed(message: String)
}

pub type LoginState {
  LoginCheckingAutofill
  LoginSettingUpConditional
  LoginConditional
  LoginModalBeginning
  LoginModalAwaiting
  LoginVerifying
  LoginReady(status: String)
}

pub type Msg {
  RouterChangedRoute(router.Route)

  UserTypedRegisterUsername(String)
  UserClickedRegister
  BackendBeganRegistration(Result(glasskey.RegistrationOptions, String))
  AuthenticatorFinishedRegistration(Result(Json, glasskey.Error))
  BackendFinishedRegistration(Result(Nil, String))

  UserTypedLoginUsername(String)
  UserClickedLogin
  BrowserReportedAutofillSupport(Bool)
  BackendBeganLogin(Result(glasskey.AuthenticationOptions, String))
  BackendBeganModalLogin(Result(glasskey.AuthenticationOptions, String))
  ConditionalAuthStarted(Result(Nil, glasskey.Error))
  AuthenticatorFinishedLogin(Result(Json, glasskey.Error))
  AuthenticatorFinishedConditionalLogin(Result(Json, glasskey.Error))
  BackendFinishedLogin(Result(String, String))
}
