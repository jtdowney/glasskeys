import frontend/router
import glasskey
import gleam/uri.{type Uri}

pub type Model {
  Unauthenticated(page: UnauthenticatedPage)
  Registering(state: RegisterState)
  Authenticated(username: String)
}

pub type UnauthenticatedPage {
  HomePage
  LoginPage(state: LoginState)
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
  UserTypedUsername(String)
  UserClickedRegister
  BackendBeganRegistration(Result(glasskey.RegistrationOptions, String))
  AuthenticatorFinishedRegistration(Result(String, glasskey.Error))
  BackendFinishedRegistration(Result(Nil, String))
}

pub type LoginMsg {
  UserClickedLogin
  AutofillSupportChecked(Bool)
  BackendBeganLogin(Result(glasskey.AuthenticationOptions, String))
  BackendBeganModalLogin(Result(glasskey.AuthenticationOptions, String))
  AuthenticatorFinishedLogin(Result(String, glasskey.Error))
  AuthenticatorFinishedConditionalLogin(Result(String, glasskey.Error))
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
