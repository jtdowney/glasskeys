import glasskey

pub type Model {
  Model(page: Page, username: String, status: String)
}

pub type Page {
  HomePage
  RegisterPage(stage: RegisterStage)
  LoginPage(stage: LoginStage)
  WelcomePage(username: String)
}

pub type RegisterStage {
  RegisterIdle
  RegisterBeginning
  RegisterAwaitingAuthenticator(session_id: String)
  RegisterVerifying(session_id: String)
}

pub type LoginStage {
  LoginSettingUpConditional
  LoginConditional(session_id: String, abort: fn() -> Nil)
  LoginModalBeginning
  LoginModalAwaiting(session_id: String)
  LoginVerifying(session_id: String)
  LoginReady
}

pub type Destination {
  DestHome
  DestRegister
  DestLogin
}

pub type BeginResponse(options) {
  BeginResponse(session_id: String, options: options)
}

pub type Msg {
  NavigateTo(Destination)
  UsernameChanged(String)
  RegisterClicked
  GotRegisterBeginResponse(
    Result(BeginResponse(glasskey.RegistrationOptions), String),
  )
  GotWebAuthnRegistrationResult(Result(String, glasskey.Error))
  GotRegisterCompleteResponse(Result(Nil, String))
  LoginClicked
  GotLoginBeginResponse(
    Result(BeginResponse(glasskey.AuthenticationOptions), String),
  )
  GotModalLoginBeginResponse(
    Result(BeginResponse(glasskey.AuthenticationOptions), String),
  )
  GotWebAuthnAuthenticationResult(Result(String, glasskey.Error))
  GotConditionalAuthenticationResult(Result(String, glasskey.Error))
  GotLoginCompleteResponse(Result(String, String))
}
