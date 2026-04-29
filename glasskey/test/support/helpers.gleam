import gleam/option.{type Option}

pub type CreateSnapshot {
  CreateSnapshot(
    challenge: BitArray,
    rp_id: String,
    timeout: Option(Int),
    authenticator_attachment: Option(String),
    exclude_credential_count: Int,
    resident_key: Option(String),
    user_verification: Option(String),
    has_authenticator_selection: Bool,
    algs: List(Int),
  )
}

pub type GetSnapshot {
  GetSnapshot(
    rp_id: Option(String),
    timeout: Option(Int),
    user_verification: String,
    allow_credential_count: Int,
  )
}

@external(javascript, "../glasskey_test_ffi.mjs", "installFakeNavigator")
pub fn install_default_fake_navigator() -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "installFakeNavigatorMinimal")
pub fn install_minimal_fake_navigator() -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "uninstallFakeNavigator")
pub fn uninstall_fake_navigator() -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setCreateCredential")
pub fn set_create_credential(
  raw_id raw_id: BitArray,
  client_data_json client_data_json: BitArray,
  attestation_object attestation_object: BitArray,
) -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setCreateNull")
pub fn set_create_null() -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setCreateDomException")
pub fn set_create_dom_exception(
  name name: String,
  message message: String,
) -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setCreatePlainError")
pub fn set_create_plain_error(message: String) -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setGetCredential")
pub fn set_get_credential(
  raw_id raw_id: BitArray,
  client_data_json client_data_json: BitArray,
  authenticator_data authenticator_data: BitArray,
  signature signature: BitArray,
  user_handle user_handle: Option(BitArray),
) -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setGetNull")
pub fn set_get_null() -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setGetDomException")
pub fn set_get_dom_exception(name name: String, message message: String) -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setGetPlainError")
pub fn set_get_plain_error(message: String) -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "lastCreateSnapshot")
pub fn last_create_snapshot() -> Result(CreateSnapshot, Nil)

@external(javascript, "../glasskey_test_ffi.mjs", "lastGetSnapshot")
pub fn last_get_snapshot() -> Result(GetSnapshot, Nil)

@external(javascript, "../glasskey_test_ffi.mjs", "lastGetSignalAborted")
pub fn last_get_signal_aborted() -> Result(Bool, Nil)

@external(javascript, "../glasskey_test_ffi.mjs", "setConditionalMediationAvailable")
pub fn set_conditional_mediation_available(available: Bool) -> Nil

@external(javascript, "../glasskey_test_ffi.mjs", "setPlatformAuthenticatorAvailable")
pub fn set_platform_authenticator_available(available: Bool) -> Nil
