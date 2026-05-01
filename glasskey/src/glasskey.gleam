//// WebAuthn/FIDO2 passkey bindings for Gleam targeting JavaScript, wrapping
//// the browser's `navigator.credentials` API for registration and
//// authentication ceremonies.
////
//// Designed for use with [glasslock](https://hexdocs.pm/glasslock) on the server side, or any
//// server that consumes JSON compatible with
//// [@simplewebauthn/browser](https://simplewebauthn.dev/docs/packages/browser).
////
//// ## Quick Start
////
//// `registration_options_decoder()` and `authentication_options_decoder()` are
//// `decode.Decoder` values that parse the options JSON glasslock produces.
//// Compose them into your server's response shape, then pass the decoded
//// value to the matching ceremony starter.
////
//// ```gleam
//// import glasskey
//// import gleam/javascript/promise
////
//// // Registration
//// use result <- promise.await(glasskey.start_registration(options))
//// case result {
////   Ok(response_json) -> send_to_server(response_json)
////   Error(e) -> handle_error(e)
//// }
////
//// // Authentication
//// use result <- promise.await(glasskey.start_authentication(options))
//// case result {
////   Ok(response_json) -> send_to_server(response_json)
////   Error(e) -> handle_error(e)
//// }
//// ```

import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/javascript/array
import gleam/javascript/promise.{type Promise}
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result

/// COSE algorithm identifier for credential key pairs.
pub type Algorithm {
  /// ECDSA with P-256 and SHA-256 (COSE -7).
  Es256
  /// EdDSA with Ed25519 (COSE -8).
  Ed25519
  /// RSASSA-PKCS1-v1_5 with SHA-256 (COSE -257).
  Rs256
}

/// Raw credential returned by the browser after `navigator.credentials.get()`.
@internal
pub type AuthenticationCredential {
  AuthenticationCredential(
    id: String,
    raw_id: BitArray,
    client_data_json: BitArray,
    authenticator_data: BitArray,
    signature: BitArray,
    user_handle: Option(BitArray),
  )
}

/// Parsed authentication ceremony options from the server.
pub type AuthenticationOptions {
  AuthenticationOptions(
    challenge: BitArray,
    rp_id: Option(String),
    timeout: Option(Int),
    user_verification: Option(Requirement),
    allow_credentials: List(CredentialDescriptor),
  )
}

/// A reference to a previously registered credential, with optional
/// transport hints to help the browser route the ceremony to the right
/// authenticator.
pub type CredentialDescriptor {
  CredentialDescriptor(id: BitArray, transports: List(Transport))
}

/// Transport hints reported by the authenticator.
pub type Transport {
  /// Removable USB authenticator.
  TransportUsb
  /// Near-field communication authenticator.
  TransportNfc
  /// Bluetooth Low Energy authenticator.
  TransportBle
  /// ISO/IEC 7816 smart card.
  TransportSmartCard
  /// Cross-device authenticator (e.g. phone acting as a roaming key).
  TransportHybrid
  /// Built-in platform authenticator (Touch ID, Windows Hello, etc.).
  TransportInternal
}

@internal
pub fn transport_to_string(transport: Transport) -> String {
  case transport {
    TransportUsb -> "usb"
    TransportNfc -> "nfc"
    TransportBle -> "ble"
    TransportSmartCard -> "smart-card"
    TransportHybrid -> "hybrid"
    TransportInternal -> "internal"
  }
}

@internal
pub fn classify_dom_exception(name: String, message: String) -> Error {
  case name {
    "NotSupportedError" -> NotSupported
    "NotAllowedError" -> NotAllowed
    "AbortError" -> Aborted
    "SecurityError" -> SecurityError
    _ -> UnknownError(name <> ": " <> message)
  }
}

/// Authenticator attachment modality.
pub type AuthenticatorAttachment {
  /// Built-in authenticator (Touch ID, Windows Hello, etc.).
  Platform
  /// Removable authenticator (USB security key, Bluetooth, etc.).
  CrossPlatform
}

/// Result of starting a conditional authentication ceremony.
///
/// Contains the promise that resolves when the user selects a passkey
/// from the browser's autofill UI, and an abort function to cancel
/// the pending ceremony.
pub type ConditionalAuthentication {
  ConditionalAuthentication(
    result: Promise(Result(String, Error)),
    abort: fn() -> Nil,
  )
}

/// Errors returned by glasskey operations.
pub type Error {
  /// The browser does not support WebAuthn.
  NotSupported
  /// The user cancelled the request or the operation timed out.
  NotAllowed
  /// The operation was aborted.
  Aborted
  /// The relying party ID is invalid for this origin.
  SecurityError
  /// An unexpected error from the browser API.
  UnknownError(String)
}

/// Raw credential returned by the browser after `navigator.credentials.create()`.
@internal
pub type RegistrationCredential {
  RegistrationCredential(
    id: String,
    raw_id: BitArray,
    client_data_json: BitArray,
    attestation_object: BitArray,
    transports: List(String),
  )
}

/// Parsed registration ceremony options from the server.
pub type RegistrationOptions {
  RegistrationOptions(
    challenge: BitArray,
    rp_id: String,
    rp_name: String,
    user_id: BitArray,
    user_name: String,
    user_display_name: String,
    algorithms: List(Algorithm),
    timeout: Option(Int),
    resident_key: Option(Requirement),
    user_verification: Option(Requirement),
    authenticator_attachment: Option(AuthenticatorAttachment),
    exclude_credentials: List(CredentialDescriptor),
  )
}

/// WebAuthn requirement level for resident keys or user verification.
pub type Requirement {
  /// The operation must satisfy this requirement.
  Required
  /// The operation should satisfy this requirement if possible.
  Preferred
  /// The operation should not satisfy this requirement.
  Discouraged
}

type AuthenticatorSelection {
  AuthenticatorSelection(
    resident_key: Option(String),
    user_verification: Option(String),
    authenticator_attachment: Option(String),
  )
}

type CreateOptions {
  CreateOptions(
    challenge: BitArray,
    rp: Rp,
    user: User,
    pub_key_cred_params: array.Array(Int),
    timeout: Option(Int),
    authenticator_selection: Option(AuthenticatorSelection),
    exclude_credentials: array.Array(CredentialDescriptor),
  )
}

type GetOptions {
  GetOptions(
    challenge: BitArray,
    rp_id: Option(String),
    timeout: Option(Int),
    user_verification: Option(String),
    allow_credentials: array.Array(CredentialDescriptor),
  )
}

type Rp {
  Rp(id: String, name: String)
}

type User {
  User(id: BitArray, name: String, display_name: String)
}

/// Start the WebAuthn authentication ceremony.
///
/// Takes options parsed with [`authentication_options_decoder`](#authentication_options_decoder),
/// then calls `navigator.credentials.get`. Returns a promise resolving to the
/// assertion response JSON on success.
pub fn start_authentication(
  options: AuthenticationOptions,
) -> Promise(Result(String, Error)) {
  use <- bool.guard(
    when: !supports_webauthn(),
    return: promise.resolve(Error(NotSupported)),
  )

  get_credential(to_get_options(options))
  |> promise.map(result.map(_, encode_authentication_response))
}

/// Start a conditional WebAuthn authentication ceremony (autofill UI).
///
/// Unlike `start_authentication` which shows a modal browser prompt,
/// this surfaces passkey suggestions in the browser's autofill dropdown.
/// Requires an `<input autocomplete="username webauthn">` element on the page.
///
/// Takes options parsed with [`authentication_options_decoder`](#authentication_options_decoder).
/// Returns synchronously with the ceremony handle or an error. Call `abort`
/// before starting a modal ceremony or when navigating away.
///
/// Conditional mediation is a separate browser capability from WebAuthn
/// itself. Callers should check
/// [`supports_webauthn_autofill`](#supports_webauthn_autofill) before
/// invoking this function. The synchronous `supports_webauthn` guard inside
/// only catches the absence of WebAuthn entirely; if WebAuthn is present
/// but conditional mediation is not, the returned `result` promise will
/// resolve to `Error(NotSupported)` rather than failing synchronously.
pub fn start_conditional_authentication(
  options: AuthenticationOptions,
) -> Result(ConditionalAuthentication, Error) {
  use <- bool.guard(when: !supports_webauthn(), return: Error(NotSupported))

  let #(raw_promise, abort) =
    get_conditional_credential(to_get_options(options))
  let result =
    raw_promise
    |> promise.map(result.map(_, encode_authentication_response))

  Ok(ConditionalAuthentication(result:, abort:))
}

@external(javascript, "./glasskey_ffi.mjs", "getConditionalCredential")
fn get_conditional_credential(
  options: GetOptions,
) -> #(Promise(Result(AuthenticationCredential, Error)), fn() -> Nil)

@external(javascript, "./glasskey_ffi.mjs", "getCredential")
fn get_credential(
  options: GetOptions,
) -> Promise(Result(AuthenticationCredential, Error))

fn to_get_options(options: AuthenticationOptions) -> GetOptions {
  GetOptions(
    challenge: options.challenge,
    rp_id: options.rp_id,
    timeout: options.timeout,
    user_verification: option.map(
      options.user_verification,
      requirement_to_string,
    ),
    allow_credentials: array.from_list(options.allow_credentials),
  )
}

/// Check whether a platform authenticator (Touch ID, Windows Hello, etc.) is available.
@external(javascript, "./glasskey_ffi.mjs", "platformAuthenticatorIsAvailable")
pub fn platform_authenticator_available() -> Promise(Bool)

/// Check whether the browser supports WebAuthn.
///
/// Returns `True` if `window.PublicKeyCredential` exists.
@external(javascript, "./glasskey_ffi.mjs", "browserSupportsWebauthn")
pub fn supports_webauthn() -> Bool

/// Check whether the browser supports WebAuthn autofill (conditional mediation).
@external(javascript, "./glasskey_ffi.mjs", "isConditionalMediationAvailable")
pub fn supports_webauthn_autofill() -> Promise(Bool)

@internal
pub fn encode_authentication_response(
  credential: AuthenticationCredential,
) -> String {
  let base_fields = [
    #("clientDataJSON", b64_json(credential.client_data_json)),
    #("authenticatorData", b64_json(credential.authenticator_data)),
    #("signature", b64_json(credential.signature)),
  ]
  let response_fields = case credential.user_handle {
    option.Some(handle) -> [#("userHandle", b64_json(handle)), ..base_fields]
    option.None -> base_fields
  }

  json.object([
    #("id", json.string(credential.id)),
    #("rawId", b64_json(credential.raw_id)),
    #("type", json.string("public-key")),
    #("response", json.object(response_fields)),
  ])
  |> json.to_string
}

@internal
pub fn encode_registration_response(
  credential: RegistrationCredential,
) -> String {
  let response_fields = [
    #("clientDataJSON", b64_json(credential.client_data_json)),
    #("attestationObject", b64_json(credential.attestation_object)),
  ]
  let response_fields = case credential.transports {
    [] -> response_fields
    _ -> [
      #("transports", json.array(credential.transports, json.string)),
      ..response_fields
    ]
  }

  json.object([
    #("id", json.string(credential.id)),
    #("rawId", b64_json(credential.raw_id)),
    #("type", json.string("public-key")),
    #("response", json.object(response_fields)),
  ])
  |> json.to_string
}

fn b64_json(bytes: BitArray) -> json.Json {
  json.string(bit_array.base64_url_encode(bytes, False))
}

/// Decoder for the `PublicKeyCredentialRequestOptionsJSON` shape produced by
/// `glasslock/authentication.request`.
///
/// Use this when decoding the server's envelope response so the `options`
/// subtree comes out as a typed `AuthenticationOptions` ready to pass to
/// `start_authentication` or `start_conditional_authentication`.
pub fn authentication_options_decoder() -> decode.Decoder(AuthenticationOptions) {
  use challenge <- decode.field("challenge", base64url_decoder())
  use rp_id <- decode.optional_field(
    "rpId",
    option.None,
    decode.optional(decode.string),
  )
  use timeout <- decode.optional_field(
    "timeout",
    option.None,
    decode.map(decode.int, option.Some),
  )
  use user_verification <- decode.optional_field(
    "userVerification",
    option.None,
    decode.map(requirement_decoder(), option.Some),
  )
  use allow_credentials <- decode.optional_field(
    "allowCredentials",
    [],
    credential_descriptor_list_decoder(),
  )
  decode.success(AuthenticationOptions(
    challenge:,
    rp_id:,
    timeout:,
    user_verification:,
    allow_credentials:,
  ))
}

/// Decoder for the `PublicKeyCredentialCreationOptionsJSON` shape produced by
/// `glasslock/registration.request`.
///
/// Use this when decoding the server's envelope response so the `options`
/// subtree comes out as a typed `RegistrationOptions` ready to pass to
/// `start_registration`.
pub fn registration_options_decoder() -> decode.Decoder(RegistrationOptions) {
  use challenge <- decode.field("challenge", base64url_decoder())
  use rp_id <- decode.subfield(["rp", "id"], decode.string)
  use rp_name <- decode.subfield(["rp", "name"], decode.string)
  use user_id <- decode.subfield(["user", "id"], base64url_decoder())
  use user_name <- decode.subfield(["user", "name"], decode.string)
  use user_display_name <- decode.subfield(
    ["user", "displayName"],
    decode.string,
  )
  use algorithms <- decode.field(
    "pubKeyCredParams",
    decode.list({
      use _ <- decode.field("type", public_key_credential_type_decoder())
      use alg <- decode.field("alg", algorithm_decoder())
      decode.success(alg)
    }),
  )
  use timeout <- decode.optional_field(
    "timeout",
    option.None,
    decode.map(decode.int, option.Some),
  )
  use #(resident_key, user_verification, authenticator_attachment) <- decode.optional_field(
    "authenticatorSelection",
    #(option.None, option.None, option.None),
    authenticator_selection_decoder(),
  )
  use exclude_credentials <- decode.optional_field(
    "excludeCredentials",
    [],
    credential_descriptor_list_decoder(),
  )
  decode.success(RegistrationOptions(
    challenge:,
    rp_id:,
    rp_name:,
    user_id:,
    user_name:,
    user_display_name:,
    algorithms:,
    timeout:,
    resident_key:,
    user_verification:,
    authenticator_attachment:,
    exclude_credentials:,
  ))
}

fn algorithm_decoder() -> decode.Decoder(Algorithm) {
  decode.int
  |> decode.then(fn(alg) {
    case alg {
      -7 -> decode.success(Es256)
      -8 -> decode.success(Ed25519)
      -257 -> decode.success(Rs256)
      _ -> decode.failure(Es256, "algorithm")
    }
  })
}

fn authenticator_selection_decoder() -> decode.Decoder(
  #(Option(Requirement), Option(Requirement), Option(AuthenticatorAttachment)),
) {
  use resident_key <- decode.optional_field(
    "residentKey",
    option.None,
    decode.map(requirement_decoder(), option.Some),
  )
  use user_verification <- decode.optional_field(
    "userVerification",
    option.None,
    decode.map(requirement_decoder(), option.Some),
  )
  use authenticator_attachment <- decode.optional_field(
    "authenticatorAttachment",
    option.None,
    decode.optional(authenticator_attachment_decoder()),
  )
  decode.success(#(resident_key, user_verification, authenticator_attachment))
}

fn authenticator_attachment_decoder() -> decode.Decoder(AuthenticatorAttachment) {
  decode.string
  |> decode.then(fn(s) {
    case s {
      "platform" -> decode.success(Platform)
      "cross-platform" -> decode.success(CrossPlatform)
      _ -> decode.failure(Platform, "authenticatorAttachment")
    }
  })
}

fn base64url_decoder() -> decode.Decoder(BitArray) {
  decode.string
  |> decode.then(fn(s) {
    case bit_array.base64_url_decode(s) {
      Ok(bytes) -> decode.success(bytes)
      Error(_) -> decode.failure(<<>>, "base64url")
    }
  })
}

fn credential_descriptor_list_decoder() -> decode.Decoder(
  List(CredentialDescriptor),
) {
  decode.list({
    use _ <- decode.field("type", public_key_credential_type_decoder())
    use id <- decode.field("id", base64url_decoder())
    use transport_strings <- decode.optional_field(
      "transports",
      [],
      decode.list(decode.string),
    )
    decode.success(CredentialDescriptor(
      id:,
      transports: list.filter_map(transport_strings, transport_from_string),
    ))
  })
}

fn transport_from_string(value: String) -> Result(Transport, Nil) {
  case value {
    "usb" -> Ok(TransportUsb)
    "nfc" -> Ok(TransportNfc)
    "ble" -> Ok(TransportBle)
    "smart-card" -> Ok(TransportSmartCard)
    "hybrid" -> Ok(TransportHybrid)
    "internal" -> Ok(TransportInternal)
    _ -> Error(Nil)
  }
}

fn public_key_credential_type_decoder() -> decode.Decoder(Nil) {
  decode.string
  |> decode.then(fn(type_) {
    case type_ {
      "public-key" -> decode.success(Nil)
      _ -> decode.failure(Nil, "public-key credential type")
    }
  })
}

fn requirement_decoder() -> decode.Decoder(Requirement) {
  decode.string
  |> decode.then(fn(s) {
    case s {
      "required" -> decode.success(Required)
      "preferred" -> decode.success(Preferred)
      "discouraged" -> decode.success(Discouraged)
      _ -> decode.failure(Required, "requirement")
    }
  })
}

/// Start the WebAuthn registration ceremony.
///
/// Takes options parsed with [`registration_options_decoder`](#registration_options_decoder),
/// then calls `navigator.credentials.create`. Returns a promise resolving to
/// the credential response JSON on success.
pub fn start_registration(
  options: RegistrationOptions,
) -> Promise(Result(String, Error)) {
  use <- bool.guard(
    when: !supports_webauthn(),
    return: promise.resolve(Error(NotSupported)),
  )

  create_credential(to_create_options(options))
  |> promise.map(result.map(_, encode_registration_response))
}

fn to_create_options(options: RegistrationOptions) -> CreateOptions {
  let resident_key = option.map(options.resident_key, requirement_to_string)
  let user_verification =
    option.map(options.user_verification, requirement_to_string)
  let authenticator_attachment =
    option.map(
      options.authenticator_attachment,
      authenticator_attachment_to_string,
    )
  let authenticator_selection = case
    resident_key,
    user_verification,
    authenticator_attachment
  {
    option.None, option.None, option.None -> option.None
    _, _, _ ->
      option.Some(AuthenticatorSelection(
        resident_key:,
        user_verification:,
        authenticator_attachment:,
      ))
  }

  CreateOptions(
    challenge: options.challenge,
    rp: Rp(id: options.rp_id, name: options.rp_name),
    user: User(
      id: options.user_id,
      name: options.user_name,
      display_name: options.user_display_name,
    ),
    pub_key_cred_params: array.from_list(list.map(
      options.algorithms,
      algorithm_to_cose,
    )),
    timeout: options.timeout,
    authenticator_selection:,
    exclude_credentials: array.from_list(options.exclude_credentials),
  )
}

@external(javascript, "./glasskey_ffi.mjs", "createCredential")
fn create_credential(
  options: CreateOptions,
) -> Promise(Result(RegistrationCredential, Error))

fn algorithm_to_cose(algorithm: Algorithm) -> Int {
  case algorithm {
    Es256 -> -7
    Ed25519 -> -8
    Rs256 -> -257
  }
}

fn authenticator_attachment_to_string(
  attachment: AuthenticatorAttachment,
) -> String {
  case attachment {
    Platform -> "platform"
    CrossPlatform -> "cross-platform"
  }
}

fn requirement_to_string(requirement: Requirement) -> String {
  case requirement {
    Required -> "required"
    Preferred -> "preferred"
    Discouraged -> "discouraged"
  }
}
