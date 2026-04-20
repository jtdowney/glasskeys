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
//// ### Registration (creating a new credential)
////
//// ```gleam
//// import glasskey
//// import gleam/dynamic/decode
//// import gleam/javascript/promise
////
//// // 1. Decode the glasslock server's envelope, using `registration_options_decoder()`
//// //    for the embedded `options` subtree.
//// let envelope_decoder = {
////   use session_id <- decode.field("session_id", decode.string)
////   use options <- decode.field("options", glasskey.registration_options_decoder())
////   decode.success(#(session_id, options))
//// }
////
//// // 2. Call the browser WebAuthn API with the parsed options.
//// glasskey.start_registration(options)
//// |> promise.map(fn(result) {
////   case result {
////     Ok(response_json) -> // Send response_json back to server
////     Error(e) -> // Handle error
////   }
//// })
//// ```
////
//// ### Authentication (verifying an existing credential)
////
//// Same envelope pattern, using `authentication_options_decoder()`:
////
//// ```gleam
//// glasskey.start_authentication(options)
//// |> promise.map(fn(result) {
////   case result {
////     Ok(response_json) -> // Send response_json back to server
////     Error(e) -> // Handle error
////   }
//// })
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

/// Attestation conveyance preference from the relying party.
pub type Attestation {
  /// No attestation requested.
  AttestationNone
  /// Attestation data returned directly from the authenticator.
  AttestationDirect
  /// Attestation data may be replaced by an anonymization CA.
  AttestationIndirect
  /// Enterprise attestation with device-identifying information.
  AttestationEnterprise
}

/// Raw credential returned by the browser after `navigator.credentials.get()`.
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
    user_verification: Requirement,
    allow_credentials: List(BitArray),
  )
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
  /// The user denied the request or the operation timed out.
  NotAllowed
  /// The operation was aborted.
  Aborted
  /// The relying party ID is invalid for this origin.
  SecurityError
  /// The options JSON could not be parsed or decoded.
  EncodingError(String)
  /// An unexpected error from the browser API.
  UnknownError(String)
}

/// Raw credential returned by the browser after `navigator.credentials.create()`.
pub type RegistrationCredential {
  RegistrationCredential(
    id: String,
    raw_id: BitArray,
    client_data_json: BitArray,
    attestation_object: BitArray,
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
    attestation: Attestation,
    resident_key: Requirement,
    user_verification: Requirement,
    authenticator_attachment: Option(AuthenticatorAttachment),
    exclude_credentials: List(BitArray),
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
    resident_key: String,
    user_verification: String,
    authenticator_attachment: Option(String),
  )
}

type CreateOptions {
  CreateOptions(
    challenge: BitArray,
    rp: Rp,
    user: User,
    pub_key_cred_params: array.Array(PubKeyCredParam),
    timeout: Int,
    attestation: String,
    authenticator_selection: AuthenticatorSelection,
    exclude_credentials: array.Array(CredentialDescriptor),
  )
}

type CredentialDescriptor {
  CredentialDescriptor(type_: String, id: BitArray)
}

type GetOptions {
  GetOptions(
    challenge: BitArray,
    rp_id: String,
    timeout: Int,
    user_verification: String,
    allow_credentials: array.Array(CredentialDescriptor),
  )
}

type PubKeyCredParam {
  PubKeyCredParam(type_: String, alg: Int)
}

type RawCredential

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

  get_credential(options)
  |> promise.map(
    result.map(_, fn(c) {
      encode_authentication_response(extract_authentication_fields(c))
    }),
  )
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
pub fn start_conditional_authentication(
  options: AuthenticationOptions,
) -> Result(ConditionalAuthentication, Error) {
  use <- bool.guard(when: !supports_webauthn(), return: Error(NotSupported))

  let #(raw_promise, abort) = get_conditional_credential(options)
  let result =
    raw_promise
    |> promise.map(
      result.map(_, fn(c) {
        encode_authentication_response(extract_authentication_fields(c))
      }),
    )

  Ok(ConditionalAuthentication(result:, abort:))
}

@external(javascript, "./glasskey_ffi.mjs", "getConditionalCredential")
fn do_get_conditional_credential(
  options: GetOptions,
) -> #(Promise(Result(RawCredential, Error)), fn() -> Nil)

@external(javascript, "./glasskey_ffi.mjs", "getCredential")
fn do_get_credential(
  options: GetOptions,
) -> Promise(Result(RawCredential, Error))

fn get_conditional_credential(
  options: AuthenticationOptions,
) -> #(Promise(Result(RawCredential, Error)), fn() -> Nil) {
  do_get_conditional_credential(to_get_options(options))
}

fn get_credential(
  options: AuthenticationOptions,
) -> Promise(Result(RawCredential, Error)) {
  do_get_credential(to_get_options(options))
}

fn to_get_options(options: AuthenticationOptions) -> GetOptions {
  GetOptions(
    challenge: options.challenge,
    rp_id: option.unwrap(options.rp_id, ""),
    timeout: option.unwrap(options.timeout, 0),
    user_verification: requirement_to_string(options.user_verification),
    allow_credentials: to_credential_descriptors(options.allow_credentials),
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
  let user_handle_json = case credential.user_handle {
    option.Some(handle) ->
      json.string(bit_array.base64_url_encode(handle, False))
    option.None -> json.null()
  }

  json.object([
    #("id", json.string(credential.id)),
    #(
      "rawId",
      json.string(bit_array.base64_url_encode(credential.raw_id, False)),
    ),
    #("type", json.string("public-key")),
    #(
      "response",
      json.object([
        #(
          "clientDataJSON",
          json.string(bit_array.base64_url_encode(
            credential.client_data_json,
            False,
          )),
        ),
        #(
          "authenticatorData",
          json.string(bit_array.base64_url_encode(
            credential.authenticator_data,
            False,
          )),
        ),
        #(
          "signature",
          json.string(bit_array.base64_url_encode(credential.signature, False)),
        ),
        #("userHandle", user_handle_json),
      ]),
    ),
  ])
  |> json.to_string
}

@internal
pub fn encode_registration_response(
  credential: RegistrationCredential,
) -> String {
  json.object([
    #("id", json.string(credential.id)),
    #(
      "rawId",
      json.string(bit_array.base64_url_encode(credential.raw_id, False)),
    ),
    #("type", json.string("public-key")),
    #(
      "response",
      json.object([
        #(
          "clientDataJSON",
          json.string(bit_array.base64_url_encode(
            credential.client_data_json,
            False,
          )),
        ),
        #(
          "attestationObject",
          json.string(bit_array.base64_url_encode(
            credential.attestation_object,
            False,
          )),
        ),
      ]),
    ),
  ])
  |> json.to_string
}

@external(javascript, "./glasskey_ffi.mjs", "extractAuthenticationFields")
fn extract_authentication_fields(
  credential: RawCredential,
) -> AuthenticationCredential

@external(javascript, "./glasskey_ffi.mjs", "extractRegistrationFields")
fn extract_registration_fields(
  credential: RawCredential,
) -> RegistrationCredential

/// Decoder for the `PublicKeyCredentialRequestOptionsJSON` shape produced by
/// `glasslock/authentication.generate_options`.
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
    Preferred,
    requirement_decoder(),
  )
  use allow_credentials <- decode.optional_field(
    "allowCredentials",
    [],
    credential_id_list_decoder(),
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
/// `glasslock/registration.generate_options`.
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
    decode.list(pub_key_cred_param_decoder()),
  )
  use timeout <- decode.optional_field(
    "timeout",
    option.None,
    decode.map(decode.int, option.Some),
  )
  use attestation <- decode.optional_field(
    "attestation",
    AttestationNone,
    attestation_decoder(),
  )
  use resident_key <- decode.subfield(
    ["authenticatorSelection", "residentKey"],
    requirement_decoder(),
  )
  use user_verification <- decode.subfield(
    ["authenticatorSelection", "userVerification"],
    requirement_decoder(),
  )
  use authenticator_attachment <- decode.field(
    "authenticatorSelection",
    optional_attachment_decoder(),
  )
  use exclude_credentials <- decode.optional_field(
    "excludeCredentials",
    [],
    credential_id_list_decoder(),
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
    attestation:,
    resident_key:,
    user_verification:,
    authenticator_attachment:,
    exclude_credentials:,
  ))
}

fn pub_key_cred_param_decoder() -> decode.Decoder(Algorithm) {
  use alg <- decode.field("alg", algorithm_decoder())
  decode.success(alg)
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

fn attestation_decoder() -> decode.Decoder(Attestation) {
  decode.string
  |> decode.then(fn(s) {
    case s {
      "none" -> decode.success(AttestationNone)
      "direct" -> decode.success(AttestationDirect)
      "indirect" -> decode.success(AttestationIndirect)
      "enterprise" -> decode.success(AttestationEnterprise)
      _ -> decode.failure(AttestationNone, "attestation")
    }
  })
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

fn optional_attachment_decoder() -> decode.Decoder(
  Option(AuthenticatorAttachment),
) {
  decode.optional_field(
    "authenticatorAttachment",
    option.None,
    decode.optional(authenticator_attachment_decoder()),
    decode.success,
  )
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

fn credential_id_list_decoder() -> decode.Decoder(List(BitArray)) {
  decode.list({
    use id <- decode.field("id", base64url_decoder())
    decode.success(id)
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

  create_credential(options)
  |> promise.map(
    result.map(_, fn(c) {
      encode_registration_response(extract_registration_fields(c))
    }),
  )
}

fn create_credential(
  options: RegistrationOptions,
) -> Promise(Result(RawCredential, Error)) {
  do_create_credential(CreateOptions(
    challenge: options.challenge,
    rp: Rp(id: options.rp_id, name: options.rp_name),
    user: User(
      id: options.user_id,
      name: options.user_name,
      display_name: options.user_display_name,
    ),
    pub_key_cred_params: array.from_list(
      list.map(options.algorithms, fn(alg) {
        PubKeyCredParam(type_: "public-key", alg: algorithm_to_cose(alg))
      }),
    ),
    timeout: option.unwrap(options.timeout, 0),
    attestation: attestation_to_string(options.attestation),
    authenticator_selection: AuthenticatorSelection(
      resident_key: requirement_to_string(options.resident_key),
      user_verification: requirement_to_string(options.user_verification),
      authenticator_attachment: option.map(
        options.authenticator_attachment,
        authenticator_attachment_to_string,
      ),
    ),
    exclude_credentials: to_credential_descriptors(options.exclude_credentials),
  ))
}

@external(javascript, "./glasskey_ffi.mjs", "createCredential")
fn do_create_credential(
  options: CreateOptions,
) -> Promise(Result(RawCredential, Error))

fn to_credential_descriptors(
  ids: List(BitArray),
) -> array.Array(CredentialDescriptor) {
  array.from_list(
    list.map(ids, fn(id) { CredentialDescriptor(type_: "public-key", id:) }),
  )
}

fn algorithm_to_cose(algorithm: Algorithm) -> Int {
  case algorithm {
    Es256 -> -7
    Ed25519 -> -8
    Rs256 -> -257
  }
}

fn attestation_to_string(attestation: Attestation) -> String {
  case attestation {
    AttestationNone -> "none"
    AttestationDirect -> "direct"
    AttestationIndirect -> "indirect"
    AttestationEnterprise -> "enterprise"
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
