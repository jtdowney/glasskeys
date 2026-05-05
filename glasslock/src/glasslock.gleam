//// Server-side WebAuthn/FIDO2 credential verification for Gleam, targeting Erlang and Node.js.
////
//// Covers both registration and authentication ceremonies: generate
//// challenge options for the browser, then verify the signed responses.
////
//// Designed for use with [glasskey](https://hexdocs.pm/glasskey) on the browser side, or any
//// client that produces the same JSON format (e.g. [@simplewebauthn/browser](https://simplewebauthn.dev/docs/packages/browser)).
////
//// ## Quick Start
////
//// ### Registration (creating a new credential)
////
//// ```gleam
//// import glasslock/registration
////
//// let #(request_json, challenge) =
////   registration.new(
////     relying_party: registration.RelyingParty(id: "example.com", name: "My App"),
////     user: registration.User(id: user_id, name: username, display_name: username),
////     origin: "https://example.com",
////   )
////   |> registration.build()
////
//// // Send request_json to browser. Keep `challenge` in memory for a
//// // single-node deploy; to span processes or nodes, serialize with
//// // `registration.encode_challenge` and recover with
//// // `registration.parse_challenge`.
////
//// case registration.verify_json(response_json:, challenge:) {
////   Ok(credential) -> todo as "store credential.id, credential.public_key, sign_count"
////   Error(e) -> todo as "handle error"
//// }
//// ```
////
//// ### Authentication (verifying an existing credential)
////
//// ```gleam
//// import glasslock/authentication
////
//// let #(request_json, challenge) =
////   authentication.new(
////     relying_party_id: "example.com",
////     origin: "https://example.com",
////   )
////   |> authentication.build()
////
//// // Send request_json to browser. Keep `challenge` in memory for a
//// // single-node deploy; to span processes or nodes, serialize with
//// // `authentication.encode_challenge` and recover with
//// // `authentication.parse_challenge`.
////
//// case authentication.verify_json(response_json:, challenge:, stored: stored_credential) {
////   Ok(updated_credential) -> todo as "update stored sign_count"
////   Error(e) -> todo as "handle error"
//// }
//// ```

import gleam/result
import gose
import gose/cose

/// User verification requirement for the authenticator.
pub type UserVerification {
  /// The authenticator must verify the user (e.g., biometric or PIN).
  VerificationRequired
  /// Verification is preferred but not required.
  VerificationPreferred
  /// Verification should be skipped if possible.
  VerificationDiscouraged
}

/// A COSE-encoded public key.
///
/// Round-trip through storage with [`parse_public_key`](#parse_public_key)
/// and [`encode_public_key`](#encode_public_key).
pub opaque type PublicKey {
  PublicKey(bytes: BitArray, key: cose.Key, alg: gose.DigitalSignatureAlg)
}

/// Errors returned by [`parse_public_key`](#parse_public_key) when stored
/// bytes cannot be interpreted as a supported COSE public key.
pub type PublicKeyError {
  /// The bytes are not a valid COSE-encoded public key.
  InvalidPublicKey(reason: String)
  /// The key uses an algorithm or curve glasslock does not support.
  UnsupportedPublicKey(reason: String)
}

/// Parse stored COSE bytes into a `PublicKey`.
///
/// Validates the encoding, key type, curve, and signature algorithm. Use
/// when loading a credential from storage before passing to
/// `authentication.verify`.
pub fn parse_public_key(bytes: BitArray) -> Result(PublicKey, PublicKeyError) {
  use parsed_key <- result.try(
    cose.key_from_cbor(bytes)
    |> result.map_error(map_gose_error_to_public_key_error),
  )
  use sig_alg <- result.try(extract_signature_alg(parsed_key))
  Ok(PublicKey(bytes:, key: parsed_key, alg: sig_alg))
}

/// Serialize a `PublicKey` back to its wire-format COSE bytes.
///
/// The returned bytes round-trip through `parse_public_key`. Use when
/// persisting a credential to storage.
pub fn encode_public_key(public_key: PublicKey) -> BitArray {
  public_key.bytes
}

@internal
pub fn public_key_cose(public_key: PublicKey) -> cose.Key {
  public_key.key
}

@internal
pub fn public_key_alg(public_key: PublicKey) -> gose.DigitalSignatureAlg {
  public_key.alg
}

fn extract_signature_alg(
  key: cose.Key,
) -> Result(gose.DigitalSignatureAlg, PublicKeyError) {
  case gose.alg(key) {
    Ok(gose.SigningAlg(gose.DigitalSignature(sig_alg))) -> Ok(sig_alg)
    Ok(_) ->
      Error(UnsupportedPublicKey("key algorithm is not a signature algorithm"))
    Error(_) ->
      Error(UnsupportedPublicKey("COSE key missing algorithm (label 3)"))
  }
}

fn map_gose_error_to_public_key_error(err: gose.GoseError) -> PublicKeyError {
  case err {
    gose.ParseError(msg) -> InvalidPublicKey(msg)
    gose.CryptoError(msg) -> UnsupportedPublicKey(msg)
    gose.VerificationFailed -> InvalidPublicKey("verification failed")
    gose.InvalidState(msg) -> UnsupportedPublicKey(msg)
  }
}

/// Transport hints reported by an authenticator during registration.
///
/// Echoed back to the browser in `allow_credentials`/`exclude_credentials` so
/// it can route the request to the right authenticator. Optional for
/// correctness; helpful for UX, especially with hybrid (cross-device)
/// transports.
pub type Transport {
  /// Removable USB authenticator.
  TransportUsb
  /// Near-field communication authenticator.
  TransportNfc
  /// Bluetooth Low Energy authenticator.
  TransportBle
  /// ISO/IEC 7816 smart card with contacts.
  TransportSmartCard
  /// Cross-device authenticator (e.g. phone acting as a roaming key).
  TransportHybrid
  /// Built-in platform authenticator (Touch ID, Windows Hello, etc.).
  TransportInternal
}

/// A verified WebAuthn credential returned after successful registration or authentication.
///
/// Store the `id`, `public_key`, `sign_count`, and `transports` after
/// registration. Update `sign_count` after each successful authentication to
/// detect cloned authenticators. To use a stored credential in a subsequent
/// ceremony, pass its `id` and `transports` to
/// `registration.exclude_credential` or `authentication.allow_credential`.
pub type Credential {
  Credential(
    /// Authenticator-generated identifier.
    id: BitArray,
    /// The public key of the credential, used for verifying signatures.
    public_key: PublicKey,
    /// The number of times this credential has been used for authentication.
    sign_count: Int,
    /// The transports supported by this credential.
    transports: List(Transport),
  )
}

/// Identifies which field failed verification in a `VerificationMismatch` error.
pub type VerificationField {
  /// The `type` field in clientDataJSON (expected `"webauthn.create"` or `"webauthn.get"`).
  TypeField
  /// The `challenge` field in clientDataJSON did not match the expected challenge bytes.
  ChallengeField
  /// The `origin` field in clientDataJSON did not match the expected origin.
  OriginField
  /// The SHA-256 hash of the Relying Party ID did not match authenticator data.
  RelyingPartyIdField
  /// The `crossOrigin` field was `true` but cross-origin requests are not allowed.
  CrossOriginField
  /// The `topOrigin` field was either set without `crossOrigin: true`, or did
  /// not match any allowed top-level origin.
  TopOriginField
  /// The `rawId` in the response did not match the credential ID in authenticator data.
  CredentialIdField
  /// The top-level credential `type` field was not `"public-key"`.
  CredentialTypeField
}
