//// Internal helpers for WebAuthn verification.

import glasslock
import glasslock/internal/cbor
import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/set.{type Set}
import gose
import gose/cose
import kryptos/crypto
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash
import kryptos/rsa

/// Supported attestation statement formats.
pub type AttestationFormat {
  FormatNone
}

/// An attested credential from registration authenticator data.
pub type AttestedCredential {
  AttestedCredential(
    aaguid: BitArray,
    credential_id: BitArray,
    public_key_cbor: BitArray,
  )
}

/// Parsed authenticator data for an authentication ceremony.
/// No attested credential is present (AT flag must not be set).
pub type AuthenticationAuthData {
  AuthenticationAuthData(
    rp_id_hash: BitArray,
    user_present: Bool,
    user_verified: Bool,
    sign_count: Int,
  )
}

pub type ChallengeData {
  ChallengeData(
    bytes: BitArray,
    origins: Set(String),
    rp_id: String,
    user_verification: glasslock.UserVerification,
    user_presence: glasslock.UserPresence,
    allow_cross_origin: Bool,
    allowed_top_origins: List(String),
  )
}

pub type ClientData {
  ClientData(
    type_: String,
    challenge: BitArray,
    origin: String,
    cross_origin: Bool,
    top_origin: Option(String),
  )
}

/// Parsed authenticator data for a registration ceremony.
/// The attested credential is guaranteed present (enforced by the parser).
pub type RegistrationAuthData {
  RegistrationAuthData(
    rp_id_hash: BitArray,
    user_present: Bool,
    user_verified: Bool,
    sign_count: Int,
    attested_credential: AttestedCredential,
  )
}

type AuthenticatorFlags {
  AuthenticatorFlags(
    user_present: Bool,
    user_verified: Bool,
    has_attested_credential: Bool,
    has_extensions: Bool,
  )
}

type AuthenticatorHeader {
  AuthenticatorHeader(
    rp_id_hash: BitArray,
    flags: AuthenticatorFlags,
    sign_count: Int,
    rest: BitArray,
  )
}

/// Extracts authData, attStmt, and fmt fields from a parsed attestation object.
pub fn extract_attestation_fields(
  cbor: cbor.Cbor,
) -> Result(#(BitArray, cbor.Cbor, String), glasslock.Error) {
  case cbor {
    cbor.Map(entries) -> {
      use auth_data <- result.try(get_cbor_bytes(entries, "authData"))
      use att_stmt <- result.try(find_string_entry(entries, "attStmt"))
      use fmt <- result.try(get_cbor_string(entries, "fmt"))
      Ok(#(auth_data, att_stmt, fmt))
    }
    _ -> Error(glasslock.ParseError("Attestation object must be a map"))
  }
}

/// Parses a format string into an AttestationFormat enum variant.
pub fn parse_attestation_format(
  format: String,
) -> Result(AttestationFormat, glasslock.Error) {
  case format {
    "none" -> Ok(FormatNone)
    _ -> Error(glasslock.InvalidAttestation("unsupported format: " <> format))
  }
}

/// Parses a CBOR-encoded attestation object.
pub fn parse_attestation_object(
  data: BitArray,
) -> Result(cbor.Cbor, glasslock.Error) {
  cbor.decode_all(data)
}

/// Verifies an attestation statement against the expected format.
pub fn verify_attestation(
  format: AttestationFormat,
  statement: cbor.Cbor,
) -> Result(Nil, glasslock.Error) {
  case format, statement {
    FormatNone, cbor.Map([]) -> Ok(Nil)
    FormatNone, _ ->
      Error(glasslock.InvalidAttestation(
        "none attestation with non-empty statement",
      ))
  }
}

fn find_string_entry(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  key: String,
) -> Result(cbor.Cbor, glasslock.Error) {
  find_entry(entries, cbor.String(key), key)
}

fn get_cbor_bytes(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  key: String,
) -> Result(BitArray, glasslock.Error) {
  use v <- result.try(find_string_entry(entries, key))
  case v {
    cbor.Bytes(bytes) -> Ok(bytes)
    _ -> Error(glasslock.ParseError("Field not bytes: " <> key))
  }
}

fn get_cbor_string(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  key: String,
) -> Result(String, glasslock.Error) {
  use v <- result.try(find_string_entry(entries, key))
  case v {
    cbor.String(s) -> Ok(s)
    _ -> Error(glasslock.ParseError("Field not string: " <> key))
  }
}

/// Parses authenticator data for authentication, rejecting the AT flag.
pub fn parse_authentication_auth_data(
  data: BitArray,
) -> Result(AuthenticationAuthData, glasslock.Error) {
  use header <- result.try(parse_authenticator_header(data))

  use <- bool.guard(
    when: header.flags.has_attested_credential,
    return: Error(glasslock.ParseError(
      "AT flag should not be set in authentication",
    )),
  )

  use <- bool.guard(
    when: !header.flags.has_extensions && bit_array.byte_size(header.rest) > 0,
    return: Error(glasslock.ParseError(
      "Unexpected trailing bytes in authenticator data",
    )),
  )

  Ok(AuthenticationAuthData(
    rp_id_hash: header.rp_id_hash,
    user_present: header.flags.user_present,
    user_verified: header.flags.user_verified,
    sign_count: header.sign_count,
  ))
}

/// Parses authenticator data for registration, requiring the AT flag and credential.
pub fn parse_registration_auth_data(
  data: BitArray,
) -> Result(RegistrationAuthData, glasslock.Error) {
  use header <- result.try(parse_authenticator_header(data))

  use <- bool.guard(
    when: !header.flags.has_attested_credential,
    return: Error(glasslock.ParseError("No attested credential in registration")),
  )

  parse_attested_credential(header.rest, header.flags.has_extensions)
  |> result.map(fn(credential) {
    RegistrationAuthData(
      rp_id_hash: header.rp_id_hash,
      user_present: header.flags.user_present,
      user_verified: header.flags.user_verified,
      sign_count: header.sign_count,
      attested_credential: credential,
    )
  })
}

fn parse_attested_credential(
  data: BitArray,
  has_extensions: Bool,
) -> Result(AttestedCredential, glasslock.Error) {
  case data {
    <<aaguid:bytes-size(16), cred_id_len:16-big-unsigned, rest:bytes>> ->
      case rest {
        <<cred_id:bytes-size(cred_id_len), key_and_rest:bytes>> -> {
          use public_key_cbor <- result.try(split_cose_key(
            key_and_rest,
            has_extensions,
          ))
          Ok(AttestedCredential(
            aaguid:,
            credential_id: cred_id,
            public_key_cbor:,
          ))
        }
        _ -> Error(glasslock.ParseError("Invalid attested credential data"))
      }
    _ -> Error(glasslock.ParseError("Missing attested credential data"))
  }
}

fn parse_authenticator_header(
  data: BitArray,
) -> Result(AuthenticatorHeader, glasslock.Error) {
  case data {
    <<
      rp_id_hash:bytes-size(32),
      flags_byte:8,
      sign_count:32-big-unsigned,
      rest:bytes,
    >> ->
      Ok(AuthenticatorHeader(
        rp_id_hash:,
        flags: parse_flags(flags_byte),
        sign_count:,
        rest:,
      ))
    _ -> Error(glasslock.ParseError("Authenticator data too short"))
  }
}

fn parse_flags(flags_byte: Int) -> AuthenticatorFlags {
  AuthenticatorFlags(
    user_present: int.bitwise_and(flags_byte, 0x01) != 0,
    user_verified: int.bitwise_and(flags_byte, 0x04) != 0,
    has_attested_credential: int.bitwise_and(flags_byte, 0x40) != 0,
    has_extensions: int.bitwise_and(flags_byte, 0x80) != 0,
  )
}

fn split_cose_key(
  data: BitArray,
  has_extensions: Bool,
) -> Result(BitArray, glasslock.Error) {
  case has_extensions {
    False -> Ok(data)
    True -> {
      use #(_, remaining) <- result.try(cbor.decode(data))
      let key_len = bit_array.byte_size(data) - bit_array.byte_size(remaining)
      case data {
        <<key_bytes:bytes-size(key_len), _:bytes>> -> Ok(key_bytes)
        _ -> Error(glasslock.ParseError("Invalid attested credential data"))
      }
    }
  }
}

/// Decodes a base64url-encoded string, returning a descriptive ParseError on failure.
pub fn decode_base64url(
  encoded: String,
  field_name: String,
) -> Result(BitArray, glasslock.Error) {
  bit_array.base64_url_decode(encoded)
  |> result.replace_error(glasslock.ParseError(
    "Invalid base64url in " <> field_name,
  ))
}

/// Decodes an optional base64url-encoded string.
pub fn decode_optional_base64url(
  value: Option(String),
  field_name: String,
) -> Result(Option(BitArray), glasslock.Error) {
  case value {
    option.None -> Ok(option.None)
    option.Some(encoded) ->
      decode_base64url(encoded, field_name)
      |> result.map(option.Some)
  }
}

pub fn parse_client_data(data: BitArray) -> Result(ClientData, glasslock.Error) {
  use json_string <- result.try(
    bit_array.to_string(data)
    |> result.replace_error(glasslock.ParseError("Invalid UTF-8")),
  )

  let decoder = {
    use type_ <- decode.field("type", decode.string)
    use challenge_b64 <- decode.field("challenge", decode.string)
    use origin <- decode.field("origin", decode.string)
    use cross_origin <- decode.optional_field("crossOrigin", False, decode.bool)
    use top_origin <- decode.optional_field(
      "topOrigin",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(#(type_, challenge_b64, origin, cross_origin, top_origin))
  }

  use #(type_, challenge_b64, origin, cross_origin, top_origin) <- result.try(
    json.parse(json_string, decoder)
    |> result.replace_error(glasslock.ParseError("Invalid JSON structure")),
  )

  bit_array.base64_url_decode(challenge_b64)
  |> result.replace_error(glasslock.ParseError("Invalid challenge encoding"))
  |> result.map(fn(challenge) {
    ClientData(type_:, challenge:, origin:, cross_origin:, top_origin:)
  })
}

fn find_entry(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  key_cbor: cbor.Cbor,
  key_name: String,
) -> Result(cbor.Cbor, glasslock.Error) {
  list.key_find(entries, key_cbor)
  |> result.replace_error(glasslock.ParseError("Missing field: " <> key_name))
}

/// Parses a CBOR-encoded COSE public key using gose.
pub fn parse_public_key(
  cbor_bytes: BitArray,
) -> Result(#(cose.Key, gose.DigitalSignatureAlg), glasslock.Error) {
  use parsed_key <- result.try(
    cose.key_from_cbor(cbor_bytes)
    |> result.map_error(map_gose_error),
  )
  use sig_alg <- result.try(extract_signature_alg(parsed_key))
  Ok(#(parsed_key, sig_alg))
}

fn extract_signature_alg(
  key: cose.Key,
) -> Result(gose.DigitalSignatureAlg, glasslock.Error) {
  case gose.alg(key) {
    Ok(gose.SigningAlg(gose.DigitalSignature(sig_alg))) -> Ok(sig_alg)
    Ok(_) ->
      Error(glasslock.UnsupportedKey(
        "key algorithm is not a signature algorithm",
      ))
    Error(_) ->
      Error(glasslock.UnsupportedKey("COSE key missing algorithm (label 3)"))
  }
}

/// Verifies a signature over `message` using the COSE key and algorithm.
///
/// Uses `gose` only for CBOR to SPKI DER conversion, then hands off to
/// `kryptos` for the actual verify. Expects WebAuthn wire-format
/// signatures: ECDSA as ASN.1 DER, Ed25519 as raw, RSA as raw PKCS#1
/// v1.5 or PSS bytes.
pub fn verify_signature(
  key key: cose.Key,
  alg alg: gose.DigitalSignatureAlg,
  message message: BitArray,
  signature signature: BitArray,
) -> Result(Nil, glasslock.Error) {
  use public_portion <- result.try(
    gose.public_key(key)
    |> result.map_error(map_gose_error),
  )
  use public_key_der <- result.try(
    gose.to_der(public_portion)
    |> result.map_error(map_gose_error),
  )
  let valid = case alg {
    gose.Ecdsa(ecdsa_alg) ->
      verify_ecdsa(public_key_der, message, signature, ecdsa_alg)
    gose.Eddsa -> verify_eddsa(public_key_der, message, signature)
    gose.RsaPkcs1(rsa_alg) ->
      verify_rsa(
        public_key_der,
        message,
        signature,
        rsa_pkcs1_hash(rsa_alg),
        rsa.Pkcs1v15,
      )
    gose.RsaPss(rsa_alg) ->
      verify_rsa(
        public_key_der,
        message,
        signature,
        rsa_pss_hash(rsa_alg),
        rsa.Pss(rsa.SaltLengthHashLen),
      )
  }
  case valid {
    True -> Ok(Nil)
    False -> Error(glasslock.InvalidSignature)
  }
}

fn verify_ecdsa(
  public_key_der: BitArray,
  message: BitArray,
  signature: BitArray,
  alg: gose.EcdsaAlg,
) -> Bool {
  case ec.public_key_from_der(public_key_der) {
    Ok(public) -> ecdsa.verify(public, message, signature, ecdsa_hash(alg))
    Error(_) -> False
  }
}

fn verify_eddsa(
  public_key_der: BitArray,
  message: BitArray,
  signature: BitArray,
) -> Bool {
  case eddsa.public_key_from_der(public_key_der) {
    Ok(public) -> eddsa.verify(public, message, signature)
    Error(_) -> False
  }
}

fn verify_rsa(
  public_key_der: BitArray,
  message: BitArray,
  signature: BitArray,
  hash_alg: hash.HashAlgorithm,
  padding: rsa.SignPadding,
) -> Bool {
  case rsa.public_key_from_der(public_key_der, rsa.Spki) {
    Ok(public) -> rsa.verify(public, message, signature, hash_alg, padding)
    Error(_) -> False
  }
}

fn ecdsa_hash(alg: gose.EcdsaAlg) -> hash.HashAlgorithm {
  case alg {
    gose.EcdsaP256 -> hash.Sha256
    gose.EcdsaP384 -> hash.Sha384
    gose.EcdsaP521 -> hash.Sha512
    gose.EcdsaSecp256k1 -> hash.Sha256
  }
}

fn rsa_pkcs1_hash(alg: gose.RsaPkcs1Alg) -> hash.HashAlgorithm {
  case alg {
    gose.RsaPkcs1Sha256 -> hash.Sha256
    gose.RsaPkcs1Sha384 -> hash.Sha384
    gose.RsaPkcs1Sha512 -> hash.Sha512
  }
}

fn rsa_pss_hash(alg: gose.RsaPssAlg) -> hash.HashAlgorithm {
  case alg {
    gose.RsaPssSha256 -> hash.Sha256
    gose.RsaPssSha384 -> hash.Sha384
    gose.RsaPssSha512 -> hash.Sha512
  }
}

fn map_gose_error(err: gose.GoseError) -> glasslock.Error {
  case err {
    gose.ParseError(msg) -> glasslock.ParseError(msg)
    gose.CryptoError(_) | gose.VerificationFailed -> glasslock.InvalidSignature
    gose.InvalidState(msg) -> glasslock.UnsupportedKey(msg)
  }
}

/// Converts a UserVerification enum to its WebAuthn string representation.
pub fn user_verification_to_string(
  verification: glasslock.UserVerification,
) -> String {
  case verification {
    glasslock.VerificationRequired -> "required"
    glasslock.VerificationPreferred -> "preferred"
    glasslock.VerificationDiscouraged -> "discouraged"
  }
}

/// Validates client data fields against expected ceremony values.
///
/// `expected_origins` is an allow-list: the authenticator-signed
/// `clientDataJSON.origin` must match one of the provided origins.
pub fn verify_client_data(
  client_data client_data: ClientData,
  expected_type expected_type: String,
  expected_challenge expected_challenge: BitArray,
  expected_origins expected_origins: Set(String),
  allow_cross_origin allow_cross_origin: Bool,
  allowed_top_origins allowed_top_origins: List(String),
) -> Result(Nil, glasslock.Error) {
  use <- bool.guard(
    when: client_data.type_ != expected_type,
    return: Error(glasslock.VerificationMismatch(glasslock.TypeField)),
  )
  use <- bool.guard(
    when: client_data.challenge != expected_challenge,
    return: Error(glasslock.VerificationMismatch(glasslock.ChallengeField)),
  )
  use <- bool.guard(
    when: !set.contains(expected_origins, client_data.origin),
    return: Error(glasslock.VerificationMismatch(glasslock.OriginField)),
  )
  use <- bool.guard(
    when: client_data.cross_origin && !allow_cross_origin,
    return: Error(glasslock.VerificationMismatch(glasslock.CrossOriginField)),
  )
  use <- bool.guard(
    when: client_data.cross_origin
      && !top_origin_allowed(client_data.top_origin, allowed_top_origins),
    return: Error(glasslock.VerificationMismatch(glasslock.TopOriginField)),
  )
  Ok(Nil)
}

fn top_origin_allowed(top_origin: Option(String), allowed: List(String)) -> Bool {
  case top_origin {
    option.Some(top) -> list.contains(allowed, top)
    option.None -> list.is_empty(allowed)
  }
}

/// Verifies the RP ID hash matches the expected RP ID.
pub fn verify_rp_id(
  actual_hash: BitArray,
  expected_rp_id: String,
) -> Result(Nil, glasslock.Error) {
  use expected_hash <- result.try(
    crypto.hash(hash.Sha256, bit_array.from_string(expected_rp_id))
    |> result.replace_error(glasslock.ParseError("Failed to hash RP ID")),
  )
  use <- bool.guard(
    when: actual_hash != expected_hash,
    return: Error(glasslock.VerificationMismatch(glasslock.RpIdField)),
  )
  Ok(Nil)
}

/// Verifies user presence and verification policies.
pub fn verify_user_policies(
  user_present: Bool,
  user_verified: Bool,
  presence: glasslock.UserPresence,
  verification: glasslock.UserVerification,
) -> Result(Nil, glasslock.Error) {
  let verification_ok = case verification {
    glasslock.VerificationRequired -> user_verified
    glasslock.VerificationPreferred -> True
    glasslock.VerificationDiscouraged -> True
  }
  use <- bool.guard(
    when: !verification_ok,
    return: Error(glasslock.UserVerificationFailed),
  )

  let presence_ok = case presence {
    glasslock.PresenceRequired -> user_present
    glasslock.PresencePreferred -> True
    glasslock.PresenceDiscouraged -> True
  }
  use <- bool.guard(
    when: !presence_ok,
    return: Error(glasslock.UserPresenceFailed),
  )

  Ok(Nil)
}

pub fn maybe_add_credential_descriptors(
  fields: List(#(String, json.Json)),
  key key: String,
  credentials credentials: List(glasslock.CredentialId),
) -> List(#(String, json.Json)) {
  case credentials {
    [] -> fields
    _ -> [#(key, encode_credential_descriptors(credentials)), ..fields]
  }
}

fn encode_credential_descriptors(
  creds: List(glasslock.CredentialId),
) -> json.Json {
  json.array(creds, fn(cred_id) {
    let glasslock.CredentialId(raw_id) = cred_id
    json.object([
      #("id", json.string(bit_array.base64_url_encode(raw_id, False))),
      #("type", json.string("public-key")),
    ])
  })
}
