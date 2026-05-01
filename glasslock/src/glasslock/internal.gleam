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

pub type AttestedCredential {
  AttestedCredential(
    aaguid: BitArray,
    credential_id: BitArray,
    public_key_cbor: BitArray,
  )
}

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

pub type Error {
  VerificationMismatch(field: glasslock.VerificationField)
  UnsupportedKey(reason: String)
  ParseError(message: String)
  UserPresenceFailed
  UserVerificationFailed
  SignatureVerificationFailed
}

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

pub fn extract_attestation_fields(
  cbor: cbor.Cbor,
) -> Result(#(BitArray, cbor.Cbor, String), Error) {
  case cbor {
    cbor.Map(entries) -> {
      use auth_data <- result.try(get_cbor_bytes(entries, "authData"))
      use att_stmt <- result.try(find_string_entry(entries, "attStmt"))
      use fmt <- result.try(get_cbor_string(entries, "fmt"))
      Ok(#(auth_data, att_stmt, fmt))
    }
    cbor.Int(_) | cbor.Bytes(_) | cbor.String(_) ->
      Error(ParseError("Attestation object must be a map"))
  }
}

pub fn parse_attestation_object(data: BitArray) -> Result(cbor.Cbor, Error) {
  cbor.decode_all(data)
  |> result.map_error(ParseError)
}

pub fn verify_attestation(statement: cbor.Cbor) -> Result(Nil, String) {
  case statement {
    cbor.Map([]) -> Ok(Nil)
    cbor.Map(_) | cbor.Int(_) | cbor.Bytes(_) | cbor.String(_) ->
      Error("none attestation with non-empty statement")
  }
}

fn find_string_entry(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  key: String,
) -> Result(cbor.Cbor, Error) {
  list.key_find(entries, cbor.String(key))
  |> result.replace_error(ParseError("Missing field: " <> key))
}

fn get_cbor_bytes(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  key: String,
) -> Result(BitArray, Error) {
  use v <- result.try(find_string_entry(entries, key))
  case v {
    cbor.Bytes(bytes) -> Ok(bytes)
    cbor.Int(_) | cbor.String(_) | cbor.Map(_) ->
      Error(ParseError("Field not bytes: " <> key))
  }
}

fn get_cbor_string(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  key: String,
) -> Result(String, Error) {
  use v <- result.try(find_string_entry(entries, key))
  case v {
    cbor.String(s) -> Ok(s)
    cbor.Int(_) | cbor.Bytes(_) | cbor.Map(_) ->
      Error(ParseError("Field not string: " <> key))
  }
}

pub fn parse_authentication_auth_data(
  data: BitArray,
) -> Result(AuthenticationAuthData, Error) {
  use header <- result.try(parse_authenticator_header(data))

  use <- bool.guard(
    when: header.flags.has_attested_credential,
    return: Error(ParseError("AT flag should not be set in authentication")),
  )

  use <- bool.guard(
    when: !header.flags.has_extensions && bit_array.byte_size(header.rest) > 0,
    return: Error(ParseError("Unexpected trailing bytes in authenticator data")),
  )

  Ok(AuthenticationAuthData(
    rp_id_hash: header.rp_id_hash,
    user_present: header.flags.user_present,
    user_verified: header.flags.user_verified,
    sign_count: header.sign_count,
  ))
}

pub fn parse_registration_auth_data(
  data: BitArray,
) -> Result(RegistrationAuthData, Error) {
  use header <- result.try(parse_authenticator_header(data))

  use <- bool.guard(
    when: !header.flags.has_attested_credential,
    return: Error(ParseError("No attested credential in registration")),
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
) -> Result(AttestedCredential, Error) {
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
        _ -> Error(ParseError("Invalid attested credential data"))
      }
    _ -> Error(ParseError("Missing attested credential data"))
  }
}

fn parse_authenticator_header(
  data: BitArray,
) -> Result(AuthenticatorHeader, Error) {
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
    _ -> Error(ParseError("Authenticator data too short"))
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
) -> Result(BitArray, Error) {
  use #(_, remaining) <- result.try(
    cbor.decode(data)
    |> result.map_error(ParseError),
  )
  let remaining_size = bit_array.byte_size(remaining)
  case has_extensions, remaining_size {
    False, 0 -> Ok(data)
    False, _ -> Error(ParseError("Trailing bytes after COSE public key"))
    True, _ -> {
      let key_len = bit_array.byte_size(data) - remaining_size
      bit_array.slice(data, at: 0, take: key_len)
      |> result.replace_error(ParseError("Invalid attested credential data"))
    }
  }
}

pub fn decode_base64url(
  encoded: String,
  field_name: String,
) -> Result(BitArray, Error) {
  bit_array.base64_url_decode(encoded)
  |> result.replace_error(ParseError("Invalid base64url in " <> field_name))
}

pub fn decode_optional_base64url(
  value: Option(String),
  field_name: String,
) -> Result(Option(BitArray), Error) {
  case value {
    option.None -> Ok(option.None)
    option.Some(encoded) ->
      decode_base64url(encoded, field_name)
      |> result.map(option.Some)
  }
}

pub fn parse_client_data(data: BitArray) -> Result(ClientData, Error) {
  use json_string <- result.try(
    bit_array.to_string(data)
    |> result.replace_error(ParseError("Invalid UTF-8")),
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
    |> result.replace_error(ParseError("Invalid JSON structure")),
  )

  bit_array.base64_url_decode(challenge_b64)
  |> result.replace_error(ParseError("Invalid challenge encoding"))
  |> result.map(fn(challenge) {
    ClientData(type_:, challenge:, origin:, cross_origin:, top_origin:)
  })
}

pub fn parse_public_key(
  cbor_bytes: BitArray,
) -> Result(#(cose.Key, gose.DigitalSignatureAlg), Error) {
  use parsed_key <- result.try(
    cose.key_from_cbor(cbor_bytes)
    |> result.map_error(map_gose_error),
  )
  use sig_alg <- result.try(extract_signature_alg(parsed_key))
  Ok(#(parsed_key, sig_alg))
}

fn extract_signature_alg(
  key: cose.Key,
) -> Result(gose.DigitalSignatureAlg, Error) {
  case gose.alg(key) {
    Ok(gose.SigningAlg(gose.DigitalSignature(sig_alg))) -> Ok(sig_alg)
    Ok(_) -> Error(UnsupportedKey("key algorithm is not a signature algorithm"))
    Error(_) -> Error(UnsupportedKey("COSE key missing algorithm (label 3)"))
  }
}

pub fn verify_signature(
  key: cose.Key,
  alg alg: gose.DigitalSignatureAlg,
  message message: BitArray,
  signature signature: BitArray,
) -> Result(Nil, Error) {
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
    False -> Error(SignatureVerificationFailed)
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

fn map_gose_error(err: gose.GoseError) -> Error {
  case err {
    gose.ParseError(msg) -> ParseError(msg)
    gose.CryptoError(_) | gose.VerificationFailed -> SignatureVerificationFailed
    gose.InvalidState(msg) -> UnsupportedKey(msg)
  }
}

pub fn user_verification_to_string(
  verification: glasslock.UserVerification,
) -> String {
  case verification {
    glasslock.VerificationRequired -> "required"
    glasslock.VerificationPreferred -> "preferred"
    glasslock.VerificationDiscouraged -> "discouraged"
  }
}

fn user_verification_from_string(
  value: String,
) -> Result(glasslock.UserVerification, Error) {
  case value {
    "required" -> Ok(glasslock.VerificationRequired)
    "preferred" -> Ok(glasslock.VerificationPreferred)
    "discouraged" -> Ok(glasslock.VerificationDiscouraged)
    _ -> Error(ParseError("Invalid user_verification: " <> value))
  }
}

pub fn check_challenge_version(version: Int) -> Result(Nil, Error) {
  case version {
    1 -> Ok(Nil)
    _ ->
      Error(ParseError(
        "Unsupported challenge version: " <> int.to_string(version),
      ))
  }
}

pub fn check_challenge_kind(
  actual: String,
  expected: String,
) -> Result(Nil, Error) {
  case actual == expected {
    True -> Ok(Nil)
    False ->
      Error(ParseError("Expected " <> expected <> " challenge, got " <> actual))
  }
}

pub fn encode_challenge_data_fields(
  data: ChallengeData,
) -> List(#(String, json.Json)) {
  [
    #("bytes", json.string(bit_array.base64_url_encode(data.bytes, False))),
    #("rp_id", json.string(data.rp_id)),
    #("origins", json.array(set.to_list(data.origins), json.string)),
    #(
      "user_verification",
      json.string(user_verification_to_string(data.user_verification)),
    ),
    #("allow_cross_origin", json.bool(data.allow_cross_origin)),
    #("allowed_top_origins", json.array(data.allowed_top_origins, json.string)),
  ]
}

pub fn challenge_data_decoder() -> decode.Decoder(Result(ChallengeData, Error)) {
  use bytes_b64 <- decode.field("bytes", decode.string)
  use rp_id <- decode.field("rp_id", decode.string)
  use origins <- decode.field("origins", decode.list(decode.string))
  use user_verification <- decode.field("user_verification", decode.string)
  use allow_cross_origin <- decode.field("allow_cross_origin", decode.bool)
  use allowed_top_origins <- decode.field(
    "allowed_top_origins",
    decode.list(decode.string),
  )
  decode.success({
    use bytes <- result.try(decode_base64url(bytes_b64, "bytes"))
    use verification <- result.try(user_verification_from_string(
      user_verification,
    ))
    Ok(ChallengeData(
      bytes:,
      origins: set.from_list(origins),
      rp_id:,
      user_verification: verification,
      allow_cross_origin:,
      allowed_top_origins:,
    ))
  })
}

pub fn parse_challenge_shared(
  encoded: String,
  expected_kind expected_kind: String,
  rest_decoder rest_decoder: decode.Decoder(tail),
) -> Result(#(ChallengeData, tail), Error) {
  let envelope_decoder = {
    use version <- decode.field("v", decode.int)
    use kind <- decode.field("kind", decode.string)
    use data_result <- decode.then(challenge_data_decoder())
    decode.success(#(version, kind, data_result))
  }
  use #(version, kind, data_result) <- result.try(
    json.parse(encoded, envelope_decoder)
    |> result.replace_error(ParseError("Invalid challenge encoding")),
  )
  use _ <- result.try(check_challenge_version(version))
  use _ <- result.try(check_challenge_kind(kind, expected_kind))
  use data <- result.try(data_result)
  use tail <- result.try(
    json.parse(encoded, rest_decoder)
    |> result.replace_error(ParseError("Invalid challenge encoding")),
  )
  Ok(#(data, tail))
}

pub fn verify_client_data(
  client_data: ClientData,
  expected_type expected_type: String,
  expected_challenge expected_challenge: BitArray,
  expected_origins expected_origins: Set(String),
  allow_cross_origin allow_cross_origin: Bool,
  allowed_top_origins allowed_top_origins: List(String),
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: set.is_empty(expected_origins),
    return: Error(ParseError(
      "no allowed origins configured; pass a non-empty origins list to request",
    )),
  )
  use <- bool.guard(
    when: client_data.type_ != expected_type,
    return: Error(VerificationMismatch(glasslock.TypeField)),
  )
  use <- bool.guard(
    when: client_data.challenge != expected_challenge,
    return: Error(VerificationMismatch(glasslock.ChallengeField)),
  )
  use <- bool.guard(
    when: !set.contains(expected_origins, client_data.origin),
    return: Error(VerificationMismatch(glasslock.OriginField)),
  )
  use <- bool.guard(
    when: client_data.cross_origin && !allow_cross_origin,
    return: Error(VerificationMismatch(glasslock.CrossOriginField)),
  )
  use <- bool.guard(
    when: !top_origin_allowed(
      client_data.cross_origin,
      client_data.top_origin,
      allowed_top_origins,
    ),
    return: Error(VerificationMismatch(glasslock.TopOriginField)),
  )
  Ok(Nil)
}

fn top_origin_allowed(
  cross_origin: Bool,
  top_origin: Option(String),
  allowed: List(String),
) -> Bool {
  case cross_origin, top_origin {
    _, option.None -> True
    True, option.Some(top) -> list.contains(allowed, top)
    False, option.Some(_) -> False
  }
}

pub fn verify_rp_id(
  actual_hash: BitArray,
  expected_rp_id: String,
) -> Result(Nil, Error) {
  use expected_hash <- result.try(
    crypto.hash(hash.Sha256, bit_array.from_string(expected_rp_id))
    |> result.replace_error(ParseError("Failed to hash RP ID")),
  )
  use <- bool.guard(
    when: actual_hash != expected_hash,
    return: Error(VerificationMismatch(glasslock.RelyingPartyIdField)),
  )
  Ok(Nil)
}

pub fn verify_user_policies(
  user_present: Bool,
  user_verified: Bool,
  verification: glasslock.UserVerification,
) -> Result(Nil, Error) {
  use <- bool.guard(when: !user_present, return: Error(UserPresenceFailed))

  let verification_ok = case verification {
    glasslock.VerificationRequired -> user_verified
    glasslock.VerificationPreferred -> True
    glasslock.VerificationDiscouraged -> True
  }
  use <- bool.guard(
    when: !verification_ok,
    return: Error(UserVerificationFailed),
  )

  Ok(Nil)
}

pub fn maybe_add_credential_descriptors(
  fields: List(#(String, json.Json)),
  key key: String,
  credentials credentials: List(glasslock.CredentialDescriptor),
) -> List(#(String, json.Json)) {
  case credentials {
    [] -> fields
    _ -> [#(key, encode_credential_descriptors(credentials)), ..fields]
  }
}

fn encode_credential_descriptors(
  creds: List(glasslock.CredentialDescriptor),
) -> json.Json {
  json.array(creds, fn(descriptor) {
    let glasslock.CredentialDescriptor(id:, transports:) = descriptor
    let glasslock.CredentialId(raw_id) = id
    let base = [
      #("id", json.string(bit_array.base64_url_encode(raw_id, False))),
      #("type", json.string("public-key")),
    ]
    let fields = case transports {
      [] -> base
      _ -> [
        #(
          "transports",
          json.array(transports, fn(t) { json.string(transport_to_string(t)) }),
        ),
        ..base
      ]
    }
    json.object(fields)
  })
}

pub fn transport_to_string(transport: glasslock.Transport) -> String {
  case transport {
    glasslock.TransportUsb -> "usb"
    glasslock.TransportNfc -> "nfc"
    glasslock.TransportBle -> "ble"
    glasslock.TransportSmartCard -> "smart-card"
    glasslock.TransportHybrid -> "hybrid"
    glasslock.TransportInternal -> "internal"
  }
}

pub fn transport_from_string(
  value: String,
) -> Result(glasslock.Transport, Nil) {
  case value {
    "usb" -> Ok(glasslock.TransportUsb)
    "nfc" -> Ok(glasslock.TransportNfc)
    "ble" -> Ok(glasslock.TransportBle)
    "smart-card" -> Ok(glasslock.TransportSmartCard)
    "hybrid" -> Ok(glasslock.TransportHybrid)
    "internal" -> Ok(glasslock.TransportInternal)
    _ -> Error(Nil)
  }
}
