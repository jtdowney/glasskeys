//// Internal helpers for WebAuthn verification.
//// This module is not part of the public API.

import gbor.{type CBOR, CBBinary, CBInt, CBMap, CBString}
import gbor/decode as cbor_decode
import glasskeys.{
  type GlasskeysError, InvalidAttestation, InvalidSignature, ParseError,
  UnsupportedFeature, UnsupportedKey,
}
import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import kryptos/ec
import kryptos/ecdsa
import kryptos/hash

const cose_key_kty = 1

const cose_key_alg = 3

const cose_key_crv = -1

const cose_key_x = -2

const cose_key_y = -3

const cose_kty_ec2 = 2

const cose_alg_es256 = -7

const cose_crv_p256 = 1

pub type ClientData {
  ClientData(
    typ: String,
    challenge: BitArray,
    origin: String,
    cross_origin: Bool,
  )
}

pub fn parse_client_data(data: BitArray) -> Result(ClientData, GlasskeysError) {
  use json_string <- result.try(
    bit_array.to_string(data)
    |> result.replace_error(ParseError("Invalid UTF-8")),
  )

  let decoder = {
    use typ <- decode.field("type", decode.string)
    use challenge_b64 <- decode.field("challenge", decode.string)
    use origin <- decode.field("origin", decode.string)
    use cross_origin <- decode.optional_field("crossOrigin", False, decode.bool)
    decode.success(#(typ, challenge_b64, origin, cross_origin))
  }

  use #(typ, challenge_b64, origin, cross_origin) <- result.try(
    json.parse(json_string, decoder)
    |> result.replace_error(ParseError("Invalid JSON structure")),
  )

  use challenge <- result.try(
    bit_array.base64_url_decode(challenge_b64)
    |> result.replace_error(ParseError("Invalid challenge encoding")),
  )

  Ok(ClientData(
    typ: typ,
    challenge: challenge,
    origin: origin,
    cross_origin: cross_origin,
  ))
}

pub type AttestedCredential {
  AttestedCredential(
    aaguid: BitArray,
    credential_id: BitArray,
    public_key_cbor: BitArray,
  )
}

pub type AuthenticatorData {
  AuthenticatorData(
    rp_id_hash: BitArray,
    user_present: Bool,
    user_verified: Bool,
    sign_count: Int,
    attested_credential: Option(AttestedCredential),
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

fn parse_flags(flags_byte: Int) -> AuthenticatorFlags {
  AuthenticatorFlags(
    user_present: int.bitwise_and(flags_byte, 0x01) != 0,
    user_verified: int.bitwise_and(flags_byte, 0x04) != 0,
    has_attested_credential: int.bitwise_and(flags_byte, 0x40) != 0,
    has_extensions: int.bitwise_and(flags_byte, 0x80) != 0,
  )
}

fn parse_authenticator_header(
  data: BitArray,
) -> Result(#(BitArray, AuthenticatorFlags, Int, BitArray), GlasskeysError) {
  case data {
    <<
      rp_id_hash:bytes-size(32),
      flags_byte:8,
      sign_count:32-big-unsigned,
      rest:bytes,
    >> -> Ok(#(rp_id_hash, parse_flags(flags_byte), sign_count, rest))
    _ -> Error(ParseError("Authenticator data too short"))
  }
}

fn parse_attested_credential(
  data: BitArray,
) -> Result(AttestedCredential, GlasskeysError) {
  case data {
    <<aaguid:bytes-size(16), cred_id_len:16-big-unsigned, rest:bytes>> ->
      case rest {
        <<cred_id:bytes-size(cred_id_len), public_key_cbor:bytes>> ->
          Ok(AttestedCredential(
            aaguid: aaguid,
            credential_id: cred_id,
            public_key_cbor: public_key_cbor,
          ))
        _ -> Error(ParseError("Invalid attested credential data"))
      }
    _ -> Error(ParseError("Missing attested credential data"))
  }
}

pub fn parse_authenticator_data(
  data: BitArray,
) -> Result(AuthenticatorData, GlasskeysError) {
  use #(rp_id_hash, flags, sign_count, rest) <- result.try(
    parse_authenticator_header(data),
  )

  use <- bool.guard(
    when: flags.has_extensions,
    return: Error(UnsupportedFeature("extensions not supported")),
  )

  case flags.has_attested_credential {
    False -> {
      use <- bool.guard(
        when: bit_array.byte_size(rest) > 0,
        return: Error(ParseError(
          "Unexpected trailing bytes in authenticator data",
        )),
      )
      Ok(AuthenticatorData(
        rp_id_hash: rp_id_hash,
        user_present: flags.user_present,
        user_verified: flags.user_verified,
        sign_count: sign_count,
        attested_credential: None,
      ))
    }
    True -> {
      use credential <- result.try(parse_attested_credential(rest))
      Ok(AuthenticatorData(
        rp_id_hash: rp_id_hash,
        user_present: flags.user_present,
        user_verified: flags.user_verified,
        sign_count: sign_count,
        attested_credential: Some(credential),
      ))
    }
  }
}

pub fn verify_es256(
  public_key: BitArray,
  message: BitArray,
  signature: BitArray,
) -> Result(Nil, GlasskeysError) {
  let der_signature = ensure_der_signature(signature)
  use pk <- result.try(
    ec.public_key_from_raw_point(ec.P256, public_key)
    |> result.replace_error(UnsupportedKey("invalid public key point")),
  )
  case ecdsa.verify(pk, message, signature: der_signature, hash: hash.Sha256) {
    True -> Ok(Nil)
    False -> Error(InvalidSignature)
  }
}

pub fn ensure_der_signature(signature: BitArray) -> BitArray {
  case bit_array.byte_size(signature) {
    64 -> {
      let assert <<r:bytes-size(32), s:bytes-size(32)>> = signature
      encode_der_signature(r, s)
    }
    _ -> signature
  }
}

fn encode_der_signature(r: BitArray, s: BitArray) -> BitArray {
  let r_der = encode_der_integer(r)
  let s_der = encode_der_integer(s)
  let content = bit_array.concat([r_der, s_der])
  let len = bit_array.byte_size(content)
  <<0x30, len, content:bits>>
}

fn strip_leading_zeros(bytes: BitArray) -> BitArray {
  case bytes {
    <<0, 0, rest:bytes>> -> strip_leading_zeros(<<0, rest:bits>>)
    <<0, first, rest:bytes>> -> <<first, rest:bits>>
    _ -> bytes
  }
}

fn encode_der_integer(bytes: BitArray) -> BitArray {
  let trimmed = strip_leading_zeros(bytes)
  let padded = case trimmed {
    <<1:1, _:bits>> -> bit_array.concat([<<0>>, trimmed])
    _ -> trimmed
  }
  let len = bit_array.byte_size(padded)
  <<0x02, len, padded:bits>>
}

pub type CoseKey {
  EC2Key(algorithm: Int, curve: Int, x: BitArray, y: BitArray)
}

pub fn parse_public_key(cbor_bytes: BitArray) -> Result(CoseKey, GlasskeysError) {
  use cbor <- result.try(
    cbor_decode.from_bit_array(cbor_bytes)
    |> result.replace_error(ParseError("Invalid CBOR")),
  )

  parse_cose_map(cbor)
}

/// Converts a COSE EC2 key to uncompressed point format (0x04 || X || Y).
pub fn cose_to_uncompressed_point(key: CoseKey) -> BitArray {
  case key {
    EC2Key(_, _, x, y) -> bit_array.concat([<<4>>, x, y])
  }
}

fn parse_cose_map(cbor: CBOR) -> Result(CoseKey, GlasskeysError) {
  case cbor {
    CBMap(entries) -> {
      use kty <- result.try(get_cose_int_field(entries, cose_key_kty))
      use alg <- result.try(get_cose_int_field(entries, cose_key_alg))

      case kty {
        k if k == cose_kty_ec2 -> parse_ec2_key(entries, alg)
        _ ->
          Error(UnsupportedKey("unsupported key type: " <> int.to_string(kty)))
      }
    }
    _ -> Error(ParseError("COSE key must be a map"))
  }
}

fn parse_ec2_key(
  entries: List(#(CBOR, CBOR)),
  alg: Int,
) -> Result(CoseKey, GlasskeysError) {
  use crv <- result.try(get_cose_int_field(entries, cose_key_crv))
  use x <- result.try(get_cose_bytes_field(entries, cose_key_x))
  use y <- result.try(get_cose_bytes_field(entries, cose_key_y))

  use <- bool.guard(
    when: alg != cose_alg_es256,
    return: Error(UnsupportedKey(
      "unsupported algorithm: " <> int.to_string(alg),
    )),
  )

  use <- bool.guard(
    when: crv != cose_crv_p256,
    return: Error(UnsupportedKey("unsupported curve: " <> int.to_string(crv))),
  )

  let x_size = bit_array.byte_size(x)
  use <- bool.guard(
    when: x_size != 32,
    return: Error(UnsupportedKey(
      "invalid x coordinate size: expected 32, got " <> int.to_string(x_size),
    )),
  )

  let y_size = bit_array.byte_size(y)
  use <- bool.guard(
    when: y_size != 32,
    return: Error(UnsupportedKey(
      "invalid y coordinate size: expected 32, got " <> int.to_string(y_size),
    )),
  )

  Ok(EC2Key(algorithm: alg, curve: crv, x: x, y: y))
}

fn get_cose_int_field(
  entries: List(#(CBOR, CBOR)),
  key: Int,
) -> Result(Int, GlasskeysError) {
  let key_cbor = CBInt(key)

  entries
  |> list.find(fn(entry) {
    let #(k, _) = entry
    k == key_cbor
  })
  |> result.replace_error(ParseError("Missing field: " <> int.to_string(key)))
  |> result.try(fn(entry) {
    let #(_, v) = entry
    case v {
      CBInt(n) -> Ok(n)
      _ -> Error(ParseError("Field not an integer"))
    }
  })
}

fn get_cose_bytes_field(
  entries: List(#(CBOR, CBOR)),
  key: Int,
) -> Result(BitArray, GlasskeysError) {
  let key_cbor = CBInt(key)

  entries
  |> list.find(fn(entry) {
    let #(k, _) = entry
    k == key_cbor
  })
  |> result.replace_error(ParseError("Missing field: " <> int.to_string(key)))
  |> result.try(fn(entry) {
    let #(_, v) = entry
    case v {
      CBBinary(bytes) -> Ok(bytes)
      _ -> Error(ParseError("Field not bytes"))
    }
  })
}

pub fn parse_attestation_object(data: BitArray) -> Result(CBOR, GlasskeysError) {
  cbor_decode.from_bit_array(data)
  |> result.replace_error(ParseError("Invalid attestation object CBOR"))
}

pub fn extract_attestation_fields(
  cbor: CBOR,
) -> Result(#(BitArray, CBOR, String), GlasskeysError) {
  case cbor {
    CBMap(entries) -> {
      use auth_data <- result.try(get_cbor_bytes(entries, "authData"))
      use att_stmt <- result.try(get_cbor_value(entries, "attStmt"))
      use fmt <- result.try(get_cbor_string(entries, "fmt"))
      Ok(#(auth_data, att_stmt, fmt))
    }
    _ -> Error(ParseError("Attestation object must be a map"))
  }
}

fn get_cbor_bytes(
  entries: List(#(CBOR, CBOR)),
  key: String,
) -> Result(BitArray, GlasskeysError) {
  entries
  |> list.find(fn(entry) {
    let #(k, _) = entry
    k == CBString(key)
  })
  |> result.replace_error(ParseError("Missing field: " <> key))
  |> result.try(fn(entry) {
    let #(_, v) = entry
    case v {
      CBBinary(bytes) -> Ok(bytes)
      _ -> Error(ParseError("Field not bytes: " <> key))
    }
  })
}

fn get_cbor_string(
  entries: List(#(CBOR, CBOR)),
  key: String,
) -> Result(String, GlasskeysError) {
  entries
  |> list.find(fn(entry) {
    let #(k, _) = entry
    k == CBString(key)
  })
  |> result.replace_error(ParseError("Missing field: " <> key))
  |> result.try(fn(entry) {
    let #(_, v) = entry
    case v {
      CBString(s) -> Ok(s)
      _ -> Error(ParseError("Field not string: " <> key))
    }
  })
}

fn get_cbor_value(
  entries: List(#(CBOR, CBOR)),
  key: String,
) -> Result(CBOR, GlasskeysError) {
  entries
  |> list.find(fn(entry) {
    let #(k, _) = entry
    k == CBString(key)
  })
  |> result.replace_error(ParseError("Missing field: " <> key))
  |> result.map(fn(entry) {
    let #(_, v) = entry
    v
  })
}

pub fn verify_attestation(
  format: String,
  statement: CBOR,
) -> Result(Nil, GlasskeysError) {
  case format, statement {
    "none", CBMap([]) -> Ok(Nil)
    "none", _ ->
      Error(InvalidAttestation("none attestation with non-empty statement"))
    _, _ -> Error(InvalidAttestation("unsupported format: " <> format))
  }
}
