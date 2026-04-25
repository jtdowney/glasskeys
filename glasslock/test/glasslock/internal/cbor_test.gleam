import glasslock/internal/cbor
import gleam/bit_array
import gleam/list
import qcheck

pub fn decode_cose_key_map_test() {
  let cose_key_bytes = <<
    // CBOR map with 5 entries: A5
    0xA5,
    // Key 1 (kty): 01 -> Value 2 (EC2): 02
    0x01, 0x02,
    // Key 3 (alg): 03 -> Value -7 (ES256): 26 (CBOR negative int -1-6 = -7)
    0x03, 0x26,
    // Key -1 (crv): 20 (CBOR negative int -1-0 = -1) -> Value 1 (P-256): 01
    0x20, 0x01,
    // Key -2 (x): 21 -> Value byte string 32 bytes: 58 20 <32 bytes>
    0x21, 0x58, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    // Key -3 (y): 22 -> Value byte string 32 bytes: 58 20 <32 bytes>
    0x22, 0x58, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
  >>
  let assert Ok(result) = cbor.decode_all(cose_key_bytes)
  let assert cbor.Map(entries) = result

  assert list.length(entries) == 5

  assert list.key_find(entries, cbor.Int(1)) == Ok(cbor.Int(2))
  assert list.key_find(entries, cbor.Int(3)) == Ok(cbor.Int(-7))
  assert list.key_find(entries, cbor.Int(-1)) == Ok(cbor.Int(1))

  let assert Ok(cbor.Bytes(_x)) = list.key_find(entries, cbor.Int(-2))
  let assert Ok(cbor.Bytes(_y)) = list.key_find(entries, cbor.Int(-3))
}

pub fn decode_partial_returns_remaining_bytes_test() {
  let trailing = <<0xFF, 0xFE>>
  let input = <<0x18, 0x2A, trailing:bits>>
  let assert Ok(#(cbor.Int(42), remaining)) = cbor.decode(input)
  assert remaining == trailing
}

pub fn decode_all_rejects_trailing_bytes_test() {
  let input = <<0x18, 0x2A, 0xFF>>
  assert cbor.decode_all(input)
    == Error("Unexpected trailing bytes after CBOR value")
}

pub fn decode_empty_input_test() {
  assert cbor.decode(<<>>) == Error("Unexpected end of CBOR input")
  assert cbor.decode_all(<<>>) == Error("Unexpected end of CBOR input")
}

pub fn decode_truncated_input_test() {
  assert cbor.decode(<<0x18>>)
    == Error("Truncated CBOR: expected 1 byte argument")
  assert cbor.decode(<<0x19, 0x01>>)
    == Error("Truncated CBOR: expected 2 byte argument")
  assert cbor.decode(<<0x43, 0x01, 0x02>>)
    == Error("Truncated CBOR byte string")
}

pub fn decode_negative_integers_test() {
  let assert Ok(cbor.Int(-1)) = cbor.decode_all(<<0x20>>)
  let assert Ok(cbor.Int(-7)) = cbor.decode_all(<<0x26>>)
  let assert Ok(cbor.Int(-24)) = cbor.decode_all(<<0x37>>)
  let assert Ok(cbor.Int(-25)) = cbor.decode_all(<<0x38, 0x18>>)
  let assert Ok(cbor.Int(-257)) = cbor.decode_all(<<0x39, 0x01, 0x00>>)
  let assert Ok(cbor.Int(-4_294_967_296)) =
    cbor.decode_all(<<0x3A, 0xFF, 0xFF, 0xFF, 0xFF>>)
  let assert Ok(cbor.Int(-4_294_967_297)) =
    cbor.decode_all(<<0x3B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00>>)
}

pub fn decode_text_string_test() {
  let assert Ok(cbor.String("none")) =
    cbor.decode_all(<<0x64, 0x6E, 0x6F, 0x6E, 0x65>>)
  let assert Ok(cbor.String("")) = cbor.decode_all(<<0x60>>)
}

pub fn decode_byte_string_test() {
  let assert Ok(cbor.Bytes(<<0x01, 0x02, 0x03>>)) =
    cbor.decode_all(<<0x43, 0x01, 0x02, 0x03>>)
  let assert Ok(cbor.Bytes(<<>>)) = cbor.decode_all(<<0x40>>)
}

pub fn decode_unsigned_integers_test() {
  let assert Ok(cbor.Int(0)) = cbor.decode_all(<<0x00>>)
  let assert Ok(cbor.Int(23)) = cbor.decode_all(<<0x17>>)
  let assert Ok(cbor.Int(24)) = cbor.decode_all(<<0x18, 0x18>>)
  let assert Ok(cbor.Int(256)) = cbor.decode_all(<<0x19, 0x01, 0x00>>)
  let assert Ok(cbor.Int(65_536)) =
    cbor.decode_all(<<0x1A, 0x00, 0x01, 0x00, 0x00>>)
  let assert Ok(cbor.Int(4_294_967_296)) =
    cbor.decode_all(<<0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00>>)
}

pub fn decode_empty_map_test() {
  let assert Ok(cbor.Map([])) = cbor.decode_all(<<0xA0>>)
}

pub fn encode_decode_round_trip_cose_key_test() {
  let cose =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let assert Ok(decoded) = cbor.decode_all(cbor.encode(cose))
  assert decoded == cose
}

pub fn encode_decode_round_trip_attestation_object_test() {
  let att_obj =
    cbor.Map([
      #(cbor.String("fmt"), cbor.String("none")),
      #(cbor.String("authData"), cbor.Bytes(<<1, 2, 3>>)),
      #(cbor.String("attStmt"), cbor.Map([])),
    ])
  let sorted =
    cbor.Map([
      #(cbor.String("fmt"), cbor.String("none")),
      #(cbor.String("attStmt"), cbor.Map([])),
      #(cbor.String("authData"), cbor.Bytes(<<1, 2, 3>>)),
    ])
  let assert Ok(decoded) = cbor.decode_all(cbor.encode(att_obj))
  assert decoded == sorted
}

pub fn encode_decode_round_trip_integers_test() {
  use n <- qcheck.given(qcheck.bounded_int(-1000, 1000))
  let value = cbor.Int(n)
  let assert Ok(decoded) = cbor.decode_all(cbor.encode(value))
  assert decoded == value
}

pub fn encode_decode_round_trip_integer_boundaries_test() {
  let boundaries = [
    0,
    23,
    24,
    255,
    256,
    65_535,
    65_536,
    4_294_967_295,
    4_294_967_296,
    -1,
    -24,
    -25,
    -256,
    -257,
    -65_536,
    -65_537,
    -4_294_967_296,
    -4_294_967_297,
  ]

  list.each(boundaries, fn(n) {
    let value = cbor.Int(n)
    let assert Ok(decoded) = cbor.decode_all(cbor.encode(value))
    assert decoded == value
  })
}

pub fn encode_decode_round_trip_bytes_test() {
  use bytes <- qcheck.given(qcheck.byte_aligned_bit_array())
  let value = cbor.Bytes(bytes)
  let assert Ok(decoded) = cbor.decode_all(cbor.encode(value))
  assert decoded == value
}

pub fn encode_decode_round_trip_strings_test() {
  use s <- qcheck.given(qcheck.string())
  let value = cbor.String(s)
  let assert Ok(decoded) = cbor.decode_all(cbor.encode(value))
  assert decoded == value
}

pub fn encode_decode_round_trip_maps_test() {
  use pairs <- qcheck.given(
    qcheck.list_from(qcheck.tuple2(qcheck.uniform_int(), qcheck.uniform_int())),
  )
  let entries =
    list.map(pairs, fn(pair) {
      let #(k, v) = pair
      #(cbor.Int(k), cbor.Int(v))
    })
  let assert Ok(decoded) = cbor.decode_all(cbor.encode(cbor.Map(entries)))
  let sorted_input =
    list.sort(entries, fn(a, b) {
      bit_array.compare(cbor.encode(a.0), cbor.encode(b.0))
    })
  assert decoded == cbor.Map(sorted_input)
}

pub fn encode_empty_map_produces_expected_bytes_test() {
  assert cbor.encode(cbor.Map([])) == <<0xA0>>
}

pub fn encode_map_sorts_keys_deterministically_test() {
  let unsorted =
    cbor.Map([
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(-1), cbor.Int(1)),
    ])
  let sorted =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
    ])
  assert cbor.encode(unsorted) == cbor.encode(sorted)
}
