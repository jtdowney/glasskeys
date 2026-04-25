//// Minimal CBOR codec: ints, bytes, strings, maps. Covers only the
//// subset WebAuthn attestation and COSE keys need.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result

pub type Cbor {
  Int(Int)
  Bytes(BitArray)
  String(String)
  Map(List(#(Cbor, Cbor)))
}

pub fn decode(data: BitArray) -> Result(#(Cbor, BitArray), String) {
  case data {
    <<major:3, info:5, rest:bytes>> -> {
      use #(argument, rest) <- result.try(decode_argument(info, rest))
      decode_value(major, argument, rest)
    }
    _ -> Error("Unexpected end of CBOR input")
  }
}

pub fn decode_all(data: BitArray) -> Result(Cbor, String) {
  use #(value, rest) <- result.try(decode(data))
  case rest {
    <<>> -> Ok(value)
    _ -> Error("Unexpected trailing bytes after CBOR value")
  }
}

fn decode_argument(
  info: Int,
  rest: BitArray,
) -> Result(#(Int, BitArray), String) {
  case info {
    n if n < 24 -> Ok(#(n, rest))
    24 ->
      case rest {
        <<value, remaining:bytes>> -> Ok(#(value, remaining))
        _ -> Error("Truncated CBOR: expected 1 byte argument")
      }
    25 ->
      case rest {
        <<value:16-big-unsigned, remaining:bytes>> -> Ok(#(value, remaining))
        _ -> Error("Truncated CBOR: expected 2 byte argument")
      }
    26 ->
      case rest {
        <<value:32-big-unsigned, remaining:bytes>> -> Ok(#(value, remaining))
        _ -> Error("Truncated CBOR: expected 4 byte argument")
      }
    27 ->
      case rest {
        <<value:64-big-unsigned, remaining:bytes>> -> Ok(#(value, remaining))
        _ -> Error("Truncated CBOR: expected 8 byte argument")
      }
    _ -> Error("Unsupported CBOR additional info: " <> int.to_string(info))
  }
}

fn decode_bytes(
  length: Int,
  rest: BitArray,
) -> Result(#(Cbor, BitArray), String) {
  case rest {
    <<bytes:bytes-size(length), remaining:bytes>> ->
      Ok(#(Bytes(bytes), remaining))
    _ -> Error("Truncated CBOR byte string")
  }
}

fn decode_map(count: Int, rest: BitArray) -> Result(#(Cbor, BitArray), String) {
  decode_map_entries(count, rest, [])
}

fn decode_map_entries(
  remaining: Int,
  data: BitArray,
  acc: List(#(Cbor, Cbor)),
) -> Result(#(Cbor, BitArray), String) {
  case remaining {
    0 -> Ok(#(Map(list.reverse(acc)), data))
    _ -> {
      use #(key, rest) <- result.try(decode(data))
      use #(value, rest) <- result.try(decode(rest))
      decode_map_entries(remaining - 1, rest, [#(key, value), ..acc])
    }
  }
}

fn decode_text(
  length: Int,
  rest: BitArray,
) -> Result(#(Cbor, BitArray), String) {
  case rest {
    <<bytes:bytes-size(length), remaining:bytes>> -> {
      use text <- result.try(
        bit_array.to_string(bytes)
        |> result.replace_error("Invalid UTF-8 in CBOR text string"),
      )
      Ok(#(String(text), remaining))
    }
    _ -> Error("Truncated CBOR text string")
  }
}

fn decode_value(
  major: Int,
  argument: Int,
  rest: BitArray,
) -> Result(#(Cbor, BitArray), String) {
  case major {
    0 -> Ok(#(Int(argument), rest))
    1 -> Ok(#(Int(-1 - argument), rest))
    2 -> decode_bytes(argument, rest)
    3 -> decode_text(argument, rest)
    5 -> decode_map(argument, rest)
    _ -> Error("Unsupported CBOR major type: " <> int.to_string(major))
  }
}

pub fn encode(value: Cbor) -> BitArray {
  case value {
    Int(n) if n >= 0 -> encode_head(0, n)
    Int(n) -> encode_head(1, -1 - n)
    Bytes(bytes) ->
      bit_array.concat([encode_head(2, bit_array.byte_size(bytes)), bytes])
    String(s) -> {
      let bytes = bit_array.from_string(s)
      bit_array.concat([encode_head(3, bit_array.byte_size(bytes)), bytes])
    }
    Map(entries) -> {
      let keyed = list.map(entries, fn(entry) { #(encode(entry.0), entry.1) })
      let sorted = list.sort(keyed, fn(a, b) { bit_array.compare(a.0, b.0) })
      let payload =
        list.map(sorted, fn(item) { bit_array.concat([item.0, encode(item.1)]) })
        |> bit_array.concat
      bit_array.concat([encode_head(5, list.length(entries)), payload])
    }
  }
}

fn encode_head(major: Int, value: Int) -> BitArray {
  case value {
    n if n < 24 -> <<major:3, n:5>>
    n if n < 0x100 -> <<major:3, 24:5, n:8>>
    n if n < 0x10000 -> <<major:3, 25:5, n:16>>
    n if n < 0x1_0000_0000 -> <<major:3, 26:5, n:32>>
    n -> <<major:3, 27:5, n:64>>
  }
}
