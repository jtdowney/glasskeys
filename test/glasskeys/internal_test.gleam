import glasskeys/internal
import gleam/bit_array
import qcheck

fn test_config() -> qcheck.Config {
  qcheck.default_config()
  |> qcheck.with_test_count(100)
}

pub fn ensure_der_signature_idempotent_test() {
  test_config()
  |> qcheck.run(qcheck.fixed_size_byte_aligned_bit_array(64), fn(raw_sig) {
    let once = internal.ensure_der_signature(raw_sig)
    let twice = internal.ensure_der_signature(once)
    assert once == twice
  })
}

pub fn raw_signature_produces_valid_der_structure_test() {
  test_config()
  |> qcheck.run(qcheck.fixed_size_byte_aligned_bit_array(64), fn(raw_sig) {
    let der = internal.ensure_der_signature(raw_sig)

    case der {
      <<0x30, len, content:bytes>> -> {
        assert bit_array.byte_size(content) == len
        let assert Ok(_) = validate_der_integers(content)
        Nil
      }
      _ -> panic as "DER signature must start with SEQUENCE tag 0x30"
    }
  })
}

pub fn high_bit_values_get_padded_test() {
  test_config()
  |> qcheck.run(
    qcheck.tuple3(
      qcheck.bounded_int(0x80, 0xFF),
      qcheck.fixed_size_byte_aligned_bit_array(31),
      qcheck.fixed_size_byte_aligned_bit_array(32),
    ),
    fn(inputs) {
      let #(r_first, r_rest, s) = inputs
      let r = bit_array.concat([<<r_first>>, r_rest])
      let raw_sig = bit_array.concat([r, s])
      let der = internal.ensure_der_signature(raw_sig)

      case der {
        <<0x30, _, 0x02, r_len, 0x00, _:bytes>> -> {
          assert r_len == 33
        }
        _ -> panic as "High-bit R value should be padded with 0x00"
      }
    },
  )
}

pub fn der_signature_passthrough_test() {
  test_config()
  |> qcheck.run(qcheck.fixed_size_byte_aligned_bit_array(70), fn(sig) {
    assert sig == internal.ensure_der_signature(sig)
  })
}

pub fn leading_zeros_stripped_test() {
  test_config()
  |> qcheck.run(
    qcheck.tuple2(
      qcheck.fixed_size_byte_aligned_bit_array(30),
      qcheck.fixed_size_byte_aligned_bit_array(32),
    ),
    fn(inputs) {
      let #(r_meaningful, s) = inputs
      let r = bit_array.concat([<<0x00, 0x01>>, r_meaningful])
      let raw_sig = bit_array.concat([r, s])
      let der = internal.ensure_der_signature(raw_sig)

      case der {
        <<0x30, _, 0x02, r_len, r_bytes:bytes-size(r_len), _:bytes>> -> {
          case r_bytes {
            <<0x00, 0x00, _:bytes>> ->
              panic as "Multiple leading zeros should be stripped"
            _ -> Nil
          }
        }
        _ -> panic as "Invalid DER structure"
      }
    },
  )
}

fn validate_der_integers(content: BitArray) -> Result(Nil, String) {
  case content {
    <<0x02, r_len, _:bytes-size(r_len), 0x02, s_len, _:bytes-size(s_len)>> ->
      Ok(Nil)
    _ -> Error("Content must contain two DER integers")
  }
}
