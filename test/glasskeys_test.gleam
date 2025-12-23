import glasskeys.{VerificationRequired}
import glasskeys/authentication
import glasskeys/registration
import gleam/bit_array
import gleam/string
import gleeunit

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn registration_challenge_builder_test() {
  let #(challenge_b64, verifier) =
    registration.new()
    |> registration.origin("https://example.com")
    |> registration.rp_id("example.com")
    |> registration.user_verification(VerificationRequired)
    |> registration.build()

  assert verifier.origin == "https://example.com"
  assert bit_array.byte_size(verifier.bytes) == 32
  assert !string.is_empty(challenge_b64)
}

pub fn authentication_challenge_builder_test() {
  let cred_ids = [<<1, 2, 3>>]
  let #(_, verifier) =
    authentication.new()
    |> authentication.origin("https://example.com")
    |> authentication.rp_id("example.com")
    |> authentication.allowed_credentials(cred_ids)
    |> authentication.build()

  assert verifier.origin == "https://example.com"
  assert verifier.allowed_credentials == [<<1, 2, 3>>]
}
