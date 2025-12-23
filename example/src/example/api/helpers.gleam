import glasskeys
import gleam/bit_array
import gleam/crypto
import gleam/json
import gleam/string
import wisp.{type Response}

pub fn generate_session_id() -> String {
  crypto.strong_random_bytes(32)
  |> bit_array.base64_url_encode(False)
}

pub fn json_error(message: String, status: Int) -> Response {
  let body = json.object([#("error", json.string(message))])
  wisp.json_response(json.to_string_tree(body), status)
}

pub fn error_to_string(error: glasskeys.GlasskeysError) -> String {
  case error {
    glasskeys.CredentialNotAllowed -> "Credential not recognized"
    glasskeys.InvalidAttestation(reason) -> "Invalid attestation: " <> reason
    glasskeys.InvalidSignature -> "Signature verification failed"
    glasskeys.ParseError(msg) -> "Parse error: " <> msg
    glasskeys.SignCountRegression -> "Possible cloned authenticator detected"
    glasskeys.UnsupportedFeature(reason) -> "Unsupported feature: " <> reason
    glasskeys.UnsupportedKey(reason) -> "Unsupported key: " <> reason
    glasskeys.UserPresenceFailed -> "User presence check failed"
    glasskeys.UserVerificationFailed -> "User verification failed"
    glasskeys.VerificationMismatch(field) ->
      "Verification failed: " <> field <> " mismatch"
  }
}

pub fn validate_username(username: String) -> Result(String, Nil) {
  case
    string.contains(username, "..")
    || string.contains(username, "/")
    || string.contains(username, "\\")
    || string.is_empty(username)
  {
    True -> Error(Nil)
    False -> Ok(username)
  }
}
