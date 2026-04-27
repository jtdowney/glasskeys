# glasslock

[![Package Version](https://img.shields.io/hexpm/v/glasslock)](https://hex.pm/packages/glasslock)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/glasslock/)

Server-side WebAuthn/FIDO2 credential verification for Gleam, targeting Erlang and JavaScript.

Covers both registration and authentication ceremonies, generating challenge options for the browser and verifying the signed responses. Designed for use with [glasskey](https://hex.pm/packages/glasskey) on the browser side, or any client that produces the same JSON format (e.g. [@simplewebauthn/browser](https://simplewebauthn.dev/docs/packages/browser)).

## Installation

```sh
gleam add glasslock
```

## Usage

### Registration

```gleam
import glasslock/registration

// 1. Generate options to send to the browser
let assert Ok(#(options_json, challenge)) =
  registration.request(
    relying_party: registration.RelyingParty(id: "example.com", name: "My App"),
    user: registration.User(id: user_id, name: username, display_name: username),
    origins: ["https://example.com"],
    options: registration.default_options(),
  )
// Send options_json to the browser. On a single node, keep `challenge`
// in memory (e.g. an actor keyed by session id). For multi-node or
// signed-cookie storage, serialize with `registration.encode_challenge`
// (returns a JSON string) and hydrate with `registration.parse_challenge`.

// 2. Verify the browser's response
case registration.verify(response_json:, challenge:) {
  Ok(credential) -> {
    // Store credential.id, credential.public_key, and credential.sign_count
    Ok(credential)
  }
  Error(e) -> Error(e)
}
```

### Authentication

```gleam
import glasslock/authentication

// 1. Generate options to send to the browser
// (empty allow_credentials is the default — discoverable/passkey flow)
let assert Ok(#(options_json, challenge)) =
  authentication.request(
    relying_party_id: "example.com",
    origins: ["https://example.com"],
    options: authentication.default_options(),
  )
// Send options_json to the browser. On a single node, keep `challenge`
// in memory (e.g. an actor keyed by session id). For multi-node or
// signed-cookie storage, serialize with `authentication.encode_challenge`
// (returns a JSON string) and hydrate with `authentication.parse_challenge`.

// 2. Verify the browser's response
case authentication.verify(response_json:, challenge:, stored: stored_credential) {
  Ok(updated_credential) -> {
    // Update the stored sign_count to detect cloned authenticators
    Ok(updated_credential)
  }
  Error(e) -> Error(e)
}
```

### Discoverable Credentials (Passkeys)

For discoverable credentials where the user doesn't provide a username upfront, use `parse_response` to extract credential info for lookup:

```gleam
case authentication.parse_response(response_json) {
  Ok(info) -> {
    // Look up stored credential by info.credential_id or info.user_handle
    case lookup_credential(info.credential_id) {
      Ok(stored) -> authentication.verify(response_json:, challenge:, stored:)
      Error(_) -> todo as "handle lookup error"
    }
  }
  Error(_) -> todo as "handle parse error"
}
```

## Storing Credentials

Each user can register multiple passkeys. After registration, store per passkey:

| Field           | Source                                                     |
| --------------- | ---------------------------------------------------------- |
| `credential_id` | `credential.id`                                            |
| `public_key`    | `credential.public_key`                                    |
| `sign_count`    | `credential.sign_count`. Update after each authentication. |

## Supported Features

- ES256 (P-256 + SHA-256), Ed25519, and RS256 (RSA PKCS#1 v1.5 + SHA-256) signatures
- "none" attestation format
- User verification and user presence policies
- Sign count verification for cloned authenticator detection
- Cross-origin and top-origin verification for iframe embeds
- Test utilities via `glasslock/testing` for building WebAuthn test data
