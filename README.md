# glasskeys

[![Package Version](https://img.shields.io/hexpm/v/glasskeys)](https://hex.pm/packages/glasskeys)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/glasskeys/)

A Gleam library for server-side verification of WebAuthn/FIDO2 credentials. Implement passwordless authentication using passkeys and security keys.

## Installation

```sh
gleam add glasskeys
```

## Quick Start

### Registration (creating a new credential)

```gleam
import glasskeys
import glasskeys/registration

pub fn handle_registration_start() {
  // 1. Build a challenge
  let #(challenge_b64, verifier) =
    registration.new()
    |> registration.origin("https://example.com")
    |> registration.rp_id("example.com")
    |> registration.build()

  // 2. Send challenge_b64 to browser as part of PublicKeyCredentialCreationOptions
  //    Store verifier in session for verification step
  #(challenge_b64, verifier)
}

pub fn handle_registration_finish(
  attestation_object: BitArray,
  client_data_json: BitArray,
  verifier: registration.Challenge,
) {
  // 3. Verify the browser's response
  case
    registration.verify(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      challenge: verifier,
    )
  {
    Ok(credential) -> {
      // Store the credential for future authentication:
      //   - credential.id (unique identifier)
      //   - credential.public_key (for signature verification)
      //   - credential.sign_count (for clone detection)
      Ok(credential)
    }
    Error(e) -> Error(e)
  }
}
```

### Authentication (verifying an existing credential)

```gleam
import glasskeys
import glasskeys/authentication

pub fn handle_authentication_start(stored_credential_ids: List(BitArray)) {
  // 1. Build a challenge
  let #(challenge_b64, verifier) =
    authentication.new()
    |> authentication.origin("https://example.com")
    |> authentication.rp_id("example.com")
    |> authentication.allowed_credentials(stored_credential_ids)
    |> authentication.build()

  // 2. Send challenge_b64 to browser as part of PublicKeyCredentialRequestOptions
  //    Store verifier in session for verification step
  #(challenge_b64, verifier)
}

pub fn handle_authentication_finish(
  authenticator_data: BitArray,
  client_data_json: BitArray,
  signature: BitArray,
  credential_id: BitArray,
  verifier: authentication.Challenge,
  stored_credential: glasskeys.Credential,
) {
  // 3. Verify the browser's response
  case
    authentication.verify(
      authenticator_data: authenticator_data,
      client_data_json: client_data_json,
      signature: signature,
      credential_id: credential_id,
      challenge: verifier,
      stored: stored_credential,
    )
  {
    Ok(updated_credential) -> {
      // Update the stored sign_count to detect cloned authenticators
      Ok(updated_credential)
    }
    Error(e) -> Error(e)
  }
}
```

## Data Modeling

It is recommended to have a one-to-many relationship between users and passkeys. Each user should be able to register multiple passkeys:

**Why multiple passkeys per user?**

- **Multiple devices**: Users authenticate from phones, laptops, tablets, and security keys
- **Redundancy**: If a device is lost or broken, other passkeys still work
- **Gradual migration**: Users can add new devices before retiring old ones

**What to store for each passkey:**

| Field           | Purpose                                       | Where it comes from                                                                                                                                                                                                                                           |
| --------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `credential_id` | Unique identifier                             | Backend generates with a strong random number generator like ([gleam/crypto](https://hexdocs.pm/gleam_crypto/gleam/crypto.html#strong_random_bytes) or [kryptos](https://hexdocs.pm/kryptos/kryptos/crypto.html#random_bytes) secure random number generator) |
| `public_key`    | For signature verification                    | Browser sends it at registration on the credential object                                                                                                                                                                                                     |
| `sign_count`    | Detect cloned authenticators                  | Backend keeps track of                                                                                                                                                                                                                                        |
| `friendly_name` | User-provided label ("Work laptop", "iPhone") | User/Browser provide at registration via a form input field                                                                                                                                                                                                   |
| `created_at`    | Audit trail                                   | Backend keeps track of                                                                                                                                                                                                                                        |
| `last_used_at`  | Help users identify stale passkeys            | Backend keeps track of                                                                                                                                                                                                                                        |

## Account Recovery

Passkeys eliminate passwords but not the need for account recovery. **Always provide an escape hatch** for users who lose access to all their passkeys similar to what would happen for forgotten passwords.

**Recommended strategies:**

- **Multiple passkeys**: Encourage users to register passkeys on at least two devices
- **Recovery codes**: Generate one-time backup codes at registration (like 2FA recovery codes)
- **Email recovery**: Send a time-limited recovery link to a verified email
- **Support-assisted recovery**: Manual identity verification for high-value accounts

**Avoid:**

- Single-passkey accounts with no recovery path
- Assuming passkey sync will always work (it won't for security keys or cross-platform scenarios)

## Resources

Learn more about passkeys and WebAuthn:

- [passkeys.dev](https://passkeys.dev) — Developer-focused passkey documentation
- [WebAuthn Guide](https://webauthn.guide) — Interactive WebAuthn explainer
- [FIDO Alliance](https://fidoalliance.org/passkeys/) — Official passkey standards body
- [W3C WebAuthn Spec](https://www.w3.org/TR/webauthn-2/) — Full specification
