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
