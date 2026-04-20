# glasskey

WebAuthn/FIDO2 passkey authentication for Gleam.

Two independent libraries, linked by shared JSON convention:

| Package                 | Target             | Description                       |
| ----------------------- | ------------------ | --------------------------------- |
| [glasslock](glasslock/) | Erlang / NodeJS    | Server-side WebAuthn verification |
| [glasskey](glasskey/)   | Browser JavaScript | Browser WebAuthn bindings         |

The libraries are independent at compile time, glasskey produces JSON that glasslock consumes by convention, with no shared dependency.

## Installation

```sh
# Server (Erlang target)
gleam add glasslock

# Browser (JavaScript target)
gleam add glasskey
```

## Example Apps

The `example/` directory contains a shared Wisp/Mist backend (using glasslock) and two interchangeable frontends that talk to it:

- `example/backend/` - Wisp/Mist server (port 3000) that accepts requests from either frontend.
- `example/frontends/lustre/` - Lustre using glasskey.
- `example/frontends/svelte/` - SvelteKit using `@simplewebauthn/browser`.

```sh
just example-lustre  # Run the Lustre-based demo
just example-svelte  # Run the Svelte/SimpleWebAuthn demo
```

## Supported Features

- ES256 (P-256 + SHA-256), Ed25519, and RS256 (RSA PKCS#1 v1.5 + SHA-256) signatures
- "none" attestation format
- Discoverable credentials (passkeys) and non-discoverable credentials
- User verification and user presence policies
- Sign count verification for cloned authenticator detection
- Cross-origin and top-origin verification for iframe embeds

## Development

Requires [Gleam](https://gleam.run) and [just](https://github.com/casey/just).

```sh
just build   # Build all projects
just test    # Test all projects
just fmt     # Format all projects
just deps    # Download all dependencies
```

## Resources

- [passkeys.dev](https://passkeys.dev) - developer-focused passkey documentation
- [WebAuthn Guide](https://webauthn.guide) - interactive WebAuthn explainer
- [W3C WebAuthn Spec](https://www.w3.org/TR/webauthn-2/) - full specification
