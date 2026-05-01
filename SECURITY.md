# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.y   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

To report a security vulnerability, please use [GitHub Security Advisories](https://github.com/jtdowney/glasskey/security/advisories/new).

**Please do not report security vulnerabilities through public GitHub issues.**

When reporting, include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

You can expect an initial response within 48 hours. We will work with you to understand the issue and coordinate disclosure.

## Security Model

This project consists of two independent libraries for WebAuthn/FIDO2 passkey authentication:

- **glasslock**: server-side credential verification (Erlang and Node.js targets)
- **glasskey**: browser WebAuthn API bindings (JavaScript target)

glasslock delegates cryptographic operations to [kryptos](https://github.com/jtdowney/kryptos), which wraps platform-native implementations: Erlang/OTP's `:crypto` module on BEAM, or `node:crypto` on Node.js.

glasskey runs in the browser and delegates to `navigator.credentials` (the Web Authentication API). It handles no cryptography directly.

### Sign Count Verification

After each authentication, glasslock compares the authenticator's reported sign count against the stored value. If the stored count is nonzero, the new count must be strictly greater than the stored count. A new count that is zero, less than the stored count, or equal to the stored count returns a `SignCountRegression` error, indicating a possible cloned authenticator.

## Supported Algorithms

- ES256: ECDSA with P-256 and SHA-256 (COSE algorithm -7)
- Ed25519: EdDSA with Ed25519 (COSE algorithm -8)
- RS256: RSASSA-PKCS1-v1_5 with SHA-256 (COSE algorithm -257)

## Runtime Requirements

### glasslock

On Erlang/OTP, use OTP 27 or newer with up-to-date OpenSSL/LibreSSL. On Node.js, use a currently supported LTS version. glasslock delegates cryptography to kryptos, which wraps `:crypto` on Erlang and `node:crypto` on Node.js.

### glasskey

Requires a browser with Web Authentication API support (`navigator.credentials`). All major browsers support WebAuthn. The library checks for `window.PublicKeyCredential` before attempting any ceremony and returns `NotSupported` if unavailable.
