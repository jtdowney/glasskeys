# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

glasskeys is a Gleam library for server-side verification of WebAuthn/FIDO2 credentials. It targets the Erlang VM (BEAM) and is distributed via Hex.

## Commands

```sh
gleam test              # Run all tests
gleam test -- test/glasskeys_test.gleam  # Run specific test file
gleam format src test   # Format code
gleam format --check src test  # Check formatting without changes
gleam deps download     # Download dependencies
gleam build             # Build the project
gleam run               # Run the main function
```

## Code Style

- Prefer `use` syntax over callbacks
- `let assert` is acceptable in tests and main but avoid deep in the call tree
- Test functions must end with `_test` suffix for gleeunit to discover them

## Architecture

### Module Structure

```
src/
  glasskeys.gleam              # Public types (Credential, Error, challenges, etc.)
  glasskeys/
    registration.gleam         # new(), build(), verify() for registration
    authentication.gleam       # new(), build(), verify() for authentication
    internal.gleam             # Shared parsing/crypto helpers (not public API)
  glasskeys_crypto_ffi.erl     # Erlang FFI for ECDSA verification
```

Types are in `glasskeys.gleam`. Each ceremony has its own module with builder and verify functions.

### Extension Points

**Adding algorithms:**
1. Add COSE key variant to `CoseKey` type in `internal.gleam`
2. Add case in `verify_es256` (or create new verify function) in `internal.gleam`
3. Add key parsing support in `parse_cose_map` in `internal.gleam`

**Adding attestation formats:**
1. Add case to `verify_attestation` function in `internal.gleam`

### Key Design Decisions

- **Erlang-only target**: Uses `:crypto` FFI for signature verification
- **CBOR via gbor**: Uses the `gbor` package for CBOR parsing
- **ES256 only**: Initially supports only ES256 (P-256 + SHA-256)
- **Challenge-centric API**: Pipeline builders for ergonomic challenge creation
- **Single Error type**: All errors are variants of `glasskeys.Error`
- **Ceremony modules**: `glasskeys/registration` and `glasskeys/authentication` each contain builder and verify functions
