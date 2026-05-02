# Example apps

Demo of `glasslock` (server) and `glasskey` (browser), plus a sibling Svelte frontend using `@simplewebauthn/browser` to show the backend speaks the same JSON shape as SimpleWebAuthn. The shared backend serves both frontends.

| Path                | Purpose                                                   |
| ------------------- | --------------------------------------------------------- |
| `backend/`          | Wisp/Mist server using `glasslock` (port 3000)            |
| `frontends/lustre/` | Lustre SPA using `glasskey` (port 1234)                   |
| `frontends/svelte/` | SvelteKit SPA using `@simplewebauthn/browser` (port 5173) |

## Run

From the repo root:

```sh
just example-lustre  # backend + Lustre frontend
just example-svelte  # backend + Svelte frontend
```

Each frontend's dev server proxies `/api` to `localhost:3000`, so there is no browser-side CORS in dev.

## Manual smoke test

After starting either example, walk both ceremonies end-to-end:

1. Open the frontend (`http://localhost:1234` for Lustre, `http://localhost:5173` for Svelte).
2. Click **Register**, enter a username, and complete the authenticator prompt (Touch ID, Windows Hello, a security key, or a virtual authenticator).
3. Confirm the welcome page shows for the new username.
4. Reload to land back on the home page, then click **Sign in** and complete the authenticator prompt again.
5. Confirm the welcome page renders for the same username.

If your machine has no built-in authenticator, enable one in Chrome DevTools: open **More tools → WebAuthn**, click **Enable**, then **Add authenticator** with **Resident keys** and **User verification** turned on.

## Configuration

The backend reads these environment variables, falling back to demo defaults:

| Variable     | Default                                       | Notes                                                              |
| ------------ | --------------------------------------------- | ------------------------------------------------------------------ |
| `RP_ID`      | `localhost`                                   | WebAuthn relying party ID (host, no scheme or port)                |
| `RP_NAME`    | `Glasslock Example`                           | Human-readable RP name shown by the authenticator                  |
| `ORIGINS`    | `http://localhost:1234,http://localhost:5173` | Comma-separated allow-list matched against `clientDataJSON.origin` |
| `SECRET_KEY` | random 64-char string per process start       | Used to sign the registration/authentication cookies               |

## API contract

The backend exposes four endpoints under `/api`:

| Endpoint                      | Request body                                                   | Response body                                           |
| ----------------------------- | -------------------------------------------------------------- | ------------------------------------------------------- |
| `POST /api/register/begin`    | `{"username": "<name>"}`                                       | `{"options": <PublicKeyCredentialCreationOptionsJSON>}` |
| `POST /api/register/complete` | `{"response": <PublicKeyCredentialJSON>}`                      | `{"verified": true}`                                    |
| `POST /api/login/begin`       | `{"username": "<name>"}` (omit or empty for discoverable flow) | `{"options": <PublicKeyCredentialRequestOptionsJSON>}`  |
| `POST /api/login/complete`    | `{"response": <PublicKeyCredentialJSON>}`                      | `{"verified": true, "username": "<name>"}`              |

The `response` field on the `*/complete` endpoints is the WebAuthn response object as returned by `navigator.credentials.create` / `.get` (already in the shape produced by `PublicKeyCredential.toJSON()`). The backend uses `glasslock`'s `response_decoder()` to extract it from the envelope and pass straight to `verify` — no re-serialization. Both frontends post it as a nested object: see `frontends/svelte/src/lib/api.js` and `frontends/lustre/src/frontend/api.gleam`.

## Production caveats

These apps are intentionally simple. Before adapting any of this for production, account for the following.

- HTTPS and a real RP ID. Browsers only allow WebAuthn over HTTPS or `localhost`. Set `RP_ID` to your registrable domain (e.g. `auth.example.com`) and put HTTPS origins in `ORIGINS`.
- Stable secret key. The default regenerates `SECRET_KEY` on every process start, which invalidates every in-flight session on restart and across replicas. Always set `SECRET_KEY` to a long, random value held in your secret store.
- Durable storage. `backend/credentials.gleam` is a `trove`-backed file store intended for the demo. Replace it with a real database, including unique constraints on credential ID and user ID, plus the appropriate indexes for credential lookup.
- Account creation safety. Username uniqueness is checked again at save time, but there is no reservation between begin and complete and no rate limiting. Production registration flows should reserve the username (or fail at commit under a uniqueness constraint), enforce per-IP and per-account rate limits, and consider email/phone verification.
- CSRF and session design. The demo treats the WebAuthn ceremony cookies as the only session state. A real app needs explicit session tokens, CSRF protection on state-changing endpoints, and a logout flow.
