import {
  browserSupportsWebAuthnAutofill,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

async function postJson(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error ?? `request failed: ${res.status}`);
  }
  return data;
}

async function completeLogin(sessionId, response) {
  const { verified, username } = await postJson("/api/login/complete", {
    session_id: sessionId,
    response: JSON.stringify(response),
  });
  if (!verified) throw new Error("authentication not verified");
  return username;
}

export async function register(username) {
  const { session_id, options } = await postJson("/api/register/begin", {
    username,
  });
  const response = await startRegistration({ optionsJSON: options });
  const { verified } = await postJson("/api/register/complete", {
    session_id,
    response: JSON.stringify(response),
  });
  if (!verified) throw new Error("registration not verified");
}

export async function login() {
  const { session_id, options } = await postJson("/api/login/begin", {});
  const response = await startAuthentication({ optionsJSON: options });
  return completeLogin(session_id, response);
}

export async function loginWithAutofill() {
  if (!(await browserSupportsWebAuthnAutofill())) return null;
  const { session_id, options } = await postJson("/api/login/begin", {});
  const response = await startAuthentication({
    optionsJSON: options,
    useBrowserAutofill: true,
  });
  return completeLogin(session_id, response);
}
