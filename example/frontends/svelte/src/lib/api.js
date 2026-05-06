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
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error ?? `request failed: ${res.status}`);
  }
  return res.json();
}

async function completeLogin(response) {
  const { verified, username } = await postJson("/api/login/complete", {
    response,
  });
  if (!verified) {
    throw new Error("authentication not verified");
  }
  return username;
}

export async function register(username) {
  const { options } = await postJson("/api/register/begin", { username });
  const response = await startRegistration({ optionsJSON: options });
  const { verified } = await postJson("/api/register/complete", { response });
  if (!verified) {
    throw new Error("registration not verified");
  }
}

export async function login(username = "") {
  const { options } = await postJson("/api/login/begin", { username });
  const response = await startAuthentication({ optionsJSON: options });
  return completeLogin(response);
}

export async function loginWithAutofill() {
  if (!(await browserSupportsWebAuthnAutofill())) {
    return null;
  }
  const { options } = await postJson("/api/login/begin", { username: "" });
  const response = await startAuthentication({
    optionsJSON: options,
    useBrowserAutofill: true,
  });
  return completeLogin(response);
}
