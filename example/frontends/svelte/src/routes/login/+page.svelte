<script>
  import { goto } from "$app/navigation";
  import { WebAuthnAbortService } from "@simplewebauthn/browser";
  import { login, loginWithAutofill } from "$lib/api.js";

  let status = $state("");
  let busy = $state(false);

  function isBenignAbort(err) {
    const name = err?.name ?? "";
    return name === "AbortError" || name === "NotAllowedError";
  }

  function finishLogin(username) {
    sessionStorage.setItem("username", username);
    goto("/welcome");
  }

  $effect(() => {
    let cancelled = false;
    (async () => {
      try {
        const who = await loginWithAutofill();
        if (cancelled || !who) return;
        finishLogin(who);
      } catch (err) {
        if (cancelled || isBenignAbort(err)) return;
        status = `Error: ${err.message ?? err}`;
      }
    })();
    return () => {
      cancelled = true;
      WebAuthnAbortService.cancelCeremony();
    };
  });

  async function handleLogin() {
    WebAuthnAbortService.cancelCeremony();
    busy = true;
    status = "Waiting for authenticator...";
    try {
      const who = await login();
      finishLogin(who);
    } catch (err) {
      status = `Error: ${err.message ?? err}`;
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>Sign In · Glasskey</title>
</svelte:head>

<h1>Sign In</h1>
<div class="stack">
  <!-- The browser attaches the WebAuthn autofill picker to this input via
       autocomplete="... webauthn"; the value is never read by our JS. -->
  <input
    type="text"
    name="username"
    placeholder="Username"
    autocomplete="username webauthn"
  />
  <button type="button" disabled={busy} onclick={handleLogin}
    >Sign in with passkey</button
  >
</div>
{#if status}
  <p class="status">{status}</p>
{/if}
<p><a href="/">Back to home</a></p>
