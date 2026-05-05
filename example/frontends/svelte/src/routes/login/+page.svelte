<script>
  import { goto } from "$app/navigation";
  import { WebAuthnAbortService } from "@simplewebauthn/browser";
  import { login, loginWithAutofill } from "$lib/api.js";

  let status = $state("");
  let busy = $state(false);
  let username = $state("");

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
        if (cancelled) return;
        if (err?.name === "AbortError" || err?.name === "NotAllowedError") {
          return;
        }

        status = `Error: ${err.message ?? err}`;
      }
    })();
    return () => {
      cancelled = true;
      WebAuthnAbortService.cancelCeremony();
    };
  });

  async function handleLogin(event) {
    event?.preventDefault?.();
    WebAuthnAbortService.cancelCeremony();
    busy = true;
    status = "Waiting for authenticator...";
    try {
      const who = await login(username);
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
<form class="stack" onsubmit={handleLogin}>
  <!-- The `webauthn` autocomplete token anchors the browser's passkey autofill
       picker. When autofill is dismissed, the typed value is sent to the
       backend so credentials are filtered to that user. -->
  <input
    type="text"
    name="username"
    placeholder="Username"
    autocomplete="username webauthn"
    bind:value={username}
    disabled={busy}
  />
  <button type="submit" disabled={busy}>Sign in with passkey</button>
</form>
{#if status}
  <p class="status">{status}</p>
{/if}
<p><a href="/">Back to home</a></p>
