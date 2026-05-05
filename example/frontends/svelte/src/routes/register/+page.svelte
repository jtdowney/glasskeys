<script>
  import { resolve } from "$app/paths";
  import { register } from "$lib/api.js";

  let username = $state("");
  let status = $state("");
  let busy = $state(false);
  const canSubmit = $derived(username.trim() !== "" && !busy);

  async function handleRegister() {
    if (!canSubmit) {
      return;
    }
    busy = true;
    status = "Starting registration...";
    try {
      await register(username.trim());
      status = "Registration successful!";
      username = "";
    } catch (err) {
      status = `Error: ${err.message ?? err}`;
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>Register · Glasskey</title>
</svelte:head>

<h1>Register</h1>
<div class="stack">
  <input
    type="text"
    placeholder="Username"
    bind:value={username}
    disabled={busy}
  />
  <button type="button" disabled={!canSubmit} onclick={handleRegister}
    >Register</button
  >
</div>
{#if status}
  <p class="status">{status}</p>
{/if}
<p><a href={resolve("/")}>Back to home</a></p>
