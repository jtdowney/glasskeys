<script>
  import { register } from "$lib/api.js";

  let username = $state("");
  let status = $state("");
  let busy = $state(false);
  const canSubmit = $derived(username.trim() !== "" && !busy);

  async function handleSubmit(event) {
    event.preventDefault();
    if (!canSubmit) return;
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
<form class="stack" onsubmit={handleSubmit}>
  <input
    type="text"
    placeholder="Username"
    bind:value={username}
    disabled={busy}
  />
  <button type="submit" disabled={!canSubmit}>Register</button>
</form>
{#if status}
  <p class="status">{status}</p>
{/if}
<p><a href="/">Back to home</a></p>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 0.5em;
  }

  .status {
    color: #555;
  }
</style>
