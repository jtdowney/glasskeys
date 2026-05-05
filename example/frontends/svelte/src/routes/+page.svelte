<script>
  import { resolve } from "$app/paths";
</script>

<svelte:head>
  <title>Glasskey Demo</title>
</svelte:head>

<h1>Glasskey Demo</h1>
<p>WebAuthn passkey authentication demo.</p>
<div class="stack">
  <a class="button" href={resolve("/register")}>Register a new passkey</a>
  <a class="button" href={resolve("/login")}>Sign in with a passkey</a>
</div>
