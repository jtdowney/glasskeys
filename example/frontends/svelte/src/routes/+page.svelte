<svelte:head>
  <title>Glasskey Demo</title>
</svelte:head>

<h1>Glasskey Demo</h1>
<p>WebAuthn passkey authentication demo.</p>
<div class="stack">
  <a class="button" href="/register">Register a new passkey</a>
  <a class="button" href="/login">Sign in with a passkey</a>
</div>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 0.5em;
  }

  .button {
    display: block;
    text-align: center;
    padding: 0.5em 1em;
    border: 1px solid #999;
    border-radius: 4px;
    background: #f5f5f5;
    color: inherit;
    text-decoration: none;
  }

  .button:hover {
    background: #eaeaea;
  }
</style>
