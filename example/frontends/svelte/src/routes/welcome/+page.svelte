<script>
  import { goto } from "$app/navigation";

  let username = $state("");

  $effect(() => {
    const stored = sessionStorage.getItem("username");
    if (!stored) {
      goto("/");
      return;
    }
    username = stored;
  });

  function logout() {
    sessionStorage.removeItem("username");
    goto("/");
  }
</script>

<svelte:head>
  <title>Welcome · Glasskey</title>
</svelte:head>

{#if username}
  <h1>Welcome, {username}!</h1>
  <p>You have successfully authenticated.</p>
  <button type="button" onclick={logout}>Log out</button>
{/if}
