<script>
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";

  let { data } = $props();

  function logout() {
    sessionStorage.removeItem("username");
    goto(resolve("/"));
  }
</script>

<svelte:head>
  <title>Welcome · Glasskey</title>
</svelte:head>

<h1>Welcome, {data.username}!</h1>
<p>You have successfully authenticated.</p>
<button type="button" class="button" onclick={logout}>Log out</button>
