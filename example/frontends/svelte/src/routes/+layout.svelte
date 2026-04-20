<script>
  let { children } = $props();
</script>

<main>
  {@render children()}
</main>

<style>
  :global(body) {
    margin: 0;
  }

  main {
    max-width: 400px;
    margin: 2em auto;
    font-family: system-ui, sans-serif;
  }
</style>
