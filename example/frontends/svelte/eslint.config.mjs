import js from "@eslint/js";
import eslintConfigPrettier from "eslint-config-prettier/flat";
import svelte from "eslint-plugin-svelte";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,svelte}"],
    plugins: { js },
    extends: ["js/recommended"],
    languageOptions: { globals: { ...globals.browser } },
  },
  ...svelte.configs.recommended,
  eslintConfigPrettier,
  {
    files: ["**/*.{js,mjs,svelte}"],
    rules: {
      curly: ["error", "all"],
    },
  },
  globalIgnores(["build", ".svelte-kit"]),
]);
