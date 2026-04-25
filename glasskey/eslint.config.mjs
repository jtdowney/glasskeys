import js from "@eslint/js";
import eslintConfigPrettier from "eslint-config-prettier/flat";
import perfectionist from "eslint-plugin-perfectionist";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";

export default defineConfig([
  {
    files: ["**/*.{mjs}"],
    plugins: { js, perfectionist },
    extends: ["js/recommended"],
    languageOptions: { globals: { ...globals.browser } },
    rules: {
      "perfectionist/sort-imports": "error",
    },
  },
  eslintConfigPrettier,
  globalIgnores(["build"]),
]);
