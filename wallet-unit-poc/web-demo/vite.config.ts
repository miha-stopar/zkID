import { defineConfig } from "vite";

export default defineConfig({
  // BigInt support requires ES2020+
  build: {
    target: "es2020",
  },
  optimizeDeps: {
    esbuildOptions: {
      target: "es2020",
    },
  },
  server: {
    headers: {
      // Required for WebAssembly.Module() in initSync()
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "credentialless",
    },
    // Allow serving files from parent directories (openac-sdk source)
    fs: {
      allow: [".."],
    },
  },
});
