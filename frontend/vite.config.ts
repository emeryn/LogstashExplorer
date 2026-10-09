import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Everything (Monaco, workers, fonts) is bundled: no CDN, works air-gapped.
export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: false,
    assetsInlineLimit: 0, // no data: URIs -> stricter CSP (img/font from 'self' only)
    chunkSizeWarningLimit: 6000,
  },
  worker: { format: "es" },
  server: {
    proxy: { "/api": { target: "http://localhost:8000", changeOrigin: false } },
  },
});
