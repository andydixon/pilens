import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: `PILENS_API=https://pi:8443 npm run dev` proxies the API to a running appliance.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false, chunkSizeWarningLimit: 800 },
  server: {
    proxy: { "/api": { target: process.env.PILENS_API ?? "https://127.0.0.1:8443", secure: false, changeOrigin: false } },
  },
});
