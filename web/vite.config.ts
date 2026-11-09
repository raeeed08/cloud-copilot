import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build lands inside the Python package so FastAPI serves it (single container).
export default defineConfig({
  plugins: [react()],
  build: { outDir: "../src/cloud_copilot/web", emptyOutDir: true, sourcemap: false },
  server: { proxy: { "/api": "http://localhost:8000", "/healthz": "http://localhost:8000" } },
});
