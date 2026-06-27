import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard is built into the Python package (src/aiaf/web) so FastAPI can
// serve it co-located with the code, both from a source checkout and when
// installed. In dev (`npm run dev`), API calls are proxied to a running server.
const API_TARGET = process.env.AIAF_API_TARGET || "http://127.0.0.1:8000";
const proxy = Object.fromEntries(
  ["/v1", "/models", "/jobs", "/health"].map((path) => [
    path,
    { target: API_TARGET, changeOrigin: true },
  ])
);

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../src/aiaf/web",
    emptyOutDir: true,
    assetsDir: "assets",
  },
  server: { proxy },
});
