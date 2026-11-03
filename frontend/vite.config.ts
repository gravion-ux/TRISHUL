import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend = "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    proxy: {
      "/api": {
        target: backend,
        changeOrigin: true,
      },
      "/ws": {
        target: backend,
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
