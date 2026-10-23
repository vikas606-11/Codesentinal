import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    // Needed for hot reload when running inside Docker on Windows/macOS
    watch: process.env.VITE_USE_POLLING ? { usePolling: true } : undefined,
  },
});
