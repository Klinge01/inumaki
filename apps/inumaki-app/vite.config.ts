import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the built files from ../dist; the dev server is fixed on 5173
// because tauri.conf.json's devUrl and devCsp name it.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: { target: "safari16", sourcemap: false, cssCodeSplit: false },
});
