import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';

// Tauri drives this dev server; it expects a fixed port and its own error output.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  // Prevent Vite from obscuring Rust compiler errors.
  clearScreen: false,
  server: {
    // Bound to localhost only: a security tool must not expose its dev server to the LAN.
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    watch: {
      // The Rust backend has its own watcher; Vite re-bundling on Rust edits is pure waste.
      ignored: ['**/src-tauri/**'],
    },
  },
});
