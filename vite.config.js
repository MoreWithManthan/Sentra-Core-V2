import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        // No rewrite — /api prefix is kept, FastAPI routes start with /api/
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    // Was 'terser', which requires installing the separate `terser` package
    // (optional since Vite 3) — it was never added as a devDependency, so
    // `npm run build` failed outright with "terser not found". Switched to
    // esbuild, Vite's built-in default minifier: verified working with zero
    // extra dependencies, and faster than terser for this project's size.
    minify: 'esbuild',
  },
});
