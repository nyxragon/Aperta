import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Default Vite production build: minified, hashed filenames, code-split chunks.
// This is the "stripped bundle" Aperta must reconstruct from. We do NOT emit source maps
// (sourcemap: false is the default), mirroring a real prod SPA.
export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: false,
    rollupOptions: {
      output: {
        // keep chunk names readable-ish in the manifest but code is still minified;
        // the admin route is React.lazy()'d so it lands in its own chunk either way.
        manualChunks: undefined,
      },
    },
  },
});
