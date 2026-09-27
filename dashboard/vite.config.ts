import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { "/api": "http://127.0.0.1:3000" } },
  build: {
    rollupOptions: {
      output: {
        /**
         * Route chunks do the bulk of the work (see the note in src/App.tsx).
         * These two vendor chunks exist so a change to console code does not
         * invalidate React, and so a page that draws no charts never pulls the
         * chart library in with it.
         *
         * `react`, `react-dom` and `scheduler` must land together: splitting
         * the renderer from the scheduler is a known way to get two copies of
         * React in one page.
         */
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("recharts") || id.includes("d3-") || id.includes("victory-vendor")) {
            return "vendor-charts";
          }
          if (
            id.includes("react-dom") ||
            id.includes("node_modules/react/") ||
            id.includes("scheduler")
          ) {
            return "vendor-react";
          }
          return undefined;
        },
      },
    },
  },
});
