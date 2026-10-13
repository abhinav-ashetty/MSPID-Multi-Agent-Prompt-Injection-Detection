import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  test: {
    // The active app and its tests live under src/. A stale copied test tree
    // under frontend/frontend/... depends on an undeclared DOM test library.
    include: ['src/**/*.{test,spec}.{js,ts,jsx,tsx}'],
  },
});
