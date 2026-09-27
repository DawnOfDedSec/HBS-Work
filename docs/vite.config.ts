import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { copyFileSync, existsSync, readFileSync } from 'node:fs';

/** custom domain support: public/CNAME presence switches the deploy mode. */
function customDomain(): string | null {
  try {
    const raw = readFileSync(new URL('./public/CNAME', import.meta.url), 'utf8').trim();
    return raw || null;
  } catch {
    return null;
  }
}

const DOMAIN = customDomain();

export default defineConfig({
  // custom domain (CNAME file present): root base. otherwise project path.
  base: DOMAIN ? '/' : '/HBS-Tool/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    target: 'es2020',
  },
});
