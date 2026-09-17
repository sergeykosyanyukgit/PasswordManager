import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';
import { CONTENT_SECURITY_POLICY } from './src/shared/content-security-policy.ts';

export default defineConfig({
  root: 'src/renderer',
  base: './',
  plugins: [vue(), {
    name: 'packaged-content-security-policy',
    transformIndexHtml: () => [{
      tag: 'meta',
      attrs: { 'http-equiv': 'Content-Security-Policy', content: CONTENT_SECURITY_POLICY },
      injectTo: 'head-prepend'
    }]
  }],
  define: {
    'import.meta.env.PM_SCREENSHOT_DIAGNOSTICS': JSON.stringify(process.env.PM_SCREENSHOT_DIAGNOSTICS === '1')
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src/renderer/src', import.meta.url)),
      '@shared': fileURLToPath(new URL('./src/shared', import.meta.url))
    }
  },
  build: {
    outDir: '../../dist/renderer',
    emptyOutDir: true,
    sourcemap: false,
    target: 'chrome142'
  }
});
