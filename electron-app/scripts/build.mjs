import { build } from 'esbuild';

const shared = {
  bundle: true,
  minify: true,
  platform: 'node',
  target: 'node24',
  // Keep ssh2 as a packaged dependency so its optional native accelerators can
  // load when compatible and cleanly fall back to the library's JavaScript path.
  external: ['electron', 'ssh2'],
  define: {
    'process.env.PM_SCREENSHOT_DIAGNOSTICS': JSON.stringify(process.env.PM_SCREENSHOT_DIAGNOSTICS === '1' ? '1' : '0')
  },
  sourcemap: false,
  logLevel: 'info'
};

await Promise.all([
  build({ ...shared, entryPoints: ['src/main/main.ts'], outfile: 'dist/main/main.cjs', format: 'cjs' }),
  build({ ...shared, entryPoints: ['src/preload/preload.ts'], outfile: 'dist/preload/preload.cjs', format: 'cjs' })
]);
