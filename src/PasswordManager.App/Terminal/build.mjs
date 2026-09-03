import { build } from 'esbuild';
import { cp, mkdir, rm } from 'node:fs/promises';

await rm('dist', { recursive: true, force: true });
await mkdir('dist', { recursive: true });
await build({
  entryPoints: ['src/terminal.js'],
  bundle: true,
  minify: true,
  sourcemap: false,
  outfile: 'dist/bundle.js',
  platform: 'browser',
  target: ['chrome120'],
  legalComments: 'none'
});
await cp('src/index.html', 'dist/index.html');

