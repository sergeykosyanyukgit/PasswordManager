import { build as viteBuild } from 'vite';
import { build } from 'esbuild';
import { spawn } from 'node:child_process';
import { copyFile, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
import { CONTENT_SECURITY_POLICY } from '../src/shared/content-security-policy.ts';

const require = createRequire(import.meta.url);
const root = resolve('.runtime-probe/notes-renderer'); await mkdir(root, { recursive: true });
await viteBuild({ configFile: resolve('vite.config.ts'), root: resolve('tests/notes-renderer'), build: { outDir: root, emptyOutDir: true } });
await copyFile(resolve(root, 'index.html'), resolve(root, 'notes.html'));
await build({ entryPoints: ['tests/notes-renderer/main.ts'], outfile: resolve(root, 'main.cjs'), platform: 'node', target: 'node24', format: 'cjs', bundle: true, external: ['electron'], logLevel: 'warning' });
await build({ entryPoints: ['src/preload/notes-preload.ts'], outfile: resolve(root, 'notes-preload.cjs'), platform: 'node', target: 'node24', format: 'cjs', bundle: true, external: ['electron'], logLevel: 'warning' });
for (const [width, height] of [[900, 720], [500, 380]]) {
  const resultPath = resolve(root, `result-${width}.json`);
  await unlink(resultPath).catch(() => undefined);
  const configPath = resolve(root, `config-${width}.json`);
  await writeFile(configPath, JSON.stringify({ root, rendererRoot: process.argv.includes('--production-renderer') ? resolve('dist/renderer') : root, preload: resolve(root, 'notes-preload.cjs'), csp: CONTENT_SECURITY_POLICY, width, height }));
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  const result = await new Promise((done, reject) => { const child = spawn(require('electron'), [resolve(root, 'main.cjs'), configPath], { env, windowsHide: true, stdio: 'inherit' }); child.on('error', reject); child.on('exit', done); });
  if (result !== 0) process.exit(result || 1);
  const report = JSON.parse(await readFile(resultPath, 'utf8'));
  if (!report.passed || report.checks.length < 16) throw new Error('Notes fixture did not complete every required check.');
}
