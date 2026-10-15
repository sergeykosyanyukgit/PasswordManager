import { build } from 'vite';
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
import { CONTENT_SECURITY_POLICY } from '../src/shared/content-security-policy.ts';

const require = createRequire(import.meta.url);
const root = resolve('.runtime-probe/history-renderer');
await mkdir(root, { recursive: true });
await build({ configFile: resolve('vite.config.ts'), root: resolve('tests/history-renderer'),
  build: { outDir: root, emptyOutDir: true } });
for (const [width, height] of [[1320, 820], [980, 640]]) {
  const configPath = resolve(root, `config-${width}.json`);
  await writeFile(configPath, JSON.stringify({ root, csp: CONTENT_SECURITY_POLICY, width, height }));
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  const exitCode = await new Promise((resolveExit, reject) => {
    const child = spawn(require('electron'), [resolve('tests/history-renderer/main.cjs'), configPath], { env, windowsHide: true, stdio: 'inherit' });
    child.on('error', reject); child.on('exit', resolveExit);
  });
  if (exitCode !== 0) process.exit(exitCode || 1);
}
