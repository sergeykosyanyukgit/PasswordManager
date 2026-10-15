import { createHash } from 'node:crypto';
import { request } from 'node:https';
import type { HibpResult } from '../../shared/contracts.js';

const MAXIMUM_RESPONSE_BYTES = 2 * 1024 * 1024;

export async function checkPwnedPassword(password: string): Promise<HibpResult> {
  const normalized = Buffer.from(password.normalize('NFC'), 'utf8');
  let hash = '';
  try { hash = createHash('sha1').update(normalized).digest('hex').toUpperCase(); }
  finally { normalized.fill(0); }
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  hash = '';
  try {
    const body = await requestRange(prefix);
    try {
      for (const rawLine of body.toString('ascii').split(/\r?\n/u)) {
        if (rawLine.length > 64 || rawLine[35] !== ':') continue;
        if (rawLine.slice(0, 35).toUpperCase() !== suffix) continue;
        const countText = rawLine.slice(36);
        if (!/^\d+$/u.test(countText)) return { status: 'failed', occurrenceCount: 0, reason: 'MalformedResponse' };
        const count = Number(countText);
        if (!Number.isSafeInteger(count)) return { status: 'failed', occurrenceCount: 0, reason: 'MalformedResponse' };
        return count === 0 ? { status: 'notFound', occurrenceCount: 0 } : { status: 'compromised', occurrenceCount: count };
      }
      return { status: 'notFound', occurrenceCount: 0 };
    } finally { body.fill(0); }
  } catch {
    return { status: 'failed', occurrenceCount: 0, reason: 'NetworkFailure' };
  }
}

function requestRange(prefix: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: 'api.pwnedpasswords.com', port: 443, method: 'GET', path: `/range/${prefix}`, headers: { 'Add-Padding': 'true', Accept: 'text/plain', 'User-Agent': 'MyNotes/1.0' }, timeout: 10_000 }, (response) => {
      if (response.statusCode !== 200 || response.headers.location) { response.resume(); reject(new Error('HIBP rejected.')); return; }
      const declared = Number(response.headers['content-length'] ?? 0);
      if (declared > MAXIMUM_RESPONSE_BYTES) { response.destroy(); reject(new Error('HIBP response too large.')); return; }
      const chunks: Buffer[] = [];
      let total = 0;
      response.on('data', (chunk: Buffer) => {
        total += chunk.length;
        if (total > MAXIMUM_RESPONSE_BYTES) { for (const item of chunks) item.fill(0); response.destroy(new Error('HIBP response too large.')); return; }
        chunks.push(Buffer.from(chunk));
      });
      response.once('end', () => resolve(Buffer.concat(chunks, total)));
      response.once('error', reject);
    });
    req.once('timeout', () => req.destroy(new Error('HIBP timeout.')));
    req.once('error', reject);
    req.end();
  });
}
