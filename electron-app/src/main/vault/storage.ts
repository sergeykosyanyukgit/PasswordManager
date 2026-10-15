import { constants } from 'node:fs';
import { access, open, readFile, rename, stat, unlink, type FileHandle } from 'node:fs/promises';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { SshProfile, VaultDocument, VaultSnapshot } from '../../shared/contracts.js';
import {
  createEmptyDocument,
  createMaterial,
  decodeVault,
  disposeMaterial,
  encodeVault,
  HEADER_SIZE,
  MAXIMUM_FILE_SIZE,
  validateDocument,
  verifyAndDecode,
  type VaultMaterial
} from './codec.js';

interface VaultSession {
  id: string;
  path: string;
  lockPath: string;
  lockHandle: FileHandle;
  sourceHash: Buffer;
  material: VaultMaterial;
  document: VaultDocument;
  revision: number;
}

export class VaultStore {
  private readonly sessions = new Map<string, VaultSession>();
  private readonly operations = new Map<string, Promise<unknown>>();

  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
    }
  }

  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    let material: VaultMaterial | undefined;
    try {
      material = await createMaterial(password);
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
        } finally {
          reread.fill(0);
        }
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      if (material) disposeMaterial(material);
      await releaseLock(lock.handle, lock.path);
      throw error;
    }
  }

  getSnapshot(sessionId: string): VaultSnapshot { return snapshot(this.requireSession(sessionId)); }

  async save(sessionId: string, document: VaultDocument, expectedRevision?: number): Promise<VaultSnapshot> {
    validateDocument(document);
    const requested = structuredClone(document);
    return this.enqueue(sessionId, async (session) => {
      if (expectedRevision !== undefined && expectedRevision !== session.revision) throw new Error('Vault revision conflict.');
      validateDocument(requested);
      constrainSshFingerprints(requested, session.document);
      requested.settings.hibpConsent = session.document.settings.hibpConsent;
      if (session.document.settings.notesWorkspace) requested.settings.notesWorkspace = structuredClone(session.document.settings.notesWorkspace);
      else delete requested.settings.notesWorkspace;
      await this.write(session, requested);
      return snapshot(session);
    });
  }

  mutate(sessionId: string, change: (document: VaultDocument) => void): Promise<VaultSnapshot> {
    return this.enqueue(sessionId, async (session) => {
      const document = structuredClone(session.document);
      change(document);
      await this.write(session, document);
      return snapshot(session);
    });
  }

  private enqueue<T>(id: string, operation: (session: VaultSession) => Promise<T>): Promise<T> {
    const result = (this.operations.get(id) ?? Promise.resolve()).catch(() => undefined).then(() => operation(this.requireSession(id)));
    this.operations.set(id, result);
    const cleanup = () => { if (this.operations.get(id) === result) this.operations.delete(id); };
    void result.then(cleanup, cleanup);
    return result;
  }

  private async write(session: VaultSession, safeDocument: VaultDocument): Promise<void> {
    validateDocument(safeDocument);
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      if (this.sessions.get(session.id) !== session) throw new Error('Vault locked during save.');
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
      session.revision++;
    } finally {
      bytes.fill(0);
      await unlink(tempPath).catch(() => undefined);
    }
  }

  getSshProfile(sessionId: string, recordId: string): SshProfile {
    const record = this.requireSession(sessionId).document.records.find((item) => item.id === recordId);
    if (record?.type !== 4 || !record.ssh || record.isDeleted) throw new Error('SSH record is unavailable.');
    return structuredClone(record.ssh);
  }

  async setSshHostKey(sessionId: string, recordId: string, fingerprint: string): Promise<void> {
    if (!/^SHA256:[A-Za-z0-9+/]{43}$/u.test(fingerprint)) throw new Error('Invalid SSH host-key fingerprint.');
    await this.mutate(sessionId, (document) => {
      const record = document.records.find((item) => item.id === recordId);
      if (record?.type !== 4 || !record.ssh || record.isDeleted) throw new Error('SSH record is unavailable.');
      record.ssh.hostKeySha256 = fingerprint;
    });
  }

  hasHibpConsent(sessionId: string): boolean {
    return this.requireSession(sessionId).document.settings.hibpConsent;
  }

  async grantHibpConsent(sessionId: string): Promise<void> {
    if (this.requireSession(sessionId).document.settings.hibpConsent) return;
    await this.mutate(sessionId, (document) => { document.settings.hibpConsent = true; });
  }

  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    await this.operations.get(sessionId)?.catch(() => undefined);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }

  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
  }

  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document, revision: 0 };
    this.sessions.set(session.id, session);
    return session;
  }

  private requireSession(id: string): VaultSession {
    const session = this.sessions.get(id);
    if (!session) throw new Error('Vault session is locked or unavailable.');
    return session;
  }
}

async function canonicalVaultPath(path: string, mustExist: boolean): Promise<string> {
  if (typeof path !== 'string' || path.length < 1 || path.length > 32_768) throw new Error('Invalid vault path.');
  let result = resolve(path);
  if (extname(result).toLowerCase() !== '.pmvault') result += '.pmvault';
  const parent = dirname(result);
  const parentStats = await stat(parent);
  if (!parentStats.isDirectory()) throw new Error('Vault parent is not a directory.');
  if (mustExist) {
    const vaultStats = await stat(result);
    if (!vaultStats.isFile() || vaultStats.size < HEADER_SIZE || vaultStats.size > MAXIMUM_FILE_SIZE) throw new Error('Invalid vault file.');
  }
  return result;
}

async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
}

async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
}

async function readBounded(path: string): Promise<Buffer> {
  const info = await stat(path);
  if (!info.isFile() || info.size < HEADER_SIZE || info.size > MAXIMUM_FILE_SIZE) throw new Error('Invalid vault size.');
  const bytes = await readFile(path);
  if (bytes.length !== info.size) { bytes.fill(0); throw new Error('Vault changed while being read.'); }
  return bytes;
}

async function writeDurably(path: string, bytes: Buffer): Promise<void> {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function createNewAtomically(destination: string, bytes: Buffer): Promise<void> {
  const temp = `${destination}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
  try { await writeDurably(temp, bytes); await rename(temp, destination); }
  finally { await unlink(temp).catch(() => undefined); }
}

async function cleanupEncryptedTemps(vaultPath: string): Promise<void> {
  const { readdir } = await import('node:fs/promises');
  const directory = dirname(vaultPath);
  const prefix = `${basename(vaultPath)}.`;
  const entries = (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.startsWith(prefix) && entry.name.endsWith('.tmp')).slice(0, 32);
  for (const entry of entries) {
    const candidate = join(directory, entry.name);
    const handle = await open(candidate, 'r').catch(() => null);
    if (!handle) continue;
    try {
      const magic = Buffer.alloc(8);
      await handle.read(magic, 0, 8, 0);
      if (magic.equals(Buffer.from('PMVAULT1'))) {
        await handle.close();
        await unlink(candidate).catch(() => undefined);
      }
    } finally {
      await handle.close().catch(() => undefined);
    }
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}

function snapshot(session: VaultSession): VaultSnapshot {
  return { revision: session.revision, sessionId: session.id, path: session.path, displayName: basename(session.path, '.pmvault'), document: structuredClone(session.document) };
}

function clearDocument(document: VaultDocument): void {
  for (const record of document.records) {
    record.name = record.userName = record.email = record.password = record.url = record.notes = '';
    for (const field of record.customFields) { field.name = ''; field.value = ''; }
    if (record.ssh) record.ssh.host = record.ssh.userName = record.ssh.password = record.ssh.privateKeyPem = record.ssh.privateKeyPassphrase = record.ssh.hostKeySha256 = '';
  }
  for (const folder of document.folders) folder.name = '';
  document.records.length = 0;
  document.folders.length = 0;
}

function constrainSshFingerprints(proposed: VaultDocument, current: VaultDocument): void {
  const currentRecords = new Map(current.records.map((record) => [record.id, record]));
  for (const record of proposed.records) {
    if (record.type !== 4 || !record.ssh) continue;
    const previous = currentRecords.get(record.id);
    record.ssh.hostKeySha256 = previous?.type === 4 && previous.ssh && previous.ssh.host === record.ssh.host && previous.ssh.port === record.ssh.port
      ? previous.ssh.hostKeySha256
      : '';
  }
}
