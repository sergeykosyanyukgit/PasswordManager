import { randomUUID } from 'node:crypto';
import { mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname, win32 } from 'node:path';
import { z } from 'zod';
import type { VaultHistory } from '../../shared/contracts.js';

const MAXIMUM_ENTRIES = 100;
const MAXIMUM_HISTORY_BYTES = 8 * 1024 * 1024;
const vaultPath = z.string().min(1).max(32_768).refine((value) =>
  win32.isAbsolute(value) && win32.extname(value).toLowerCase() === '.pmvault' && !/[\u0000-\u001f\u007f]/u.test(value));
const entrySchema = z.object({
  id: z.string().uuid(), path: vaultPath,
  lastOpenedUtc: z.string().refine((value) => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value)
}).strict();
const historySchema = z.object({
  version: z.literal(1), order: z.enum(['recent', 'manual']), entries: z.array(entrySchema).max(MAXIMUM_ENTRIES)
}).strict().refine(({ entries }) => new Set(entries.map((entry) => entry.id)).size === entries.length &&
  new Set(entries.map((entry) => pathKey(entry.path))).size === entries.length);

// Only file paths and opening dates live here. Never accept decrypted names or content.
export class VaultHistoryStore {
  private state: VaultHistory = { entries: [], order: 'recent', persisted: true };
  private readonly ready: Promise<void>;
  private pending: Promise<unknown> = Promise.resolve();

  constructor(private readonly filePath: string) { this.ready = this.load(); }

  async list(): Promise<VaultHistory> {
    await this.ready;
    await this.pending;
    return structuredClone(this.state);
  }

  recordOpened(path: string): Promise<VaultHistory> {
    return this.update(() => {
      const normalized = vaultPath.parse(win32.normalize(path));
      const existing = this.state.entries.find((entry) => pathKey(entry.path) === pathKey(normalized));
      if (existing) existing.lastOpenedUtc = new Date().toISOString();
      else this.state.entries.unshift({ id: randomUUID(), path: normalized, lastOpenedUtc: new Date().toISOString() });
      if (this.state.order === 'recent') this.sortEntries();
      this.state.entries = this.state.entries.slice(0, MAXIMUM_ENTRIES);
    });
  }

  reorder(input: unknown): Promise<VaultHistory> {
    return this.update(() => {
      const ids = z.array(z.string().uuid()).max(MAXIMUM_ENTRIES).parse(input);
      const byId = new Map(this.state.entries.map((entry) => [entry.id, entry]));
      if (ids.length !== byId.size || new Set(ids).size !== ids.length || ids.some((id) => !byId.has(id))) throw new Error('Invalid history order.');
      this.state.entries = ids.map((id) => byId.get(id)!);
      this.state.order = 'manual';
    });
  }

  remove(input: unknown): Promise<VaultHistory> {
    return this.update(() => {
      const id = z.string().uuid().parse(input);
      // Removing a history entry never opens, changes, or deletes its vault file.
      this.state.entries = this.state.entries.filter((entry) => entry.id !== id);
    });
  }

  useRecentOrder(): Promise<VaultHistory> {
    return this.update(() => { this.state.order = 'recent'; this.sortEntries(); });
  }

  private sortEntries(): void {
    this.state.entries.sort((left, right) => right.lastOpenedUtc.localeCompare(left.lastOpenedUtc));
  }

  private update(change: () => void): Promise<VaultHistory> {
    const operation = this.pending.then(async () => {
      await this.ready;
      change();
      try { await this.save(); this.state.persisted = true; }
      catch { this.state.persisted = false; }
      return structuredClone(this.state);
    });
    this.pending = operation.catch(() => undefined);
    return operation;
  }

  private async load(): Promise<void> {
    try {
      const file = await open(this.filePath, 'r');
      try {
        const size = (await file.stat()).size;
        if (size > MAXIMUM_HISTORY_BYTES) throw new Error('History exceeds limit.');
        const bytes = Buffer.alloc(size + 1);
        const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
        if (bytesRead !== size) throw new Error('History changed during read.');
        const parsed = historySchema.parse(JSON.parse(bytes.subarray(0, size).toString('utf8')));
        this.state = { entries: parsed.entries, order: parsed.order, persisted: true };
        if (this.state.order === 'recent') this.sortEntries();
      } finally { await file.close(); }
    } catch (error) {
      if (!(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT')) this.state.persisted = false;
    }
  }

  private async save(): Promise<void> {
    const serialized = Buffer.from(JSON.stringify({ version: 1, order: this.state.order, entries: this.state.entries }), 'utf8');
    if (serialized.length > MAXIMUM_HISTORY_BYTES) throw new Error('History exceeds limit.');
    await mkdir(dirname(this.filePath), { recursive: true });
    const temporaryPath = `${this.filePath}.${randomUUID()}.tmp`;
    try {
      const file = await open(temporaryPath, 'wx', 0o600);
      try {
        await file.writeFile(serialized);
        await file.sync();
      } finally { await file.close(); }
      await rename(temporaryPath, this.filePath);
    } finally { await unlink(temporaryPath).catch(() => undefined); }
  }
}

function pathKey(path: string): string { return win32.normalize(path).toLowerCase(); }
