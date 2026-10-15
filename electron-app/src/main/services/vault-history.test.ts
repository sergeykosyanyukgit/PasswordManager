import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultHistoryStore } from './vault-history.js';

const firstPath = 'C:\\Synthetic-Tests\\First.pmvault';
const secondPath = 'C:\\Synthetic-Tests\\Second.pmvault';
let directory: string;
let historyPath: string;

beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), 'mynotes-history-test-')); historyPath = join(directory, 'history.json'); });
afterEach(async () => { vi.useRealTimers(); await rm(directory, { recursive: true, force: true }); });

describe('vault history', () => {
  it('starts empty and persists only bounded path metadata after successful opens', async () => {
    const history = new VaultHistoryStore(historyPath);
    expect(await history.list()).toEqual({ entries: [], order: 'recent', persisted: true });
    const state = await history.recordOpened(firstPath);
    expect(Object.keys(state.entries[0]!).sort()).toEqual(['id', 'lastOpenedUtc', 'path']);
    expect((await new VaultHistoryStore(historyPath).list()).entries).toEqual(state.entries);
    expect(JSON.parse(await readFile(historyPath, 'utf8')).version).toBe(1);
  });

  it('deduplicates normalized Windows paths and sorts by most recent opening', async () => {
    vi.useFakeTimers();
    const history = new VaultHistoryStore(historyPath);
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
    await history.recordOpened(firstPath);
    vi.setSystemTime(new Date('2026-01-02T00:00:00.000Z'));
    await history.recordOpened(secondPath);
    vi.setSystemTime(new Date('2026-01-03T00:00:00.000Z'));
    const state = await history.recordOpened('c:\\synthetic-tests\\.\\FIRST.pmvault');
    expect(state.entries.map((entry) => entry.path)).toEqual([firstPath, secondPath]);
    expect(state.entries[0]!.lastOpenedUtc).toBe('2026-01-03T00:00:00.000Z');
  });

  it('retains manual order across opens and restarts, and can restore recent order', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
    const history = new VaultHistoryStore(historyPath);
    await history.recordOpened(firstPath);
    vi.setSystemTime(new Date('2026-01-02T00:00:00.000Z'));
    const initial = await history.recordOpened(secondPath);
    const ids = initial.entries.map((entry) => entry.id).reverse();
    await history.reorder(ids);
    const restarted = new VaultHistoryStore(historyPath);
    expect((await restarted.list()).entries.map((entry) => entry.id)).toEqual(ids);
    vi.setSystemTime(new Date('2026-01-03T00:00:00.000Z'));
    expect((await restarted.recordOpened(secondPath)).entries.map((entry) => entry.id)).toEqual(ids);
    expect((await restarted.useRecentOrder()).entries.map((entry) => entry.path)).toEqual([secondPath, firstPath]);
  });

  it('removes only the history entry and preserves vault bytes', async () => {
    const vaultFile = join(directory, 'Synthetic.pmvault');
    await writeFile(vaultFile, 'SYNTHETIC-NON-VAULT-BYTES');
    const history = new VaultHistoryStore(historyPath);
    const state = await history.recordOpened(vaultFile);
    expect((await history.remove(state.entries[0]!.id)).entries).toEqual([]);
    expect(await readFile(vaultFile, 'utf8')).toBe('SYNTHETIC-NON-VAULT-BYTES');
    expect((await new VaultHistoryStore(historyPath).list()).entries).toEqual([]);
  });

  it('rejects incomplete, duplicate, invented, oversized, and malformed reorder requests', async () => {
    const history = new VaultHistoryStore(historyPath);
    await history.recordOpened(firstPath);
    const state = await history.recordOpened(secondPath);
    const id = state.entries[0]!.id;
    for (const ids of [[], [id, id], [id, randomUUID()], [id], Array(101).fill(id), 'invalid']) {
      await expect(history.reorder(ids)).rejects.toThrow();
    }
    await expect(history.remove({ path: firstPath })).rejects.toThrow();
    expect((await history.list()).entries).toEqual(state.entries);
  });

  it.each(['relative.pmvault', 'C:\\Synthetic\\file.txt', 'C:\\Synthetic\\bad\u0000.pmvault'])('rejects unsafe history path %s', async (path) => {
    const history = new VaultHistoryStore(historyPath);
    await expect(history.recordOpened(path)).rejects.toThrow();
    expect((await history.list()).entries).toEqual([]);
  });

  it.each(['not json', '{"version":2,"order":"recent","entries":[]}', '{"version":1,"order":"recent","entries":[{"id":"invalid"}]}'])('ignores invalid history without trusting its contents', async (input) => {
    await writeFile(historyPath, input);
    expect(await new VaultHistoryStore(historyPath).list()).toEqual({ entries: [], order: 'recent', persisted: false });
  });

  it('rejects excessive files before JSON parsing', async () => {
    const file = await import('node:fs/promises').then((fs) => fs.open(historyPath, 'w'));
    try { await file.truncate(8 * 1024 * 1024 + 1); } finally { await file.close(); }
    expect((await new VaultHistoryStore(historyPath).list()).persisted).toBe(false);
  });

  it('bounds the entry count and evicts the last item when a new vault is opened', async () => {
    const entries = Array.from({ length: 100 }, (_, index) => ({
      id: randomUUID(), path: `C:\\Synthetic-Tests\\Entry-${index}.pmvault`, lastOpenedUtc: '2026-01-01T00:00:00.000Z'
    }));
    await writeFile(historyPath, JSON.stringify({ version: 1, order: 'manual', entries }));
    const state = await new VaultHistoryStore(historyPath).recordOpened(firstPath);
    expect(state.entries).toHaveLength(100);
    expect(state.entries[0]!.path).toBe(firstPath);
    expect(state.entries.some((entry) => entry.id === entries[99]!.id)).toBe(false);
    await writeFile(historyPath, JSON.stringify({ version: 1, order: 'recent', entries: [...entries, state.entries[0]] }));
    expect((await new VaultHistoryStore(historyPath).list()).persisted).toBe(false);
  });

  it('rejects invalid dates, duplicate paths, duplicate IDs, and extra decrypted fields', async () => {
    const entry = { id: randomUUID(), path: firstPath, lastOpenedUtc: '2026-01-01T00:00:00.000Z' };
    for (const entries of [
      [{ ...entry, lastOpenedUtc: 'invalid' }],
      [entry, { ...entry, id: randomUUID(), path: firstPath.toLowerCase() }],
      [entry, { ...entry, path: secondPath }],
      [{ ...entry, decryptedName: 'SYNTHETIC-NAME-MUST-NOT-BE-IN-HISTORY' }]
    ]) {
      await writeFile(historyPath, JSON.stringify({ version: 1, order: 'recent', entries }));
      expect(await new VaultHistoryStore(historyPath).list()).toEqual({ entries: [], order: 'recent', persisted: false });
    }
  });

  it('serializes concurrent mutations without losing entries', async () => {
    const history = new VaultHistoryStore(historyPath);
    await Promise.all([history.recordOpened(firstPath), history.recordOpened(secondPath)]);
    expect((await new VaultHistoryStore(historyPath).list()).entries).toHaveLength(2);
  });

  it('keeps an opened vault usable when history cannot be written', async () => {
    await writeFile(join(directory, 'blocked'), 'SYNTHETIC');
    const state = await new VaultHistoryStore(join(directory, 'blocked', 'history.json')).recordOpened(firstPath);
    expect(state.persisted).toBe(false);
    expect(state.entries).toHaveLength(1);
    expect((await stat(join(directory, 'blocked'))).isFile()).toBe(true);
  });
});
