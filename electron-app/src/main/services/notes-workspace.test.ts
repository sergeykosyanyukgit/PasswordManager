import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { VaultStore } from '../vault/storage.js';
import { addTextImports } from './vault-items.js';
import { NotesWorkspaceService } from './notes-workspace.js';
import type { VaultSnapshot } from '../../shared/contracts.js';

const password = 'Synthetic-Test-Password-Only!42';
let directory: string; let path: string; let store: VaultStore; let initial: VaultSnapshot;
let service: NotesWorkspaceService; let ids: string[]; const changes: VaultSnapshot[] = [];
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'mynotes-synthetic-notes-')); path = join(directory, 'Synthetic.pmvault');
  store = new VaultStore(); initial = await store.create(path, password);
  initial = await store.mutate(initial.sessionId, (document) => addTextImports(document, document.rootFolderId, [
    { name: 'Synthetic Alpha.txt', text: 'SYNTHETIC NOTE ALPHA ONLY' }, { name: 'Synthetic Beta.txt', text: 'SYNTHETIC NOTE BETA ONLY' }
  ]));
  ids = initial.document.records.map((record) => record.id); changes.length = 0;
  service = new NotesWorkspaceService(store, (snapshot) => changes.push(snapshot));
});
afterEach(async () => { await store.closeAll(); await rm(directory, { recursive: true, force: true }); });

describe('encrypted notes workspace', () => {
  it('aggregates documents into tabs and sends only note title and text', async () => {
    await service.open(initial.sessionId, ids[0]); await service.open(initial.sessionId, ids[1]);
    const state = service.state();
    expect(state.tabs).toHaveLength(2);
    expect(Object.keys(state.tabs[0]!).sort()).toEqual(['recordId', 'sessionId', 'text', 'title']);
    expect(state.activeKey).toBe(`${initial.sessionId}:${ids[1]}`);
    expect((await readFile(path)).includes(Buffer.from('Synthetic Alpha.txt'))).toBe(false);
  });
  it('restores tabs on unlock, retains them after manual close, and honors auto-open suppression', async () => {
    await service.open(initial.sessionId, ids[0]); await service.open(initial.sessionId, ids[1]);
    await store.close(initial.sessionId);
    const reopened = await store.open(path, password);
    service = new NotesWorkspaceService(store, () => undefined);
    expect(service.restore(reopened)).toBe(true);
    expect(service.state().tabs).toHaveLength(2);
    await service.manualClose();
    expect(service.state().tabs).toHaveLength(0);
    expect(new NotesWorkspaceService(store, () => undefined).restore(store.getSnapshot(reopened.sessionId))).toBe(false);
    await service.open(reopened.sessionId);
    expect(service.state().tabs).toHaveLength(2);
    expect(store.getSnapshot(reopened.sessionId).document.settings.notesWorkspace?.autoOpen).toBe(true);
  });
  it('saves title/text without touching other note fields and rejects a stale editor', async () => {
    await store.mutate(initial.sessionId, (document) => { document.records[0]!.password = 'Synthetic-Test-Password-Only!42'; });
    await service.open(initial.sessionId, ids[0]);
    const view = service.state().tabs[0]!;
    const input = { ...view, baseTitle: view.title, baseText: view.text, title: 'Synthetic updated title', text: 'SYNTHETIC UPDATED TEXT ONLY' };
    await service.update(input);
    expect(store.getSnapshot(initial.sessionId).document.records[0]!.password).toBe('Synthetic-Test-Password-Only!42');
    await expect(service.update(input)).rejects.toThrow(/changed/);
    expect(store.getSnapshot(initial.sessionId).document.records[0]!.notes).toBe(input.text);
  });
  it('rejects unopened records, extra payload fields and saves after locking', async () => {
    await service.open(initial.sessionId, ids[0]); const view = service.state().tabs[0]!;
    const input = { ...view, baseTitle: view.title, baseText: view.text };
    await expect(service.update({ ...input, recordId: ids[1] })).rejects.toThrow();
    await expect(service.update({ ...input, password: 'SYNTHETIC-UNEXPECTED-FIELD' })).rejects.toThrow();
    await expect(service.update({ ...input, recordId: randomUUID() })).rejects.toThrow();
    service.forget(initial.sessionId); await store.close(initial.sessionId);
    expect(service.state().tabs).toHaveLength(0);
    await expect(service.update(input)).rejects.toThrow();
  });
  it('persists tab activation and removes closed tabs from future restores', async () => {
    await service.open(initial.sessionId, ids[0]); await service.open(initial.sessionId, ids[1]);
    await service.activate({ sessionId: initial.sessionId, recordId: ids[0] });
    expect(service.state().activeKey).toBe(`${initial.sessionId}:${ids[0]}`);
    await service.closeTab({ sessionId: initial.sessionId, recordId: ids[0] });
    expect(service.state().tabs.map((tab) => tab.recordId)).toEqual([ids[1]]);
  });
  it('serializes mutations, rejects stale full-document saves, and preserves source bytes on failure', async () => {
    const stale = store.getSnapshot(initial.sessionId);
    await Promise.all([service.open(initial.sessionId, ids[0]), service.open(initial.sessionId, ids[1])]);
    await expect(store.save(stale.sessionId, stale.document, stale.revision)).rejects.toThrow(/revision/);
    const before = await readFile(path);
    await expect(store.mutate(stale.sessionId, () => { throw new Error('Synthetic failure injection'); })).rejects.toThrow();
    expect(await readFile(path)).toEqual(before);
    expect(service.state().tabs).toHaveLength(2);
  });
});
