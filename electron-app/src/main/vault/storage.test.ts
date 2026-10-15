import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { VaultStore } from './storage.js';

const SYNTHETIC_PASSWORD = 'Synthetic-Test-Password-Only!42';
const directories: string[] = [];
const stores: VaultStore[] = [];

afterEach(async () => {
  await Promise.all(stores.splice(0).map((store) => store.closeAll()));
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function testPath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'passwordmanager-synthetic-'));
  directories.push(directory);
  return join(directory, 'synthetic.pmvault');
}

function store(): VaultStore {
  const value = new VaultStore();
  stores.push(value);
  return value;
}

describe('vault storage', () => {
  it('releases the writer lock when password validation fails during creation', async () => {
    const path = await testPath();
    const vaultStore = store();
    await expect(vaultStore.create(path, 'Synth7!')).rejects.toThrow();
    const created = await vaultStore.create(path, SYNTHETIC_PASSWORD);
    expect(created.sessionId).toBeTruthy();
  });
  it('creates, saves, closes, and reopens a vault', async () => {
    const path = await testPath();
    const first = store();
    const created = await first.create(path, SYNTHETIC_PASSWORD);
    created.document.folders.push({ id: crypto.randomUUID(), parentId: created.document.rootFolderId, name: 'Synthetic folder', isDeleted: false, deletedUtc: null });
    await first.save(created.sessionId, created.document);
    await first.close(created.sessionId);

    const second = store();
    const reopened = await second.open(path, SYNTHETIC_PASSWORD);
    expect(reopened.document.folders.some((folder) => folder.name === 'Synthetic folder')).toBe(true);
  });

  it('prevents a second writer', async () => {
    const path = await testPath();
    const first = store();
    await first.create(path, SYNTHETIC_PASSWORD);
    await expect(store().open(path, SYNTHETIC_PASSWORD)).rejects.toThrow(/already open|lock/i);
  });

  it('does not overwrite a source changed outside the session', async () => {
    const path = await testPath();
    const vaultStore = store();
    const snapshot = await vaultStore.create(path, SYNTHETIC_PASSWORD);
    const externalBytes = await readFile(path);
    externalBytes[externalBytes.length - 1] = externalBytes[externalBytes.length - 1]! ^ 0x40;
    await writeFile(path, externalBytes);
    const changedHash = Buffer.from(externalBytes);
    externalBytes.fill(0);

    snapshot.document.settings.sessionLanguage = 'ru';
    await expect(vaultStore.save(snapshot.sessionId, snapshot.document)).rejects.toThrow(/conflict/i);
    const after = await readFile(path);
    expect(after.equals(changedHash)).toBe(true);
    after.fill(0);
    changedHash.fill(0);
  });

  it('keeps SSH host-key pins under main-process authority', async () => {
    const path = await testPath();
    const vaultStore = store();
    const snapshot = await vaultStore.create(path, SYNTHETIC_PASSWORD);
    const recordId = crypto.randomUUID();
    snapshot.document.records.push({
      id: recordId,
      folderId: snapshot.document.rootFolderId,
      type: 4,
      name: 'Synthetic SSH record',
      userName: '', email: '', password: '', url: '', notes: '',
      ssh: {
        host: 'synthetic.example.invalid', port: 22, userName: 'synthetic-user', authenticationKind: 0,
        password: 'Synthetic-SSH-Password-Only!42', privateKeyPem: '', privateKeyPassphrase: '', hostKeySha256: `SHA256:${'A'.repeat(43)}`, allowLegacyAlgorithms: false
      },
      customFields: [],
      breach: { status: 0, occurrenceCount: 0, checkedUtc: null, compromisedSaveConfirmed: false },
      isDeleted: false, deletedUtc: null, modifiedUtc: new Date().toISOString()
    });
    await vaultStore.save(snapshot.sessionId, snapshot.document);
    expect(vaultStore.getSshProfile(snapshot.sessionId, recordId).hostKeySha256).toBe('');

    const trustedFingerprint = `SHA256:${'B'.repeat(43)}`;
    await vaultStore.setSshHostKey(snapshot.sessionId, recordId, trustedFingerprint);
    const rendererDocument = structuredClone(snapshot.document);
    rendererDocument.records.find((record) => record.id === recordId)!.ssh!.hostKeySha256 = `SHA256:${'C'.repeat(43)}`;
    await vaultStore.save(snapshot.sessionId, rendererDocument);
    expect(vaultStore.getSshProfile(snapshot.sessionId, recordId).hostKeySha256).toBe(trustedFingerprint);

    rendererDocument.records.find((record) => record.id === recordId)!.ssh!.host = 'changed.example.invalid';
    await vaultStore.save(snapshot.sessionId, rendererDocument);
    expect(vaultStore.getSshProfile(snapshot.sessionId, recordId).hostKeySha256).toBe('');
  });

  it('keeps HIBP consent transitions under main-process authority', async () => {
    const path = await testPath();
    const vaultStore = store();
    const snapshot = await vaultStore.create(path, SYNTHETIC_PASSWORD);

    snapshot.document.settings.hibpConsent = true;
    await vaultStore.save(snapshot.sessionId, snapshot.document);
    expect(vaultStore.hasHibpConsent(snapshot.sessionId)).toBe(false);

    await vaultStore.grantHibpConsent(snapshot.sessionId);
    expect(vaultStore.hasHibpConsent(snapshot.sessionId)).toBe(true);

    snapshot.document.settings.hibpConsent = false;
    await vaultStore.save(snapshot.sessionId, snapshot.document);
    expect(vaultStore.hasHibpConsent(snapshot.sessionId)).toBe(true);
  });

  it('selects only elapsed sessions with enabled auto-lock', async () => {
    const path = await testPath();
    const vaultStore = store();
    const snapshot = await vaultStore.create(path, SYNTHETIC_PASSWORD);

    snapshot.document.settings.autoLockMinutes = 5;
    await vaultStore.save(snapshot.sessionId, snapshot.document);
    expect(vaultStore.autoLockSessionIds(4 * 60_000)).toEqual([]);
    expect(vaultStore.autoLockSessionIds(5 * 60_000)).toEqual([snapshot.sessionId]);

    snapshot.document.settings.autoLockMinutes = 0;
    await vaultStore.save(snapshot.sessionId, snapshot.document);
    expect(vaultStore.autoLockSessionIds(Number.MAX_SAFE_INTEGER)).toEqual([]);
  });
});
