import { randomUUID } from 'node:crypto';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createEmptyDocument, validateDocument } from '../vault/codec.js';
import { addTextImports, MAXIMUM_TEXT_FILE_BYTES, moveVaultItem, readTextImports } from './vault-items.js';

let directory: string;
beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), 'mynotes-synthetic-import-')); });
afterEach(async () => { await rm(directory, { recursive: true, force: true }); });
describe('TXT import and item movement', () => {
  it('imports UTF-8 and UTF-16 BOM text, legacy Windows text and empty files', async () => {
    const utf16 = Buffer.from('SYNTHETIC UTF16 TEXT ONLY', 'utf16le');
    const files = [
      ['utf8.txt', Buffer.from('\ufeffSYNTHETIC UTF8 TEXT ONLY')],
      ['utf16.txt', Buffer.concat([Buffer.from([255, 254]), utf16])],
      ['utf16be.txt', Buffer.concat([Buffer.from([254, 255]), Buffer.from(utf16).swap16()])],
      ['legacy.TXT', Buffer.from([0xd2, 0xe5, 0xf1, 0xf2])], ['empty.txt', Buffer.alloc(0)]
    ] as const;
    for (const [name, data] of files) await writeFile(join(directory, name), data);
    const imports = await readTextImports(files.map(([name]) => join(directory, name)));
    expect(imports.map((entry) => entry.text)).toEqual(['SYNTHETIC UTF8 TEXT ONLY', 'SYNTHETIC UTF16 TEXT ONLY', 'SYNTHETIC UTF16 TEXT ONLY', 'Тест', '']);
    const document = createEmptyDocument(); addTextImports(document, document.rootFolderId, imports);
    expect(document.records).toHaveLength(5);
    expect(document.records.every((record) => record.type === 3 && !record.password && record.folderId === document.rootFolderId)).toBe(true);
    expect(() => validateDocument(document)).not.toThrow();
  });
  it('rejects wrong extensions, virtual/relative paths, binary text, excessive count and oversized files', async () => {
    const binary = join(directory, 'binary.txt'); await writeFile(binary, Buffer.from([0, 1, 2]));
    const huge = join(directory, 'huge.txt'); const handle = await open(huge, 'w');
    try { await handle.truncate(MAXIMUM_TEXT_FILE_BYTES + 1); } finally { await handle.close(); }
    for (const files of [[join(directory, 'file.exe')], ['relative.txt'], [binary], [huge], Array(33).fill(binary), []]) await expect(readTextImports(files)).rejects.toThrow();
  });
  it('moves records and folder subtrees while rejecting root, self, descendant and deleted targets', () => {
    const document = createEmptyDocument(); const root = document.rootFolderId;
    const a = randomUUID(), b = randomUUID(), child = randomUUID();
    document.folders.push(...[
      { id: a, parentId: root, name: 'Synthetic A', isDeleted: false, deletedUtc: null },
      { id: b, parentId: root, name: 'Synthetic B', isDeleted: false, deletedUtc: null },
      { id: child, parentId: a, name: 'Synthetic Child', isDeleted: false, deletedUtc: null }
    ]);
    addTextImports(document, a, [{ name: 'Synthetic.txt', text: 'SYNTHETIC ONLY' }]);
    const base = { sessionId: randomUUID(), targetFolderId: b };
    moveVaultItem(document, { ...base, kind: 'record', id: document.records[0]!.id });
    expect(document.records[0]!.folderId).toBe(b);
    moveVaultItem(document, { ...base, kind: 'folder', id: a });
    expect(document.folders.find((folder) => folder.id === child)!.parentId).toBe(a);
    for (const [id, targetFolderId] of [[root, b], [a, a], [a, child]]) expect(() => moveVaultItem(document, { ...base, kind: 'folder', id: id!, targetFolderId: targetFolderId! })).toThrow();
    document.folders.find((folder) => folder.id === b)!.isDeleted = true;
    expect(() => moveVaultItem(document, { ...base, kind: 'record', id: document.records[0]!.id })).toThrow();
  });
  it('the validator rejects a moved subtree exceeding the depth cap', () => {
    const document = createEmptyDocument(); let parent = document.rootFolderId;
    for (let i = 0; i < 64; i++) { const id = randomUUID(); document.folders.push({ id, parentId: parent, name: `Synthetic ${i}`, isDeleted: false, deletedUtc: null }); parent = id; }
    const moved = randomUUID(); document.folders.push({ id: moved, parentId: document.rootFolderId, name: 'Synthetic moved', isDeleted: false, deletedUtc: null });
    moveVaultItem(document, { sessionId: randomUUID(), kind: 'folder', id: moved, targetFolderId: parent });
    expect(() => validateDocument(document)).toThrow(/depth/);
  });
});
