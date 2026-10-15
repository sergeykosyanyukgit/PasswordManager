import { randomUUID } from 'node:crypto';
import { open } from 'node:fs/promises';
import { basename, extname, isAbsolute } from 'node:path';
import { z } from 'zod';
import type { MoveItem, VaultDocument, VaultRecord } from '../../shared/contracts.js';

export const MAXIMUM_TEXT_FILE_BYTES = 16 * 1024 * 1024;
export const MAXIMUM_IMPORT_BYTES = 32 * 1024 * 1024;
const pathsSchema = z.array(z.string().min(1).max(32_768).refine((path) => isAbsolute(path) && extname(path).toLowerCase() === '.txt' && !path.includes('\0'))).min(1).max(32);
export const moveSchema = z.object({ sessionId: z.string().uuid(), kind: z.enum(['folder', 'record']), id: z.string().uuid(), targetFolderId: z.string().uuid() }).strict();

export async function readTextImports(input: unknown): Promise<Array<{ name: string; text: string }>> {
  const paths = pathsSchema.parse(input);
  const result: Array<{ name: string; text: string }> = [];
  let total = 0;
  for (const path of paths) {
    const file = await open(path, 'r');
    let bytes: Buffer | undefined;
    try {
      const info = await file.stat();
      if (!info.isFile() || info.size > MAXIMUM_TEXT_FILE_BYTES || (total += info.size) > MAXIMUM_IMPORT_BYTES) throw new Error('Text import exceeds limit.');
      bytes = Buffer.alloc(info.size + 1);
      let count = 0;
      while (count < bytes.length) {
        const read = await file.read(bytes, count, bytes.length - count, count);
        if (!read.bytesRead) break;
        count += read.bytesRead;
      }
      const after = await file.stat();
      if (count !== info.size || after.size !== info.size || after.mtimeMs !== info.mtimeMs) throw new Error('Text file changed during import.');
      const content = bytes.subarray(0, count);
      let text: string;
      if (content[0] === 0xff && content[1] === 0xfe) text = new TextDecoder('utf-16le', { fatal: true }).decode(content.subarray(2));
      else if (content[0] === 0xfe && content[1] === 0xff) text = new TextDecoder('utf-16be', { fatal: true }).decode(content.subarray(2));
      else {
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(content); }
        catch { text = new TextDecoder('windows-1251', { fatal: true }).decode(content); }
      }
      if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(text)) throw new Error('Binary content is not a text document.');
      const name = basename(path);
      if (!name.trim() || name.length > 512 || text.length > 16 * 1024 * 1024) throw new Error('Invalid text import.');
      result.push({ name, text });
    } finally { bytes?.fill(0); await file.close(); }
  }
  return result;
}

export function addTextImports(document: VaultDocument, folderId: string, imports: Array<{ name: string; text: string }>): void {
  requireFolder(document, folderId);
  for (const item of imports) {
    const record: VaultRecord = {
      id: randomUUID(), folderId, type: 3, name: item.name, notes: item.text,
      userName: '', email: '', password: '', url: '', ssh: null, customFields: [],
      breach: { status: 0, occurrenceCount: 0, checkedUtc: null, compromisedSaveConfirmed: false },
      isDeleted: false, deletedUtc: null, modifiedUtc: new Date().toISOString()
    };
    document.records.push(record);
  }
}

export function moveVaultItem(document: VaultDocument, item: MoveItem): void {
  requireFolder(document, item.targetFolderId);
  if (item.kind === 'record') {
    const record = document.records.find((entry) => entry.id === item.id && !entry.isDeleted);
    if (!record) throw new Error('Record unavailable.');
    record.folderId = item.targetFolderId;
    record.modifiedUtc = new Date().toISOString();
    return;
  }
  const folder = requireFolder(document, item.id);
  if (folder.id === document.rootFolderId) throw new Error('Cannot move the root folder.');
  const byId = new Map(document.folders.map((entry) => [entry.id, entry]));
  let ancestor = byId.get(item.targetFolderId);
  const seen = new Set<string>();
  while (ancestor) {
    if (ancestor.id === folder.id || seen.has(ancestor.id)) throw new Error('Cannot move a folder into itself or its descendants.');
    seen.add(ancestor.id);
    ancestor = ancestor.parentId ? byId.get(ancestor.parentId) : undefined;
  }
  folder.parentId = item.targetFolderId;
  // The storage validator checks the full subtree's resulting depth before writing.
}

function requireFolder(document: VaultDocument, id: string) {
  const folder = document.folders.find((entry) => entry.id === id && !entry.isDeleted);
  if (!folder) throw new Error('Folder unavailable.');
  return folder;
}
