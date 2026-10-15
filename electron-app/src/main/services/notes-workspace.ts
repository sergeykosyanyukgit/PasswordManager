import { z } from 'zod';
import type { NoteUpdate, NotesViewState, NotesWorkspace, VaultDocument, VaultSnapshot } from '../../shared/contracts.js';
import type { VaultStore } from '../vault/storage.js';

const reference = z.object({ sessionId: z.string().uuid(), recordId: z.string().uuid() }).strict();
const updateSchema = reference.extend({ title: z.string().trim().min(1).max(512), text: z.string().max(16 * 1024 * 1024), baseTitle: z.string().max(512), baseText: z.string().max(16 * 1024 * 1024) }).strict();
export const noteReferenceSchema = reference;

export class NotesWorkspaceService {
  private readonly sessions = new Set<string>();
  private activeKey: string | null = null;
  theme: 'light' | 'dark' = 'light';

  constructor(private readonly store: VaultStore, private readonly changed: (snapshot: VaultSnapshot) => void) {}

  restore(snapshot: VaultSnapshot): boolean {
    const workspace = snapshot.document.settings.notesWorkspace;
    if (!workspace?.autoOpen || !workspace.openRecordIds.some((id) => isNote(snapshot.document, id))) return false;
    this.sessions.add(snapshot.sessionId);
    this.activeKey = `${snapshot.sessionId}:${workspace.activeRecordId ?? workspace.openRecordIds[0]}`;
    return true;
  }

  async open(sessionId: string, recordId?: string): Promise<void> {
    z.string().uuid().parse(sessionId);
    if (recordId !== undefined) z.string().uuid().parse(recordId);
    const snapshot = await this.store.mutate(sessionId, (document) => {
      const workspace = notesWorkspace(document);
      workspace.openRecordIds = workspace.openRecordIds.filter((id) => isNote(document, id));
      if (recordId) {
        if (!isNote(document, recordId)) throw new Error('Note unavailable.');
        if (!workspace.openRecordIds.includes(recordId)) {
          if (workspace.openRecordIds.length >= 128 || this.state().tabs.length >= 128) throw new Error('Too many note tabs.');
          workspace.openRecordIds.push(recordId);
        }
        workspace.activeRecordId = recordId;
      } else if (!workspace.openRecordIds.includes(workspace.activeRecordId ?? '')) workspace.activeRecordId = workspace.openRecordIds[0] ?? null;
      workspace.autoOpen = true;
    });
    this.sessions.add(sessionId);
    const activeId = snapshot.document.settings.notesWorkspace?.activeRecordId;
    this.activeKey = activeId ? `${sessionId}:${activeId}` : this.activeKey;
    this.changed(snapshot);
  }

  state(): NotesViewState {
    const tabs: NotesViewState['tabs'] = [];
    for (const id of this.sessions) {
      let snapshot: VaultSnapshot;
      try { snapshot = this.store.getSnapshot(id); } catch { continue; }
      const byId = new Map(snapshot.document.records.map((record) => [record.id, record]));
      for (const recordId of snapshot.document.settings.notesWorkspace?.openRecordIds ?? []) {
        const record = byId.get(recordId);
        if (record?.type === 3 && !record.isDeleted && tabs.length < 128) tabs.push({ sessionId: id, recordId, title: record.name, text: record.notes });
      }
    }
    const activeKey = tabs.some((tab) => `${tab.sessionId}:${tab.recordId}` === this.activeKey) ? this.activeKey : tabs[0] ? `${tabs[0].sessionId}:${tabs[0].recordId}` : null;
    return { tabs, activeKey, theme: this.theme };
  }

  async update(input: unknown): Promise<NotesViewState> {
    const value: NoteUpdate = updateSchema.parse(input);
    this.assertOpen(value.sessionId, value.recordId);
    const snapshot = await this.store.mutate(value.sessionId, (document) => {
      const record = document.records.find((item) => item.id === value.recordId && item.type === 3 && !item.isDeleted);
      if (!record || record.name !== value.baseTitle || record.notes !== value.baseText) throw new Error('Note changed in another editor.');
      record.name = value.title;
      record.notes = value.text;
      record.modifiedUtc = new Date().toISOString();
    });
    this.changed(snapshot);
    return this.state();
  }

  async activate(input: unknown): Promise<void> {
    const value = reference.parse(input);
    this.assertOpen(value.sessionId, value.recordId);
    const snapshot = await this.store.mutate(value.sessionId, (document) => { notesWorkspace(document).activeRecordId = value.recordId; });
    this.activeKey = `${value.sessionId}:${value.recordId}`;
    this.changed(snapshot);
  }

  async closeTab(input: unknown): Promise<void> {
    const value = reference.parse(input);
    this.assertOpen(value.sessionId, value.recordId);
    const snapshot = await this.store.mutate(value.sessionId, (document) => {
      const workspace = notesWorkspace(document);
      workspace.openRecordIds = workspace.openRecordIds.filter((id) => id !== value.recordId);
      if (workspace.activeRecordId === value.recordId) workspace.activeRecordId = workspace.openRecordIds[0] ?? null;
    });
    this.changed(snapshot);
  }

  async manualClose(): Promise<void> {
    for (const id of this.sessions) {
      const snapshot = await this.store.mutate(id, (document) => { notesWorkspace(document).autoOpen = false; });
      this.changed(snapshot);
    }
    this.clear();
  }

  forget(sessionId: string): void { this.sessions.delete(sessionId); }
  clear(): void { this.sessions.clear(); this.activeKey = null; }
  get hasSessions(): boolean { return this.sessions.size > 0; }

  private assertOpen(sessionId: string, recordId: string): void {
    if (!this.sessions.has(sessionId) || !this.store.getSnapshot(sessionId).document.settings.notesWorkspace?.openRecordIds.includes(recordId)) throw new Error('Note tab is unavailable.');
  }
}

function isNote(document: VaultDocument, id: string): boolean { return document.records.some((record) => record.id === id && record.type === 3 && !record.isDeleted); }
function notesWorkspace(document: VaultDocument): NotesWorkspace {
  return document.settings.notesWorkspace ??= { openRecordIds: [], activeRecordId: null, autoOpen: true };
}
