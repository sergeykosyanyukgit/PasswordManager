import { contextBridge, ipcRenderer } from 'electron';
import type { AppCommand, EditingContext, NoteEditorApi, NoteUpdate, NotesViewState } from '../shared/contracts.js';

const api: NoteEditorApi = Object.freeze({
  getState: () => ipcRenderer.invoke('notes:state'),
  updateNote: (input: NoteUpdate) => ipcRenderer.invoke('notes:update', input),
  activateTab: (sessionId: string, recordId: string) => ipcRenderer.invoke('notes:activate', { sessionId, recordId }),
  closeTab: (sessionId: string, recordId: string) => ipcRenderer.invoke('notes:close-tab', { sessionId, recordId }),
  finishClose: () => ipcRenderer.invoke('notes:finish-close'),
  cancelClose: () => ipcRenderer.invoke('notes:cancel-close'),
  setEditingContext: (context: EditingContext) => ipcRenderer.send('app:editing-context', context),
  notifyActivity: () => ipcRenderer.send('app:activity'),
  onState: (callback: (state: NotesViewState) => void) => subscribe('notes:state-changed', callback),
  onCommand: (callback: (command: AppCommand) => void) => subscribe('app:command', callback),
  onCloseRequested: (callback: () => void) => subscribe('notes:close-requested', callback)
});
contextBridge.exposeInMainWorld('noteEditor', api);

function subscribe<T>(channel: string, callback: (value: T) => void): () => void {
  const listener = (_event: Electron.IpcRendererEvent, value: T) => callback(value);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}
