import { contextBridge, ipcRenderer, webUtils } from 'electron';
import type { AppCommand, EditingContext, MoveItem, MyNotesApi, SshTerminalClosedEvent, SshTerminalDataEvent, SshTerminalStartRequest, VaultDocument, VaultSnapshot } from '../shared/contracts.js';

const api: MyNotesApi = Object.freeze({
  getStartupState: () => ipcRenderer.invoke('app:startup'),
  listRecentVaults: () => ipcRenderer.invoke('history:list'),
  reorderRecentVaults: (ids: string[]) => ipcRenderer.invoke('history:reorder', ids),
  removeRecentVault: (id: string) => ipcRenderer.invoke('history:remove', id),
  sortRecentVaults: () => ipcRenderer.invoke('history:sort-recent'),
  chooseVaultToOpen: () => ipcRenderer.invoke('vault:choose-open'),
  chooseVaultToCreate: () => ipcRenderer.invoke('vault:choose-create'),
  openVault: (path: string, password: string) => ipcRenderer.invoke('vault:open', { path, password }),
  createVault: (path: string, password: string) => ipcRenderer.invoke('vault:create', { path, password }),
  saveVault: (sessionId: string, document: VaultDocument, revision: number) => ipcRenderer.invoke('vault:save', { sessionId, document, revision }),
  getVaultSnapshot: (sessionId: string) => ipcRenderer.invoke('vault:snapshot', sessionId),
  openNotes: (sessionId: string, recordId?: string) => ipcRenderer.invoke('notes:open', { sessionId, recordId }),
  importTextFiles: (sessionId: string, folderId: string) => ipcRenderer.invoke('vault:import-text', { sessionId, folderId }),
  importDroppedTextFiles: (sessionId: string, folderId: string, files: File[]) => {
    if (!Array.isArray(files) || files.length < 1 || files.length > 32) return Promise.reject(new Error('Invalid file selection.'));
    const paths = files.map((file) => webUtils.getPathForFile(file));
    if (paths.some((path) => !path)) return Promise.reject(new Error('A dropped file must be backed by a local file.'));
    return ipcRenderer.invoke('vault:import-drop', { sessionId, folderId, paths });
  },
  moveItem: (input: MoveItem) => ipcRenderer.invoke('vault:move-item', input),
  setEditingContext: (context: EditingContext) => ipcRenderer.send('app:editing-context', context),
  onCommand: (callback: (command: AppCommand) => void) => subscribe('app:command', callback),
  onVaultChanged: (callback: (snapshot: VaultSnapshot) => void) => subscribe('vault:changed', callback),
  closeVault: (sessionId: string) => ipcRenderer.invoke('vault:close', { sessionId }),
  checkPassword: (sessionId: string, password: string) => ipcRenderer.invoke('hibp:check', { sessionId, password }),
  copySecret: (value: string, clearSeconds: number) => ipcRenderer.invoke('clipboard:copy', { value, clearSeconds }),
  startSshTerminal: (request: SshTerminalStartRequest) => ipcRenderer.invoke('ssh-terminal:start', request),
  writeSshTerminal: (terminalId: string, data: string) => ipcRenderer.invoke('ssh-terminal:write', { terminalId, data }),
  resizeSshTerminal: (terminalId: string, cols: number, rows: number) => ipcRenderer.invoke('ssh-terminal:resize', { terminalId, cols, rows }),
  closeSshTerminal: (terminalId: string) => ipcRenderer.invoke('ssh-terminal:close', { terminalId }),
  showSshTerminalContextMenu: (terminalId: string, selection: string, clearSeconds: number) => ipcRenderer.invoke('ssh-terminal:context-menu', { terminalId, selection, clearSeconds }),
  onSshTerminalData: (callback: (event: SshTerminalDataEvent) => void) => subscribe('ssh-terminal:data', callback),
  onSshTerminalClosed: (callback: (event: SshTerminalClosedEvent) => void) => subscribe('ssh-terminal:closed', callback),
  onSshTerminalSelectAll: (callback: (terminalId: string) => void) => subscribe('ssh-terminal:select-all', callback),
  setColorTheme: (theme: 'light' | 'dark') => ipcRenderer.invoke('app:set-theme', theme),
  notifyActivity: () => ipcRenderer.send('app:activity'),
  onOpenPaths: (callback: (paths: string[]) => void) => subscribe('app:open-paths', callback),
  onLock: (callback: () => void) => subscribe('app:lock', callback),
  onVaultLocked: (callback: (sessionId: string) => void) => subscribe('app:vault-locked', callback),
  platform: 'win32'
});

contextBridge.exposeInMainWorld('myNotes', api);

function subscribe<T>(channel: string, callback: (payload: T) => void): () => void {
  const listener = (_event: Electron.IpcRendererEvent, payload: T) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}
