import { contextBridge, ipcRenderer } from 'electron';
import type { PasswordManagerApi, SshTerminalClosedEvent, SshTerminalDataEvent, SshTerminalStartRequest, VaultDocument } from '../shared/contracts.js';

const api: PasswordManagerApi = Object.freeze({
  chooseVaultToOpen: () => ipcRenderer.invoke('vault:choose-open'),
  chooseVaultToCreate: () => ipcRenderer.invoke('vault:choose-create'),
  openVault: (path: string, password: string) => ipcRenderer.invoke('vault:open', { path, password }),
  createVault: (path: string, password: string) => ipcRenderer.invoke('vault:create', { path, password }),
  saveVault: (sessionId: string, document: VaultDocument) => ipcRenderer.invoke('vault:save', { sessionId, document }),
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

contextBridge.exposeInMainWorld('passwordManager', api);

function subscribe<T>(channel: string, callback: (payload: T) => void): () => void {
  const listener = (_event: Electron.IpcRendererEvent, payload: T) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}
