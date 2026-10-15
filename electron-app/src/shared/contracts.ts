export type RecordType = 0 | 1 | 2 | 3 | 4;

export interface CustomField {
  name: string;
  value: string;
  isSecret: boolean;
}

export interface SshProfile {
  host: string;
  port: number;
  userName: string;
  authenticationKind: 0 | 1;
  password: string;
  privateKeyPem: string;
  privateKeyPassphrase: string;
  hostKeySha256: string;
  allowLegacyAlgorithms: boolean;
}

export interface VaultFolder {
  id: string;
  parentId: string | null;
  name: string;
  isDeleted: boolean;
  deletedUtc: string | null;
}

export interface VaultRecord {
  id: string;
  folderId: string;
  type: RecordType;
  name: string;
  userName: string;
  email: string;
  password: string;
  url: string;
  notes: string;
  ssh: SshProfile | null;
  customFields: CustomField[];
  breach: {
    status: 0 | 1 | 2 | 3;
    occurrenceCount: number;
    checkedUtc: string | null;
    compromisedSaveConfirmed: boolean;
  };
  isDeleted: boolean;
  deletedUtc: string | null;
  modifiedUtc: string;
}

export interface VaultDocument {
  rootFolderId: string;
  folders: VaultFolder[];
  records: VaultRecord[];
  settings: {
    hibpConsent: boolean;
    clipboardClearSeconds: number;
    autoLockMinutes: number;
    sessionLanguage: string;
    notesWorkspace?: NotesWorkspace;
  };
  modifiedUtc: string;
}

export interface VaultSnapshot {
  revision: number;
  sessionId: string;
  path: string;
  displayName: string;
  document: VaultDocument;
}

export interface NotesWorkspace {
  openRecordIds: string[];
  activeRecordId: string | null;
  autoOpen: boolean;
}

export interface NoteView {
  sessionId: string;
  recordId: string;
  title: string;
  text: string;
}

export interface NotesViewState { tabs: NoteView[]; activeKey: string | null; theme: 'light' | 'dark' }
export interface NoteUpdate extends NoteView { baseTitle: string; baseText: string }
export type AppCommand = 'save' | 'open' | 'new-note' | 'new-folder' | 'close-tab' | 'next-tab' | 'previous-tab' | 'find';
export type EditingContext = 'text' | 'terminal' | 'none';
export interface MoveItem { sessionId: string; kind: 'folder' | 'record'; id: string; targetFolderId: string }

export interface NoteEditorApi {
  getState(): Promise<NotesViewState>;
  updateNote(input: NoteUpdate): Promise<NotesViewState>;
  activateTab(sessionId: string, recordId: string): Promise<void>;
  closeTab(sessionId: string, recordId: string): Promise<void>;
  finishClose(): Promise<void>;
  cancelClose(): Promise<void>;
  setEditingContext(context: EditingContext): void;
  notifyActivity(): void;
  onState(callback: (state: NotesViewState) => void): () => void;
  onCommand(callback: (command: AppCommand) => void): () => void;
  onCloseRequested(callback: () => void): () => void;
}

export interface SshTerminalStartRequest {
  terminalId: string;
  vaultSessionId: string;
  recordId: string;
  cols: number;
  rows: number;
}

export type SshTerminalStartResult =
  | { status: 'connected'; fingerprint: string }
  | { status: 'hostKeyMismatch'; fingerprint: string }
  | { status: 'failed'; reason: SshConnectionFailureReason }
  | { status: 'cancelled'; fingerprint: string | null };

export type SshConnectionFailureReason =
  | 'dns'
  | 'refused'
  | 'timeout'
  | 'authentication'
  | 'algorithms'
  | 'kexAlgorithm'
  | 'hostKeyAlgorithm'
  | 'cipherAlgorithm'
  | 'macAlgorithm'
  | 'compressionAlgorithm'
  | 'clientConfiguration'
  | 'strictKex'
  | 'signatureVerification'
  | 'hostKeyProtocol'
  | 'keyExchangeComputation'
  | 'malformedHandshake'
  | 'protocolHandshake'
  | 'shell'
  | 'privateKey'
  | 'network';

export interface SshTerminalDataEvent {
  terminalId: string;
  data: string;
}

export interface SshTerminalClosedEvent {
  terminalId: string;
  reason: 'closed' | 'error';
}

export type HibpResult =
  | { status: 'notFound'; occurrenceCount: 0 }
  | { status: 'compromised'; occurrenceCount: number }
  | { status: 'failed'; occurrenceCount: 0; reason: string };

export interface RecentVault {
  id: string;
  path: string;
  lastOpenedUtc: string;
}

export interface VaultHistory {
  entries: RecentVault[];
  order: 'recent' | 'manual';
  persisted: boolean;
}

export interface MyNotesApi {
  getStartupState(): Promise<{ paths: string[]; history: VaultHistory }>;
  listRecentVaults(): Promise<VaultHistory>;
  reorderRecentVaults(ids: string[]): Promise<VaultHistory>;
  removeRecentVault(id: string): Promise<VaultHistory>;
  sortRecentVaults(): Promise<VaultHistory>;
  chooseVaultToOpen(): Promise<string | null>;
  chooseVaultToCreate(): Promise<string | null>;
  openVault(path: string, password: string): Promise<VaultSnapshot>;
  createVault(path: string, password: string): Promise<VaultSnapshot>;
  saveVault(sessionId: string, document: VaultDocument, revision: number): Promise<VaultSnapshot>;
  getVaultSnapshot(sessionId: string): Promise<VaultSnapshot>;
  openNotes(sessionId: string, recordId?: string): Promise<void>;
  importTextFiles(sessionId: string, folderId: string): Promise<VaultSnapshot | null>;
  importDroppedTextFiles(sessionId: string, folderId: string, files: File[]): Promise<VaultSnapshot>;
  moveItem(input: MoveItem): Promise<VaultSnapshot>;
  setEditingContext(context: EditingContext): void;
  onCommand(callback: (command: AppCommand) => void): () => void;
  onVaultChanged(callback: (snapshot: VaultSnapshot) => void): () => void;
  closeVault(sessionId: string): Promise<void>;
  checkPassword(sessionId: string, password: string): Promise<HibpResult>;
  copySecret(value: string, clearSeconds: number): Promise<void>;
  startSshTerminal(request: SshTerminalStartRequest): Promise<SshTerminalStartResult>;
  writeSshTerminal(terminalId: string, data: string): Promise<void>;
  resizeSshTerminal(terminalId: string, cols: number, rows: number): Promise<void>;
  closeSshTerminal(terminalId: string): Promise<void>;
  showSshTerminalContextMenu(terminalId: string, selection: string, clearSeconds: number): Promise<void>;
  onSshTerminalData(callback: (event: SshTerminalDataEvent) => void): () => void;
  onSshTerminalClosed(callback: (event: SshTerminalClosedEvent) => void): () => void;
  onSshTerminalSelectAll(callback: (terminalId: string) => void): () => void;
  setColorTheme(theme: 'light' | 'dark'): Promise<void>;
  notifyActivity(): void;
  onOpenPaths(callback: (paths: string[]) => void): () => void;
  onLock(callback: () => void): () => void;
  onVaultLocked(callback: (sessionId: string) => void): () => void;
  platform: 'win32';
}

declare global {
  interface Window {
    myNotes: MyNotesApi;
    noteEditor: NoteEditorApi;
  }
}
