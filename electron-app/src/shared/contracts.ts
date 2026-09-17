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
  };
  modifiedUtc: string;
}

export interface VaultSnapshot {
  sessionId: string;
  path: string;
  displayName: string;
  document: VaultDocument;
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

export interface PasswordManagerApi {
  chooseVaultToOpen(): Promise<string | null>;
  chooseVaultToCreate(): Promise<string | null>;
  openVault(path: string, password: string): Promise<VaultSnapshot>;
  createVault(path: string, password: string): Promise<VaultSnapshot>;
  saveVault(sessionId: string, document: VaultDocument): Promise<void>;
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
    passwordManager: PasswordManagerApi;
  }
}
