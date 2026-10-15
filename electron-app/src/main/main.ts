import { app, BrowserWindow, clipboard, dialog, ipcMain, Menu, nativeTheme, net, powerMonitor, protocol, session } from 'electron';
import { createHash, timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import { dirname, extname, isAbsolute, join, normalize, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import { VaultStore } from './vault/storage.js';
import { checkPwnedPassword } from './services/hibp.js';
import { SshTerminalManager } from './services/ssh-terminal.js';
import { configureCaptureProtection } from './services/capture-protection.js';
import { VaultHistoryStore } from './services/vault-history.js';
import { NotesWorkspaceService, noteReferenceSchema } from './services/notes-workspace.js';
import { addTextImports, moveSchema, moveVaultItem, readTextImports } from './services/vault-items.js';
import { installWindowBehavior, setEditingContext } from './services/window-behavior.js';
import { isTrustedRenderer } from './services/ipc-sender.js';
import { CONTENT_SECURITY_POLICY } from '../shared/content-security-policy.js';
import type { SshProfile, SshTerminalStartRequest, SshTerminalStartResult, VaultDocument, VaultSnapshot } from '../shared/contracts.js';

protocol.registerSchemesAsPrivileged([{ scheme: 'pmapp', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false } }]);
app.setName('MyNotes');

const gotLock = app.requestSingleInstanceLock({ paths: safeVaultPaths(process.argv.slice(1)) });
if (!gotLock) app.quit();

const store = new VaultStore();
const notes = new NotesWorkspaceService(store, publishSnapshot);
let notesWindow: BrowserWindow | null = null;
let notesCloseIntent: 'manual' | 'app' | null = null;
let notesCloseTimer: ReturnType<typeof setTimeout> | null = null;
let vaultHistory: VaultHistoryStore;
const sshTerminals = new SshTerminalManager((channel, event) => mainWindow?.webContents.send(channel, event));
let mainWindow: BrowserWindow | null = null;
let lastActivity = Date.now();
let idleLockRunning = false;
let quitting = false;
let lifecycleEpoch = 0;
const MAXIMUM_TERMINAL_CLIPBOARD_TEXT = 1024 * 1024;

app.on('second-instance', (_event, argv, _cwd, data) => {
  if (!mainWindow) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
  const supplied = typeof data === 'object' && data && 'paths' in data && Array.isArray(data.paths) ? data.paths : argv;
  const paths = safeVaultPaths(supplied.filter((item): item is string => typeof item === 'string'));
  if (paths.length > 0) mainWindow.webContents.send('app:open-paths', paths);
});

app.whenReady().then(async () => {
  if (process.platform !== 'win32') throw new Error('MyNotes supports Windows only.');
  vaultHistory = new VaultHistoryStore(join(app.getPath('userData'), 'vault-history.json'));
  await registerLocalProtocol();
  configureSession();
  registerIpc();
  createMainWindow();
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  powerMonitor.on('shutdown', lockAll);
  setInterval(() => { void lockIdleVaults().catch(() => undefined); }, 15_000).unref();
});

app.on('before-quit', (event) => {
  if (!quitting && notesWindow) { event.preventDefault(); requestNotesClose('app'); return; }
  quitting = true;
  lifecycleEpoch++;
  destroyNotesWindow();
  void sshTerminals.closeAll(); void store.closeAll();
});
app.on('window-all-closed', () => app.quit());

async function registerLocalProtocol(): Promise<void> {
  const rendererRoot = resolve(app.getAppPath(), 'dist', 'renderer');
  protocol.handle('pmapp', async (request) => {
    const url = new URL(request.url);
    if (url.hostname !== 'local' || request.method !== 'GET') return new Response('Denied', { status: 403 });
    const requested = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
    const filePath = resolve(rendererRoot, `.${normalize(requested)}`);
    const relation = relative(rendererRoot, filePath);
    if (relation.startsWith('..') || isAbsolute(relation)) return new Response('Denied', { status: 403 });
    return net.fetch(pathToFileURL(filePath).toString());
  });
}

function configureSession(): void {
  session.defaultSession.on('will-download', (event) => event.preventDefault());
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': [CONTENT_SECURITY_POLICY],
      'X-Content-Type-Options': ['nosniff']
    }
  }));
}

function createMainWindow(): void {
  const useDarkTheme = nativeTheme.shouldUseDarkColors;
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 820,
    minWidth: 980,
    minHeight: 640,
    show: false,
    backgroundColor: useDarkTheme ? '#202020' : '#f3f3f3',
    title: 'MyNotes',
    icon: join(app.getAppPath(), 'dist', 'icon.ico'),
    titleBarStyle: 'hidden',
    titleBarOverlay: useDarkTheme
      ? { color: '#202020', symbolColor: '#f1f1f1', height: 46 }
      : { color: '#f3f3f3', symbolColor: '#202020', height: 46 },
    webPreferences: {
      preload: join(app.getAppPath(), 'dist', 'preload', 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      devTools: !app.isPackaged,
      webviewTag: false
    }
  });
  mainWindow.setMenu(null);
  try {
    // Replaced with a literal by the build script; runtime environment and IPC
    // cannot turn an ordinary build into a screenshot diagnostic build.
    configureCaptureProtection(mainWindow, process.env.PM_SCREENSHOT_DIAGNOSTICS === '1');
  } catch (error) {
    mainWindow = null;
    throw error;
  }
  mainWindow.setBackgroundMaterial('mica');
  installWindowBehavior(mainWindow, (command) => mainWindow?.webContents.send('app:command', command), scheduleNativeClipboardClear);
  mainWindow.on('close', (event) => { if (!quitting && notesWindow) { event.preventDefault(); requestNotesClose('app'); } });
  mainWindow.once('ready-to-show', () => mainWindow?.show());
  mainWindow.on('closed', () => { mainWindow = null; if (!quitting) { void sshTerminals.closeAll(); void store.closeAll(); } });
  void mainWindow.loadURL('pmapp://local/index.html');
}

function registerIpc(): void {
  ipcMain.handle('app:startup', trusted(async () => ({ paths: safeVaultPaths(process.argv.slice(1)), history: await vaultHistory.list() })));
  const credentials = z.object({ path: z.string().min(1).max(32_768), password: z.string().max(1_000_000) }).strict();
  const sessionId = z.string().uuid();
  ipcMain.handle('vault:choose-open', trusted(async () => {
    const result = await dialog.showOpenDialog(mainWindow!, { title: 'Открыть хранилище MyNotes', properties: ['openFile'], filters: [{ name: 'Хранилище MyNotes', extensions: ['pmvault'] }] });
    return result.canceled ? null : result.filePaths[0] ?? null;
  }));
  ipcMain.handle('vault:choose-create', trusted(async () => {
    const result = await dialog.showSaveDialog(mainWindow!, { title: 'Создать хранилище MyNotes', defaultPath: 'Мои заметки.pmvault', filters: [{ name: 'Хранилище MyNotes', extensions: ['pmvault'] }] });
    return result.canceled ? null : result.filePath ?? null;
  }));
  ipcMain.handle('vault:open', trusted(async (_event, input) => {
    const epoch = lifecycleEpoch;
    const value = credentials.parse(input);
    const snapshot = await store.open(value.path, value.password);
    try {
      if (epoch !== lifecycleEpoch || quitting) throw new Error('Unlock cancelled by lock.');
      await vaultHistory.recordOpened(snapshot.path);
      if (epoch !== lifecycleEpoch || quitting) throw new Error('Unlock cancelled by lock.');
      if (notes.restore(snapshot)) showNotesWindow();
    }
    catch (error) { forgetNotesVault(snapshot.sessionId); await store.close(snapshot.sessionId); throw error; }
    return snapshot;
  }));
  ipcMain.handle('vault:create', trusted(async (_event, input) => {
    const epoch = lifecycleEpoch;
    const value = credentials.parse(input);
    const snapshot = await store.create(value.path, value.password);
    try {
      if (epoch !== lifecycleEpoch || quitting) throw new Error('Creation interrupted by lock.');
      await vaultHistory.recordOpened(snapshot.path);
      if (epoch !== lifecycleEpoch || quitting) throw new Error('Creation interrupted by lock.');
    } catch (error) { await store.close(snapshot.sessionId); throw error; }
    return snapshot;
  }));
  ipcMain.handle('history:list', trusted(async () => vaultHistory.list()));
  ipcMain.handle('history:reorder', trusted(async (_event, input: unknown) => vaultHistory.reorder(input)));
  ipcMain.handle('history:remove', trusted(async (_event, input: unknown) => vaultHistory.remove(input)));
  ipcMain.handle('history:sort-recent', trusted(async () => vaultHistory.useRecentOrder()));
  ipcMain.handle('vault:save', trusted(async (_event, input: unknown) => {
    const value = z.object({ sessionId, revision: z.number().int().nonnegative(), document: z.unknown() }).strict().parse(input);
    const snapshot = await store.save(value.sessionId, value.document as VaultDocument, value.revision);
    publishSnapshot(snapshot);
    return snapshot;
  }));
  ipcMain.handle('vault:snapshot', trusted(async (_event, input) => store.getSnapshot(sessionId.parse(input))));
  ipcMain.handle('vault:close', trusted(async (_event, input) => { const value = z.object({ sessionId }).strict().parse(input); forgetNotesVault(value.sessionId); await Promise.all([store.close(value.sessionId), sshTerminals.closeByVault(value.sessionId)]); }));
  ipcMain.handle('notes:open', trusted(async (_event, input) => {
    const epoch = lifecycleEpoch;
    const value = z.object({ sessionId, recordId: z.string().uuid().optional() }).strict().parse(input);
    await notes.open(value.sessionId, value.recordId);
    if (epoch !== lifecycleEpoch || quitting) { notes.forget(value.sessionId); throw new Error('Notes opening interrupted by lock.'); }
    store.getSnapshot(value.sessionId); showNotesWindow();
  }));
  ipcMain.handle('notes:state', trustedNotes(async () => notes.state()));
  ipcMain.handle('notes:update', trustedNotes(async (_event, input: unknown) => notes.update(input)));
  ipcMain.handle('notes:activate', trustedNotes(async (_event, input: unknown) => { await notes.activate(noteReferenceSchema.parse(input)); }));
  ipcMain.handle('notes:close-tab', trustedNotes(async (_event, input: unknown) => { await notes.closeTab(noteReferenceSchema.parse(input)); }));
  ipcMain.handle('notes:finish-close', trustedNotes(async () => {
    const intent = notesCloseIntent;
    if (!intent) throw new Error('No window close is pending.');
    if (intent === 'manual') await notes.manualClose();
    destroyNotesWindow();
    if (intent === 'app') { quitting = true; app.quit(); }
  }));
  ipcMain.handle('notes:cancel-close', trustedNotes(async () => {
    if (notesCloseTimer) clearTimeout(notesCloseTimer);
    notesCloseTimer = null; notesCloseIntent = null;
  }));
  ipcMain.handle('vault:move-item', trusted(async (_event, input: unknown) => {
    const value = moveSchema.parse(input);
    const snapshot = await store.mutate(value.sessionId, (document) => moveVaultItem(document, value));
    publishSnapshot(snapshot); return snapshot;
  }));
  const importTarget = z.object({ sessionId, folderId: z.string().uuid() }).strict();
  ipcMain.handle('vault:import-text', trusted(async (_event, input: unknown) => {
    const value = importTarget.parse(input);
    store.getSnapshot(value.sessionId);
    const result = await dialog.showOpenDialog(mainWindow!, { title: 'Импорт текстовых документов', properties: ['openFile', 'multiSelections'], filters: [{ name: 'Текстовые документы', extensions: ['txt'] }] });
    if (result.canceled) return null;
    return importText(value.sessionId, value.folderId, result.filePaths);
  }));
  ipcMain.handle('vault:import-drop', trusted(async (_event, input: unknown) => {
    const value = importTarget.extend({ paths: z.array(z.string().min(1).max(32_768)).min(1).max(32) }).strict().parse(input);
    return importText(value.sessionId, value.folderId, value.paths);
  }));
  ipcMain.handle('hibp:check', trusted(async (_event, input) => {
    const value = z.object({ sessionId, password: z.string().min(1).max(1_000_000) }).strict().parse(input);
    if (!store.hasHibpConsent(value.sessionId)) {
      const consent = await dialog.showMessageBox(mainWindow!, {
        type: 'question',
        title: 'Проверка пароля в Have I Been Pwned',
        message: 'Разрешить сетевую проверку завершённого пароля?',
        detail: 'Будут отправлены только первые 5 символов SHA-1. Сам пароль и полный хеш не передаются. Согласие сохранится внутри зашифрованного хранилища.',
        buttons: ['Разрешить проверку', 'Отмена'],
        defaultId: 1,
        cancelId: 1,
        noLink: true
      });
      if (consent.response !== 0) return { status: 'failed', occurrenceCount: 0, reason: 'ConsentDeclined' } as const;
      await store.grantHibpConsent(value.sessionId);
      publishSnapshot(store.getSnapshot(value.sessionId));
    }
    return checkPwnedPassword(value.password);
  }));
  ipcMain.handle('clipboard:copy', trusted(async (_event, input) => {
    const value = z.object({ value: z.string().max(16 * 1024 * 1024), clearSeconds: z.number().int().min(5).max(600) }).strict().parse(input);
    await writeClipboardWithConditionalClear(value.value, value.clearSeconds);
  }));
  ipcMain.handle('ssh-terminal:start', trusted(async (_event, input: unknown) => startSshTerminal(input)));
  ipcMain.handle('ssh-terminal:write', trusted(async (_event, input: unknown) => sshTerminals.write(input)));
  ipcMain.handle('ssh-terminal:resize', trusted(async (_event, input: unknown) => sshTerminals.resize(input)));
  ipcMain.handle('ssh-terminal:close', trusted(async (_event, input: unknown) => sshTerminals.close(input)));
  ipcMain.handle('ssh-terminal:context-menu', trusted(async (_event, input: unknown) => {
    const value = z.object({ terminalId: z.string().uuid(), selection: z.string().max(MAXIMUM_TERMINAL_CLIPBOARD_TEXT), clearSeconds: z.number().int().min(5).max(600) }).strict().parse(input);
    const menu = Menu.buildFromTemplate([
      { label: 'Копировать', accelerator: 'Ctrl+Shift+C', enabled: value.selection.length > 0, click: () => { void writeClipboardWithConditionalClear(value.selection, value.clearSeconds); } },
      { label: 'Вставить', accelerator: 'Ctrl+Shift+V', click: () => { void pasteClipboardToTerminal(value.terminalId).catch(() => undefined); } },
      { type: 'separator' },
      { label: 'Выделить всё', accelerator: 'Ctrl+Shift+A', click: () => mainWindow?.webContents.send('ssh-terminal:select-all', value.terminalId) }
    ]);
    menu.popup({ window: mainWindow ?? undefined });
  }));
  ipcMain.handle('app:set-theme', trusted(async (_event, input: unknown) => {
    const theme = z.enum(['light', 'dark']).parse(input);
    const dark = theme === 'dark';
    mainWindow?.setBackgroundColor(dark ? '#202020' : '#f3f3f3');
    mainWindow?.setTitleBarOverlay({ color: dark ? '#202020' : '#f3f3f3', symbolColor: dark ? '#f1f1f1' : '#202020', height: 46 });
    notes.theme = theme;
    notesWindow?.setBackgroundColor(dark ? '#202020' : '#f8f8f8');
    sendNotesState();
  }));
  ipcMain.on('app:activity', (event) => { try { assertTrustedSender(event, 'either'); lastActivity = Date.now(); } catch { /* Drop stale or untrusted one-way messages. */ } });
  ipcMain.on('app:editing-context', (event, input: unknown) => { try { assertTrustedSender(event, 'either'); setEditingContext(event.sender, z.enum(['text', 'terminal', 'none']).parse(input)); } catch { /* No action for stale frames or invalid contexts. */ } });
}

async function importText(sessionId: string, folderId: string, paths: unknown): Promise<VaultSnapshot> {
  store.getSnapshot(sessionId);
  const imports = await readTextImports(paths);
  const snapshot = await store.mutate(sessionId, (document) => addTextImports(document, folderId, imports));
  publishSnapshot(snapshot); return snapshot;
}

function publishSnapshot(snapshot: VaultSnapshot): void {
  mainWindow?.webContents.send('vault:changed', snapshot);
  sendNotesState();
}

function sendNotesState(): void { if (notesWindow && !notesWindow.isDestroyed()) notesWindow.webContents.send('notes:state-changed', notes.state()); }

function showNotesWindow(): void {
  if (notesWindow) { if (notesWindow.isMinimized()) notesWindow.restore(); notesWindow.show(); notesWindow.focus(); sendNotesState(); return; }
  const window = new BrowserWindow({ width: 900, height: 720, minWidth: 500, minHeight: 380, show: false,
    title: 'Заметки — MyNotes', backgroundColor: notes.theme === 'dark' ? '#202020' : '#f8f8f8', icon: join(app.getAppPath(), 'dist', 'icon.ico'),
    webPreferences: { preload: join(app.getAppPath(), 'dist', 'preload', 'notes-preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false, webviewTag: false, webSecurity: true, allowRunningInsecureContent: false, devTools: !app.isPackaged }
  });
  configureCaptureProtection(window, process.env.PM_SCREENSHOT_DIAGNOSTICS === '1');
  notesWindow = window;
  window.setMenu(null);
  installWindowBehavior(window, (command) => window.webContents.send('app:command', command), scheduleNativeClipboardClear);
  window.on('close', (event) => { event.preventDefault(); requestNotesClose('manual'); });
  window.on('closed', () => { if (notesWindow === window) notesWindow = null; });
  window.once('ready-to-show', () => window.show());
  void window.loadURL('pmapp://local/notes.html');
}

function requestNotesClose(intent: 'manual' | 'app'): void {
  if (!notesWindow) return;
  if (notesCloseIntent) { if (intent === 'app') notesCloseIntent = 'app'; return; }
  notesCloseIntent = intent;
  notesWindow.webContents.send('notes:close-requested');
  notesCloseTimer = setTimeout(() => { notesCloseIntent = null; notesCloseTimer = null; }, 10_000);
}

function destroyNotesWindow(): void {
  if (notesCloseTimer) clearTimeout(notesCloseTimer);
  notesCloseTimer = null; notesCloseIntent = null;
  const window = notesWindow; notesWindow = null;
  window?.destroy(); notes.clear();
}

function forgetNotesVault(sessionId: string): void {
  // Remove secret-bearing note views synchronously, before awaiting I/O or SSH shutdown.
  notes.forget(sessionId);
  if (!notes.hasSessions) destroyNotesWindow(); else sendNotesState();
}

function scheduleNativeClipboardClear(): void {
  setTimeout(async () => {
    try {
      const value = await clipboard.readText();
      if (!value) return;
      const expected = createHash('sha256').update(value, 'utf8').digest();
      setTimeout(() => { void clearClipboardIfUnchanged(expected).catch(() => undefined); }, 30_000).unref();
    } catch { /* Clipboard can be temporarily unavailable; never print its contents. */ }
  }, 50).unref();
}

async function startSshTerminal(input: unknown): Promise<SshTerminalStartResult> {
  const request = z.object({
    terminalId: z.string().uuid(),
    vaultSessionId: z.string().uuid(),
    recordId: z.string().uuid(),
    cols: z.number().int().min(20).max(500),
    rows: z.number().int().min(5).max(300)
  }).strict().parse(input) as SshTerminalStartRequest;
  let profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!(await confirmSshDestination(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  if (profile.allowLegacyAlgorithms && !(await confirmLegacySshAlgorithms(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  const approvedProfile = profile;
  profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!sameSshTarget(approvedProfile, profile)) throw new Error('SSH record changed during confirmation.');
  const runtime = { terminalId: request.terminalId, vaultSessionId: request.vaultSessionId, cols: request.cols, rows: request.rows };
  let result = await sshTerminals.start(runtime, profile);
  if (result.status === 'hostKeyRequired') {
    const confirmation = await dialog.showMessageBox(mainWindow!, {
      type: 'warning',
      title: 'Проверка ключа SSH-сервера',
      message: `Первое подключение к ${profile.host}:${profile.port}`,
      detail: `SHA-256 отпечаток ключа сервера:\n${result.fingerprint}\n\nСверьте отпечаток с администратором сервера. Сохранить его в зашифрованном хранилище и продолжить?`,
      buttons: ['Доверять и подключиться', 'Отмена'],
      defaultId: 1,
      cancelId: 1,
      noLink: true
    });
    if (confirmation.response !== 0) return { status: 'cancelled', fingerprint: result.fingerprint };
    const currentProfile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(profile, currentProfile)) throw new Error('SSH record changed during host-key confirmation.');
    await store.setSshHostKey(request.vaultSessionId, request.recordId, result.fingerprint);
    publishSnapshot(store.getSnapshot(request.vaultSessionId));
    const approvedPinnedProfile: SshProfile = { ...profile, hostKeySha256: result.fingerprint };
    profile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(approvedPinnedProfile, profile)) throw new Error('SSH record changed while the host key was being saved.');
    result = await sshTerminals.start(runtime, profile);
  }
  if (result.status === 'hostKeyRequired') throw new Error('SSH host key was not persisted.');
  return result;
}

function sameSshTarget(left: SshProfile, right: SshProfile): boolean {
  return left.host === right.host && left.port === right.port && left.userName === right.userName && left.authenticationKind === right.authenticationKind && left.hostKeySha256 === right.hostKeySha256 && left.allowLegacyAlgorithms === right.allowLegacyAlgorithms;
}

async function confirmLegacySshAlgorithms(profile: SshProfile): Promise<boolean> {
  const confirmation = await dialog.showMessageBox(mainWindow!, {
    type: 'warning',
    title: 'Устаревшие SSH-алгоритмы',
    message: `Сервер ${profile.host}:${profile.port} требует режим совместимости`,
    detail: 'Будут разрешены крайне устаревшие Group1/SHA-1, DSA, 3DES/AES-CBC, MD5/SHA-1 MAC и zlib-сжатие. Они существенно слабее современных алгоритмов. Используйте режим только для известного изолированного сервера и обязательно сверяйте SHA-256 отпечаток его ключа. RC4 по-прежнему запрещён.',
    buttons: ['Подключиться в режиме совместимости', 'Отмена'],
    defaultId: 1,
    cancelId: 1,
    noLink: true
  });
  return confirmation.response === 0;
}

async function confirmSshDestination(profile: SshProfile): Promise<boolean> {
  const fingerprint = profile.hostKeySha256 ? `\nЗакреплённый ключ: ${profile.hostKeySha256}` : '\nКлюч сервера ещё не закреплён.';
  const confirmation = await dialog.showMessageBox(mainWindow!, {
    type: 'question',
    title: 'SSH-подключение',
    message: `Подключиться к ${profile.userName}@${profile.host}:${profile.port}?`,
    detail: `Приложение откроет прямое SSH-соединение от имени сохранённой записи.${fingerprint}`,
    buttons: ['Подключиться', 'Отмена'],
    defaultId: 1,
    cancelId: 1,
    noLink: true
  });
  return confirmation.response === 0;
}

function trusted<T extends unknown[], R>(handler: (event: Electron.IpcMainInvokeEvent, ...args: T) => R | Promise<R>) {
  return async (event: Electron.IpcMainInvokeEvent, ...args: T) => {
    try { assertTrustedSender(event); lastActivity = Date.now(); return await handler(event, ...args); }
    catch { throw new Error('The requested operation could not be completed.'); }
  };
}

function assertTrustedSender(event: Electron.IpcMainEvent | Electron.IpcMainInvokeEvent, role: 'main' | 'notes' | 'either' = 'main'): void {
  const isMain = isTrustedRenderer(event, mainWindow?.webContents, '/index.html');
  const isNotes = isTrustedRenderer(event, notesWindow?.webContents, '/notes.html');
  if (!(role === 'main' ? isMain : role === 'notes' ? isNotes : isMain || isNotes)) throw new Error('Untrusted IPC sender.');
}

function trustedNotes<T extends unknown[], R>(handler: (event: Electron.IpcMainInvokeEvent, ...args: T) => R | Promise<R>) {
  return async (event: Electron.IpcMainInvokeEvent, ...args: T) => {
    try { assertTrustedSender(event, 'notes'); lastActivity = Date.now(); return await handler(event, ...args); }
    catch { throw new Error('The requested note operation could not be completed.'); }
  };
}

async function lockAll(): Promise<void> {
  lifecycleEpoch++;
  destroyNotesWindow();
  mainWindow?.webContents.send('app:lock');
  await Promise.all([store.closeAll(), sshTerminals.closeAll(), clipboard.clear()]);
}

async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      forgetNotesVault(sessionId);
      mainWindow?.webContents.send('app:vault-locked', sessionId);
      const closingVault = store.close(sessionId);
      try { await Promise.all([closingVault, sshTerminals.closeByVault(sessionId)]); }
      catch { /* Secret-bearing UI was removed before I/O and SSH shutdown. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
  } finally {
    idleLockRunning = false;
  }
}

async function pasteClipboardToTerminal(terminalId: string): Promise<void> {
  const value = await clipboard.readText();
  if (!value) return;
  if (value.length > MAXIMUM_TERMINAL_CLIPBOARD_TEXT) {
    await dialog.showMessageBox(mainWindow!, { type: 'warning', title: 'Вставка отменена', message: 'Текст в буфере обмена превышает 1 МиБ.', buttons: ['Закрыть'], noLink: true });
    return;
  }
  for (let offset = 0; offset < value.length; offset += 64 * 1024) {
    await sshTerminals.write({ terminalId, data: value.slice(offset, offset + 64 * 1024) });
  }
}

async function writeClipboardWithConditionalClear(value: string, clearSeconds: number): Promise<void> {
  const expected = createHash('sha256').update(value, 'utf8').digest();
  try {
    await clipboard.writeText(value);
    setTimeout(() => { void clearClipboardIfUnchanged(expected); }, clearSeconds * 1000).unref();
  } catch (error) {
    expected.fill(0);
    throw error;
  }
}

async function clearClipboardIfUnchanged(expected: Buffer): Promise<void> {
  let actual: Buffer | null = null;
  try {
    actual = createHash('sha256').update(await clipboard.readText(), 'utf8').digest();
    if (timingSafeEqual(actual, expected)) await clipboard.clear();
  } finally {
    actual?.fill(0);
    expected.fill(0);
  }
}

function safeVaultPaths(values: string[]): string[] {
  const result: string[] = [];
  for (const value of values.slice(0, 32)) {
    if (value.startsWith('--')) continue;
    const path = resolve(value);
    if (path.length <= 32_768 && extname(path).toLowerCase() === '.pmvault' && existsSync(path)) result.push(path);
  }
  return result;
}
