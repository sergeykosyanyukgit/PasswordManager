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
import { CONTENT_SECURITY_POLICY } from '../shared/content-security-policy.js';
import type { SshProfile, SshTerminalStartRequest, SshTerminalStartResult } from '../shared/contracts.js';

protocol.registerSchemesAsPrivileged([{ scheme: 'pmapp', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false } }]);

const gotLock = app.requestSingleInstanceLock({ paths: safeVaultPaths(process.argv.slice(1)) });
if (!gotLock) app.quit();

const store = new VaultStore();
const sshTerminals = new SshTerminalManager((channel, event) => mainWindow?.webContents.send(channel, event));
let mainWindow: BrowserWindow | null = null;
let lastActivity = Date.now();
let idleLockRunning = false;
let quitting = false;
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
  if (process.platform !== 'win32') throw new Error('PasswordManager supports Windows only.');
  await registerLocalProtocol();
  configureSession();
  registerIpc();
  createMainWindow();
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  powerMonitor.on('shutdown', lockAll);
  setInterval(() => { void lockIdleVaults().catch(() => undefined); }, 15_000).unref();
});

app.on('before-quit', () => { quitting = true; void sshTerminals.closeAll(); void store.closeAll(); });
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
    title: 'PasswordManager',
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
  mainWindow.webContents.on('will-navigate', (event) => event.preventDefault());
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());
  mainWindow.webContents.on('did-finish-load', () => {
    const initialPaths = safeVaultPaths(process.argv.slice(1));
    if (initialPaths.length > 0) mainWindow?.webContents.send('app:open-paths', initialPaths);
  });
  mainWindow.once('ready-to-show', () => mainWindow?.show());
  mainWindow.on('closed', () => { mainWindow = null; if (!quitting) { void sshTerminals.closeAll(); void store.closeAll(); } });
  void mainWindow.loadURL('pmapp://local/index.html');
}

function registerIpc(): void {
  const credentials = z.object({ path: z.string().min(1).max(32_768), password: z.string().max(1_000_000) }).strict();
  const sessionId = z.string().uuid();
  ipcMain.handle('vault:choose-open', trusted(async () => {
    const result = await dialog.showOpenDialog(mainWindow!, { title: 'Open vault', properties: ['openFile'], filters: [{ name: 'PasswordManager vault', extensions: ['pmvault'] }] });
    return result.canceled ? null : result.filePaths[0] ?? null;
  }));
  ipcMain.handle('vault:choose-create', trusted(async () => {
    const result = await dialog.showSaveDialog(mainWindow!, { title: 'Create vault', defaultPath: 'My vault.pmvault', filters: [{ name: 'PasswordManager vault', extensions: ['pmvault'] }] });
    return result.canceled ? null : result.filePath ?? null;
  }));
  ipcMain.handle('vault:open', trusted(async (_event, input) => { const value = credentials.parse(input); return store.open(value.path, value.password); }));
  ipcMain.handle('vault:create', trusted(async (_event, input) => { const value = credentials.parse(input); return store.create(value.path, value.password); }));
  ipcMain.handle('vault:save', trusted(async (_event, input: unknown) => {
    if (!input || typeof input !== 'object' || !('sessionId' in input) || !('document' in input)) throw new Error('Invalid save request.');
    const id = sessionId.parse(input.sessionId);
    await store.save(id, input.document as never);
  }));
  ipcMain.handle('vault:close', trusted(async (_event, input) => { const value = z.object({ sessionId }).strict().parse(input); await sshTerminals.closeByVault(value.sessionId); await store.close(value.sessionId); }));
  ipcMain.handle('hibp:check', trusted(async (_event, input) => {
    const value = z.object({ sessionId, password: z.string().min(1).max(1_000_000) }).strict().parse(input);
    if (!store.hasHibpConsent(value.sessionId)) {
      const consent = await dialog.showMessageBox(mainWindow!, {
        type: 'question',
        title: 'Проверка пароля в Have I Been Pwned',
        message: 'Разрешить сетевую проверку завершённого пароля?',
        detail: 'Будут отправлены только первые 5 символов SHA-1. Сам пароль и полный хеш не передаются. Согласие сохранится внутри зашифрованного сейфа.',
        buttons: ['Разрешить проверку', 'Отмена'],
        defaultId: 1,
        cancelId: 1,
        noLink: true
      });
      if (consent.response !== 0) return { status: 'failed', occurrenceCount: 0, reason: 'ConsentDeclined' } as const;
      await store.grantHibpConsent(value.sessionId);
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
  }));
  ipcMain.on('app:activity', (event) => { assertTrustedSender(event); lastActivity = Date.now(); });
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
      detail: `SHA-256 отпечаток ключа сервера:\n${result.fingerprint}\n\nСверьте отпечаток с администратором сервера. Сохранить его в зашифрованном сейфе и продолжить?`,
      buttons: ['Доверять и подключиться', 'Отмена'],
      defaultId: 1,
      cancelId: 1,
      noLink: true
    });
    if (confirmation.response !== 0) return { status: 'cancelled', fingerprint: result.fingerprint };
    const currentProfile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(profile, currentProfile)) throw new Error('SSH record changed during host-key confirmation.');
    await store.setSshHostKey(request.vaultSessionId, request.recordId, result.fingerprint);
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
  return (event: Electron.IpcMainInvokeEvent, ...args: T) => { assertTrustedSender(event); lastActivity = Date.now(); return handler(event, ...args); };
}

function assertTrustedSender(event: Electron.IpcMainEvent | Electron.IpcMainInvokeEvent): void {
  const url = new URL(event.senderFrame?.url ?? 'about:blank');
  if (url.protocol !== 'pmapp:' || url.hostname !== 'local') throw new Error('Untrusted IPC sender.');
}

async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
}

async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
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
