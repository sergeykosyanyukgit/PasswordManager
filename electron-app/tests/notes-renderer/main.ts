import { app, BrowserWindow, clipboard, ipcMain, net, protocol, session } from 'electron';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import { VaultStore } from '../../src/main/vault/storage.js';
import { NotesWorkspaceService } from '../../src/main/services/notes-workspace.js';
import { addTextImports } from '../../src/main/services/vault-items.js';
import { installWindowBehavior, setEditingContext } from '../../src/main/services/window-behavior.js';
import { isTrustedRenderer } from '../../src/main/services/ipc-sender.js';

const config = JSON.parse(readFileSync(process.argv[2]!, 'utf8'));
const profile = join(config.root, `profile-${config.width}`);
mkdirSync(profile, { recursive: true }); app.setPath('userData', profile);
const checks: string[] = [];
const store = new VaultStore();
let window: BrowserWindow | undefined;
let directory: string;
let closed = false;
let holdUpdates = false;
let releaseUpdate: (() => void) | null = null;
const assert = (value: unknown, message: string) => { if (!value) throw new Error(message); checks.push(message); };
const pause = () => new Promise((done) => setTimeout(done, 70));
const until = async (check: () => boolean | Promise<boolean>) => { const end = Date.now() + 8000; while (!(await check())) { if (Date.now() > end) throw new Error('Synthetic notes condition timed out'); await pause(); } };
const notes = new NotesWorkspaceService(store, () => { if (window && !window.isDestroyed()) window.webContents.send('notes:state-changed', notes.state()); });
function trusted(event: Electron.IpcMainInvokeEvent | Electron.IpcMainEvent): void {
  if (!isTrustedRenderer(event, window?.webContents, '/notes.html')) throw new Error('Synthetic fixture rejected IPC sender');
}
const evaluate = (code: string) => window!.webContents.executeJavaScript(code);
async function shortcut(keyCode: string, modifiers = ['control']): Promise<void> {
  window!.webContents.sendInputEvent({ type: 'keyDown', keyCode, modifiers });
  window!.webContents.sendInputEvent({ type: 'keyUp', keyCode, modifiers });
  await pause();
}

protocol.registerSchemesAsPrivileged([{ scheme: 'pmapp', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false } }]);
app.on('window-all-closed', () => { /* Complete encrypted-state assertions after the test window closes. */ });
app.whenReady().then(async () => {
  try {
    directory = await mkdtemp(join(tmpdir(), 'mynotes-synthetic-editor-'));
    let snapshot = await store.create(join(directory, 'Synthetic.pmvault'), 'Synthetic-Test-Password-Only!42');
    snapshot = await store.mutate(snapshot.sessionId, (document) => addTextImports(document, document.rootFolderId, [
      { name: 'Synthetic Alpha.txt', text: 'SYNTHETIC ALPHA DOCUMENT ONLY' }, { name: 'Synthetic Beta.txt', text: 'SYNTHETIC BETA DOCUMENT ONLY' }
    ]));
    const alpha = snapshot.document.records[0]!.id, beta = snapshot.document.records[1]!.id;
    await notes.open(snapshot.sessionId, alpha); await notes.open(snapshot.sessionId, beta);
    notes.theme = config.width === 500 ? 'dark' : 'light';
    const rendererRoot = config.rendererRoot ?? config.root;
    protocol.handle('pmapp', (request) => {
      const url = new URL(request.url); const file = resolve(rendererRoot, `.${decodeURIComponent(url.pathname)}`); const relation = relative(rendererRoot, file);
      if (url.hostname !== 'local' || request.method !== 'GET' || relation.startsWith('..') || isAbsolute(relation)) return new Response('Denied', { status: 403 });
      return net.fetch(pathToFileURL(file).toString());
    });
    session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    session.defaultSession.on('will-download', (event) => event.preventDefault());
    session.defaultSession.webRequest.onHeadersReceived((details, callback) => callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': [config.csp] } }));
    ipcMain.handle('notes:state', (event) => { trusted(event); return notes.state(); });
    ipcMain.handle('notes:update', async (event, value) => { trusted(event); if (holdUpdates) await new Promise<void>((done) => { releaseUpdate = done; }); return notes.update(value); });
    ipcMain.handle('notes:activate', (event, value) => { trusted(event); return notes.activate(value); });
    ipcMain.handle('notes:close-tab', (event, value) => { trusted(event); return notes.closeTab(value); });
    ipcMain.handle('notes:finish-close', async (event) => { trusted(event); await notes.manualClose(); closed = true; window!.destroy(); });
    ipcMain.handle('notes:cancel-close', (event) => trusted(event));
    ipcMain.on('app:activity', (event) => { if (window && !window.isDestroyed()) trusted(event); });
    ipcMain.on('app:editing-context', (event, value) => { if (!window || window.isDestroyed()) return; trusted(event); setEditingContext(event.sender, z.enum(['text', 'terminal', 'none']).parse(value)); });
    // Separate synthetic, offscreen fixture: no real vault or production capture-gate switch.
    window = new BrowserWindow({ width: config.width, height: config.height, useContentSize: true, show: false,
      webPreferences: { preload: config.preload, sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true, webviewTag: false, offscreen: true, backgroundThrottling: false } });
    installWindowBehavior(window, (command) => window!.webContents.send('app:command', command), () => undefined);
    await window.loadURL('pmapp://local/notes.html'); window.webContents.focus();
    await until(async () => await evaluate('document.querySelectorAll(".notes-tab").length === 2'));
    assert(await evaluate('window.myNotes === undefined && window.noteEditor !== undefined'), 'Notes window exposes only its narrow preload API');
    assert(await evaluate('document.querySelector(".note-body-input").value === "SYNTHETIC BETA DOCUMENT ONLY"'), 'Further notes open as tabs with the active document');
    await evaluate('document.querySelector(".note-title-input").value = "Synthetic Renamed.txt"; document.querySelector(".note-title-input").dispatchEvent(new Event("input", {bubbles:true}));');
    await shortcut('S');
    await until(() => store.getSnapshot(snapshot.sessionId).document.records.find((record) => record.id === beta)!.name === 'Synthetic Renamed.txt');
    assert(true, 'Ctrl+S saves the edited title through the real IPC and encrypted store');
    await shortcut('Tab', ['control', 'shift']);
    await until(async () => await evaluate('document.querySelector(".note-body-input").value === "SYNTHETIC ALPHA DOCUMENT ONLY"'));
    assert(true, 'Ctrl+Shift+Tab switches note tabs');
    await clipboard.writeText('SYNTHETIC CLIPBOARD SENTINEL ONLY');
    await evaluate('document.querySelector(".note-body-input").focus()'); await pause();
    await shortcut('A'); await shortcut('C');
    assert((await clipboard.readText()) === 'SYNTHETIC ALPHA DOCUMENT ONLY', 'Ctrl+A and Ctrl+C copy selected note text');
    await shortcut('X');
    assert(await evaluate('document.querySelector(".note-body-input").value.length === 0'), 'Ctrl+X cuts selected note text');
    await clipboard.writeText('SYNTHETIC ALPHA DOCUMENT ONLY'); await shortcut('V');
    assert(await evaluate('document.querySelector(".note-body-input").value === "SYNTHETIC ALPHA DOCUMENT ONLY"'), 'Ctrl+V pastes into the focused editor');
    await shortcut('Z');
    assert(await evaluate('document.querySelector(".note-body-input").value.length === 0'), 'Ctrl+Z undoes an edit');
    await shortcut('Y');
    assert(await evaluate('document.querySelector(".note-body-input").value === "SYNTHETIC ALPHA DOCUMENT ONLY"'), 'Ctrl+Y redoes an edit');
    await evaluate('document.querySelector(".note-body-input").value = "SYNTHETIC AUTOSAVE TEXT ONLY"; document.querySelector(".note-body-input").dispatchEvent(new Event("input", {bubbles:true}));');
    await until(() => store.getSnapshot(snapshot.sessionId).document.records.find((record) => record.id === alpha)!.notes === 'SYNTHETIC AUTOSAVE TEXT ONLY');
    assert(true, 'Note edits autosave into authenticated ciphertext');
    await evaluate('document.querySelector(".note-body-input").value = "SYNTHETIC LOCAL UNSAVED DRAFT"; document.querySelector(".note-body-input").dispatchEvent(new Event("input", {bubbles:true}));');
    await store.mutate(snapshot.sessionId, (document) => { document.records.find((record) => record.id === alpha)!.notes = 'SYNTHETIC OTHER EDITOR UPDATE'; });
    window.webContents.send('notes:state-changed', notes.state()); await shortcut('S');
    await until(async () => await evaluate('!!document.querySelector(".note-error")'));
    assert(store.getSnapshot(snapshot.sessionId).document.records.find((record) => record.id === alpha)!.notes === 'SYNTHETIC OTHER EDITOR UPDATE', 'A stale note editor cannot overwrite another window update');
    assert(await evaluate('document.querySelector(".note-body-input").value === "SYNTHETIC LOCAL UNSAVED DRAFT"'), 'A failed save retains the local draft');
    window.webContents.send('notes:close-requested'); await pause();
    assert(!closed && !window.isDestroyed(), 'A note save conflict prevents closing the window');
    await evaluate('document.querySelector(".note-error button").click()'); await pause();
    assert(await evaluate('document.querySelector(".note-body-input").value === "SYNTHETIC OTHER EDITOR UPDATE" && !document.querySelector(".note-error")'), 'The user can explicitly discard a conflicting draft and reload the saved text');
    assert(await evaluate('document.querySelectorAll(".details-pane, .commandbar, input[type=password]").length === 0 && document.querySelectorAll(".note-page input, .note-page textarea").length === 2'), 'Notes window contains only document title/text and tab controls');
    assert(await evaluate('document.documentElement.scrollWidth === innerWidth && document.querySelector(".note-body-input").getBoundingClientRect().bottom <= innerHeight'), 'Minimal editor fits the supported window dimensions');
    writeFileSync(join(config.root, `notes-${config.width}.png`), (await window.webContents.capturePage()).toPNG());
    await shortcut('Tab'); await shortcut('W');
    await until(() => store.getSnapshot(snapshot.sessionId).document.settings.notesWorkspace!.openRecordIds.length === 1);
    assert(true, 'Ctrl+W closes only the active note tab');
    await notes.open(snapshot.sessionId, beta);
    await until(async () => await evaluate('document.querySelectorAll(".notes-tab").length === 2'));
    await shortcut('Tab', ['control', 'shift']);
    await until(async () => await evaluate('document.querySelector(".note-body-input").value === "SYNTHETIC OTHER EDITOR UPDATE"'));
    await evaluate('document.querySelector(".note-body-input").value = "SYNTHETIC CLOSE SAVE ONLY"; document.querySelector(".note-body-input").dispatchEvent(new Event("input", {bubbles:true}));');
    holdUpdates = true;
    window.webContents.send('notes:close-requested');
    await until(() => releaseUpdate !== null);
    assert(await evaluate('document.querySelector(".note-title-input").readOnly && document.querySelector(".note-body-input").readOnly'), 'Window close prevents new edits while its last save is pending');
    holdUpdates = false; (releaseUpdate as (() => void) | null)?.();
    await until(() => closed);
    const final = store.getSnapshot(snapshot.sessionId);
    assert(final.document.records.find((record) => record.id === alpha)!.notes === 'SYNTHETIC CLOSE SAVE ONLY', 'Closing the notes window flushes pending edits');
    assert(final.document.settings.notesWorkspace?.autoOpen === false && final.document.settings.notesWorkspace.openRecordIds.length === 2, 'Manual close suppresses automatic restoration and retains remembered tabs');
    assert(!new NotesWorkspaceService(store, () => undefined).restore(final), 'A manually closed workspace stays closed after unlock');
    await notes.open(snapshot.sessionId);
    assert(notes.state().tabs.length === 2, 'Open notes restores every remembered document');
    const result = { passed: true, checks, size: [config.width, config.height] };
    writeFileSync(join(config.root, `result-${config.width}.json`), JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result));
    await store.closeAll(); await clipboard.clear(); await rm(directory, { recursive: true, force: true }); app.exit(0);
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Synthetic notes fixture failed');
    window?.destroy(); await store.closeAll(); await clipboard.clear(); if (directory!) await rm(directory, { recursive: true, force: true }); app.exit(1);
  }
});
