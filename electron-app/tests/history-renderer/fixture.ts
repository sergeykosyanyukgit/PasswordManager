import { createApp, nextTick, type App as VueApp } from 'vue';
import App from '../../src/renderer/src/App.vue';
import type { AppCommand, MyNotesApi, VaultHistory, VaultRecord, VaultSnapshot } from '../../src/shared/contracts';
import '../../src/renderer/src/styles.css';

// Synthetic presentation-only fixture: no production preload, vault, filesystem or network.
const first = { id: '10000000-0000-4000-8000-000000000001', path: 'C:\\Synthetic-Tests\\First.pmvault', lastOpenedUtc: '2026-01-01T10:00:00.000Z' };
const second = { id: '10000000-0000-4000-8000-000000000002', path: 'D:\\Synthetic-Tests\\Second.pmvault', lastOpenedUtc: '2026-01-02T11:30:00.000Z' };
let state: VaultHistory;
let instance: VueApp | undefined;
let openCalls = 0;
let createCalls = 0;
let unlockSucceeds = false;
let currentSnapshot: VaultSnapshot;
const folderA = '20000000-0000-4000-8000-000000000002';
const folderB = '20000000-0000-4000-8000-000000000003';
const recordA = '40000000-0000-4000-8000-000000000001';
const commandListeners = new Set<(value: AppCommand) => void>();
const changeListeners = new Set<(value: VaultSnapshot) => void>();
const openedNotes: Array<string | undefined> = [];
const syntheticRecord = (id: string, folderId: string, name: string): VaultRecord => ({ id, folderId, type: 3, name, notes: 'SYNTHETIC DOCUMENT ONLY', userName: '', email: '', password: '', url: '', ssh: null, customFields: [], breach: { status: 0, occurrenceCount: 0, checkedUtc: null, compromisedSaveConfirmed: false }, isDeleted: false, deletedUtc: null, modifiedUtc: '2026-01-01T00:00:00.000Z' });
function changedSnapshot(): VaultSnapshot { currentSnapshot.revision++; const value = structuredClone(currentSnapshot); changeListeners.forEach((listener) => listener(value)); return value; }
const checks: string[] = [];
const violations: string[] = [];
document.addEventListener('securitypolicyviolation', (event) => violations.push(event.effectiveDirective));

const settle = async () => { await nextTick(); await new Promise((resolve) => setTimeout(resolve, 60)); };
const assert = (condition: unknown, description: string) => { if (!condition) throw new Error(description); checks.push(description); };
const button = (text: string) => Array.from(document.querySelectorAll<HTMLButtonElement>('button')).find((element) => element.textContent?.trim() === text)!;
const rows = () => document.querySelectorAll('.recent-row');

async function mount(entries: VaultHistory['entries'], paths: string[] = []): Promise<void> {
  instance?.unmount();
  changeListeners.clear(); commandListeners.clear(); openedNotes.length = 0;
  document.querySelector('#app')!.textContent = '';
  state = { entries: structuredClone(entries), order: 'recent', persisted: true };
  const api = {
    getStartupState: async () => ({ paths, history: structuredClone(state) }),
    listRecentVaults: async () => structuredClone(state),
    reorderRecentVaults: async (ids: string[]) => {
      state.entries = ids.map((id) => state.entries.find((entry) => entry.id === id)!);
      state.order = 'manual'; return structuredClone(state);
    },
    removeRecentVault: async (id: string) => { state.entries = state.entries.filter((entry) => entry.id !== id); return structuredClone(state); },
    sortRecentVaults: async () => { state.entries.sort((a, b) => b.lastOpenedUtc.localeCompare(a.lastOpenedUtc)); state.order = 'recent'; return structuredClone(state); },
    chooseVaultToCreate: async () => 'C:\\Synthetic-Tests\\New.pmvault',
    chooseVaultToOpen: async () => second.path,
    openVault: async (path: string) => {
      openCalls++;
      if (!unlockSucceeds) throw new Error('Synthetic authentication failure');
      const rootFolderId = '20000000-0000-4000-8000-000000000001';
      currentSnapshot = {
        revision: 0, sessionId: '30000000-0000-4000-8000-000000000001', path, displayName: 'Synthetic Notebook',
        document: {
          rootFolderId, folders: [
            { id: rootFolderId, parentId: null, name: 'Synthetic Folder', isDeleted: false, deletedUtc: null },
            { id: folderA, parentId: rootFolderId, name: 'Synthetic Folder A', isDeleted: false, deletedUtc: null },
            { id: folderB, parentId: rootFolderId, name: 'Synthetic Folder B', isDeleted: false, deletedUtc: null }
          ], records: [syntheticRecord(recordA, rootFolderId, 'Synthetic Alpha.txt'), syntheticRecord('40000000-0000-4000-8000-000000000002', folderA, 'Synthetic Nested.txt')],
          settings: { hibpConsent: false, clipboardClearSeconds: 30, autoLockMinutes: 15, sessionLanguage: '' }, modifiedUtc: '2026-01-01T00:00:00.000Z'
        }
      };
      return structuredClone(currentSnapshot);
    },
    openNotes: async (_sessionId: string, recordId?: string) => { openedNotes.push(recordId); },
    saveVault: async (_sessionId, document, revision) => { if (revision !== currentSnapshot.revision) throw new Error('Synthetic revision conflict'); currentSnapshot.document = document; return changedSnapshot(); },
    getVaultSnapshot: async () => structuredClone(currentSnapshot),
    importTextFiles: async (_sessionId, folderId) => { currentSnapshot.document.records.push(syntheticRecord(crypto.randomUUID(), folderId, 'Synthetic Imported.txt')); return changedSnapshot(); },
    importDroppedTextFiles: async (_sessionId, folderId, files) => { for (const file of files) currentSnapshot.document.records.push(syntheticRecord(crypto.randomUUID(), folderId, file.name)); return changedSnapshot(); },
    moveItem: async (value) => { if (value.kind === 'record') currentSnapshot.document.records.find((record) => record.id === value.id)!.folderId = value.targetFolderId; else currentSnapshot.document.folders.find((folder) => folder.id === value.id)!.parentId = value.targetFolderId; return changedSnapshot(); },
    onVaultChanged: (listener) => { changeListeners.add(listener); return () => changeListeners.delete(listener); },
    onCommand: (listener) => { commandListeners.add(listener); return () => commandListeners.delete(listener); },
    setEditingContext: () => undefined,
    closeVault: async () => undefined,
    createVault: async () => { createCalls++; throw new Error('Synthetic creation failure'); },
    setColorTheme: async () => undefined, notifyActivity: () => undefined,
    onOpenPaths: () => () => undefined, onLock: () => () => undefined, onVaultLocked: () => () => undefined
  } satisfies Partial<MyNotesApi>;
  Object.assign(window, { myNotes: Object.freeze(api) });
  instance = createApp(App);
  instance.mount('#app');
  await settle();
}

async function input(element: HTMLInputElement, value: string): Promise<void> {
  element.value = value;
  element.dispatchEvent(new Event('input', { bubbles: true }));
  await nextTick();
}

async function run(): Promise<void> {
  await mount([]);
  assert(document.querySelector('h1')?.textContent === 'MyNotes', 'Empty startup shows MyNotes branding');
  assert(!document.querySelector('.modal-backdrop'), 'Empty history does not prompt for a password');
  button('Создать хранилище').click(); await settle();
  const inputs = document.querySelectorAll<HTMLInputElement>('.modal input');
  await input(inputs[0]!, 'Synth7!'); await input(inputs[1]!, 'Synth7!');
  button('Создать').click(); await settle();
  assert(createCalls === 0 && document.querySelector('.modal-error')?.textContent?.includes('8 символов'), 'Seven characters are rejected before IPC');
  await input(inputs[0]!, 'Synth8!!'); await input(inputs[1]!, 'Synth8!!');
  button('Создать').click(); await settle();
  assert(createCalls === 1, 'Eight characters reach the main-process create method');

  await mount([first]);
  assert(document.querySelector('.path-hint')?.textContent === first.path, 'One history entry opens its unlock prompt automatically');
  assert(document.activeElement === document.querySelector('.modal input'), 'Master-password input receives focus');
  assert(openCalls === 0, 'Automatic selection never unlocks without a submitted password');
  button('Отмена').click(); await settle();
  assert(rows().length === 1 && !document.querySelector('.modal-backdrop'), 'Cancel returns to the history list without reopening');

  await mount([second, first]);
  assert(rows().length === 2 && !document.querySelector('.modal-backdrop'), 'Multiple history entries show a selectable list');
  assert(document.querySelector('.recent-path')?.textContent === second.path && document.querySelector('.recent-date')?.textContent?.includes('2026'), 'History shows file paths and opening dates');
  document.querySelector<HTMLButtonElement>('[title="Переместить ниже"]')!.click(); await settle();
  assert(state.order === 'manual' && state.entries[0]!.id === first.id, 'Arrow controls save an arbitrary manual order');
  button('Сначала недавние').click(); await settle();
  assert(state.order === 'recent' && state.entries[0]!.id === second.id, 'Recent sorting restores date order');
  const rowElements = rows();
  rowElements[0]!.dispatchEvent(new Event('dragstart', { bubbles: true }));
  rowElements[1]!.dispatchEvent(new Event('drop', { bubbles: true, cancelable: true }));
  await settle();
  assert(state.entries[0]!.id === first.id && state.order === 'manual', 'Dragging saves the requested order');
  document.querySelector<HTMLButtonElement>('.recent-open')!.click(); await settle();
  assert(document.querySelector('.path-hint')?.textContent === first.path, 'Selecting a row prompts for that vault');
  await input(document.querySelector<HTMLInputElement>('.modal input')!, 'Synthetic-Wrong-Password-Only!42');
  button('Открыть').click(); await settle();
  assert(openCalls === 1 && !!document.querySelector('.modal-error'), 'Authentication failure stays in the password dialog');
  assert(state.entries[0]!.lastOpenedUtc === first.lastOpenedUtc, 'Authentication failure preserves history timestamps');
  button('Отмена').click(); await settle();
  document.querySelector<HTMLButtonElement>('.history-remove')!.click(); await settle();
  assert(rows().length === 1 && !document.querySelector('.modal-backdrop'), 'Removing an entry changes only the list and does not auto-open');
  document.querySelector<HTMLButtonElement>('.history-remove')!.click(); await settle();
  assert(rows().length === 0 && !!button('Открыть файл'), 'Removing the last entry leaves file opening available');

  unlockSucceeds = true;
  await mount([second, first]);
  document.querySelector<HTMLButtonElement>('.recent-open')!.click(); await settle();
  await input(document.querySelector<HTMLInputElement>('.modal input')!, 'Synthetic-Test-Password-Only!42');
  button('Открыть').click(); await settle();
  assert(document.querySelector('.vault-tab')?.textContent?.includes('Synthetic Notebook') && !document.querySelector('.modal-backdrop'), 'Successful unlock opens the vault workspace');
  assert(document.querySelectorAll('.folder-file-row').length === 2 && document.querySelectorAll('.tree-file').length === 2, 'Folders appear in the file list and files appear inside the folder tree');
  assert(parseFloat(getComputedStyle(document.querySelector('.file-menu summary')!).fontSize) > 0, 'File menu label remains visible at the minimum window width');
  document.querySelector<HTMLElement>(`.file-row[data-record-id="${recordA}"] .file-select`)!.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); await settle();
  assert(openedNotes.at(-1) === recordA, 'Double-clicking a text document opens it in the notes workspace');
  button('Открыть заметки').click(); await settle();
  assert(openedNotes.length === 2 && openedNotes.at(-1) === undefined, 'Open notes requests restoration of remembered documents');
  document.querySelector<HTMLElement>('.file-menu summary')!.click();
  document.querySelector<HTMLButtonElement>('.file-menu-items button')!.click(); await settle();
  assert(currentSnapshot.document.records.some((record) => record.name === 'Synthetic Imported.txt' && record.folderId === currentSnapshot.document.rootFolderId), 'File Open imports TXT into the current folder and saves it');
  document.querySelector<HTMLElement>('.file-menu summary')!.click();
  const fileTransfer = new DataTransfer(); fileTransfer.items.add(new File(['SYNTHETIC DROP ONLY'], 'Synthetic Dropped.txt', { type: 'text/plain' }));
  document.querySelector<HTMLElement>('.file-rows')!.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: fileTransfer })); await settle();
  assert(currentSnapshot.document.records.some((record) => record.name === 'Synthetic Dropped.txt'), 'Dropping TXT files imports and saves them');
  const itemTransfer = new DataTransfer();
  document.querySelector<HTMLElement>(`.file-row[data-record-id="${recordA}"]`)!.dispatchEvent(new DragEvent('dragstart', { bubbles: true, dataTransfer: itemTransfer }));
  document.querySelector<HTMLElement>(`.tree-row[data-folder-id="${folderA}"]`)!.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: itemTransfer })); await settle();
  assert(currentSnapshot.document.records.find((record) => record.id === recordA)!.folderId === folderA && !document.querySelector(`.file-row[data-record-id="${recordA}"]`), 'Dragging a document onto a tree folder moves it and refreshes the list');
  const folderTransfer = new DataTransfer();
  document.querySelector<HTMLElement>(`.folder-file-row[data-folder-id="${folderA}"]`)!.dispatchEvent(new DragEvent('dragstart', { bubbles: true, dataTransfer: folderTransfer }));
  document.querySelector<HTMLElement>(`.tree-row[data-folder-id="${folderB}"]`)!.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: folderTransfer })); await settle();
  assert(currentSnapshot.document.folders.find((folder) => folder.id === folderA)!.parentId === folderB, 'Dragging a folder moves its subtree');
  commandListeners.forEach((listener) => listener('new-note')); await settle();
  await input(document.querySelector<HTMLInputElement>('.details-pane input')!, 'Synthetic Hotkey Note');
  commandListeners.forEach((listener) => listener('save')); await settle();
  assert(currentSnapshot.document.records.some((record) => record.name === 'Synthetic Hotkey Note'), 'Main-window save hotkey persists the current text document');
  button('Хранилища').click(); await settle();
  const historyModal = document.querySelector('.history-modal')!.getBoundingClientRect();
  assert(rows().length === 2 && historyModal.width >= 750 && historyModal.right <= innerWidth, 'History remains available in a readable dialog while a vault is open');
  const callsBeforeSelecting = openCalls;
  document.querySelector<HTMLButtonElement>('.recent-open')!.click(); await settle();
  assert(openCalls === callsBeforeSelecting && !document.querySelector('.modal-backdrop'), 'Selecting an already open vault activates its existing tab');
  document.querySelector<HTMLSpanElement>('.tab-close')!.click(); await settle();
  assert(rows().length === 2 && !document.querySelector('.vault-tab'), 'Closing the vault returns to the saved history');
  unlockSucceeds = false;

  await mount([first], [second.path]);
  assert(document.querySelector('.path-hint')?.textContent === second.path, 'Explicit startup path takes precedence over history');
  await mount([second, first]);
  button(innerWidth > 1000 ? 'Светлая' : 'Тёмная')?.click(); await settle();
  const lastRow = document.querySelector('.recent-row:last-child')!.getBoundingClientRect();
  assert(lastRow.left >= 0 && lastRow.right <= innerWidth && lastRow.bottom < innerHeight, 'Both history entries fit the supported window width and height');
  assert(document.documentElement.scrollWidth === innerWidth, 'History introduces no horizontal page overflow');
  assert(violations.length === 0, 'History UI respects the packaged CSP');
  Object.assign(window, { __historyTestResult: { passed: true, checks, violations } });
}

void run().catch((error: Error) => Object.assign(window, { __historyTestResult: { passed: false, checks, error: error.message, violations } }));
