<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import type { RecordType, VaultDocument, VaultFolder, VaultRecord, VaultSnapshot } from '@shared/contracts';
import appIcon from '../assets/passwordmanager-strict.png';
import FluentIcon from './components/FluentIcon.vue';
import FolderTreeNode from './components/FolderTreeNode.vue';
import TerminalSession from './components/TerminalSession.vue';
import { applyRecordType, createEmptySshProfile, isRecordType, normalizeRecordTypePayload } from './recordDraft';
import { clampTerminalHeight, DEFAULT_TERMINAL_BACKGROUND, DEFAULT_TERMINAL_FOREGROUND, MINIMUM_TERMINAL_HEIGHT, terminalContrastRatio } from './terminalAppearance';

interface UiTab extends VaultSnapshot {
  selectedFolderId: string;
  selectedRecordId: string | null;
}

interface TerminalTab {
  id: string;
  vaultSessionId: string;
  recordId: string;
  title: string;
  backgroundColor: string;
  foregroundColor: string;
  clipboardClearSeconds: number;
}

const tabs = ref<UiTab[]>([]);
const activeId = ref<string | null>(null);
const search = ref('');
const draft = ref<VaultRecord | null>(null);
const busy = ref(false);
const message = ref('');
const revealPassword = ref(false);
const breachMessage = ref('');
const dialogState = ref<{ kind: 'open' | 'create'; path: string; password: string; confirmation: string } | null>(null);
const dialogError = ref('');
const folderDialog = ref<{ name: string } | null>(null);
const settingsDialog = ref<{ sessionId: string; autoLockMinutes: number } | null>(null);
const queuedPaths = ref<string[]>([]);
const terminalTabs = ref<TerminalTab[]>([]);
const activeTerminalId = ref<string | null>(null);
const revealSshPassword = ref(false);
const revealSshPassphrase = ref(false);
const colorTheme = ref<'light' | 'dark'>(window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
const screenshotDiagnostics = import.meta.env.PM_SCREENSHOT_DIAGNOSTICS === true;
const terminalDockHeight = ref(350);
const terminalViewportHeight = ref(window.innerHeight);
let restoredTerminalHeight = 350;
let terminalResize: { pointerId: number; startY: number; startHeight: number } | null = null;

const activeTab = computed(() => tabs.value.find((tab) => tab.sessionId === activeId.value) ?? null);
const activeTerminalTab = computed(() => terminalTabs.value.find((terminal) => terminal.id === activeTerminalId.value) ?? null);
const terminalDockExpanded = computed(() => terminalDockHeight.value >= clampTerminalHeight(Number.MAX_SAFE_INTEGER, terminalViewportHeight.value));
const activeTerminalContrast = computed(() => activeTerminalTab.value
  ? terminalContrastRatio(activeTerminalTab.value.backgroundColor, activeTerminalTab.value.foregroundColor)
  : 21);
const currentFolder = computed(() => activeTab.value?.document.folders.find((folder) => folder.id === activeTab.value?.selectedFolderId) ?? null);
const rootFolder = computed(() => activeTab.value?.document.folders.find((folder) => folder.id === activeTab.value?.document.rootFolderId) ?? null);
const visibleRecords = computed(() => {
  if (!activeTab.value) return [];
  const query = search.value.trim().toLocaleLowerCase();
  return activeTab.value.document.records
    .filter((record) => !record.isDeleted && record.folderId === activeTab.value?.selectedFolderId)
    .filter((record) => !query || [record.name, record.userName, record.email].some((value) => value.toLocaleLowerCase().includes(query)))
    .sort((a, b) => a.name.localeCompare(b.name));
});
const breadcrumbs = computed(() => {
  if (!activeTab.value || !currentFolder.value) return [];
  const result: VaultFolder[] = [];
  const byId = new Map(activeTab.value.document.folders.map((folder) => [folder.id, folder]));
  let item: VaultFolder | undefined = currentFolder.value;
  while (item) {
    result.unshift(item);
    item = item.parentId ? byId.get(item.parentId) : undefined;
  }
  return result;
});

const labels = ['Login', 'Email', 'Password', 'Secure note', 'SSH'];
const icons = ['login', 'email', 'password', 'note', 'ssh'];

const activityEvents = ['pointerdown', 'keydown', 'wheel'] as const;
const activity = (): void => window.passwordManager.notifyActivity();
const fitTerminalDockToViewport = (): void => {
  terminalViewportHeight.value = window.innerHeight;
  terminalDockHeight.value = clampTerminalHeight(terminalDockHeight.value, window.innerHeight);
};
let stopPaths = (): void => undefined;
let stopLock = (): void => undefined;
let stopVaultLock = (): void => undefined;

onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
  for (const event of activityEvents) window.addEventListener(event, activity, { passive: true });
  window.addEventListener('resize', fitTerminalDockToViewport);
  fitTerminalDockToViewport();
  void window.passwordManager.setColorTheme(colorTheme.value);
});

onBeforeUnmount(() => {
  stopPaths();
  stopLock();
  stopVaultLock();
  for (const event of activityEvents) window.removeEventListener(event, activity);
  window.removeEventListener('resize', fitTerminalDockToViewport);
});

async function chooseOpen(): Promise<void> {
  const path = await window.passwordManager.chooseVaultToOpen();
  if (path) {
    dialogError.value = '';
    dialogState.value = { kind: 'open', path, password: '', confirmation: '' };
  }
}

async function chooseCreate(): Promise<void> {
  const path = await window.passwordManager.chooseVaultToCreate();
  if (path) {
    dialogError.value = '';
    dialogState.value = { kind: 'create', path, password: '', confirmation: '' };
  }
}

async function submitVaultDialog(): Promise<void> {
  const state = dialogState.value;
  if (!state || busy.value) return;
  if (state.kind === 'create' && state.password.length < 15) {
    dialogError.value = 'Мастер-пароль должен содержать не менее 15 символов.';
    return;
  }
  if (state.kind === 'create' && state.password !== state.confirmation) {
    dialogError.value = 'Пароль и подтверждение не совпадают.';
    return;
  }
  busy.value = true;
  dialogError.value = '';
  message.value = '';
  try {
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
  finally { busy.value = false; }
}

function addTab(snapshot: VaultSnapshot): void {
  const existing = tabs.value.find((tab) => tab.path.toLocaleLowerCase() === snapshot.path.toLocaleLowerCase());
  if (existing) { activeId.value = existing.sessionId; return; }
  tabs.value.push({ ...snapshot, selectedFolderId: snapshot.document.rootFolderId, selectedRecordId: null });
  activeId.value = snapshot.sessionId;
  draft.value = null;
}

async function closeTab(tab: UiTab): Promise<void> {
  terminalTabs.value = terminalTabs.value.filter((terminal) => terminal.vaultSessionId !== tab.sessionId);
  if (!terminalTabs.value.some((terminal) => terminal.id === activeTerminalId.value)) activeTerminalId.value = terminalTabs.value.at(-1)?.id ?? null;
  await window.passwordManager.closeVault(tab.sessionId).catch(() => undefined);
  const index = tabs.value.indexOf(tab);
  tabs.value.splice(index, 1);
  activeId.value = tabs.value[Math.max(0, index - 1)]?.sessionId ?? null;
  draft.value = null;
}

function selectFolder(id: string): void {
  if (!activeTab.value) return;
  activeTab.value.selectedFolderId = id;
  activeTab.value.selectedRecordId = null;
  draft.value = null;
}

function selectRecord(record: VaultRecord): void {
  if (!activeTab.value) return;
  activeTab.value.selectedRecordId = record.id;
  const selectedDraft = clone(record);
  normalizeRecordTypePayload(selectedDraft);
  draft.value = selectedDraft;
  revealPassword.value = false;
  revealSshPassword.value = false;
  revealSshPassphrase.value = false;
  breachMessage.value = record.breach.status === 2 ? `Скомпрометирован: ${record.breach.occurrenceCount.toLocaleString('ru-RU')} совпадений` : '';
}

function newRecord(type: RecordType = 0): void {
  if (!activeTab.value) return;
  activeTab.value.selectedRecordId = null;
  draft.value = {
    id: crypto.randomUUID(), folderId: activeTab.value.selectedFolderId, type, name: '', userName: '', email: '', password: '', url: '', notes: '',
    ssh: type === 4 ? createEmptySshProfile() : null,
    customFields: [], breach: { status: 0, occurrenceCount: 0, checkedUtc: null, compromisedSaveConfirmed: false }, isDeleted: false, deletedUtc: null, modifiedUtc: new Date().toISOString()
  };
}

function changeDraftType(event: Event): void {
  if (!draft.value) return;
  const type = Number((event.currentTarget as HTMLSelectElement).value);
  if (!isRecordType(type)) return;
  applyRecordType(draft.value, type);
  revealPassword.value = false;
  revealSshPassword.value = false;
  revealSshPassphrase.value = false;
}

async function saveDraft(): Promise<boolean> {
  const tab = activeTab.value;
  if (!tab || !draft.value || !draft.value.name.trim()) { message.value = 'Введите имя записи.'; return false; }
  if (draft.value.breach.status === 2 && !draft.value.breach.compromisedSaveConfirmed) {
    message.value = 'Пароль найден в утечках. Отметьте явное подтверждение перед сохранением.'; return false;
  }
  const saved = clone(draft.value);
  saved.name = saved.name.trim(); saved.modifiedUtc = new Date().toISOString();
  const index = tab.document.records.findIndex((record) => record.id === saved.id);
  const previous = index >= 0 ? tab.document.records[index] : null;
  if (index >= 0) tab.document.records[index] = saved; else tab.document.records.push(saved);
  if (!(await persistVault(tab))) {
    if (index >= 0 && previous) tab.document.records[index] = previous;
    else tab.document.records.splice(tab.document.records.findIndex((record) => record.id === saved.id), 1);
    return false;
  }
  tab.selectedRecordId = saved.id;
  draft.value = clone(saved);
  return true;
}

async function deleteRecord(): Promise<void> {
  if (!activeTab.value || !draft.value) return;
  const record = activeTab.value.document.records.find((item) => item.id === draft.value?.id);
  if (!record) { draft.value = null; return; }
  record.isDeleted = true; record.deletedUtc = new Date().toISOString();
  draft.value = null; activeTab.value.selectedRecordId = null;
  await persist();
}

async function createFolder(): Promise<void> {
  if (!activeTab.value || !folderDialog.value?.name.trim()) return;
  activeTab.value.document.folders.push({ id: crypto.randomUUID(), parentId: activeTab.value.selectedFolderId, name: folderDialog.value.name.trim(), isDeleted: false, deletedUtc: null });
  folderDialog.value = null;
  await persist();
}

async function persist(): Promise<void> {
  if (activeTab.value) await persistVault(activeTab.value);
}

async function persistVault(tab: UiTab): Promise<boolean> {
  busy.value = true; message.value = '';
  try { await window.passwordManager.saveVault(tab.sessionId, plainDocument(tab.document)); message.value = 'Сохранено'; return true; }
  catch { message.value = 'Сохранение остановлено: конфликт файла, потеря блокировки или ошибка диска. Исходный файл не перезаписан.'; return false; }
  finally { busy.value = false; }
}

async function copy(value: string): Promise<void> {
  if (!activeTab.value || !value) return;
  await window.passwordManager.copySecret(value, activeTab.value.document.settings.clipboardClearSeconds);
  message.value = `Скопировано. Буфер будет очищен через ${activeTab.value.document.settings.clipboardClearSeconds} секунд.`;
}

async function checkBreach(): Promise<void> {
  const tab = activeTab.value;
  const checkedDraft = draft.value;
  if (!tab || !checkedDraft) return;
  const password = checkedDraft.type === 4 ? checkedDraft.ssh?.password ?? '' : checkedDraft.password;
  if (!password) return;
  busy.value = true;
  try {
    const result = await window.passwordManager.checkPassword(tab.sessionId, password);
    if (draft.value !== checkedDraft) return;
    if (result.status === 'failed' && result.reason === 'ConsentDeclined') {
      breachMessage.value = 'Проверка отменена пользователем.';
      return;
    }
    tab.document.settings.hibpConsent = true;
    checkedDraft.breach.status = result.status === 'compromised' ? 2 : result.status === 'notFound' ? 1 : 3;
    checkedDraft.breach.occurrenceCount = result.occurrenceCount;
    checkedDraft.breach.checkedUtc = new Date().toISOString();
    checkedDraft.breach.compromisedSaveConfirmed = false;
    breachMessage.value = result.status === 'compromised' ? `Этот пароль скомпрометирован — ${result.occurrenceCount.toLocaleString('ru-RU')} совпадений в Have I Been Pwned.` : result.status === 'notFound' ? 'Не найден в HIBP на момент проверки.' : 'Не проверено: сеть или сервис недоступны.';
  } finally { busy.value = false; }
}

async function openTerminal(): Promise<void> {
  const tab = activeTab.value;
  const ssh = draft.value?.type === 4 ? draft.value.ssh : null;
  if (busy.value || !tab || !draft.value || !ssh) return;
  const recordId = draft.value.id;
  if (!ssh.host.trim() || !ssh.userName.trim() || ssh.port < 1 || ssh.port > 65_535) {
    message.value = 'Для SSH укажите хост, порт и пользователя.';
    return;
  }
  if (ssh.authenticationKind === 0 && !ssh.password) { message.value = 'Введите пароль SSH.'; return; }
  if (ssh.authenticationKind === 1 && !ssh.privateKeyPem.trim()) { message.value = 'Вставьте закрытый SSH-ключ.'; return; }
  if (!(await saveDraft())) return;
  openSavedTerminal(recordId, tab);
}

function openSavedTerminal(recordId: string, tab: UiTab | null = activeTab.value): void {
  if (busy.value || !tab || !tabs.value.includes(tab)) return;
  const record = tab.document.records.find((item) => item.id === recordId);
  if (!record || record.isDeleted || record.type !== 4 || !record.ssh) return;
  const terminal: TerminalTab = {
    id: crypto.randomUUID(),
    vaultSessionId: tab.sessionId,
    recordId: record.id,
    title: `${record.ssh.userName}@${record.ssh.host}`,
    backgroundColor: DEFAULT_TERMINAL_BACKGROUND,
    foregroundColor: DEFAULT_TERMINAL_FOREGROUND,
    clipboardClearSeconds: tab.document.settings.clipboardClearSeconds
  };
  terminalTabs.value.push(terminal);
  activeTerminalId.value = terminal.id;
}

function enableLegacySshAlgorithms(): void {
  const ssh = draft.value?.type === 4 ? draft.value.ssh : null;
  if (!ssh || ssh.allowLegacyAlgorithms) return;
  const accepted = window.confirm('Режим совместимости разрешает крайне устаревшие Group1/SHA-1, DSA, 3DES/AES-CBC, MD5/SHA-1 MAC и zlib-сжатие. Они существенно слабее современных алгоритмов. Включайте режим только для известного изолированного сервера и обязательно сверяйте SHA-256 отпечаток ключа. Продолжить?');
  if (!accepted) return;
  ssh.allowLegacyAlgorithms = true;
  message.value = 'Режим совместимости включён для этой SSH-записи. Сохраните запись.';
}

function disableLegacySshAlgorithms(): void {
  const ssh = draft.value?.type === 4 ? draft.value.ssh : null;
  if (!ssh) return;
  ssh.allowLegacyAlgorithms = false;
  message.value = 'Режим совместимости отключён. Сохраните запись.';
}

function updateTerminalHostKey(terminal: TerminalTab, fingerprint: string): void {
  const tab = tabs.value.find((item) => item.sessionId === terminal.vaultSessionId);
  const record = tab?.document.records.find((item) => item.id === terminal.recordId);
  if (!tab || record?.type !== 4 || !record.ssh) return;
  record.ssh.hostKeySha256 = fingerprint;
  if (draft.value?.id === record.id && draft.value.ssh) draft.value.ssh.hostKeySha256 = fingerprint;
}

function closeTerminalTab(terminal: TerminalTab): void {
  const index = terminalTabs.value.indexOf(terminal);
  terminalTabs.value.splice(index, 1);
  if (activeTerminalId.value === terminal.id) activeTerminalId.value = terminalTabs.value[Math.max(0, index - 1)]?.id ?? null;
}

function openAnotherTerminal(): void {
  const terminal = activeTerminalTab.value;
  if (!terminal) return;
  const tab = tabs.value.find((item) => item.sessionId === terminal.vaultSessionId);
  if (tab) openSavedTerminal(terminal.recordId, tab);
}

function closeAllTerminalTabs(): void {
  terminalTabs.value = [];
  activeTerminalId.value = null;
}

function closeTerminalAppearance(event: FocusEvent): void {
  const settings = event.currentTarget as HTMLDetailsElement;
  if (!settings.contains(event.relatedTarget as Node | null)) settings.open = false;
}

function beginTerminalResize(event: PointerEvent): void {
  if (event.button !== 0) return;
  terminalResize = { pointerId: event.pointerId, startY: event.clientY, startHeight: terminalDockHeight.value };
  (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  event.preventDefault();
}

function moveTerminalResize(event: PointerEvent): void {
  if (!terminalResize || terminalResize.pointerId !== event.pointerId) return;
  terminalDockHeight.value = clampTerminalHeight(terminalResize.startHeight + terminalResize.startY - event.clientY, window.innerHeight);
}

function finishTerminalResize(event: PointerEvent): void {
  if (!terminalResize || terminalResize.pointerId !== event.pointerId) return;
  const target = event.currentTarget as HTMLElement;
  if (target.hasPointerCapture(event.pointerId)) target.releasePointerCapture(event.pointerId);
  terminalResize = null;
}

function adjustTerminalHeight(delta: number): void {
  terminalDockHeight.value = clampTerminalHeight(terminalDockHeight.value + delta, window.innerHeight);
}

function toggleTerminalDockSize(): void {
  if (terminalDockExpanded.value) {
    terminalDockHeight.value = clampTerminalHeight(restoredTerminalHeight, window.innerHeight);
  } else {
    restoredTerminalHeight = terminalDockHeight.value;
    terminalDockHeight.value = clampTerminalHeight(Number.MAX_SAFE_INTEGER, window.innerHeight);
  }
}

function resetActiveTerminalColors(): void {
  if (!activeTerminalTab.value) return;
  activeTerminalTab.value.backgroundColor = DEFAULT_TERMINAL_BACKGROUND;
  activeTerminalTab.value.foregroundColor = DEFAULT_TERMINAL_FOREGROUND;
}

function openSettings(): void {
  const tab = activeTab.value;
  if (!tab) return;
  settingsDialog.value = { sessionId: tab.sessionId, autoLockMinutes: tab.document.settings.autoLockMinutes };
}

async function saveSettings(): Promise<void> {
  const state = settingsDialog.value;
  const tab = tabs.value.find((item) => item.sessionId === state?.sessionId);
  if (!state || !tab || !Number.isInteger(state.autoLockMinutes) || state.autoLockMinutes < 0 || state.autoLockMinutes > 240) {
    message.value = 'Автоблокировка должна быть целым числом от 0 до 240 минут.';
    return;
  }
  const previous = tab.document.settings.autoLockMinutes;
  tab.document.settings.autoLockMinutes = state.autoLockMinutes;
  if (await persistVault(tab)) {
    settingsDialog.value = null;
    message.value = state.autoLockMinutes === 0 ? 'Автоблокировка по бездействию отключена.' : `Автоблокировка: ${state.autoLockMinutes} мин.`;
  } else {
    tab.document.settings.autoLockMinutes = previous;
  }
}

function toggleApplicationTheme(): void {
  colorTheme.value = colorTheme.value === 'light' ? 'dark' : 'light';
  void window.passwordManager.setColorTheme(colorTheme.value);
}

function removeLockedVault(sessionId: string): void {
  const wasActive = activeId.value === sessionId;
  terminalTabs.value = terminalTabs.value.filter((terminal) => terminal.vaultSessionId !== sessionId);
  if (!terminalTabs.value.some((terminal) => terminal.id === activeTerminalId.value)) activeTerminalId.value = terminalTabs.value.at(-1)?.id ?? null;
  const index = tabs.value.findIndex((tab) => tab.sessionId === sessionId);
  if (index < 0) return;
  const tab = tabs.value[index]!;
  clearTabSecrets(tab);
  tabs.value.splice(index, 1);
  if (wasActive) {
    activeId.value = tabs.value[Math.max(0, index - 1)]?.sessionId ?? null;
    if (draft.value) clearRecordSecrets(draft.value);
    draft.value = null;
  }
  if (settingsDialog.value?.sessionId === sessionId) settingsDialog.value = null;
  message.value = `Сейф «${tab.displayName}» заблокирован по бездействию.`;
}

function enqueuePaths(paths: string[]): void { queuedPaths.value.push(...paths); openNextQueuedPath(); }
function openNextQueuedPath(): void {
  if (dialogState.value || queuedPaths.value.length === 0) return;
  const path = queuedPaths.value.shift();
  if (path) {
    dialogError.value = '';
    dialogState.value = { kind: 'open', path, password: '', confirmation: '' };
  }
}
function clearRecordSecrets(record: VaultRecord): void { record.password = ''; if (record.ssh) { record.ssh.password = ''; record.ssh.privateKeyPem = ''; record.ssh.privateKeyPassphrase = ''; } for (const field of record.customFields) if (field.isSecret) field.value = ''; }
function clearTabSecrets(tab: UiTab): void { for (const record of tab.document.records) clearRecordSecrets(record); }
function clearRendererSecrets(): void { terminalTabs.value = []; activeTerminalId.value = null; for (const tab of tabs.value) clearTabSecrets(tab); if (draft.value) clearRecordSecrets(draft.value); tabs.value = []; activeId.value = null; draft.value = null; dialogState.value = null; settingsDialog.value = null; dialogError.value = ''; }
function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function plainDocument(value: VaultDocument): VaultDocument { return clone(value); }
</script>

<template>
  <main class="app-shell" :data-theme="colorTheme">
    <header class="titlebar">
      <img :src="appIcon" alt="" class="app-mark" />
      <span class="app-title">PasswordManager</span>
      <span v-if="screenshotDiagnostics" class="screenshot-diagnostic-badge">Скриншоты разрешены · диагностика</span>
      <button class="theme-toggle" type="button" :title="colorTheme === 'light' ? 'Включить тёмную тему' : 'Включить светлую тему'" @click="toggleApplicationTheme">
        <FluentIcon :name="colorTheme === 'light' ? 'moon' : 'sun'" :size="15" />
        {{ colorTheme === 'light' ? 'Тёмная' : 'Светлая' }}
      </button>
      <span class="security-chip"><FluentIcon name="lock" :size="14" /> AES-256-GCM</span>
    </header>

    <section v-if="tabs.length === 0" class="welcome">
      <div class="welcome-card">
        <img :src="appIcon" alt="Защищённая папка" class="welcome-icon" />
        <div class="eyebrow">ЛОКАЛЬНЫЙ ЗАЩИЩЁННЫЙ СЕЙФ</div>
        <h1>Ваши секреты — как файлы.<br />Только зашифрованы.</h1>
        <p>Открывайте независимые <b>.pmvault</b> во вкладках. Никакой телеметрии, облака и установленного сервера.</p>
        <div class="welcome-actions">
          <button class="primary-button" @click="chooseCreate"><FluentIcon name="plus" /> Создать сейф</button>
          <button class="secondary-button" @click="chooseOpen"><FluentIcon name="open" /> Открыть файл</button>
        </div>
        <div class="feature-row"><span><FluentIcon name="lock" /> Argon2id</span><span>•</span><span>Атомарное сохранение</span><span>•</span><span>Без recovery/backdoor</span></div>
      </div>
    </section>

    <template v-else>
      <nav class="tabstrip">
        <button v-for="tab in tabs" :key="tab.sessionId" class="vault-tab" :class="{ active: activeId === tab.sessionId }" @click="activeId = tab.sessionId; draft = null">
          <FluentIcon name="vault" :size="17" /><span>{{ tab.displayName }}</span><span class="tab-close" @click.stop="closeTab(tab)"><FluentIcon name="close" :size="13" /></span>
        </button>
        <button class="icon-button tab-add" title="Открыть ещё один сейф" @click="chooseOpen"><FluentIcon name="plus" /></button>
      </nav>

      <div class="commandbar">
        <div class="command-group">
          <button class="command-button strong" @click="newRecord(0)"><FluentIcon name="plus" /> Новая запись</button>
          <button class="command-button" @click="folderDialog = { name: '' }"><FluentIcon name="folder" /> Новая папка</button>
          <span class="separator"></span>
          <button class="command-button" :disabled="!draft" @click="saveDraft"><FluentIcon name="save" /> Сохранить</button>
          <button class="command-button" :disabled="!draft" @click="deleteRecord"><FluentIcon name="delete" /> Удалить</button>
          <span class="separator"></span>
          <button class="command-button" @click="openSettings"><FluentIcon name="settings" /> Настройки</button>
        </div>
        <div class="search-box"><FluentIcon name="search" /><input v-model="search" placeholder="Поиск в сейфе" autocomplete="off" /></div>
      </div>

      <div class="addressbar">
        <button class="icon-button" disabled><FluentIcon name="back" /></button>
        <div class="breadcrumb"><template v-for="(item, index) in breadcrumbs" :key="item.id"><FluentIcon v-if="index" name="chevron" :size="12" /><button @click="selectFolder(item.id)">{{ item.name }}</button></template></div>
      </div>

      <section v-if="activeTab" class="explorer-grid">
        <aside class="navigation-pane">
          <div class="pane-label">ПАПКИ</div>
          <FolderTreeNode v-if="rootFolder" :folder="rootFolder" :folders="activeTab.document.folders" :selected-id="activeTab.selectedFolderId" @select="selectFolder" />
          <div class="nav-footer"><button class="nav-item"><FluentIcon name="delete" /> Корзина</button></div>
        </aside>

        <section class="file-pane">
          <div class="list-head"><span>Имя</span><span>Тип</span><span>Изменено</span><span>Действия</span></div>
          <div v-for="record in visibleRecords" :key="record.id" class="file-row" :class="{ selected: activeTab.selectedRecordId === record.id }">
            <button type="button" class="file-select" @click="selectRecord(record)">
              <span class="name-cell"><span class="file-icon" :class="`type-${record.type}`"><FluentIcon :name="icons[record.type]!" :size="20" /></span><span><b>{{ record.name }}</b><small>{{ record.userName || record.email || 'Без дополнительного имени' }}</small></span></span>
              <span>{{ labels[record.type] }}</span><span>{{ new Date(record.modifiedUtc).toLocaleDateString('ru-RU') }}</span>
            </button>
            <span class="file-actions">
              <button v-if="record.type === 4 && record.ssh" type="button" class="secondary-button compact" :disabled="busy" title="Открыть SSH по сохранённым данным записи" :aria-label="`Открыть SSH-терминал: ${record.name}`" @click="openSavedTerminal(record.id)"><FluentIcon name="ssh" :size="16" /> SSH</button>
            </span>
          </div>
          <div v-if="visibleRecords.length === 0" class="empty-folder"><FluentIcon name="folder" :size="42" /><b>Эта папка пуста</b><span>Создайте запись или вложенную папку.</span></div>
          <footer class="statusbar"><span>{{ visibleRecords.length }} элементов</span><span v-if="busy" class="busy-dot">Выполняется…</span><span v-else>{{ message }}</span></footer>
        </section>

        <aside class="details-pane">
          <template v-if="draft">
            <div class="details-title"><span class="large-file-icon" :class="`type-${draft.type}`"><FluentIcon :name="icons[draft.type]!" :size="26" /></span><div><span class="pane-label">ЗАПИСЬ</span><h2>{{ draft.name || 'Новая запись' }}</h2></div></div>
            <label>Тип<select :value="draft.type" @change="changeDraftType"><option v-for="(label, index) in labels" :key="label" :value="index">{{ label }}</option></select></label>
            <label>Имя<input v-model="draft.name" maxlength="512" autocomplete="off" /></label>
            <template v-if="draft.type !== 4">
              <label>Логин<input v-model="draft.userName" autocomplete="off" /></label>
              <label>Email<input v-model="draft.email" type="email" autocomplete="off" /></label>
              <label>Пароль<div class="field-with-action"><input v-model="draft.password" :type="revealPassword ? 'text' : 'password'" autocomplete="new-password" /><button @click="revealPassword = !revealPassword">{{ revealPassword ? 'Скрыть' : 'Показать' }}</button><button title="Копировать" @click="copy(draft.password)"><FluentIcon name="copy" :size="16" /></button></div></label>
              <div class="breach-actions"><button class="secondary-button compact" @click="checkBreach">Проверить в HIBP</button><span :class="{ danger: draft.breach.status === 2 }">{{ breachMessage }}</span></div>
              <label v-if="draft.breach.status === 2" class="danger-confirm"><input v-model="draft.breach.compromisedSaveConfirmed" type="checkbox" /> Я понимаю риск и всё равно сохраняю пароль</label>
              <label>Сайт<input v-model="draft.url" autocomplete="off" /></label>
            </template>
            <label>Заметка<textarea v-model="draft.notes" rows="5"></textarea></label>
            <div v-if="draft.type === 4 && draft.ssh" class="ssh-panel">
              <div class="pane-label">SSH-ПОДКЛЮЧЕНИЕ</div>
              <div class="ssh-address-row"><label>Хост<input v-model="draft.ssh.host" autocomplete="off" /></label><label>Порт<input v-model.number="draft.ssh.port" type="number" min="1" max="65535" /></label></div>
              <label>Пользователь<input v-model="draft.ssh.userName" autocomplete="off" /></label>
              <label>Способ входа<select v-model.number="draft.ssh.authenticationKind"><option :value="0">Пароль</option><option :value="1">Закрытый ключ</option></select></label>
              <template v-if="draft.ssh.authenticationKind === 0">
                <label>Пароль SSH<div class="field-with-action"><input v-model="draft.ssh.password" :type="revealSshPassword ? 'text' : 'password'" autocomplete="new-password" /><button @click="revealSshPassword = !revealSshPassword">{{ revealSshPassword ? 'Скрыть' : 'Показать' }}</button><button title="Копировать" @click="copy(draft.ssh.password)"><FluentIcon name="copy" :size="16" /></button></div></label>
                <div class="breach-actions"><button class="secondary-button compact" @click="checkBreach">Проверить пароль в HIBP</button><span :class="{ danger: draft.breach.status === 2 }">{{ breachMessage }}</span></div>
                <label v-if="draft.breach.status === 2" class="danger-confirm"><input v-model="draft.breach.compromisedSaveConfirmed" type="checkbox" /> Я понимаю риск и всё равно сохраняю пароль</label>
              </template>
              <template v-else>
                <label>Закрытый ключ OpenSSH/PEM<textarea v-model="draft.ssh.privateKeyPem" rows="6" spellcheck="false" autocomplete="off"></textarea></label>
                <label>Пароль ключа<div class="field-with-action"><input v-model="draft.ssh.privateKeyPassphrase" :type="revealSshPassphrase ? 'text' : 'password'" autocomplete="new-password" /><button @click="revealSshPassphrase = !revealSshPassphrase">{{ revealSshPassphrase ? 'Скрыть' : 'Показать' }}</button></div></label>
              </template>
              <div class="legacy-ssh-setting">
                <button v-if="!draft.ssh.allowLegacyAlgorithms" class="secondary-button" type="button" @click="enableLegacySshAlgorithms">Разрешить устаревшие алгоритмы…</button>
                <template v-else>
                  <div class="danger">Расширенный режим совместимости подтверждён: разрешены Group1/SHA-1, DSA, 3DES/AES-CBC, старые MAC и zlib.</div>
                  <button class="secondary-button" type="button" @click="disableLegacySshAlgorithms">Отключить режим совместимости</button>
                </template>
              </div>
              <label>SHA-256 отпечаток сервера<input v-model="draft.ssh.hostKeySha256" readonly placeholder="Будет сохранён после первого подтверждения" /></label>
              <button class="primary-button ssh-connect" type="button" :disabled="busy" @click="openTerminal"><FluentIcon name="ssh" /> Открыть терминал</button>
            </div>
            <div class="details-actions"><button class="primary-button" @click="saveDraft"><FluentIcon name="save" /> Сохранить</button><button class="secondary-button" @click="draft = null">Отмена</button></div>
          </template>
          <div v-else class="details-placeholder"><div class="placeholder-icon"><FluentIcon name="note" :size="34" /></div><b>Выберите запись</b><span>Сведения и редактирование появятся здесь.</span></div>
        </aside>
      </section>

      <section
        v-if="terminalTabs.length"
        class="terminal-dock"
        :style="{ height: `${terminalDockHeight}px`, flexBasis: `${terminalDockHeight}px`, backgroundColor: activeTerminalTab?.backgroundColor ?? DEFAULT_TERMINAL_BACKGROUND }"
      >
        <div
          class="terminal-resize-handle"
          role="separator"
          aria-label="Изменить высоту терминала"
          title="Перетащите для изменения высоты; двойной щелчок — развернуть или восстановить"
          aria-orientation="horizontal"
          :aria-valuemin="MINIMUM_TERMINAL_HEIGHT"
          :aria-valuemax="clampTerminalHeight(Number.MAX_SAFE_INTEGER, terminalViewportHeight)"
          :aria-valuenow="terminalDockHeight"
          :aria-valuetext="`${terminalDockHeight} пикселей`"
          tabindex="0"
          @pointerdown="beginTerminalResize"
          @pointermove="moveTerminalResize"
          @pointerup="finishTerminalResize"
          @pointercancel="finishTerminalResize"
          @dblclick="toggleTerminalDockSize"
          @keydown.up.prevent="adjustTerminalHeight(24)"
          @keydown.down.prevent="adjustTerminalHeight(-24)"
        ></div>
        <nav class="terminal-tabstrip" aria-label="SSH-терминалы">
          <div class="terminal-tabs-list">
            <div
              v-for="terminalTab in terminalTabs"
              :key="terminalTab.id"
              class="terminal-tab"
              :class="{ active: activeTerminalId === terminalTab.id }"
            >
              <button type="button" class="terminal-tab-select" :title="terminalTab.title" :aria-pressed="activeTerminalId === terminalTab.id" @click="activeTerminalId = terminalTab.id"><FluentIcon name="ssh" :size="15" /><span>{{ terminalTab.title }}</span></button>
              <button type="button" class="terminal-tab-close" title="Закрыть терминал" :aria-label="`Закрыть терминал ${terminalTab.title}`" @click="closeTerminalTab(terminalTab)"><FluentIcon name="close" :size="12" /></button>
            </div>
          </div>
          <button type="button" class="terminal-toolbar-button" :disabled="busy || !activeTerminalTab" title="Ещё один сеанс текущего SSH-подключения" aria-label="Новый SSH-терминал" @click="openAnotherTerminal"><FluentIcon name="plus" :size="16" /></button>
          <div class="terminal-toolbar-actions">
            <details v-if="activeTerminalTab" class="terminal-settings" @focusout="closeTerminalAppearance" @keydown.esc.prevent="($event.currentTarget as HTMLDetailsElement).open = false">
              <summary class="terminal-toolbar-button" title="Настройки цветов терминала" aria-label="Настройки цветов терминала"><FluentIcon name="settings" :size="15" /></summary>
              <div class="terminal-appearance">
                <span class="terminal-appearance-title">Цвета этой вкладки</span>
                <label><span>Фон</span><input v-model="activeTerminalTab.backgroundColor" type="color" aria-label="Цвет фона терминала" /></label>
                <label><span>Текст</span><input v-model="activeTerminalTab.foregroundColor" type="color" aria-label="Цвет текста терминала" /></label>
                <span v-if="activeTerminalContrast < 4.5" class="terminal-contrast-warning">Низкий контраст</span>
                <button type="button" class="terminal-colors-reset" @click="resetActiveTerminalColors">Сбросить цвета</button>
              </div>
            </details>
            <button type="button" class="terminal-toolbar-button terminal-expand" :class="{ 'is-expanded': terminalDockExpanded }" :title="terminalDockExpanded ? 'Восстановить высоту терминала' : 'Развернуть терминал'" :aria-label="terminalDockExpanded ? 'Восстановить высоту терминала' : 'Развернуть терминал'" @click="toggleTerminalDockSize"><FluentIcon name="chevron" :size="15" /></button>
            <button type="button" class="terminal-toolbar-button" title="Закрыть все SSH-терминалы" aria-label="Закрыть все SSH-терминалы" @click="closeAllTerminalTabs"><FluentIcon name="close" :size="15" /></button>
          </div>
        </nav>
        <div class="terminal-stack">
          <TerminalSession
            v-for="terminalTab in terminalTabs"
            v-show="activeTerminalId === terminalTab.id"
            :key="terminalTab.id"
            :terminal-id="terminalTab.id"
            :vault-session-id="terminalTab.vaultSessionId"
            :record-id="terminalTab.recordId"
            :active="activeTerminalId === terminalTab.id"
            :background-color="terminalTab.backgroundColor"
            :foreground-color="terminalTab.foregroundColor"
            :clipboard-clear-seconds="terminalTab.clipboardClearSeconds"
            @host-key-observed="(fingerprint) => updateTerminalHostKey(terminalTab, fingerprint)"
          />
        </div>
      </section>
    </template>

    <div v-if="dialogState" class="modal-backdrop">
      <form class="modal" @submit.prevent="submitVaultDialog">
        <div class="modal-icon"><FluentIcon name="lock" :size="25" /></div><h2>{{ dialogState.kind === 'create' ? 'Новый защищённый сейф' : 'Разблокировка сейфа' }}</h2><p class="path-hint">{{ dialogState.path }}</p>
        <label>Мастер-пароль<input v-model="dialogState.password" type="password" autofocus autocomplete="current-password" @input="dialogError = ''" /></label>
        <label v-if="dialogState.kind === 'create'">Подтверждение пароля<input v-model="dialogState.confirmation" type="password" autocomplete="new-password" @input="dialogError = ''" /></label>
        <p v-if="dialogState.kind === 'create'" class="modal-note">Не менее 15 символов. Recovery и backdoor отсутствуют.</p>
        <p v-if="dialogError" class="modal-error" role="alert"><FluentIcon name="warning" :size="16" />{{ dialogError }}</p>
        <div class="modal-actions"><button type="button" class="secondary-button" :disabled="busy" @click="dialogState = null; dialogError = ''">Отмена</button><button type="submit" class="primary-button" :disabled="busy">{{ busy ? (dialogState.kind === 'create' ? 'Создание…' : 'Открытие…') : (dialogState.kind === 'create' ? 'Создать' : 'Открыть') }}</button></div>
      </form>
    </div>

    <div v-if="folderDialog" class="modal-backdrop"><form class="modal small" @submit.prevent="createFolder"><div class="modal-icon folder"><FluentIcon name="folder" :size="26" /></div><h2>Новая папка</h2><label>Имя<input v-model="folderDialog.name" autofocus maxlength="512" /></label><div class="modal-actions"><button type="button" class="secondary-button" @click="folderDialog = null">Отмена</button><button class="primary-button">Создать</button></div></form></div>

    <div v-if="settingsDialog" class="modal-backdrop">
      <form class="modal" @submit.prevent="saveSettings">
        <div class="modal-icon"><FluentIcon name="settings" :size="25" /></div>
        <h2>Настройки сейфа</h2>
        <label>Автоблокировка при бездействии, минут
          <input v-model.number="settingsDialog.autoLockMinutes" type="number" min="0" max="240" step="1" autofocus />
        </label>
        <p class="modal-note"><b>0 — отключено.</b> Значение хранится только внутри зашифрованного сейфа. Блокировка Windows, сон и завершение приложения всё равно немедленно закроют сейф и SSH-сеансы.</p>
        <div class="modal-actions"><button type="button" class="secondary-button" :disabled="busy" @click="settingsDialog = null">Отмена</button><button type="submit" class="primary-button" :disabled="busy">Сохранить</button></div>
      </form>
    </div>
  </main>
</template>
