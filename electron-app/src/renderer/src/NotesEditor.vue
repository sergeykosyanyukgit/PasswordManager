<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue';
import type { AppCommand, NoteView, NotesViewState } from '@shared/contracts';
import { trackEditingContext } from './editingContext';
import FluentIcon from './components/FluentIcon.vue';

interface EditorTab extends NoteView { baseTitle: string; baseText: string; error: string }
const tabs = ref<EditorTab[]>([]);
const activeKey = ref<string | null>(null);
const theme = ref<'light' | 'dark'>('light');
const status = ref('');
const closingWindow = ref(false);
const closingTab = ref<string | null>(null);
const editingBlocked = computed(() => closingWindow.value || closingTab.value !== null);
const textInput = ref<HTMLTextAreaElement | null>(null);
const timers = new Map<string, ReturnType<typeof setTimeout>>();
const saves = new Map<string, Promise<void>>();
const stops: Array<() => void> = [];
const key = (tab: NoteView) => `${tab.sessionId}:${tab.recordId}`;
const dirty = (tab: EditorTab) => tab.title !== tab.baseTitle || tab.text !== tab.baseText;
const active = computed(() => tabs.value.find((tab) => key(tab) === activeKey.value) ?? null);
const diagnostics = import.meta.env.PM_SCREENSHOT_DIAGNOSTICS === true;

function apply(state: NotesViewState): void {
  const previous = new Map(tabs.value.map((tab) => [key(tab), tab]));
  tabs.value = state.tabs.map((item) => {
    const existing = previous.get(key(item));
    if (existing && (dirty(existing) || saves.has(key(existing)))) return existing;
    return { ...item, baseTitle: item.title, baseText: item.text, error: '' };
  });
  for (const [id, tab] of previous) if (!state.tabs.some((item) => key(item) === id)) { clearTimeout(timers.get(id)); timers.delete(id); tab.title = tab.text = tab.baseTitle = tab.baseText = ''; }
  activeKey.value = state.activeKey;
  theme.value = state.theme;
}

function changed(tab: EditorTab): void {
  tab.error = ''; status.value = '';
  const id = key(tab);
  clearTimeout(timers.get(id));
  timers.set(id, setTimeout(() => { void save(tab).catch(() => undefined); }, 800));
}

async function save(tab: EditorTab): Promise<void> {
  const id = key(tab);
  clearTimeout(timers.get(id)); timers.delete(id);
  const pending = saves.get(id);
  if (pending) { await pending; if (dirty(tab)) return save(tab); return; }
  if (!dirty(tab)) return;
  if (!tab.title.trim()) { tab.error = 'Введите название документа.'; throw new Error('Empty note title.'); }
  const input = { sessionId: tab.sessionId, recordId: tab.recordId, title: tab.title.trim(), text: tab.text, baseTitle: tab.baseTitle, baseText: tab.baseText };
  const operation = (async () => {
    try {
      const state = await window.noteEditor.updateNote(input);
      if (tab.title.trim() === input.title) tab.title = input.title;
      tab.baseTitle = input.title; tab.baseText = input.text;
      tab.error = ''; status.value = 'Сохранено';
      apply(state);
    } catch {
      tab.error = 'Не удалось сохранить: документ изменён в другом окне, хранилище заблокировано или возникла ошибка диска. Ваши правки остались в этом окне.';
      throw new Error('Note save failed.');
    }
  })();
  saves.set(id, operation);
  try { await operation; } finally { saves.delete(id); }
  if (dirty(tab)) changed(tab);
}

async function select(tab: EditorTab): Promise<void> {
  try { await window.noteEditor.activateTab(tab.sessionId, tab.recordId); await nextTick(); textInput.value?.focus(); }
  catch { status.value = 'Вкладка недоступна.'; }
}

async function closeTab(tab: EditorTab): Promise<void> {
  if (editingBlocked.value) return;
  closingTab.value = key(tab);
  try { await save(tab); await window.noteEditor.closeTab(tab.sessionId, tab.recordId); }
  catch { activeKey.value = key(tab); }
  finally { closingTab.value = null; }
}

async function restoreSaved(tab: EditorTab): Promise<void> {
  const state = await window.noteEditor.getState();
  const item = state.tabs.find((entry) => key(entry) === key(tab));
  if (item) { clearTimeout(timers.get(key(tab))); Object.assign(tab, item, { baseTitle: item.title, baseText: item.text, error: '' }); status.value = ''; }
}

async function closeWindow(): Promise<void> {
  if (closingWindow.value) return;
  closingWindow.value = true;
  try {
    for (const tab of tabs.value) { activeKey.value = key(tab); await save(tab); }
    await window.noteEditor.finishClose();
  } catch { status.value = 'Окно осталось открытым: сначала сохраните или отмените правки.'; await window.noteEditor.cancelClose().catch(() => undefined); }
  finally { closingWindow.value = false; }
}

function command(value: AppCommand): void {
  if (editingBlocked.value) return;
  const tab = active.value;
  if (value === 'save' && tab) void save(tab).catch(() => undefined);
  else if (value === 'close-tab' && tab) void closeTab(tab);
  else if (value === 'next-tab' || value === 'previous-tab') {
    const index = tabs.value.findIndex((item) => key(item) === activeKey.value);
    const next = tabs.value[(index + (value === 'next-tab' ? 1 : tabs.value.length - 1)) % tabs.value.length];
    if (next) void select(next);
  }
}

onMounted(async () => {
  stops.push(window.noteEditor.onState(apply), window.noteEditor.onCommand(command), window.noteEditor.onCloseRequested(() => { void closeWindow(); }), trackEditingContext(window.noteEditor));
  for (const event of ['pointerdown', 'keydown', 'wheel']) window.addEventListener(event, window.noteEditor.notifyActivity, { passive: true });
  try { apply(await window.noteEditor.getState()); await nextTick(); textInput.value?.focus(); }
  catch { status.value = 'Хранилище заблокировано.'; }
});
onBeforeUnmount(() => {
  stops.forEach((stop) => stop()); timers.forEach(clearTimeout);
  for (const event of ['pointerdown', 'keydown', 'wheel']) window.removeEventListener(event, window.noteEditor.notifyActivity);
  for (const tab of tabs.value) tab.title = tab.text = tab.baseTitle = tab.baseText = '';
});
</script>

<template>
  <main class="app-shell notes-shell" :data-theme="theme">
    <span v-if="diagnostics" class="screenshot-diagnostic-badge">Скриншоты разрешены · диагностика</span>
    <nav class="notes-tabs" aria-label="Открытые заметки">
      <div v-for="tab in tabs" :key="key(tab)" class="notes-tab" :class="{ active: key(tab) === activeKey }">
        <button class="notes-tab-title" :disabled="editingBlocked" :aria-pressed="key(tab) === activeKey" @click="select(tab)">{{ tab.title || 'Без названия' }}<span v-if="dirty(tab)" aria-label="Есть несохранённые изменения"> •</span></button>
        <button class="notes-tab-close" :disabled="editingBlocked" :aria-label="`Закрыть ${tab.title}`" @click="closeTab(tab)"><FluentIcon name="close" :size="13" /></button>
      </div>
    </nav>
    <section v-if="active" class="note-page">
      <input v-model="active.title" :readonly="editingBlocked" class="note-title-input" maxlength="512" aria-label="Название документа" placeholder="Название документа" autocomplete="off" @input="changed(active)" />
      <textarea ref="textInput" v-model="active.text" :readonly="editingBlocked" class="note-body-input" maxlength="16777216" aria-label="Текст документа" spellcheck="false" autocomplete="off" @input="changed(active)"></textarea>
      <div v-if="active.error" class="note-error" role="alert">{{ active.error }} <button class="secondary-button compact" @click="restoreSaved(active)">Отменить мои правки</button></div>
    </section>
    <p v-else class="notes-empty">Откройте текстовый документ двойным кликом.</p>
    <p class="note-save-status" :class="{ 'has-error': status.startsWith('Окно') }" role="status">{{ status }}</p>
  </main>
</template>
