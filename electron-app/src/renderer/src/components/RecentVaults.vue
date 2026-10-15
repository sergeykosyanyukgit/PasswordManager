<script setup lang="ts">
import { ref } from 'vue';
import type { VaultHistory } from '@shared/contracts';
import FluentIcon from './FluentIcon.vue';

const props = defineProps<{ history: VaultHistory; busy: boolean }>();
const emit = defineEmits<{ open: [path: string]; reorder: [ids: string[]]; remove: [id: string]; sort: [] }>();
const draggedId = ref<string | null>(null);

function move(id: string, targetIndex: number): void {
  const ids = props.history.entries.map((entry) => entry.id);
  const from = ids.indexOf(id);
  if (props.busy || from < 0 || targetIndex < 0 || targetIndex >= ids.length || from === targetIndex) return;
  ids.splice(from, 1);
  ids.splice(targetIndex, 0, id);
  emit('reorder', ids);
}

function drop(index: number): void {
  if (draggedId.value) move(draggedId.value, index);
  draggedId.value = null;
}

function fileName(path: string): string { return path.split(/[\\/]/u).at(-1) ?? path; }
function openedDate(value: string): string { return new Date(value).toLocaleString('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }); }
</script>

<template>
  <section class="recent-vaults" aria-label="Ранее открытые хранилища">
    <div class="recent-heading">
      <h2>Ваши хранилища <span>{{ history.entries.length }}</span></h2>
      <button type="button" class="history-sort" :disabled="busy || history.order === 'recent'" @click="emit('sort')">Сначала недавние</button>
    </div>
    <p class="recent-help">{{ history.order === 'manual' ? 'Ваш порядок сохранён.' : 'Сверху — недавно открытые.' }} Перетаскивайте строки или используйте стрелки.</p>
    <ol class="recent-list">
      <li v-for="(entry, index) in history.entries" :key="entry.id" class="recent-row" :class="{ dragging: draggedId === entry.id }"
        :draggable="!busy" @dragstart="draggedId = entry.id" @dragend="draggedId = null" @dragover.prevent @drop.prevent="drop(index)">
        <span class="drag-grip" aria-hidden="true">⠿</span>
        <button type="button" class="recent-open" :disabled="busy" :title="entry.path" @click="emit('open', entry.path)">
          <FluentIcon name="notebook" :size="27" />
          <span class="recent-info"><strong>{{ fileName(entry.path) }}</strong><span class="recent-path">{{ entry.path }}</span><span class="recent-date">Открыто {{ openedDate(entry.lastOpenedUtc) }}</span></span>
        </button>
        <div class="recent-controls">
          <button type="button" class="icon-button" :disabled="busy || index === 0" :aria-label="`Переместить выше: ${fileName(entry.path)}`" title="Переместить выше" @click="move(entry.id, index - 1)">↑</button>
          <button type="button" class="icon-button" :disabled="busy || index === history.entries.length - 1" :aria-label="`Переместить ниже: ${fileName(entry.path)}`" title="Переместить ниже" @click="move(entry.id, index + 1)">↓</button>
          <button type="button" class="icon-button history-remove" :disabled="busy" :aria-label="`Убрать из списка: ${fileName(entry.path)}`" title="Убрать из списка — файл останется на диске" @click="emit('remove', entry.id)"><FluentIcon name="delete" :size="16" /></button>
        </div>
      </li>
    </ol>
    <p class="recent-footnote">Удаление из списка оставляет файл на диске.</p>
  </section>
</template>
