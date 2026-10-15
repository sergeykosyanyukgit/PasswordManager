<script setup lang="ts">
import { computed, ref } from 'vue';
import type { VaultFolder, VaultRecord } from '@shared/contracts';
import FluentIcon from './FluentIcon.vue';
import { acceptsVaultDrop, beginItemDrag } from '../vaultDrag';

const props = defineProps<{ folder: VaultFolder; folders: VaultFolder[]; records: VaultRecord[]; sessionId: string; selectedId: string; selectedRecordId: string | null; busy: boolean }>();
const emit = defineEmits<{ select: [id: string]; 'select-record': [record: VaultRecord]; 'open-note': [id: string]; 'drop-folder': [id: string, event: DragEvent] }>();
const expanded = ref(true);
const dropTarget = ref(false);
const children = computed(() => props.folders.filter((item) => !item.isDeleted && item.parentId === props.folder.id).sort((a, b) => a.name.localeCompare(b.name)));
const files = computed(() => props.records.filter((item) => !item.isDeleted && item.folderId === props.folder.id).sort((a, b) => a.name.localeCompare(b.name)));
</script>

<template>
  <div class="tree-branch">
    <button class="tree-row" :data-folder-id="folder.id" :class="{ selected: selectedId === folder.id, 'drop-target': dropTarget }" :draggable="!busy && folder.parentId !== null" @dragstart.stop="beginItemDrag($event, sessionId, 'folder', folder.id)" @dragover.stop.prevent="dropTarget = acceptsVaultDrop($event)" @dragleave="dropTarget = false" @drop.stop.prevent="dropTarget = false; emit('drop-folder', folder.id, $event)" @click="emit('select', folder.id)">
      <span class="tree-expander" @click.stop="expanded = !expanded"><FluentIcon v-if="children.length || files.length" name="chevron" :size="13" :class="{ rotated: expanded }" /></span>
      <FluentIcon name="folder" :size="20" />
      <span class="tree-name">{{ folder.name }}</span>
    </button>
    <div v-if="expanded" class="tree-children">
      <FolderTreeNode v-for="child in children" :key="child.id" :folder="child" :folders="folders" :records="records" :session-id="sessionId" :selected-id="selectedId" :selected-record-id="selectedRecordId" :busy="busy" @select="emit('select', $event)" @select-record="emit('select-record', $event)" @open-note="emit('open-note', $event)" @drop-folder="(id, event) => emit('drop-folder', id, event)" />
      <button v-for="record in files" :key="record.id" class="tree-row tree-file" :data-record-id="record.id" :class="{ selected: selectedRecordId === record.id }" :draggable="!busy" @dragstart.stop="beginItemDrag($event, sessionId, 'record', record.id)" @click="emit('select-record', record)" @dblclick="record.type === 3 && emit('open-note', record.id)"><span class="tree-expander"></span><FluentIcon :name="['login', 'email', 'password', 'note', 'ssh'][record.type]!" :size="17" /><span class="tree-name">{{ record.name }}</span></button>
    </div>
  </div>
</template>
