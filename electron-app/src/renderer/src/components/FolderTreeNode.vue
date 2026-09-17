<script setup lang="ts">
import { computed, ref } from 'vue';
import type { VaultFolder } from '@shared/contracts';
import FluentIcon from './FluentIcon.vue';

const props = defineProps<{ folder: VaultFolder; folders: VaultFolder[]; selectedId: string }>();
const emit = defineEmits<{ select: [id: string] }>();
const expanded = ref(true);
const children = computed(() => props.folders.filter((item) => !item.isDeleted && item.parentId === props.folder.id).sort((a, b) => a.name.localeCompare(b.name)));
</script>

<template>
  <div class="tree-branch">
    <button class="tree-row" :class="{ selected: selectedId === folder.id }" @click="emit('select', folder.id)">
      <span class="tree-expander" @click.stop="expanded = !expanded"><FluentIcon v-if="children.length" name="chevron" :size="13" :class="{ rotated: expanded }" /></span>
      <FluentIcon name="folder" :size="20" />
      <span class="tree-name">{{ folder.name }}</span>
    </button>
    <div v-if="expanded" class="tree-children">
      <FolderTreeNode v-for="child in children" :key="child.id" :folder="child" :folders="folders" :selected-id="selectedId" @select="emit('select', $event)" />
    </div>
  </div>
</template>
