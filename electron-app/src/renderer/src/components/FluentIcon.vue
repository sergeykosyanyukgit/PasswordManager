<script setup lang="ts">
defineProps<{ name: string; size?: number }>();
</script>

<template>
  <svg class="fluent-icon" :width="size ?? 18" :height="size ?? 18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <template v-if="name === 'folder'">
      <path d="M2.75 6.5A2.75 2.75 0 0 1 5.5 3.75h4.08c.73 0 1.43.29 1.94.8l1.2 1.2h5.78a2.75 2.75 0 0 1 2.75 2.75v8A3.75 3.75 0 0 1 17.5 20.25h-11a3.75 3.75 0 0 1-3.75-3.75v-10Z" fill="#D99B22" stroke="#7A5B20" stroke-width="1.2"/>
      <path d="M3.35 8.25h17.3" stroke="#F5C75C" stroke-width="1.4"/>
    </template>
    <template v-else-if="name === 'vault'">
      <rect x="3" y="3" width="18" height="18" rx="3.2" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="4.5" stroke="currentColor" stroke-width="1.5"/><path d="M12 9.6v2.8l2 1.2M5.2 7.2h1.6M5.2 16.8h1.6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    </template>
    <template v-else-if="name === 'login'">
      <circle cx="9" cy="8" r="3" stroke="currentColor" stroke-width="1.5"/><path d="M3.8 19c.5-3.4 2.2-5.2 5.2-5.2 1.7 0 3 .6 3.9 1.8M15 10.5h6M18 7.5v6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    </template>
    <template v-else-if="name === 'email'">
      <rect x="2.8" y="5" width="18.4" height="14" rx="2.5" stroke="currentColor" stroke-width="1.5"/><path d="m4 7 8 6 8-6" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
    </template>
    <template v-else-if="name === 'password'">
      <circle cx="8" cy="12" r="4" stroke="currentColor" stroke-width="1.5"/><path d="M12 12h9M17 12v3M20 12v2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    </template>
    <template v-else-if="name === 'note'">
      <path d="M5 2.8h9.5L20 8.3V21H5V2.8Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M14.5 3v5.3H20M8 12h8M8 16h6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
    </template>
    <template v-else-if="name === 'ssh'">
      <rect x="2.8" y="4" width="18.4" height="16" rx="2.8" stroke="currentColor" stroke-width="1.5"/><path d="m6.5 9 3 3-3 3M12 15h5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </template>
    <template v-else-if="name === 'plus'"><path d="M12 4v16M4 12h16" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></template>
    <template v-else-if="name === 'open'"><path d="M4 19V5h6l2 2h8v12H4Z" stroke="currentColor" stroke-width="1.5"/><path d="m8 14 4-4 4 4M12 10v8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></template>
    <template v-else-if="name === 'save'"><path d="M4 3h13l3 3v15H4V3Z" stroke="currentColor" stroke-width="1.5"/><path d="M8 3v6h8V3M8 21v-7h8v7" stroke="currentColor" stroke-width="1.5"/></template>
    <template v-else-if="name === 'delete'"><path d="M5 7h14M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></template>
    <template v-else-if="name === 'copy'"><rect x="8" y="8" width="11" height="12" rx="2" stroke="currentColor" stroke-width="1.5"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h2" stroke="currentColor" stroke-width="1.5"/></template>
    <template v-else-if="name === 'search'"><circle cx="10.5" cy="10.5" r="6.5" stroke="currentColor" stroke-width="1.6"/><path d="m15.5 15.5 5 5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></template>
    <template v-else-if="name === 'chevron'"><path d="m9 6 6 6-6 6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></template>
    <template v-else-if="name === 'close'"><path d="m6 6 12 12M18 6 6 18" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></template>
    <template v-else-if="name === 'lock'"><rect x="4" y="10" width="16" height="11" rx="2.5" stroke="currentColor" stroke-width="1.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></template>
    <template v-else-if="name === 'warning'"><path d="M12 3.5 21 20H3l9-16.5Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M12 9v5M12 17.2v.2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></template>
    <template v-else-if="name === 'back'"><path d="m14 5-7 7 7 7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></template>
    <template v-else-if="name === 'moon'"><path d="M20.2 15.2A8.5 8.5 0 0 1 8.8 3.8 8.5 8.5 0 1 0 20.2 15.2Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></template>
    <template v-else-if="name === 'sun'"><circle cx="12" cy="12" r="3.8" stroke="currentColor" stroke-width="1.5"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></template>
    <template v-else-if="name === 'settings'"><circle cx="12" cy="12" r="3.2" stroke="currentColor" stroke-width="1.5"/><path d="M12 2.8v2.1M12 19.1v2.1M2.8 12h2.1M19.1 12h2.1M5.5 5.5 7 7M17 17l1.5 1.5M18.5 5.5 17 7M7 17l-1.5 1.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="12" cy="12" r="7.1" stroke="currentColor" stroke-width="1.2" stroke-dasharray="2.4 2.2"/></template>
    <template v-else><circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="1.5"/></template>
  </svg>
</template>
