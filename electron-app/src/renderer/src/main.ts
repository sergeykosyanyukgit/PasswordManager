import { createApp } from 'vue';
import App from './App.vue';
import NotesEditor from './NotesEditor.vue';
import './styles.css';

createApp(location.pathname === '/notes.html' ? NotesEditor : App).mount('#app');
