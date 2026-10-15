import { Menu, type BrowserWindow, type WebContents } from 'electron';
import type { AppCommand, EditingContext } from '../../shared/contracts.js';

const contexts = new WeakMap<WebContents, EditingContext>();
export function setEditingContext(contents: WebContents, context: EditingContext): void { contexts.set(contents, context); }

export function installWindowBehavior(window: BrowserWindow, command: (value: AppCommand) => void, copied: () => void): void {
  const contents = window.webContents;
  contents.on('will-navigate', (event) => event.preventDefault());
  contents.on('will-frame-navigate', (event) => event.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.on('will-attach-webview', (event) => event.preventDefault());
  contents.on('will-prevent-unload', (event) => event.preventDefault());
  contents.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown' || input.alt || input.meta || contexts.get(contents) === 'terminal') return;
    const code = input.code;
    if (contexts.get(contents) === 'text') {
      let edit: 'copy' | 'cut' | 'paste' | 'selectAll' | 'undo' | 'redo' | undefined;
      if (input.control && code === 'KeyC' || input.control && code === 'Insert') edit = 'copy';
      else if (input.control && code === 'KeyX' || input.shift && code === 'Delete') edit = 'cut';
      else if (input.control && code === 'KeyV' || input.shift && code === 'Insert') edit = 'paste';
      else if (input.control && code === 'KeyA') edit = 'selectAll';
      else if (input.control && code === 'KeyY' || input.control && input.shift && code === 'KeyZ') edit = 'redo';
      else if (input.control && code === 'KeyZ') edit = 'undo';
      if (edit) { event.preventDefault(); contents[edit](); if (edit === 'copy' || edit === 'cut') copied(); return; }
    }
    if (!input.control) return;
    const action: AppCommand | undefined = code === 'KeyS' ? 'save' : code === 'KeyO' ? 'open' :
      code === 'KeyN' ? input.shift ? 'new-folder' : 'new-note' : code === 'KeyW' ? 'close-tab' :
      code === 'Tab' ? input.shift ? 'previous-tab' : 'next-tab' : code === 'KeyF' ? 'find' : undefined;
    if (action) { event.preventDefault(); command(action); }
  });
  contents.on('context-menu', (_event, params) => {
    if (!params.isEditable) return;
    const items: Electron.MenuItemConstructorOptions[] = [
      { label: 'Отменить', click: () => contents.undo() }, { label: 'Повторить', click: () => contents.redo() },
      { type: 'separator' },
      { label: 'Вырезать', enabled: params.selectionText.length > 0, click: () => { contents.cut(); copied(); } },
      { label: 'Копировать', enabled: params.selectionText.length > 0, click: () => { contents.copy(); copied(); } },
      { label: 'Вставить', click: () => contents.paste() }, { type: 'separator' },
      { label: 'Выделить всё', click: () => contents.selectAll() }
    ];
    Menu.buildFromTemplate(items).popup({ window });
  });
}
