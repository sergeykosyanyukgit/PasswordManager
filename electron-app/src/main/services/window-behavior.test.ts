import { describe, expect, it, vi } from 'vitest';
vi.mock('electron', () => ({ Menu: { buildFromTemplate: vi.fn(() => ({ popup: vi.fn() })) } }));
import type { BrowserWindow, WebContents } from 'electron';
import { installWindowBehavior, setEditingContext } from './window-behavior.js';

function fixture(context: 'text' | 'terminal' | 'none') {
  const listeners = new Map<string, (...args: any[]) => void>();
  const contents = { on: (name: string, callback: (...args: any[]) => void) => listeners.set(name, callback), setWindowOpenHandler: vi.fn(), copy: vi.fn(), cut: vi.fn(), paste: vi.fn(), selectAll: vi.fn(), undo: vi.fn(), redo: vi.fn() };
  const command = vi.fn(); const copied = vi.fn();
  installWindowBehavior({ webContents: contents } as unknown as BrowserWindow, command, copied);
  setEditingContext(contents as unknown as WebContents, context);
  const key = (code: string, control = true, shift = false) => { const event = { preventDefault: vi.fn() }; listeners.get('before-input-event')!(event, { type: 'keyDown', code, control, shift, alt: false, meta: false }); return event; };
  return { contents, command, copied, key, listeners };
}
describe('native editing shortcuts', () => {
  it('dispatches native copy/cut/paste/select/undo/redo only for text fields', () => {
    const value = fixture('text');
    for (const [code, name] of [['KeyC', 'copy'], ['KeyX', 'cut'], ['KeyV', 'paste'], ['KeyA', 'selectAll'], ['KeyZ', 'undo'], ['KeyY', 'redo']] as const) {
      expect(value.key(code).preventDefault).toHaveBeenCalled(); expect(value.contents[name]).toHaveBeenCalledTimes(1);
    }
    expect(value.copied).toHaveBeenCalledTimes(2);
    value.key('Insert', true); value.key('Insert', false, true); value.key('Delete', false, true); value.key('KeyZ', true, true);
    expect(value.contents.copy).toHaveBeenCalledTimes(2); expect(value.contents.paste).toHaveBeenCalledTimes(2); expect(value.contents.cut).toHaveBeenCalledTimes(2); expect(value.contents.redo).toHaveBeenCalledTimes(2);
  });
  it('preserves terminal keystrokes and scopes save/tab shortcuts to the focused application window', () => {
    const terminal = fixture('terminal');
    for (const code of ['KeyC', 'KeyV', 'KeyS', 'Tab']) expect(terminal.key(code).preventDefault).not.toHaveBeenCalled();
    expect(terminal.command).not.toHaveBeenCalled(); expect(terminal.contents.copy).not.toHaveBeenCalled();
    const application = fixture('none'); application.key('KeyS'); application.key('KeyO'); application.key('Tab', true, true);
    expect(application.command.mock.calls.map((call) => call[0])).toEqual(['save', 'open', 'previous-tab']);
    expect(application.key('KeyC').preventDefault).not.toHaveBeenCalled();
  });
});
