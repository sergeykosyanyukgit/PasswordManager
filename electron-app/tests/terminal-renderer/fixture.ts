import { createApp, h, nextTick, ref } from 'vue';
import TerminalSession from '../../src/renderer/src/components/TerminalSession.vue';
import '../../src/renderer/src/styles.css';

// This fixture has no vault, credentials, network, filesystem, or production IPC.
const active = ref('synthetic-a');
const height = ref(350);
const foreground = ref('#f0f0f0');
const dataListeners = new Set<(event: object) => void>();
const selectListeners = new Set<(id: string) => void>();
const starts: any[] = [];
const resizes: any[] = [];
const writes: string[] = [];
const violations: string[] = [];
const checks: string[] = [];
document.addEventListener('securitypolicyviolation', event => violations.push(event.effectiveDirective));
const listen = (listeners: Set<any>, callback: any) => { listeners.add(callback); return () => listeners.delete(callback); };
Object.assign(window, { passwordManager: Object.freeze({
  startSshTerminal: async (request: any) => {
    starts.push(request);
    return { status: 'connected', fingerprint: 'SHA256:SyntheticTestFingerprintOnly' };
  },
  writeSshTerminal: async (_id: string, text: string) => { writes.push(text); },
  resizeSshTerminal: async (id: string, cols: number, rows: number) => { resizes.push({ id, cols, rows }); },
  closeSshTerminal: async () => undefined,
  copySecret: async () => undefined,
  showSshTerminalContextMenu: async () => undefined,
  onSshTerminalData: (callback: any) => listen(dataListeners, callback),
  onSshTerminalClosed: () => () => undefined,
  onSshTerminalSelectAll: (callback: any) => listen(selectListeners, callback)
}) });

createApp({ setup: () => () => h('div', { class: 'app-shell', 'data-theme': 'dark' }, [
  h('header', { class: 'titlebar' }, 'Synthetic terminal rendering test'),
  h('section', { class: 'explorer-grid' }, 'Synthetic records only'),
  h('section', { class: 'terminal-dock', style: { height: `${height.value}px`, flexBasis: `${height.value}px` } }, [
    h('div', { class: 'terminal-resize-handle' }),
    h('div', { class: 'terminal-tabstrip' }, [
      h('button', { class: 'terminal-tab active', id: 'blur-target' }, 'synthetic@terminal.invalid'),
    ]),
    h('div', { class: 'terminal-stack' }, ['synthetic-a', 'synthetic-b'].map(id => h(TerminalSession, {
      key: id, terminalId: id, vaultSessionId: 'synthetic-vault', recordId: 'synthetic-record',
      active: active.value === id, backgroundColor: '#181818', foregroundColor: foreground.value,
      clipboardClearSeconds: 30, style: { display: active.value === id ? undefined : 'none' },
      'data-test-session': id
    })))
  ])
]) }).mount('#app');

const settle = () => new Promise(resolve => setTimeout(resolve, 160));
const session = () => document.querySelector<HTMLElement>(`[data-test-session="${active.value}"]`)!;
const output = async (text: string) => {
  dataListeners.forEach(callback => callback({ terminalId: active.value, data: text }));
  await settle();
};
const assert = (condition: unknown, message: string) => {
  if (!condition) throw new Error(message);
  checks.push(message);
};
const colorsVisible = (element: Element) => {
  const style = getComputedStyle(element);
  return style.backgroundColor !== 'rgba(0, 0, 0, 0)' || style.boxShadow !== 'none' || style.outlineStyle !== 'none';
};

async function run() {
  await document.fonts.ready;
  await settle();
  assert(starts.length === 2, 'Both synthetic sessions connect');
  // Offscreen windows do not receive native activation. Deliver the same DOM
  // focus event that xterm receives when a user clicks its input in the app.
  session().querySelector('textarea')!.dispatchEvent(new FocusEvent('focus'));
  await output('\x1b[?25h\x1b[2J\x1b[HSYNTHETIC     STATUS        PORT\r\n' +
    'sample-a      Running       8080\r\n' + 'sample-b      Stopped       9090\r\nsynthetic$ ');
  const rows = session().querySelector('.xterm-rows')!;
  const rowStyle = getComputedStyle(rows);
  const cursor = session().querySelector('.xterm-cursor')!;
  const beforeMetrics = { font: rowStyle.fontFamily, whitespace: rowStyle.whiteSpace, cursor: cursor && colorsVisible(cursor), violations: [...violations] };
  Object.assign(window, { __terminalTestMetrics: beforeMetrics });
  assert(rowStyle.whiteSpace === 'pre' && /Cascadia|Consolas|monospace/.test(rowStyle.fontFamily), 'Monospace font and repeated spaces render under packaged CSP');
  const charX = (row: Element, offset: number) => {
    const walker = document.createTreeWalker(row, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (offset < node.textContent!.length) {
        const range = document.createRange();
        range.setStart(node, offset); range.setEnd(node, offset + 1);
        return range.getBoundingClientRect().x;
      }
      offset -= node.textContent!.length;
    }
    throw new Error('Missing synthetic table cell');
  };
  assert(Math.abs(charX(rows.children[0], 14) - charX(rows.children[1], 14)) < 0.6, 'Table columns align at equal character offsets');
  assert(cursor && colorsVisible(cursor), 'Prompt cursor has a visible painted style');
  selectListeners.forEach(callback => callback(active.value));
  await settle();
  const selected = session().querySelector('.xterm-selection > div')!;
  assert(selected && colorsVisible(selected) && selected.getBoundingClientRect().width > 0, 'Selection has a visible background');
  document.querySelector<HTMLButtonElement>('#blur-target')!.focus();
  await settle();
  assert(colorsVisible(selected), 'Selection stays visible after focus leaves the terminal');
  assert(colorsVisible(session().querySelector('.xterm-cursor')!), 'Inactive cursor stays visible');
  assert(violations.length === 0, 'Rendering produces no CSP violations');

  for (const nextHeight of [190, 350, innerHeight - 170]) {
    height.value = nextHeight;
    await nextTick(); await settle();
    const dock = document.querySelector('.terminal-dock')!.getBoundingClientRect();
    const fit = session().querySelector('.terminal-fit-host')!.getBoundingClientRect();
    const screen = session().querySelector('.xterm-screen')!.getBoundingClientRect();
    const legacy = session().querySelector('.xterm-viewport')!;
    assert(Math.abs(dock.bottom - innerHeight) < 1, `Dock stays at window bottom at height ${nextHeight}`);
    assert(screen.width <= fit.width && screen.height <= fit.height && screen.y >= fit.y, `Terminal grid fits its padded host at height ${nextHeight}`);
    assert(getComputedStyle(legacy).overflowY === 'hidden' && getComputedStyle(legacy).backgroundColor === 'rgba(0, 0, 0, 0)', 'Legacy viewport cannot paint an extra bottom scrollbar');
    assert(document.documentElement.scrollHeight === innerHeight, 'Document has no vertical overflow');
    const size = resizes.filter(item => item.id === active.value).at(-1);
    assert(size && size.cols >= 20 && size.rows >= 5, 'PTY receives usable dimensions after resize');
  }

  active.value = 'synthetic-b'; await nextTick(); await settle();
  assert(session().contains(document.activeElement), 'Switching tabs focuses the active terminal');
  await output('Synthetic second session\r\nsynthetic$ ');
  foreground.value = '#aaddff'; await nextTick(); await settle();
  assert(getComputedStyle(session().querySelector('.xterm-rows')!).color === 'rgb(170, 221, 255)', 'Theme updates regenerate working terminal styles');
  active.value = 'synthetic-a'; await nextTick(); await settle();
  await output('\x1b[2J\x1b[H' + Array.from({ length: 100 }, (_, i) => `Synthetic history ${i}\r\n`).join('') + 'synthetic$ ');
  const textarea = session().querySelector('textarea')!;
  textarea.dispatchEvent(new KeyboardEvent('keydown', { key: 'PageUp', shiftKey: true, bubbles: true }));
  await settle();
  assert(!session().querySelector('.xterm-rows')!.textContent!.includes('synthetic$'), 'History scrolls with Shift+PageUp');
  textarea.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', ctrlKey: true, shiftKey: true, bubbles: true }));
  await settle();
  assert(session().querySelector('.xterm-rows')!.textContent!.includes('synthetic$'), 'Ctrl+Shift+End returns to the prompt');

  // Regression checks for the security boundary next to the style exception.
  const evilScript = document.createElement('script');
  evilScript.textContent = 'window.__syntheticInlineScriptRan = true';
  document.head.append(evilScript);
  const evilStyle = document.createElement('link');
  evilStyle.rel = 'stylesheet'; evilStyle.href = 'https://synthetic.invalid/blocked.css'; document.head.append(evilStyle);
  await settle();
  assert(!(window as any).__syntheticInlineScriptRan && violations.includes('script-src-elem'), 'Inline script remains blocked');
  assert(violations.includes('style-src-elem'), 'Remote stylesheet remains blocked');
  await output('\x1b[2J\x1b[H\x1b[38;2;170;221;255mSynthetic RGB text\x1b[0m\r\nsynthetic$ ');
  assert(getComputedStyle(session().querySelector('.xterm-rows span')!).color === 'rgb(170, 221, 255)', 'Truecolor style attributes render correctly');
  const styleCount = session().querySelectorAll('style').length;
  await output('\x1b[2J\x1b[H<style>body{display:none}</style>\r\n\x1b]52;c;U3ludGhldGlj\x07\r\nsynthetic$ ');
  assert(session().querySelectorAll('style').length === styleCount && document.body.getBoundingClientRect().height > 0, 'Remote HTML is rendered as terminal text');
  assert(writes.length === 0, 'Remote OSC-52 has no clipboard response');
  await output('\x1b[2J\x1b[HSYNTHETIC     STATUS        PORT\r\nsample-a      Running       8080\r\nsample-b      Stopped       9090\r\n\r\nsynthetic$ ');
  selectListeners.forEach(callback => callback(active.value));
  await settle();
  return { passed: true, checks, size: [innerWidth, innerHeight], metrics: beforeMetrics };
}
run().then(result => Object.assign(window, { __terminalTestResult: result }))
  .catch(error => Object.assign(window, { __terminalTestResult: { passed: false, error: error.message, checks, metrics: (window as any).__terminalTestMetrics, violations } }));
