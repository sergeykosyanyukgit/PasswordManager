import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import './terminal.css';

const terminal = new Terminal({
  allowProposedApi: false,
  convertEol: false,
  cursorBlink: true,
  disableStdin: false,
  scrollback: 10000,
  termName: 'xterm-256color',
  theme: { background: '#0b1020', foreground: '#e2e8f0', cursor: '#60a5fa' }
});
const fit = new FitAddon();
terminal.loadAddon(fit);
terminal.open(document.getElementById('terminal'));
terminal.parser.registerOscHandler(52, () => true);
fit.fit();

function post(message) {
  if (window.chrome?.webview) {
    window.chrome.webview.postMessage(message);
  }
}

terminal.onData(data => post({ type: 'input', data }));
terminal.onResize(size => post({ type: 'resize', cols: size.cols, rows: size.rows }));
window.addEventListener('resize', () => fit.fit());
window.chrome.webview.addEventListener('message', event => {
  const message = event.data;
  if (message?.type === 'output' && typeof message.data === 'string') {
    terminal.write(message.data);
  } else if (message?.type === 'focus') {
    terminal.focus();
  }
});
post({ type: 'ready' });
