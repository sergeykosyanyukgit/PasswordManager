<script setup lang="ts">
import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { DEFAULT_TERMINAL_BACKGROUND, DEFAULT_TERMINAL_FOREGROUND, normalizeTerminalColor } from '../terminalAppearance';
const props = defineProps<{
  terminalId: string;
  vaultSessionId: string;
  recordId: string;
  active: boolean;
  backgroundColor: string;
  foregroundColor: string;
  clipboardClearSeconds: number;
}>();
const emit = defineEmits<{ connected: []; hostKeyObserved: [fingerprint: string] }>();

const fitHost = ref<HTMLElement | null>(null);
const status = ref('Подключение…');
const statusKind = ref<'pending' | 'connected' | 'error'>('pending');
let terminal: Terminal | null = null;
let fitAddon: FitAddon | null = null;
let resizeObserver: ResizeObserver | null = null;
let disposed = false;
let connected = false;
let removeDataListener = (): void => undefined;
let removeClosedListener = (): void => undefined;
let removeSelectAllListener = (): void => undefined;
const terminalDisposables: Array<{ dispose(): void }> = [];
const safeBackgroundColor = computed(() => normalizeTerminalColor(props.backgroundColor, DEFAULT_TERMINAL_BACKGROUND));
const safeForegroundColor = computed(() => normalizeTerminalColor(props.foregroundColor, DEFAULT_TERMINAL_FOREGROUND));

const baseTheme = {
  selectionBackground: '#3b4d63',
  selectionForeground: '#ffffff',
  selectionInactiveBackground: '#3b4656',
  scrollbarSliderBackground: '#ffffff18',
  scrollbarSliderHoverBackground: '#ffffff30',
  scrollbarSliderActiveBackground: '#ffffff45',
  black: '#181818', red: '#cd3131', green: '#0dbc79', yellow: '#e5e510', blue: '#2472c8',
  magenta: '#bc3fbc', cyan: '#11a8cd', white: '#e5e5e5', brightBlack: '#666666', brightRed: '#f14c4c',
  brightGreen: '#23d18b', brightYellow: '#f5f543', brightBlue: '#3b8eea', brightMagenta: '#d670d6',
  brightCyan: '#29b8db', brightWhite: '#ffffff'
};

function terminalTheme() {
  return {
    ...baseTheme,
    background: safeBackgroundColor.value,
    foreground: safeForegroundColor.value,
    cursor: safeForegroundColor.value,
    cursorAccent: safeBackgroundColor.value
  };
}

onMounted(async () => {
  terminal = new Terminal({
    allowProposedApi: false,
    cursorBlink: false,
    cursorStyle: 'bar',
    cursorWidth: 2,
    cursorInactiveStyle: 'outline',
    fontFamily: '"Cascadia Mono", "Cascadia Code", Consolas, "Liberation Mono", monospace',
    fontSize: 12,
    fontWeight: '400',
    fontWeightBold: '700',
    // Keep the cell pitch exact. The corrected fit container provides the
    // visual spacing without distorting shell-calculated table columns.
    letterSpacing: 0,
    lineHeight: 1.15,
    tabStopWidth: 8,
    rescaleOverlappingGlyphs: true,
    customGlyphs: true,
    drawBoldTextInBrightColors: true,
    minimumContrastRatio: 4.5,
    scrollback: 5_000,
    scrollOnUserInput: true,
    smoothScrollDuration: 100,
    rightClickSelectsWord: true,
    theme: terminalTheme()
  });
  fitAddon = new FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(fitHost.value!);

  // Remote output must not be allowed to write to the local clipboard or rename UI surfaces.
  terminal.parser.registerOscHandler(52, () => true);
  terminal.parser.registerOscHandler(0, () => true);
  terminal.parser.registerOscHandler(1, () => true);
  terminal.parser.registerOscHandler(2, () => true);
  terminalDisposables.push(terminal.onData((data) => {
    if (connected) void window.passwordManager.writeSshTerminal(props.terminalId, data).catch(() => markClosed('Ошибка отправки данных.'));
  }));
  terminal.attachCustomKeyEventHandler(handleTerminalKey);
  removeDataListener = window.passwordManager.onSshTerminalData((event) => {
    if (event.terminalId === props.terminalId) terminal?.write(event.data);
  });
  removeClosedListener = window.passwordManager.onSshTerminalClosed((event) => {
    if (event.terminalId === props.terminalId) markClosed(event.reason === 'error' ? 'SSH-соединение прервано.' : 'SSH-соединение закрыто.');
  });
  removeSelectAllListener = window.passwordManager.onSshTerminalSelectAll((terminalId) => {
    if (terminalId === props.terminalId) terminal?.selectAll();
  });
  resizeObserver = new ResizeObserver(() => { if (props.active) void fitAndResize(); });
  resizeObserver.observe(fitHost.value!);
  // Measure the actual monospace font and padded content area before asking
  // the SSH server to draw its initial screen at the resulting PTY width.
  await document.fonts.ready;
  if (disposed) return;
  terminal.clearTextureAtlas();
  await fitAndResize();
  await connect();
});

watch(() => props.active, async (active) => {
  if (!active) return;
  await nextTick();
  await fitAndResize();
  terminal?.focus();
});

watch([() => props.backgroundColor, () => props.foregroundColor], () => {
  if (terminal) terminal.options.theme = terminalTheme();
});

onBeforeUnmount(() => {
  disposed = true;
  connected = false;
  removeDataListener();
  removeClosedListener();
  removeSelectAllListener();
  resizeObserver?.disconnect();
  for (const disposable of terminalDisposables) disposable.dispose();
  void window.passwordManager.closeSshTerminal(props.terminalId).catch(() => undefined);
  terminal?.dispose();
  terminal = null;
  fitAddon = null;
});

async function connect(): Promise<void> {
  if (!terminal || disposed) return;
  try {
    const result = await window.passwordManager.startSshTerminal({
      terminalId: props.terminalId,
      vaultSessionId: props.vaultSessionId,
      recordId: props.recordId,
      cols: terminal.cols,
      rows: terminal.rows
    });
    if (result.status === 'cancelled') {
      markClosed('Подключение отменено пользователем.');
      return;
    }
    if (result.status === 'hostKeyMismatch') {
      markClosed(`Подключение заблокировано: ключ сервера изменился (${result.fingerprint}).`);
      return;
    }
    if (result.status === 'failed') {
      markClosed(connectionFailureText(result.reason));
      return;
    }
    if (result.status !== 'connected') {
      markClosed('Не удалось подтвердить ключ SSH-сервера.');
      return;
    }
    if (disposed) {
      await window.passwordManager.closeSshTerminal(props.terminalId).catch(() => undefined);
      return;
    }
    connected = true;
    status.value = `Подключено · ${result.fingerprint}`;
    statusKind.value = 'connected';
    terminal.focus();
    emit('hostKeyObserved', result.fingerprint);
    emit('connected');
  } catch {
    markClosed('Внутренняя ошибка запуска SSH. Закройте вкладку и повторите попытку.');
  }
}

function connectionFailureText(reason: 'dns' | 'refused' | 'timeout' | 'authentication' | 'algorithms' | 'kexAlgorithm' | 'hostKeyAlgorithm' | 'cipherAlgorithm' | 'macAlgorithm' | 'compressionAlgorithm' | 'clientConfiguration' | 'strictKex' | 'signatureVerification' | 'hostKeyProtocol' | 'keyExchangeComputation' | 'malformedHandshake' | 'protocolHandshake' | 'shell' | 'privateKey' | 'network'): string {
  switch (reason) {
    case 'dns': return 'SSH: имя сервера не найдено. Проверьте адрес или DNS.';
    case 'refused': return 'SSH: сервер отклонил соединение. Проверьте порт и запущен ли SSH.';
    case 'timeout': return 'SSH: превышено время ожидания. Проверьте сеть, VPN, firewall и порт.';
    case 'authentication': return 'SSH: сервер отклонил логин или пароль.';
    case 'kexAlgorithm': return 'SSH: не найден совместимый алгоритм обмена ключами (KEX). Режим совместимости уже учтён, если он включён в записи.';
    case 'hostKeyAlgorithm': return 'SSH: не найден совместимый тип ключа сервера. Режим совместимости уже учтён, если он включён в записи.';
    case 'cipherAlgorithm': return 'SSH: не найден совместимый шифр. Режим совместимости уже учтён, если он включён в записи.';
    case 'macAlgorithm': return 'SSH: не найден совместимый алгоритм контроля целостности (MAC). Режим совместимости уже учтён, если он включён в записи.';
    case 'compressionAlgorithm': return 'SSH: не найден совместимый режим сжатия. Режим совместимости уже учтён, если он включён в записи.';
    case 'clientConfiguration': return 'SSH: встроенная криптографическая библиотека не поддерживает один из настроенных алгоритмов. Установите обновлённую сборку приложения.';
    case 'strictKex': return 'SSH: сервер нарушил порядок строгого обмена ключами (strict KEX). Подключение заблокировано как небезопасное.';
    case 'signatureVerification': return 'SSH: криптографическая подпись ключа сервера неверна. Подключение заблокировано — отключать эту проверку небезопасно.';
    case 'hostKeyProtocol': return 'SSH: сервер прислал некорректный тип или формат ключа/подписи. Подключение заблокировано.';
    case 'keyExchangeComputation': return 'SSH: сервер прислал недопустимые параметры обмена ключами DH. Подключение заблокировано.';
    case 'malformedHandshake': return 'SSH: сервер прислал повреждённые данные рукопожатия. Подключение заблокировано.';
    case 'protocolHandshake': return 'SSH: сервер нарушил протокол во время рукопожатия. Это не ошибка списка алгоритмов; подключение заблокировано.';
    case 'algorithms': return 'SSH: согласование алгоритмов завершилось ошибкой. Обновите приложение для получения точной категории.';
    case 'shell': return 'SSH подключён, но сервер не разрешил открыть интерактивный терминал.';
    case 'privateKey': return 'SSH: закрытый ключ повреждён, неверна парольная фраза или тип ключа не поддерживается.';
    default: return 'SSH-соединение прервано до открытия терминала.';
  }
}

async function fitAndResize(): Promise<void> {
  if (!props.active || !terminal || !fitAddon || !fitHost.value || fitHost.value.clientWidth === 0 || fitHost.value.clientHeight === 0) return;
  try {
    fitAddon.fit();
    if (connected) await window.passwordManager.resizeSshTerminal(props.terminalId, terminal.cols, terminal.rows);
  } catch {
    // A resize can race with a remote disconnect; the close event supplies the visible state.
  }
}

function markClosed(text: string): void {
  connected = false;
  status.value = text;
  statusKind.value = 'error';
}

function focusTerminal(): void {
  terminal?.focus();
}

function handleTerminalKey(event: KeyboardEvent): boolean {
  if (event.type !== 'keydown' || !terminal) return true;
  const key = event.key.toLowerCase();
  if (event.ctrlKey && !event.altKey && key === 'c' && terminal.hasSelection()) {
    void window.passwordManager.copySecret(terminal.getSelection(), props.clipboardClearSeconds);
    return false;
  }
  if (event.ctrlKey && event.shiftKey && key === 'a') {
    terminal.selectAll();
    return false;
  }
  if (event.shiftKey && key === 'pageup') { terminal.scrollPages(-1); return false; }
  if (event.shiftKey && key === 'pagedown') { terminal.scrollPages(1); return false; }
  if (event.ctrlKey && event.shiftKey && key === 'home') { terminal.scrollToTop(); return false; }
  if (event.ctrlKey && event.shiftKey && key === 'end') { terminal.scrollToBottom(); return false; }
  return true;
}

function showContextMenu(): void {
  const selection = terminal?.getSelection().slice(0, 1024 * 1024) ?? '';
  void window.passwordManager.showSshTerminalContextMenu(props.terminalId, selection, props.clipboardClearSeconds);
}

</script>

<template>
  <section class="terminal-session" :style="{ backgroundColor: safeBackgroundColor }">
    <div class="terminal-status" :class="`is-${statusKind}`" :title="status" role="status" aria-live="polite" aria-atomic="true">{{ status }}</div>
    <div class="terminal-host" @pointerdown="focusTerminal" @contextmenu.prevent="showContextMenu">
      <div ref="fitHost" class="terminal-fit-host"></div>
    </div>
  </section>
</template>
