export const DEFAULT_TERMINAL_BACKGROUND = '#181818';
export const DEFAULT_TERMINAL_FOREGROUND = '#f0f0f0';
export const MINIMUM_TERMINAL_HEIGHT = 190;

const HEX_COLOR = /^#[0-9a-f]{6}$/iu;
// The fixed title, vault tabs, command bar, and address bar occupy about 168 px.
// Keeping only that chrome visible lets the terminal expand to the top of the
// content area without pushing application controls outside the viewport.
const MINIMUM_REMAINING_WORKSPACE_HEIGHT = 170;

export function normalizeTerminalColor(value: string, fallback: string): string {
  return HEX_COLOR.test(value) ? value.toLowerCase() : fallback;
}

export function clampTerminalHeight(requestedHeight: number, viewportHeight: number): number {
  const maximum = Math.max(MINIMUM_TERMINAL_HEIGHT, Math.floor(viewportHeight) - MINIMUM_REMAINING_WORKSPACE_HEIGHT);
  return Math.min(maximum, Math.max(MINIMUM_TERMINAL_HEIGHT, Math.round(requestedHeight)));
}

export function terminalContrastRatio(background: string, foreground: string): number {
  const backgroundLuminance = relativeLuminance(normalizeTerminalColor(background, DEFAULT_TERMINAL_BACKGROUND));
  const foregroundLuminance = relativeLuminance(normalizeTerminalColor(foreground, DEFAULT_TERMINAL_FOREGROUND));
  const lighter = Math.max(backgroundLuminance, foregroundLuminance);
  const darker = Math.min(backgroundLuminance, foregroundLuminance);
  return (lighter + 0.05) / (darker + 0.05);
}

function relativeLuminance(color: string): number {
  const channels = [color.slice(1, 3), color.slice(3, 5), color.slice(5, 7)]
    .map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return (channels[0] ?? 0) * 0.2126 + (channels[1] ?? 0) * 0.7152 + (channels[2] ?? 0) * 0.0722;
}
