import { describe, expect, it } from 'vitest';
import {
  clampTerminalHeight,
  DEFAULT_TERMINAL_BACKGROUND,
  DEFAULT_TERMINAL_FOREGROUND,
  MINIMUM_TERMINAL_HEIGHT,
  normalizeTerminalColor,
  terminalContrastRatio
} from './terminalAppearance';

describe('terminal appearance', () => {
  it('keeps the default terminal palette readable', () => {
    expect(terminalContrastRatio(DEFAULT_TERMINAL_BACKGROUND, DEFAULT_TERMINAL_FOREGROUND)).toBeGreaterThan(7);
  });

  it('accepts only complete hexadecimal colors', () => {
    expect(normalizeTerminalColor('#A1b2C3', DEFAULT_TERMINAL_BACKGROUND)).toBe('#a1b2c3');
    expect(normalizeTerminalColor('rgb(0, 0, 0)', DEFAULT_TERMINAL_BACKGROUND)).toBe(DEFAULT_TERMINAL_BACKGROUND);
    expect(normalizeTerminalColor('#fff', DEFAULT_TERMINAL_BACKGROUND)).toBe(DEFAULT_TERMINAL_BACKGROUND);
  });

  it('keeps the terminal and workspace above their minimum heights', () => {
    expect(clampTerminalHeight(40, 900)).toBe(MINIMUM_TERMINAL_HEIGHT);
    expect(clampTerminalHeight(2_000, 900)).toBe(730);
    expect(clampTerminalHeight(400, 300)).toBe(MINIMUM_TERMINAL_HEIGHT);
  });

  it('detects readable and unreadable color combinations', () => {
    expect(terminalContrastRatio('#000000', '#ffffff')).toBeCloseTo(21);
    expect(terminalContrastRatio('#111111', '#151515')).toBeLessThan(4.5);
  });
});
