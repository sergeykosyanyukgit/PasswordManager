import { describe, expect, it } from 'vitest';
import { isTrustedRenderer } from './ipc-sender.js';

describe('window-specific IPC boundary', () => {
  it('accepts only the intended top-level local window and document', () => {
    const frame = { url: 'pmapp://local/index.html' };
    const sender = { mainFrame: frame };
    expect(isTrustedRenderer({ sender, senderFrame: frame }, sender, '/index.html')).toBe(true);
    expect(isTrustedRenderer({ sender, senderFrame: frame }, sender, '/notes.html')).toBe(false);
    expect(isTrustedRenderer({ sender, senderFrame: frame }, { mainFrame: frame }, '/index.html')).toBe(false);
    expect(isTrustedRenderer({ sender, senderFrame: { ...frame } }, sender, '/index.html')).toBe(false);
    expect(isTrustedRenderer({ sender, senderFrame: null }, sender, '/index.html')).toBe(false);
  });
  it.each(['https://local/index.html', 'pmapp://remote/index.html', 'pmapp://local/index.html?file=synthetic', 'pmapp://local/index.html#other', 'invalid'])('rejects a hostile frame URL', (url) => {
    const frame = { url }; const sender = { mainFrame: frame };
    expect(isTrustedRenderer({ sender, senderFrame: frame }, sender, '/index.html')).toBe(false);
  });
});
