interface Sender { mainFrame: unknown }
interface SenderEvent { sender: Sender; senderFrame: { url: string } | null }

export function isTrustedRenderer(event: SenderEvent, expected: Sender | undefined, pathname: '/index.html' | '/notes.html'): boolean {
  if (!expected || event.sender !== expected || event.senderFrame !== expected.mainFrame) return false;
  try {
    const url = new URL(event.senderFrame?.url ?? 'about:blank');
    return url.protocol === 'pmapp:' && url.hostname === 'local' && url.pathname === pathname && !url.search && !url.hash && !url.username && !url.password;
  } catch { return false; }
}
