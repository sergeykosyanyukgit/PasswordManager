import { createHash } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { Client, utils, type Algorithms, type ClientChannel, type ConnectConfig } from 'ssh2';
import { z } from 'zod';
import type {
  SshProfile,
  SshConnectionFailureReason,
  SshTerminalClosedEvent,
  SshTerminalDataEvent,
  SshTerminalStartResult
} from '../../shared/contracts.js';

const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/u;
const CONTROL_CHARACTER = /[\u0000-\u001F\u007F]/u;
const MAXIMUM_TERMINAL_WRITE = 64 * 1024;

export const SSH_ALGORITHMS = Object.freeze({
  kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group18-sha512', 'diffie-hellman-group16-sha512', 'diffie-hellman-group14-sha256'],
  // Electron 44's Windows OpenSSL build does not expose ChaCha20-Poly1305 to
  // Node. Passing it explicitly makes ssh2 reject the whole configuration
  // before KEXINIT, even when the server also supports AES-GCM.
  cipher: ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'],
  serverHostKey: ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256'],
  hmac: ['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256'],
  compress: ['none']
} satisfies Algorithms);

export const SSH_COMPATIBILITY_ALGORITHMS = Object.freeze({
  kex: [...SSH_ALGORITHMS.kex, 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1'],
  cipher: [...SSH_ALGORITHMS.cipher, 'aes256-cbc', 'aes192-cbc', 'aes128-cbc', '3des-cbc', 'aes256-gcm', 'aes128-gcm'],
  serverHostKey: [...SSH_ALGORITHMS.serverHostKey, 'ssh-rsa', 'ssh-dss'],
  hmac: [...SSH_ALGORITHMS.hmac, 'hmac-sha1-etm@openssh.com', 'hmac-sha1', 'hmac-sha1-96', 'hmac-ripemd160', 'hmac-md5', 'hmac-md5-96'],
  compress: ['none', 'zlib@openssh.com', 'zlib']
} satisfies Algorithms);

const profileSchema = z.object({
  host: z.string().trim().min(1).max(253).refine((value) => !CONTROL_CHARACTER.test(value)),
  port: z.number().int().min(1).max(65_535),
  userName: z.string().min(1).max(512).refine((value) => !CONTROL_CHARACTER.test(value)),
  authenticationKind: z.union([z.literal(0), z.literal(1)]),
  password: z.string().max(1_000_000),
  privateKeyPem: z.string().max(4 * 1024 * 1024),
  privateKeyPassphrase: z.string().max(1_000_000),
  hostKeySha256: z.string().max(128).refine((value) => value === '' || FINGERPRINT.test(value)),
  allowLegacyAlgorithms: z.boolean()
}).strict().superRefine((profile, context) => {
  if (profile.authenticationKind === 0 && profile.password.length === 0) context.addIssue({ code: 'custom', path: ['password'], message: 'SSH password is required.' });
  if (profile.authenticationKind === 1 && profile.privateKeyPem.trim().length === 0) context.addIssue({ code: 'custom', path: ['privateKeyPem'], message: 'SSH private key is required.' });
});

const startSchema = z.object({
  terminalId: z.string().uuid(),
  vaultSessionId: z.string().uuid(),
  cols: z.number().int().min(20).max(500),
  rows: z.number().int().min(5).max(300)
}).strict();
const idSchema = z.string().uuid();
const writeSchema = z.object({ terminalId: idSchema, data: z.string().max(MAXIMUM_TERMINAL_WRITE) }).strict();
const resizeSchema = z.object({ terminalId: idSchema, cols: z.number().int().min(20).max(500), rows: z.number().int().min(5).max(300) }).strict();

interface TerminalSession {
  vaultSessionId: string;
  client: Client;
  stream: ClientChannel;
  decoder: StringDecoder;
  closed: boolean;
}

type TerminalEvent = SshTerminalDataEvent | SshTerminalClosedEvent;
type TerminalEmitter = (channel: 'ssh-terminal:data' | 'ssh-terminal:closed', event: TerminalEvent) => void;
type RuntimeRequest = z.infer<typeof startSchema>;
export type InternalSshStartResult = SshTerminalStartResult | { status: 'hostKeyRequired'; fingerprint: string };

export class SshTerminalManager {
  private readonly sessions = new Map<string, TerminalSession>();

  constructor(private readonly emit: TerminalEmitter) {}

  async start(input: unknown, profileInput: unknown): Promise<InternalSshStartResult> {
    const request = startSchema.parse(input);
    const profile = profileSchema.parse(profileInput) as SshProfile;
    if (this.sessions.has(request.terminalId)) throw new Error('SSH terminal already exists.');
    return this.connect(request, profile);
  }

  async write(input: unknown): Promise<void> {
    const request = writeSchema.parse(input);
    const session = this.requireSession(request.terminalId);
    if (!session.stream.writable) throw new Error('SSH terminal is closed.');
    session.stream.write(request.data, 'utf8');
  }

  async resize(input: unknown): Promise<void> {
    const request = resizeSchema.parse(input);
    this.requireSession(request.terminalId).stream.setWindow(request.rows, request.cols, 0, 0);
  }

  async close(input: unknown): Promise<void> {
    const terminalId = idSchema.parse(typeof input === 'object' && input && 'terminalId' in input ? input.terminalId : input);
    this.finish(terminalId, 'closed');
  }

  async closeAll(): Promise<void> {
    for (const terminalId of [...this.sessions.keys()]) this.finish(terminalId, 'closed');
  }

  async closeByVault(vaultSessionId: string): Promise<void> {
    const id = idSchema.parse(vaultSessionId);
    for (const [terminalId, session] of this.sessions) if (session.vaultSessionId === id) this.finish(terminalId, 'closed');
  }

  private connect(request: RuntimeRequest, profile: SshProfile): Promise<InternalSshStartResult> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      const expectedFingerprint = profile.hostKeySha256 || null;
      let observedFingerprint: string | null = null;
      let fingerprintRejected = false;
      let keyboardPasswordSent = false;
      let settled = false;
      const privateKey = profile.authenticationKind === 1 ? Buffer.from(profile.privateKeyPem, 'utf8') : null;
      const settle = (result: InternalSshStartResult | Error): void => {
        if (settled) return;
        settled = true;
        privateKey?.fill(0);
        profile.password = '';
        profile.privateKeyPem = '';
        profile.privateKeyPassphrase = '';
        if (result instanceof Error) reject(result); else resolve(result);
      };

      client.once('ready', () => {
        client.shell({ term: 'xterm-256color', cols: request.cols, rows: request.rows, width: 0, height: 0 }, (error, stream) => {
          if (error || !observedFingerprint) {
            client.end();
            settle({ status: 'failed', reason: 'shell' });
            return;
          }
          const session: TerminalSession = { vaultSessionId: request.vaultSessionId, client, stream, decoder: new StringDecoder('utf8'), closed: false };
          this.sessions.set(request.terminalId, session);
          stream.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.stderr.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.once('close', () => this.finish(request.terminalId, 'closed'));
          stream.once('error', () => this.finish(request.terminalId, 'error'));
          client.once('close', () => this.finish(request.terminalId, 'closed'));
          client.once('error', () => this.finish(request.terminalId, 'error'));
          settle({ status: 'connected', fingerprint: observedFingerprint });
        });
      });

      client.once('error', (error) => {
        client.end();
        if (observedFingerprint && !expectedFingerprint) settle({ status: 'hostKeyRequired', fingerprint: observedFingerprint });
        else if (observedFingerprint && fingerprintRejected) settle({ status: 'hostKeyMismatch', fingerprint: observedFingerprint });
        else settle({ status: 'failed', reason: classifyConnectionFailure(error) });
      });
      client.once('close', () => {
        if (!settled) settle({ status: 'failed', reason: 'network' });
      });

      if (profile.authenticationKind === 0) {
        client.on('keyboard-interactive', (_name, _instructions, _language, prompts, finish) => {
          const isSingleHiddenPasswordPrompt = !keyboardPasswordSent && prompts.length === 1 && prompts[0]?.echo === false;
          if (isSingleHiddenPasswordPrompt) keyboardPasswordSent = true;
          finish(isSingleHiddenPasswordPrompt ? [profile.password] : []);
        });
      }

      const config: ConnectConfig = {
        host: profile.host,
        port: profile.port,
        username: profile.userName,
        readyTimeout: 15_000,
        keepaliveInterval: 15_000,
        keepaliveCountMax: 3,
        strictVendor: true,
        tryKeyboard: profile.authenticationKind === 0,
        algorithms: profile.allowLegacyAlgorithms ? SSH_COMPATIBILITY_ALGORITHMS : SSH_ALGORITHMS,
        authHandler: profile.authenticationKind === 0 ? ['password', 'keyboard-interactive'] : ['publickey'],
        hostVerifier: (key: Buffer) => {
          observedFingerprint = hostKeyFingerprintSha256(key);
          const accepted = expectedFingerprint !== null && observedFingerprint === expectedFingerprint;
          fingerprintRejected = !accepted;
          return accepted;
        }
      };
      if (profile.authenticationKind === 0) config.password = profile.password;
      else {
        try { assertModernPrivateKey(privateKey!, profile.privateKeyPassphrase); }
        catch { client.end(); settle({ status: 'failed', reason: 'privateKey' }); return; }
        config.privateKey = privateKey!;
        if (profile.privateKeyPassphrase) config.passphrase = profile.privateKeyPassphrase;
      }
      try { client.connect(config); }
      catch (error) { client.end(); settle({ status: 'failed', reason: classifyConnectionFailure(error) }); }
    });
  }

  private requireSession(terminalId: string): TerminalSession {
    const session = this.sessions.get(terminalId);
    if (!session || session.closed) throw new Error('SSH terminal is not connected.');
    return session;
  }

  private emitText(terminalId: string, data: string): void {
    for (let offset = 0; offset < data.length; offset += MAXIMUM_TERMINAL_WRITE) {
      this.emit('ssh-terminal:data', { terminalId, data: data.slice(offset, offset + MAXIMUM_TERMINAL_WRITE) });
    }
  }

  private finish(terminalId: string, reason: 'closed' | 'error'): void {
    const session = this.sessions.get(terminalId);
    if (!session || session.closed) return;
    session.closed = true;
    this.sessions.delete(terminalId);
    const tail = session.decoder.end();
    if (tail) this.emitText(terminalId, tail);
    session.stream.removeAllListeners();
    session.stream.stderr.removeAllListeners();
    session.stream.end();
    session.client.removeAllListeners();
    session.client.end();
    this.emit('ssh-terminal:closed', { terminalId, reason });
  }
}

export function hostKeyFingerprintSha256(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`;
}

export function assertModernPrivateKey(key: Buffer, passphrase: string): void {
  const parsed = utils.parseKey(key, passphrase || undefined);
  if (parsed instanceof Error || !parsed.isPrivateKey() || !['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'].includes(parsed.type)) {
    throw new Error('Only Ed25519 and ECDSA private keys are allowed.');
  }
}

export function classifyConnectionFailure(error: unknown): SshConnectionFailureReason {
  const code = error && typeof error === 'object' && 'code' in error ? String(error.code).toUpperCase() : '';
  const message = error instanceof Error ? error.message.toLowerCase() : '';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'dns';
  if (code === 'ECONNREFUSED') return 'refused';
  if (code === 'ETIMEDOUT' || message.includes('timed out') || message.includes('timeout')) return 'timeout';
  if (message.includes('authentication') || message.includes('all configured authentication methods failed')) return 'authentication';
  if (message.includes('no matching key exchange')) return 'kexAlgorithm';
  if (message.includes('no matching host key')) return 'hostKeyAlgorithm';
  if (message.includes('no matching') && message.includes('cipher')) return 'cipherAlgorithm';
  if (message.includes('no matching') && message.includes('mac')) return 'macAlgorithm';
  if (message.includes('no matching') && message.includes('compression')) return 'compressionAlgorithm';
  if (message.includes('unsupported algorithm')) return 'clientConfiguration';
  if (message.includes('strict kex')) return 'strictKex';
  if (message.includes('signature verification failed')) return 'signatureVerification';
  if (message.includes('wrong signature type') || message.includes('malformed signature') || message.includes('malformed host public key') || message.includes('host key does not match negotiated type')) return 'hostKeyProtocol';
  if (message.includes('computing dh secret') || message.includes('invalid prime') || message.includes('invalid generator')) return 'keyExchangeComputation';
  if (message.includes('malformed kex') || message.includes('malformed packet while reading signature') || message.includes('received malformed')) return 'malformedHandshake';
  if (message.includes('received packet') || message.includes('unexpected packet') || message.includes('extra kexinit')) return 'protocolHandshake';
  if (message.includes('handshake') || message.includes('algorithm') || message.includes('no matching') || message.includes('key exchange')) return 'protocolHandshake';
  return 'network';
}
