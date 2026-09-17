import { generateKeyPairSync, randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { Server } from 'ssh2';
import { afterEach, describe, expect, it } from 'vitest';
import type { SshProfile, SshTerminalDataEvent } from '../../shared/contracts.js';
import { assertModernPrivateKey, classifyConnectionFailure, hostKeyFingerprintSha256, SSH_ALGORITHMS, SSH_COMPATIBILITY_ALGORITHMS, SshTerminalManager } from './ssh-terminal.js';

const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => { while (cleanup.length) await cleanup.pop()?.(); });

describe('SSH terminal policy', () => {
  it('formats SHA-256 host-key fingerprints without base64 padding', () => {
    const fingerprint = hostKeyFingerprintSha256(Buffer.from('Synthetic SSH host key bytes only.', 'utf8'));
    expect(fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/u);
  });

  it('does not enable legacy SSH algorithms', () => {
    const policy = JSON.stringify(SSH_ALGORITHMS);
    expect(policy).not.toMatch(/ssh-rsa|sha1|cbc|3des|arcfour|blowfish|cast128|chacha20/u);
  });

  it('keeps expanded legacy algorithms behind an explicit policy and still excludes broken stream ciphers', () => {
    const compatibility = JSON.stringify(SSH_COMPATIBILITY_ALGORITHMS);
    expect(compatibility).toMatch(/diffie-hellman-group1-sha1|ssh-dss|3des-cbc|aes128-cbc|hmac-md5|hmac-sha1-96|zlib/u);
    expect(compatibility).not.toMatch(/arcfour|blowfish|cast128/u);
  });

  it('rejects RSA private keys because ssh2 can fall back to ssh-rsa/SHA-1 user authentication', () => {
    const privateKey = generateKeyPairSync('rsa', { modulusLength: 2_048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
    expect(() => assertModernPrivateKey(Buffer.from(privateKey), '')).toThrow(/Ed25519|ECDSA/u);
  });

  it('maps connection failures without exposing raw server messages', () => {
    expect(classifyConnectionFailure(Object.assign(new Error('synthetic'), { code: 'ENOTFOUND' }))).toBe('dns');
    expect(classifyConnectionFailure(Object.assign(new Error('synthetic'), { code: 'ECONNREFUSED' }))).toBe('refused');
    expect(classifyConnectionFailure(new Error('All configured authentication methods failed'))).toBe('authentication');
    expect(classifyConnectionFailure(new Error('Handshake failed: no matching key exchange algorithm'))).toBe('kexAlgorithm');
    expect(classifyConnectionFailure(new Error('Handshake failed: no matching host key format'))).toBe('hostKeyAlgorithm');
    expect(classifyConnectionFailure(new Error('Handshake failed: no matching C->S cipher'))).toBe('cipherAlgorithm');
    expect(classifyConnectionFailure(new Error('Handshake failed: no matching S->C MAC'))).toBe('macAlgorithm');
    expect(classifyConnectionFailure(new Error('Handshake failed: no matching compression'))).toBe('compressionAlgorithm');
    expect(classifyConnectionFailure(new Error('Unsupported algorithm: chacha20-poly1305@openssh.com'))).toBe('clientConfiguration');
    expect(classifyConnectionFailure(new Error('Handshake failed: KEXINIT not first packet in strict KEX mode'))).toBe('strictKex');
    expect(classifyConnectionFailure(new Error('Handshake failed: signature verification failed'))).toBe('signatureVerification');
    expect(classifyConnectionFailure(new Error('Wrong signature type: ssh-rsa'))).toBe('hostKeyProtocol');
    expect(classifyConnectionFailure(new Error('Error while computing DH secret (group): synthetic'))).toBe('keyExchangeComputation');
    expect(classifyConnectionFailure(new Error('Received malformed KEXDH_REPLY'))).toBe('malformedHandshake');
    expect(classifyConnectionFailure(new Error('Received unexpected packet type 5'))).toBe('protocolHandshake');
    expect(classifyConnectionFailure(new Error('Handshake failed: synthetic negotiation error'))).toBe('protocolHandshake');
  });

  it('requires TOFU confirmation and then opens a password-authenticated shell', async () => {
    const privateKey = generateKeyPairSync('rsa', { modulusLength: 2_048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
    const server = new Server({ hostKeys: [privateKey] }, (client) => {
      client.on('error', () => undefined);
      client.on('authentication', (context) => {
        if (context.method === 'password' && context.username === 'synthetic-user' && context.password === 'Synthetic-Test-Password-Only!42') context.accept();
        else context.reject();
      });
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (acceptPty) => acceptPty());
        session.on('shell', (acceptShell) => {
          const stream = acceptShell();
          stream.write('synthetic-shell-ready\r\n');
          stream.on('data', (data: Buffer) => stream.write(data));
        });
      }));
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = (server.address() as AddressInfo).port;
    const output: SshTerminalDataEvent[] = [];
    const manager = new SshTerminalManager((channel, event) => { if (channel === 'ssh-terminal:data') output.push(event as SshTerminalDataEvent); });
    cleanup.push(async () => {
      await manager.closeAll();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const vaultSessionId = randomUUID();
    const makeRequest = () => ({ terminalId: randomUUID(), vaultSessionId, cols: 80, rows: 24 });
    const makeProfile = (): SshProfile => ({
      host: '127.0.0.1', port, userName: 'synthetic-user', authenticationKind: 0,
      password: 'Synthetic-Test-Password-Only!42', privateKeyPem: '', privateKeyPassphrase: '', hostKeySha256: '', allowLegacyAlgorithms: false
    });

    const first = await manager.start(makeRequest(), makeProfile());
    expect(first.status).toBe('hostKeyRequired');
    if (first.status !== 'hostKeyRequired') throw new Error('Expected synthetic TOFU challenge.');
    expect(first.fingerprint).toMatch(/^SHA256:/u);

    const accepted = makeRequest();
    const acceptedProfile = makeProfile();
    acceptedProfile.hostKeySha256 = first.fingerprint;
    const result = await manager.start(accepted, acceptedProfile);
    expect(result).toEqual({ status: 'connected', fingerprint: first.fingerprint });
    await expect.poll(() => output.map((event) => event.data).join('')).toContain('synthetic-shell-ready');
    await manager.write({ terminalId: accepted.terminalId, data: 'synthetic-input\n' });
    await expect.poll(() => output.map((event) => event.data).join('')).toContain('synthetic-input');
  });

  it('uses one hidden keyboard-interactive prompt as password authentication', async () => {
    const privateKey = generateKeyPairSync('rsa', { modulusLength: 2_048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
    const server = new Server({ hostKeys: [privateKey] }, (client) => {
      client.on('error', () => undefined);
      client.on('authentication', (context) => {
        if (context.method === 'keyboard-interactive' && context.username === 'synthetic-user') {
          context.prompt({ prompt: 'Synthetic password: ', echo: false }, (responses) => {
            if (responses[0] === 'Synthetic-Test-Password-Only!42') context.accept();
            else context.reject();
          });
        } else {
          context.reject(['keyboard-interactive']);
        }
      });
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (acceptPty) => acceptPty());
        session.on('shell', (acceptShell) => acceptShell().end('synthetic-keyboard-interactive-ready\r\n'));
      }));
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = (server.address() as AddressInfo).port;
    const output: SshTerminalDataEvent[] = [];
    const manager = new SshTerminalManager((channel, event) => { if (channel === 'ssh-terminal:data') output.push(event as SshTerminalDataEvent); });
    cleanup.push(async () => {
      await manager.closeAll();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const vaultSessionId = randomUUID();
    const makeRequest = () => ({ terminalId: randomUUID(), vaultSessionId, cols: 80, rows: 24 });
    const makeProfile = (): SshProfile => ({
      host: '127.0.0.1', port, userName: 'synthetic-user', authenticationKind: 0,
      password: 'Synthetic-Test-Password-Only!42', privateKeyPem: '', privateKeyPassphrase: '', hostKeySha256: '', allowLegacyAlgorithms: false
    });

    const first = await manager.start(makeRequest(), makeProfile());
    expect(first.status).toBe('hostKeyRequired');
    if (first.status !== 'hostKeyRequired') throw new Error('Expected synthetic TOFU challenge.');
    const acceptedProfile = makeProfile();
    acceptedProfile.hostKeySha256 = first.fingerprint;
    const result = await manager.start(makeRequest(), acceptedProfile);
    expect(result).toEqual({ status: 'connected', fingerprint: first.fingerprint });
    await expect.poll(() => output.map((event) => event.data).join('')).toContain('synthetic-keyboard-interactive-ready');
  });

  it('connects to an explicitly approved legacy algorithm server only in compatibility mode', async () => {
    const privateKey = generateKeyPairSync('rsa', { modulusLength: 2_048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
    const server = new Server({
      hostKeys: [privateKey],
      algorithms: {
        kex: ['diffie-hellman-group1-sha1'],
        cipher: ['3des-cbc'],
        serverHostKey: ['ssh-rsa'],
        hmac: ['hmac-md5'],
        compress: ['zlib']
      }
    }, (client) => {
      client.on('error', () => undefined);
      client.on('authentication', (context) => {
        if (context.method === 'password' && context.username === 'synthetic-user' && context.password === 'Synthetic-Test-Password-Only!42') context.accept();
        else context.reject();
      });
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (acceptPty) => acceptPty());
        session.on('shell', (acceptShell) => acceptShell().end('synthetic-legacy-ready\r\n'));
      }));
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = (server.address() as AddressInfo).port;
    const manager = new SshTerminalManager(() => undefined);
    cleanup.push(async () => {
      await manager.closeAll();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const vaultSessionId = randomUUID();
    const request = () => ({ terminalId: randomUUID(), vaultSessionId, cols: 80, rows: 24 });
    const profile = (allowLegacyAlgorithms: boolean): SshProfile => ({
      host: '127.0.0.1', port, userName: 'synthetic-user', authenticationKind: 0,
      password: 'Synthetic-Test-Password-Only!42', privateKeyPem: '', privateKeyPassphrase: '', hostKeySha256: '', allowLegacyAlgorithms
    });

    await expect(manager.start(request(), profile(false))).resolves.toEqual({ status: 'failed', reason: 'kexAlgorithm' });
    const first = await manager.start(request(), profile(true));
    expect(first.status).toBe('hostKeyRequired');
    if (first.status !== 'hostKeyRequired') throw new Error('Expected synthetic legacy TOFU challenge.');
    const pinned = profile(true);
    pinned.hostKeySha256 = first.fingerprint;
    await expect(manager.start(request(), pinned)).resolves.toEqual({ status: 'connected', fingerprint: first.fingerprint });
  });
});
