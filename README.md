# PasswordManager

PasswordManager is a Windows-only portable local vault for logins, email accounts, passwords, secure notes, and SSH profiles. Each vault is one authenticated encrypted `.pmvault`; folder names, record names, settings, fingerprints, and values are encrypted.

The active rewrite uses TypeScript, Electron, Vue 3, and a sandboxed Chromium renderer. The cryptographic format remains AES-256-GCM with Argon2id and HKDF-SHA-256 and is byte-oriented for compatibility with `.pmvault` v1. It is not “512-bit encryption”. See [SECURITY.md](SECURITY.md), [the threat model](docs/threat-model.md), and [the binary format](docs/vault-format.md).

> This is a development build. Use synthetic secrets until Windows clipboard-history suppression, stale-lock recovery, the full release gate, and independent security review are complete.

## Development

Requirements: Windows 10 22H2/11 x64 and Node.js 24 or newer. The packaged application uses the pinned `hash-wasm` Argon2id v1.3 implementation because Electron's embedded Node build does not enable the native Argon2 provider.

```powershell
cd electron-app
npm ci
npm run typecheck
npm test
npm run build
npm start
```

The current test suite covers authenticated round trips, fresh ciphertext, header/ciphertext mutations, wrong passwords, writer exclusion, and source-conflict preservation using synthetic data.

## Text notes

Select a vault folder, click **Новая заметка**, enter a title and multiline text, then click **Сохранить**. Notes appear in the selected folder alongside other records; select a note to edit it or use **Удалить** to remove it. The title and text stay inside the encrypted vault using the existing secure-note record format. Existing notes with login or password fields retain access to those fields and any required breach confirmation.

## SSH terminal

Create or select an SSH record, fill in host, port, user and either a password or an Ed25519/ECDSA OpenSSH/PEM private key, then press **Open terminal**. Password records support both the SSH `password` method and one hidden `keyboard-interactive` password prompt used by many PAM-based servers; arbitrary multi-prompt challenges are not answered automatically. RSA and DSA client keys are rejected in v1 to prevent legacy authentication-signature fallback. The privileged main process shows a native confirmation before every connection. On first contact it separately shows the server's SHA-256 host-key fingerprint; verify it out of band before accepting it. The fingerprint is saved inside the encrypted vault, cannot be replaced by renderer data, and a later mismatch blocks the connection.

Modern mode also supports SHA-256 group14/group-exchange key exchange. AES-GCM and AES-CTR are used on Windows; ChaCha20-Poly1305 is omitted because Electron 44's Windows OpenSSL runtime does not expose it to Node and `ssh2` rejects an explicitly unavailable algorithm before negotiation. A per-record confirmation button can additionally enable Group1/SHA-1 KEX, `ssh-rsa`, `ssh-dss`, 3DES/AES-CBC, old MD5/SHA-1 MACs, and legacy compression after a separate native warning on every connection. RC4, Blowfish, and CAST remain forbidden. A negotiation failure identifies whether KEX, host key, cipher, MAC, compression, local algorithm configuration, signature verification, strict-KEX ordering, DH parameters, or protocol formatting failed without exposing the server's raw error text. Invalid signatures and malformed handshakes always fail closed.

Each connection opens in a terminal tab at the bottom of the window. Switching vault or terminal tabs preserves the live session; closing its terminal tab, closing its vault, locking Windows, sleeping, or auto-locking ends the SSH connection. Terminal rendering uses embedded xterm.js only, while the SSH socket and credentials remain in the Electron main process.

The final **Actions / Действия** column in the record list provides an **SSH** button for saved SSH records. It connects using the saved record without selecting it or saving or discarding the current editor draft. The editor's **Open terminal** button still saves its draft before connecting.

The terminal dock uses a neutral dark palette, compact rounded tabs, 12 px monospace text, and a separately measured inner viewport with 12 px side padding. Its cell grid and SSH PTY dimensions resize together. Drag the upper separator to resize, or use its double-click action or the expand button to toggle between expanded and previous height. The **+** button opens another session for the active terminal's saved SSH record; the far-right close button ends all terminal sessions. Independent foreground/background colors are available from the terminal's settings menu. Connection errors remain visible, while the connected status does not take up a row of output.

The viewport has fixed 8 px top/bottom padding, a steady cursor, and visible selection even when focus moves away. Only xterm 6's active scrollbar is shown; the retained legacy viewport cannot create a second scrollbar underneath the terminal. On Windows, `npm --prefix electron-app run test:terminal` builds the actual terminal component and verifies its layout, selection, cursor, resizing and CSP behavior in sandboxed Electron using synthetic data only. Screenshots and results are written under `electron-app/.runtime-probe/terminal-renderer/`.

Each terminal tab supports mouse selection, wheel scrolling, selection auto-scroll, a native right-click menu, `Ctrl+C`/`Ctrl+Shift+C` copy when text is selected, `Ctrl+V`/`Ctrl+Shift+V` and `Shift+Insert` paste, `Ctrl+Shift+A` select all, and Shift+PageUp/PageDown scrolling. Keyboard paste is accepted only from a trusted paste event scoped to the focused xterm; native-menu paste is read and written directly by the main process and is never returned through the preload bridge.

For explicitly requested screenshot troubleshooting, build a separate diagnostic candidate with `PM_SCREENSHOT_DIAGNOSTICS=1` set for the build process. Its header says **Скриншоты разрешены · диагностика**, and Windows capture protection is disabled. The flag is compiled into both processes and has no runtime switch. Keep this candidate in a separate output directory and never release it. Hide passwords, private keys, and identifying server data before sharing a screenshot. Ordinary builds keep capture protection enabled.

Each vault stores its own inactivity auto-lock interval from 0 to 240 minutes inside authenticated ciphertext. Zero disables only inactivity auto-lock; Windows lock, suspend, shutdown, application close, and explicit vault close always lock immediately. When several vaults are open, each enabled timeout is enforced independently.

Connection failures are reduced to non-secret categories in the UI: DNS, refused port, timeout, rejected credentials, incompatible algorithms, denied shell, invalid private key, or an interrupted network connection. Raw remote error text is not shown or logged.

## Portable build

```powershell
cd electron-app
npm run dist
```

The portable artifact is `electron-app/release/PasswordManager.exe`. Release signing reads only `SIGNING_PFX_PATH` and `SIGNING_PFX_PASSWORD`; PFX files must remain outside the repository. A self-signed certificate is acceptable only for explicitly labelled test builds and remains untrusted by Windows.

For a Windows x64 installer with a selectable installation directory, run `npm --prefix electron-app run dist:installer` from the repository root. Its artifact is `electron-app/release/PasswordManager-Setup.exe`.

## Security boundaries

- The Vue renderer has no Node.js, filesystem, shell, or network access; a narrow preload bridge validates IPC in the main process.
- Packaged content uses a local secure protocol, strict CSP, denied permissions/navigation, and fail-closed Windows capture protection in ordinary builds.
- CSP permits inline CSS required by xterm's generated cell, cursor, selection and truecolor styles. Inline scripts, remote scripts/styles and renderer network connections remain blocked. The response header and built HTML use the same policy definition.
- HIBP is opt-in and sends only a five-character SHA-1 prefix with `Add-Padding: true` after a completed password is submitted.
- SSH uses an explicit modern algorithm allowlist, password or in-memory private-key authentication, pinned SHA-256 host keys, and no external terminal or temporary key file.
- Saving uses an authenticated encrypted temp, durable flush, authenticated reread, source hash check, and replacement without automatic backups.
- JavaScript/V8 cannot guarantee physical erasure of immutable strings or defend an unlocked process from an administrator, malware, keylogger, debugger, or memory dump.

The previous `src/`, `tests/`, and .NET solution remain temporarily as a compatibility reference and are not included in the Electron release.
