# MyNotes

MyNotes is a Windows-only portable local vault for logins, email accounts, passwords, secure notes, and SSH profiles. Each vault is one authenticated encrypted `.pmvault`; folder names, record names, settings, fingerprints, and values are encrypted.

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

## Opening vaults

MyNotes shows previously opened vaults at startup, with each file path and last successful opening date. With one history entry, the master-password prompt opens immediately. Create a vault or use **Открыть файл** for a different file; new master passwords require at least 8 characters after NFC normalization. Existing `.pmvault` v1 files remain compatible; the format and cryptographic derivation constants have not changed.

History defaults to most recently opened first. Drag rows or use their up/down buttons to save a custom order; **Сначала недавние** restores date sorting. The **Хранилища** button opens the list while other vaults are open. The delete button removes only the history entry, leaving the vault file intact. Failed unlock attempts do not add entries or change opening dates.

The main process stores up to 100 history entries in `%APPDATA%/MyNotes/vault-history.json`, outside the encrypted vault. Only file paths, successful opening timestamps and list order are saved; passwords, decrypted names, settings, and content are excluded. History reveals vault locations and usage times to the local Windows account. If history cannot be saved, vaults remain usable and the UI reports the problem. This local history is the user-requested exception to the original no-recent-files policy; the portable executable still needs no installation, and history belongs to the current Windows account.

The synthetic UI regression test is `npm --prefix electron-app run test:history`; it covers empty/single/multiple histories, password length, selection, failed authentication, drag/arrow ordering, removal, date sorting, explicit startup paths, layout and CSP at 1320×820 and 980×640. It uses an offscreen presentation fixture with no production preload or vault.

## Text notes

Double-click a text note in the list or folder tree to open it in the shared notes window. Further notes become tabs in that window. It contains only the tabs, editable title and text, with transient save errors when needed. Edits autosave after 800 ms; **Ctrl+S** saves immediately, and closing a tab/window first saves its edits. A failed save keeps the editor open and retains its draft; **Отменить мои правки** reloads the saved text. Concurrent edits to the same record are rejected rather than silently overwritten.

Open note IDs, the active tab and the manual-close preference are stored inside each encrypted vault. The notes window restores at unlock unless it was manually closed. **Открыть заметки** reopens remembered tabs and enables restoration again. Vault/system lock immediately removes note views and ends access to their sessions; any remaining unsaved draft is discarded by that security action.

Drag TXT files into the current folder, or choose **Файл → Открыть…** / **Ctrl+O** while a vault is open. The application imports and saves copies as text notes; source files are unchanged. Import supports UTF-8 (including BOM), UTF-16 LE/BE with BOM, and legacy Windows-1251. Limits are 32 files, 16 MiB per file and 32 MiB total per import; binary content and oversized/changed files are rejected. A batch is committed in one authenticated save.

Drag records or folders onto another folder in the tree or file list to move them within the same vault. Root-folder moves, folder cycles and depths over 64 are rejected. Expanded folders show their files in the tree, and the main file list also shows immediate subfolders.

Text fields in both windows support **Ctrl+C/X/V**, **Ctrl+A**, **Ctrl+Z**, **Ctrl+Y / Ctrl+Shift+Z**, **Ctrl+Insert**, **Shift+Insert**, **Shift+Delete** and a native edit context menu. **Ctrl+S** saves, **Ctrl+W** closes the active tab, **Ctrl+Tab / Ctrl+Shift+Tab** switches tabs. In the main window, **Ctrl+N** starts a note, **Ctrl+Shift+N** creates a folder and **Ctrl+F** focuses search. Existing xterm shortcuts remain scoped to the terminal. Keyboard/context-menu copying uses conditional clipboard clearing after 30 seconds.

`npm --prefix electron-app run test:notes` checks the actual notes renderer, narrow preload, native editing shortcuts, encrypted storage, autosave, conflicts and close/restore behavior at 900×720 and 500×380 with synthetic documents. After `build`, add `-- --production-renderer` to exercise the production renderer bundle in the same synthetic fixture. `test:history` also checks TXT import, folder/file display, double-click opening and drag moves in the main interface.

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

The portable artifact is `electron-app/release/MyNotes.exe`. Release signing reads only `SIGNING_PFX_PATH` and `SIGNING_PFX_PASSWORD`; PFX files must remain outside the repository. A self-signed certificate is acceptable only for explicitly labelled test builds and remains untrusted by Windows.

For a Windows x64 installer with a selectable installation directory, run `npm --prefix electron-app run dist:installer` from the repository root. Its artifact is `electron-app/release/MyNotes-Setup.exe`.

## Security boundaries

- The Vue renderer has no Node.js, filesystem, shell, or network access; a narrow preload bridge validates IPC in the main process.
- Packaged content uses a local secure protocol, strict CSP, denied permissions/navigation, and fail-closed Windows capture protection in ordinary builds.
- CSP permits inline CSS required by xterm's generated cell, cursor, selection and truecolor styles. Inline scripts, remote scripts/styles and renderer network connections remain blocked. The response header and built HTML use the same policy definition.
- HIBP is opt-in and sends only a five-character SHA-1 prefix with `Add-Padding: true` after a completed password is submitted.
- SSH uses an explicit modern algorithm allowlist, password or in-memory private-key authentication, pinned SHA-256 host keys, and no external terminal or temporary key file.
- Saving uses an authenticated encrypted temp, durable flush, authenticated reread, source hash check, and replacement without automatic backups.
- JavaScript/V8 cannot guarantee physical erasure of immutable strings or defend an unlocked process from an administrator, malware, keylogger, debugger, or memory dump.

The previous `src/`, `tests/`, and .NET solution remain temporarily as a compatibility reference and are not included in the Electron release.
