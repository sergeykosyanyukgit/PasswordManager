# PasswordManager v1 threat model

## Assets and actors

The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries.

## Data flow and boundaries

1. A master password crosses the UI/process boundary and is immediately normalized and processed by Argon2id. The root-key buffer remains only in the main process and is zeroed on disposal; JavaScript cannot guarantee locked/non-pageable memory.
2. Untrusted vault bytes cross the filesystem/parser boundary. Fixed bounds are checked before KDF memory allocation or ciphertext allocation; authenticated decryption precedes JSON parsing.
3. A completed password may cross the HTTPS boundary only after per-vault consent. Only its five-character SHA-1 prefix is sent with response padding enabled.
4. The renderer requests SSH by vault-session and record identifiers only. The Electron main process reads the destination and credentials from its main-owned vault copy, requires a native confirmation before network access, and supplies credentials directly from memory to `ssh2`. The server host key must match a main-owned SHA-256 fingerprint, or first use must be explicitly confirmed in another native dialog.
5. Terminal bytes cross a bounded IPC event boundary to embedded xterm.js in the already sandboxed application renderer. CSP permits inline CSS required by xterm's generated cell, cursor, selection and truecolor styles, but blocks inline scripts, remote scripts/styles and renderer network connections. Terminal bytes are never inserted as HTML. Navigation/download blocking, disabled packaged DevTools, absence of link/host-object integration, and OSC-52 filtering restrict terminal capabilities. The main-process response header and built HTML share one policy definition.
6. A secret copied by the user crosses the Windows clipboard boundary with conditional timed clearing. Windows clipboard-history and roaming suppression is not yet implemented in this development build.
7. Release signing crosses a separate build boundary. The certificate path/password exist only as environment values and the produced executable is verified after signing.

## High-priority scenarios and controls

- Offline guessing: Argon2id raises cost; a 15-character minimum and local strength feedback reduce weak choices. There is intentionally no recovery path.
- Vault tampering/mix-and-match: independent GCM authentication plus AAD-bound VaultId/header fields rejects changes, truncation, cross-vault key material, and mixed saves.
- Resource exhaustion: file, header, ciphertext, JSON, KDF, response, message, and folder-depth limits are enforced before allocation or recursive traversal.
- Lost update/ransomware-style replacement: an exclusive sibling lock and source digest check reject concurrent change. Network reconnection revalidates both; overwrite is never automatic.
- Password privacy leak: no incremental request, full hash, suffix, password, redirect, or log; padded range query only. Network failure stays indeterminate.
- SSH interception/downgrade: modern allowlist by default, TOFU fingerprint confirmation, changed-key hard failure, and no external process or key file. A per-record legacy mode adds a bounded Group1/SHA-1, DSA, 3DES/AES-CBC, old-MAC, and zlib-compression compatibility set only after explicit UI activation and a native warning on every connection; it never permits RC4, Blowfish, or CAST.
- UI capture: ordinary builds verify Windows content protection before any secret-bearing top-level window is usable. Failure blocks unlock and SSH. Explicitly requested screenshot diagnostic builds compile `PM_SCREENSHOT_DIAGNOSTICS=1`, allow capture, and display a persistent diagnostic badge; they are excluded from release distribution. Runtime environment, IPC, and vault data cannot enable this exception in ordinary builds.
- Second-instance path injection: Electron's single-instance channel accepts only bounded, canonicalized existing `.pmvault` paths before forwarding them to the trusted renderer.
- Terminal renderer escape: local embedded assets only, restrictive CSP, bounded validated IPC, blocked navigation/download/new-window/host objects, no link provider, and consumed OSC-52 sequences.

## Residual risks

Valid historical vault rollback cannot be distinguished after a fresh process without an external trusted counter. SSD wear leveling prevents a physical-erasure promise. A Windows administrator, malware, debugging, unlocked-memory capture, keylogging, camera, hardware capture, malicious runtime, or compromised signing environment can defeat guarantees. Availability is not protected against file deletion or network outage.

Repository: PasswordManager
Version: working-tree
