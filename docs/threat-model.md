# PasswordManager v1 threat model

## Assets and actors

The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries.

## Data flow and boundaries

1. A master password crosses the UI/process boundary and is immediately normalized and processed by Argon2id. Only an unmanaged, best-effort locked root-key buffer persists for the unlocked session.
2. Untrusted vault bytes cross the filesystem/parser boundary. Fixed bounds are checked before KDF memory allocation or ciphertext allocation; authenticated decryption precedes JSON parsing.
3. A completed password may cross the HTTPS boundary only after per-vault consent. Only its five-character SHA-1 prefix is sent with response padding enabled.
4. SSH credentials cross the SSH.NET connection boundary directly from memory. The server host key must match a stored SHA-256 fingerprint, or first use must be explicitly confirmed.
5. Terminal bytes cross an in-process WebView message boundary. A local-only CSP, navigation/download blocking, disabled DevTools and OSC-52 filtering prevent the terminal renderer from acquiring broader browser capabilities.
6. A secret copied by the user crosses the Windows clipboard boundary with history and roaming disabled and conditional timed clearing.
7. Release signing crosses a separate build boundary. The certificate path/password exist only as environment values and the produced executable is verified after signing.

## High-priority scenarios and controls

- Offline guessing: Argon2id raises cost; a 15-character minimum and local strength feedback reduce weak choices. There is intentionally no recovery path.
- Vault tampering/mix-and-match: independent GCM authentication plus AAD-bound VaultId/header fields rejects changes, truncation, cross-vault key material, and mixed saves.
- Resource exhaustion: file, header, ciphertext, JSON, KDF, response, message, and folder-depth limits are enforced before allocation or recursive traversal.
- Lost update/ransomware-style replacement: an exclusive sibling lock and source digest check reject concurrent change. Network reconnection revalidates both; overwrite is never automatic.
- Password privacy leak: no incremental request, full hash, suffix, password, redirect, or log; padded range query only. Network failure stays indeterminate.
- SSH interception/downgrade: modern allowlist, TOFU fingerprint confirmation, changed-key hard failure, and no external process or key file.
- UI capture: every secret-bearing top-level window verifies `WDA_EXCLUDEFROMCAPTURE` before use. Failure blocks unlock and SSH.
- Cross-user process injection: the single-instance pipe is ACL-restricted to the current SID and accepts bounded, canonicalized file paths only.
- Terminal renderer escape: local embedded assets only, restrictive CSP, JSON message schema/size bounds, blocked navigation/download/new-window/host objects, and removal of OSC-52 sequences.

## Residual risks

Valid historical vault rollback cannot be distinguished after a fresh process without an external trusted counter. SSD wear leveling prevents a physical-erasure promise. A Windows administrator, malware, debugging, unlocked-memory capture, keylogging, camera, hardware capture, malicious runtime, or compromised signing environment can defeat guarantees. Availability is not protected against file deletion or network outage.

Repository: PasswordManager
Version: working-tree

