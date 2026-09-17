# Security Review: PasswordManager security workflow patch

## Scope

Security diff review of the six files added or extended by this task; immutable workflow.patch. Existing application changes audited separately.

- Scan mode: working_tree
- Target kind: git_diff
- Target ID: target_sha256_db09c38aabe06c89e0cccc44a3d1d3d6125310e49adf077d3a679bf0ef5b3afe
- Revision range: 6adef8dcd41928ef799ee7c410c1b6ec671ccedd...working-tree
- Snapshot digest: codex-security-snapshot/v1:sha256:ec9e2247e3a99c02e6f1cb1587c39dd65f13d7fe790d639058fca6a884468d2d
- Inventory strategy: diff
- Included paths: scripts/security-check.ps1, scripts/security-check.py, scripts/test_security_check.py, security-check/modules.json, docs/security-check-workflow.md, .gitignore
- Excluded paths: electron-app, security-check/runs
- Runtime or test status: 15 tests passed; PowerShell syntax parsed. Current actual audit used seven isolated native module agents; standalone full CLI model run not repeated.
- Artifacts reviewed: scripts/security-check.ps1, scripts/security-check.py, scripts/test_security_check.py, security-check/modules.json, docs/security-check-workflow.md, .gitignore
- Scan context: Supplied project threat model retained verbatim. Developer tooling consumes untrusted model JSON; the local account and Codex host are trusted. One native parent review of every changed workflow source; no extra module agent.

Limitations and exclusions:
- No exploit execution or new release; model isolation is context separation, not a VM.
- Prompt instructions forbid network/apps; read-only shell sandbox does not independently prove app-tool network denial.
- Excluded electron-app/\*\*: Existing application changes belong to the independently completed module audit.
- Excluded security-check/runs/\*\*: Derived audit inputs/results; consumed as data and validated by reviewed merger.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 0 |
| Severity mix | none |
| Confidence mix | none |
| Coverage | complete |
| Validation mode | offline static diff review plus 15 regression tests |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Text: # PasswordManager v1 threat model ## Assets and actors The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries. ## Data flow and boundaries 1. A master password crosses the UI/process boundary and is immediately normalized and processed by Argon2id. The root-key buffer remains only in the main process and is zeroed on disposal; JavaScript cannot guarantee locked/non-pageable memory. 2. Untrusted vault bytes cross the filesystem/parser boundary. Fixed bounds are checked before KDF memory allocation or ciphertext allocation; authenticated decryption precedes JSON parsing. 3. A completed password may cross the HTTPS boundary only after per-vault consent. Only its five-character SHA-1 prefix is sent with response padding enabled. 4. The renderer requests SSH by vault-session and record identifiers only. The Electron main process reads the destination and credentials from its main-owned vault copy, requires a native confirmation before network access, and supplies credentials directly from memory to `ssh2`. The server host key must match a main-owned SHA-256 fingerprint, or first use must be explicitly confirmed in another native dialog. 5. Terminal bytes cross a bounded IPC event boundary to embedded xterm.js in the already sandboxed application renderer. CSP permits inline CSS required by xterm's generated cell, cursor, selection and truecolor styles, but blocks inline scripts, remote scripts/styles and renderer network connections. Terminal bytes are never inserted as HTML. Navigation/download blocking, disabled packaged DevTools, absence of link/host-object integration, and OSC-52 filtering restrict terminal capabilities. The main-process response header and built HTML share one policy definition. 6. A secret copied by the user crosses the Windows clipboard boundary with conditional timed clearing. Windows clipboard-history and roaming suppression is not yet implemented in this development build. 7. Release signing crosses a separate build boundary. The certificate path/password exist only as environment values and the produced executable is verified after signing. ## High-priority scenarios and controls - Offline guessing: Argon2id raises cost; a 15-character minimum and local strength feedback reduce weak choices. There is intentionally no recovery path. - Vault tampering/mix-and-match: independent GCM authentication plus AAD-bound VaultId/header fields rejects changes, truncation, cross-vault key material, and mixed saves. - Resource exhaustion: file, header, ciphertext, JSON, KDF, response, message, and folder-depth limits are enforced before allocation or recursive traversal. - Lost update/ransomware-style replacement: an exclusive sibling lock and source digest check reject concurrent change. Network reconnection revalidates both; overwrite is never automatic. - Password privacy leak: no incremental request, full hash, suffix, password, redirect, or log; padded range query only. Network failure stays indeterminate. - SSH interception/downgrade: modern allowlist by default, TOFU fingerprint confirmation, changed-key hard failure, and no external process or key file. A per-record legacy mode adds a bounded Group1/SHA-1, DSA, 3DES/AES-CBC, old-MAC, and zlib-compression compatibility set only after explicit UI activation and a native warning on every connection; it never permits RC4, Blowfish, or CAST. - UI capture: ordinary builds verify Windows content protection before any secret-bearing top-level window is usable. Failure blocks unlock and SSH. Explicitly requested screenshot diagnostic builds compile `PM_SCREENSHOT_DIAGNOSTICS=1`, allow capture, and display a persistent diagnostic badge; they are excluded from release distribution. Runtime environment, IPC, and vault data cannot enable this exception in ordinary builds. - Second-instance path injection: Electron's single-instance channel accepts only bounded, canonicalized existing `.pmvault` paths before forwarding them to the trusted renderer. - Terminal renderer escape: local embedded assets only, restrictive CSP, bounded validated IPC, blocked navigation/download/new-window/host objects, no link provider, and consumed OSC-52 sequences. ## Residual risks Valid historical vault rollback cannot be distinguished after a fresh process without an external trusted counter. SSD wear leveling prevents a physical-erasure promise. A Windows administrator, malware, debugging, unlocked-memory capture, keylogging, camera, hardware capture, malicious runtime, or compromised signing environment can defeat guarantees. Availability is not protected against file deletion or network outage. Repository: PasswordManager Version: working-tree

## Findings

### No findings

No reportable findings survived the canonical discovery, validation, and reportability gates.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| scripts/security-check.ps1 | not recorded | No issue found | scripts/security-check.ps1:1 - Fresh ephemeral read-only sessions; fixed CLI flags; no shell-string evaluation of model JSON. RunId/module IDs are bounded. Process failure stops; merger propagates nonzero status. |
| scripts/security-check.py | not recorded | No issue found | scripts/security-check.py:1 - Strict module/result/decision schema, source hashes, exact line bounds, complete coverage, duplicate target closure, constrained supporting sources and output containment/link checks. Markdown values are escaped. An output hash is drift evidence, not a signature of model truth. |
| scripts/test_security_check.py | not recorded | No issue found | scripts/test_security_check.py:1 - Fifteen synthetic regression cases cover traversal, stale source, missing coverage/decisions, duplicate cycles, severity preservation, support-source drift and report escaping. |
| security-check/modules.json | not recorded | No issue found | security-check/modules.json:1 - Exactly one owner per active source file; explicit generated/binary exclusions. No real credentials or additional dependency introduced. |
| docs/security-check-workflow.md | not recorded | No issue found | docs/security-check-workflow.md:1 - Documents execution scope, process-only ExecutionPolicy flag, context-isolation limits, result codes and pre-v1 Deep Scan requirement. |
| .gitignore | not recorded | No issue found | .gitignore:1 - Only this task addition ignores Python bytecode under scripts; existing user modifications preserved. |

## Open Questions And Follow Up

- The first standalone full CLI audit should use a fresh run ID; current production audit ran through native isolated agents.
