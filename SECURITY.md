# Security policy

## Supported versions

Security fixes are made on the current `main` branch until the first stable release. After v1, only the newest stable release line is supported. Pre-release builds are not suitable for storing real secrets.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository host's private security-advisory channel and include the affected revision, prerequisites, impact, and a minimal reproduction containing synthetic data only. Do not attach a real `.pmvault`, password, private key, certificate, server address, or signing material.

Maintainers should acknowledge a report within seven days, validate it privately, coordinate a fix, and publish credit and disclosure timing with the reporter. No bounty is promised.

## Security objective

PasswordManager protects confidentiality and integrity when an attacker obtains, copies, truncates, rolls back, or modifies a locked `.pmvault`. It also prevents accidental password disclosure to the HIBP service, refuses changed SSH host keys, detects concurrent file replacement, and in ordinary builds fails closed when Windows screen-capture exclusion cannot be enabled.

User-requested screenshot diagnostic builds are a deliberate exception to screen-capture exclusion. They are compiled separately with `PM_SCREENSHOT_DIAGNOSTICS=1`, visibly identify themselves in the application header, and allow screen capture for UI troubleshooting. They must not be distributed as releases. The build scripts replace this flag with a literal; an ordinary build cannot switch it through runtime environment variables, renderer IPC, or vault settings. Screenshots from diagnostic builds may expose everything visible in the window.

The product does not claim to protect an unlocked process against malware, keyloggers, an OS administrator, a debugger, process or kernel dumps, physical cameras, or hardware capture. Availability attacks, deletion, and rollback to an older valid copy remain possible; the application detects in-session conflicts but has no trusted monotonic counter.

## Protected assets and trust boundaries

- Master passwords, derived root keys, data keys, record fields, SSH credentials and private keys, folder and record names, vault settings, HIBP consent, and SSH fingerprints are confidential.
- The local Windows account and kernel, Electron/Chromium/Node runtime, Node cryptographic implementation, Windows RNG, destination filesystem, HTTPS PKI, HIBP range endpoint, SSH server, and release-signing environment are explicit trust dependencies.
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
- A vault is authenticated before JSON parsing. Resource limits are enforced before allocations. Ordinary builds verify screen-capture exclusion before any secret-bearing window is usable.
- The HIBP boundary receives only a five-character uppercase SHA-1 prefix after explicit consent and only for a completed password. A failure is reported as “not checked”, never “safe”.
- The SSH boundary uses an explicit modern algorithm policy by default and a pinned SHA-256 host fingerprint. Per-record legacy compatibility requires explicit UI activation and a native warning on every connection, and permits only the documented bounded Group1/SHA-1, DSA, 3DES/AES-CBC, old-MAC, and zlib-compression set. RC4, Blowfish, and CAST remain prohibited. A changed key is a hard failure.
- The storage boundary uses a writer lock, authenticated encrypted temp, durable flush, authenticated reread, source-version hash check, and atomic replacement. Conflicts are never overwritten.
- The renderer CSP allows inline CSS for xterm's generated styles and truecolor attributes, while restricting scripts to packaged local assets and blocking external styles and network connections. SSH bytes are parsed by xterm and never inserted as HTML. The shared policy supplies both the main-process response header and the built HTML meta tag.

## Mandatory invariants

1. No plaintext vault metadata or payload is written outside authenticated ciphertext.
2. No custom cryptographic primitive is accepted. Nonce reuse under the same key is forbidden.
3. Authentication failure, unknown version, unsafe KDF setting, oversized length, or malformed input must not change the source file.
4. Real secrets never appear in logs, test fixtures, crash uploads, telemetry, command lines, MCP prompts, or temporary key files.
5. Capture-protection configuration, host-key, algorithm-policy, authentication, conflict, and signature-verification failures are fail closed. The requested capture state differs only in explicitly compiled screenshot diagnostic builds.
6. Release binaries are portable, single-file, signed with a trusted Code Signing certificate and RFC 3161 timestamp, and verified after signing. Self-signed certificates are test-build-only and never satisfy the release gate.
7. Critical and High security findings block release.

## Reportable issues

Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
