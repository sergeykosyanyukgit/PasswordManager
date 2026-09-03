# Security policy

## Supported versions

Security fixes are made on the current `main` branch until the first stable release. After v1, only the newest stable release line is supported. Pre-release builds are not suitable for storing real secrets.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository host's private security-advisory channel and include the affected revision, prerequisites, impact, and a minimal reproduction containing synthetic data only. Do not attach a real `.pmvault`, password, private key, certificate, server address, or signing material.

Maintainers should acknowledge a report within seven days, validate it privately, coordinate a fix, and publish credit and disclosure timing with the reporter. No bounty is promised.

## Security objective

PasswordManager protects confidentiality and integrity when an attacker obtains, copies, truncates, rolls back, or modifies a locked `.pmvault`. It also prevents accidental password disclosure to the HIBP service, refuses changed SSH host keys, detects concurrent file replacement, and fails closed when Windows screen-capture exclusion cannot be enabled.

The product does not claim to protect an unlocked process against malware, keyloggers, an OS administrator, a debugger, process or kernel dumps, physical cameras, or hardware capture. Availability attacks, deletion, and rollback to an older valid copy remain possible; the application detects in-session conflicts but has no trusted monotonic counter.

## Protected assets and trust boundaries

- Master passwords, derived root keys, data keys, record fields, SSH credentials and private keys, folder and record names, vault settings, HIBP consent, and SSH fingerprints are confidential.
- The local Windows account and kernel, .NET runtime, cryptographic libraries, Windows cryptographic RNG, destination filesystem, HTTPS PKI, HIBP range endpoint, SSH server, WebView2 runtime, and release-signing environment are explicit trust dependencies.
- `.pmvault` bytes, sibling lock/temp files, command-line paths, named-pipe messages, HIBP responses, SSH banners/output, WebView messages, filesystem metadata, and all network errors are untrusted inputs.
- A vault is authenticated before JSON parsing. Resource limits are enforced before allocations. Screen-capture exclusion is verified before any secret-bearing window is usable.
- The HIBP boundary receives only a five-character uppercase SHA-1 prefix after explicit consent and only for a completed password. A failure is reported as “not checked”, never “safe”.
- The SSH boundary uses an explicit modern algorithm policy and a pinned SHA-256 host fingerprint. A changed key is a hard failure.
- The storage boundary uses a writer lock, authenticated encrypted temp, durable flush, authenticated reread, source-version hash check, and atomic replacement. Conflicts are never overwritten.

## Mandatory invariants

1. No plaintext vault metadata or payload is written outside authenticated ciphertext.
2. No custom cryptographic primitive is accepted. Nonce reuse under the same key is forbidden.
3. Authentication failure, unknown version, unsafe KDF setting, oversized length, or malformed input must not change the source file.
4. Real secrets never appear in logs, test fixtures, crash uploads, telemetry, command lines, MCP prompts, or temporary key files.
5. Capture-protection, host-key, algorithm-policy, authentication, conflict, and signature-verification failures are fail closed.
6. Release binaries are self-contained, single-file, signed with a trusted Code Signing certificate and RFC 3161 timestamp, and verified after signing.
7. Critical and High security findings block release.

## Reportable issues

Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.

