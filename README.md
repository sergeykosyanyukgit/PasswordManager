# PasswordManager

PasswordManager is a Windows-only, portable local vault for logins, email accounts, passwords, secure notes, and direct SSH sessions. A vault is one authenticated encrypted `.pmvault` file; folder names, record names, settings, host fingerprints, and all values are encrypted.

The security scheme is AES-256-GCM with Argon2id and HKDF-SHA-256. It is not described as “512-bit encryption”. See [SECURITY.md](SECURITY.md), [the threat model](docs/threat-model.md), and [the v1 binary format](docs/vault-format.md) before using or reviewing the application.

> The current repository is a development build, not a signed stable release. Use only synthetic secrets until the full release gate and independent security review have passed.

## Requirements for development

- Windows 10 22H2 or Windows 11 x64
- .NET SDK 10.0.400 x64 (pinned by `global.json`)
- Node.js/npm for the pinned xterm.js bundle
- Windows SDK x64 SignTool for release signing
- System WebView2 Runtime for the optional SSH terminal

## Build and test

```powershell
./scripts/test.ps1
```

The script performs npm locked install/audit/build, NuGet locked restore, formatting verification, Release build, and tests. No real password, private key, server address, vault, or signing secret belongs in this repository or its test output.

## Run

```powershell
dotnet run --project src/PasswordManager.App/PasswordManager.App.csproj -- --lang en C:\path\example.pmvault
```

Supported session languages are `ru` and `en`. Paths can also be opened through drag-and-drop or Windows “Open with”. The application does not register a file association and does not retain recent paths.

## Signed single-file release

Keep the PFX outside the repository and provide it only through the current process environment:

```powershell
$env:SIGNING_PFX_PATH = 'X:\secure\codesigning.pfx'
# Set SIGNING_PFX_PASSWORD through the trusted release runner or secret manager.
./scripts/publish.ps1
```

SignTool requires the password as a process environment value; inject it with a trusted release wrapper and clear it when the process ends. Never commit it or paste it into Codex/chat. The release gate fails if the certificate, Code Signing EKU, trust chain, timestamp, or signature verification is invalid. A successful release directory contains only `artifacts/release/win-x64/PasswordManager.exe`.

## Privacy and limitations

- HIBP checks are opt-in per vault and send only a five-character SHA-1 prefix with `Add-Padding: true` after the complete password is submitted.
- SSH credentials remain in process memory and are never written to a key file or passed to a child process.
- Unlock and SSH fail closed if Windows cannot verify `WDA_EXCLUDEFROMCAPTURE`.
- The threat model excludes malware, keyloggers, administrators, process dumps, cameras, hardware capture, and a compromised OS/runtime while the vault is unlocked.
- TOTP, attachments, import/export, recovery keys, Windows Hello, ARM64, other operating systems, SFTP/SCP, forwarding, jump hosts, cloud merge, and automatic backups are outside v1.
