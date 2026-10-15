# Third-party notices

The application uses pinned dependencies. Their upstream license texts remain authoritative and are included by their packages or linked below.

- Bouncy Castle C# (`BouncyCastle.Cryptography` 2.7.0) — MIT License — https://www.bouncycastle.org/csharp/licence.html
- SSH.NET 2026.0.0 — MIT License — https://github.com/sshnet/SSH.NET/blob/develop/LICENSE
- Microsoft Edge WebView2 SDK 1.0.4191.47 — Microsoft software license terms — https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.4191.47/license
- xterm.js 6.0.0 and `@xterm/addon-fit` 0.11.0 — MIT License — https://github.com/xtermjs/xterm.js/blob/master/LICENSE
- esbuild 0.28.2 (build-time only) — MIT License — https://github.com/evanw/esbuild/blob/master/LICENSE.md
- xUnit, Microsoft.NET.Test.Sdk, coverlet, and FsCheck.Xunit are test/build dependencies and are not application runtime components.

The built-in generated passphrase vocabulary is original project data distributed under the same repository license. It contains no user data or leaked-password corpus.

## Electron dependency security update — 2026-10-15

The updated packages' published manifests and included license files were reviewed. The following licenses apply to the changed versions; upstream copyright notices and license texts must be retained. `type-fest` is used under its MIT option.

| Package | Updated versions | License |
|---|---|---|
| brace-expansion | 1.1.21, 2.1.7, 5.0.12 | MIT |
| fast-uri | 3.1.8 | BSD-3-Clause |
| global-agent | 4.1.3 | BSD-3-Clause |
| http-cache-semantics | 4.3.0 | BSD-2-Clause |
| matcher | 4.0.0 | MIT |
| serialize-error | 8.1.0 | MIT |
| source-map-js | 1.2.2 | BSD-3-Clause |
| type-fest | 0.20.2 | MIT OR CC0-1.0; MIT selected |
| undici | 6.29.0, 7.30.0 | MIT |

`source-map-js` belongs to the production Vue dependency tree. The other changed packages serve development, downloads, or packaging. The obsolete `global-agent` 3 / `roarr` / `sprintf-js` chain and its unused dependencies were removed. See [the dependency review](docs/dependency-security-review.md).

