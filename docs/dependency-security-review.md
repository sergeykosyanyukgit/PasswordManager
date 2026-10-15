# Dependency security review — 2026-10-15

The Electron dependency audit initially reported 13 affected packages: 4 High and 9 Moderate. The production-only audit reported one High finding in `source-map-js`. Direct application and build-tool versions remain pinned; the lockfile records the exact replacement versions and integrity hashes.

| Dependency | Previous | Replacement | Resolution |
|---|---|---|---|
| source-map-js | 1.2.1 | 1.2.2 | Fix indexed source-map resource exhaustion in the Vue dependency tree. |
| brace-expansion | 1.1.18 / 2.1.4 / 5.0.9 | 1.1.21 / 2.1.7 / 5.0.12 | Update every installed branch for recursion and excessive expansion fixes. |
| fast-uri | 3.1.7 | 3.1.8 | Fix inconsistent encoded-host normalization. |
| http-cache-semantics | 4.2.0 | 4.3.0 | Fix shared-cache max-stale handling. |
| undici | 6.28.0 / 7.29.0 | 6.29.0 / 7.30.0 | Update both branches for the audited HTTP, TLS, WebSocket and resource-limit fixes. |
| global-agent | 3.0.0 | 4.1.3 | Remove the unpatched `roarr` / `sprintf-js` dependency chain. |

The `@electron/get` override selects exactly `global-agent` 4.1.3. Upstream's 4.1 release removes `roarr`, and 4.1.3 retains the named CommonJS `bootstrap()` API used by electron-builder's downloader. This intentionally crosses global-agent's major version while retaining the pinned Electron and electron-builder versions. Its dependency changes also update matcher 3.0.0 → 4.0.0, serialize-error 7.0.1 → 8.1.0, and type-fest 0.13.1 → 0.20.2. Removed packages include boolean, detect-node, es6-error, json-stringify-safe, roarr, semver-compare and sprintf-js.

`npm run test:build-proxy` exercises the actual downloader's `initializeProxy()` against loopback synthetic servers: HTTP routing, NO_PROXY bypass, HTTPS CONNECT and rejection of a failed tunnel. It makes no external requests and prints no inherited proxy configuration. Remove the override only after the downloader's declared dependencies no longer bring back the vulnerable chain, and rerun these checks.

License review checked the changed packages' manifests and included LICENSE/license texts: MIT, BSD-2-Clause, BSD-3-Clause, and the MIT option of type-fest's dual license. No new restrictive license was introduced; attribution requirements remain in force. Exact versions are listed in [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).

After a clean `npm ci`, both `npm audit` and `npm audit --omit=dev` report zero vulnerabilities. This describes npm's advisory results on the review date, not a guarantee that the application has no security defects. The separately required Codex Security diff scan remains unavailable in this session; npm audit does not substitute for that scan or the pre-v1 Deep Scan.

Validation completed: clean install, standalone typecheck, production build, 68 application tests, 3 downloader/proxy compatibility tests, and the history and embedded-terminal Electron fixtures at 1320×820 and 980×640. Existing application protections and vault format were not changed by this dependency update.

Portable packaging also completed with `npm run dist -- --config.directories.output=artifacts/dependency-review/portable-candidate`. The output is an unsigned development candidate, not a release. The packaged ASAR was inspected and contains `source-map-js` 1.2.2. The lockfile's stale fast-uri MIT metadata was corrected to BSD-3-Clause to match both the 3.1.8 registry manifest and its included license.

Upstream references:

- [source-map-js advisory and fixed release](https://github.com/advisories/GHSA-68fv-2mgg-jv7q)
- [sprintf-js advisory](https://github.com/advisories/GHSA-hp3w-g68c-fv3c)
- [global-agent 4.1.0 removes roarr](https://github.com/gajus/global-agent/releases/tag/v4.1.0)
- [global-agent 4.1.3 release](https://github.com/gajus/global-agent/releases/tag/v4.1.3)
