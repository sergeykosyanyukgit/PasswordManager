# Security Review: PasswordManager

## Scope

36 active Electron source/config/test files reviewed by seven fresh-context module agents; parent validates each unique candidate and merges duplicate control failures.

- Scan mode: scoped_path
- Target kind: git_worktree
- Target ID: target_sha256_afa278ad7b2b8e83eac78b36ef31537f9046bab7e159eea5491252c1db9bc24b
- Revision: 6adef8dcd41928ef799ee7c410c1b6ec671ccedd
- Snapshot digest: codex-security-snapshot/v1:sha256:f30ed2bc3f8b477cdfd6093b45fdf9247b437c2fe252a1994272edbb7899ffef
- Inventory strategy: scoped_path
- Included paths: electron-app
- Excluded paths: none
- Runtime or test status: npm ci/typecheck/build succeeded; 49/49 tests passed; npm audit and npm audit --omit=dev found 0 vulnerabilities. No exploit execution, release packaging or signing.
- Artifacts reviewed: electron-app/src/main/vault/codec.test.ts, electron-app/src/main/vault/codec.ts, electron-app/src/shared/contracts.ts, electron-app/src/main/vault/storage.test.ts, electron-app/src/main/vault/storage.ts, electron-app/src/main/main.ts, electron-app/src/main/services/capture-protection.test.ts, electron-app/src/main/services/capture-protection.ts, electron-app/src/preload/preload.ts, electron-app/src/shared/content-security-policy.ts, electron-app/src/main/services/ssh-terminal.test.ts, electron-app/src/main/services/ssh-terminal.ts, electron-app/src/main/services/hibp.ts, electron-app/src/renderer/index.html, electron-app/src/renderer/src/App.vue, electron-app/src/renderer/src/components/FluentIcon.vue, electron-app/src/renderer/src/components/FolderTreeNode.vue, electron-app/src/renderer/src/components/TerminalSession.vue, electron-app/src/renderer/src/main.ts, electron-app/src/renderer/src/recordDraft.test.ts, electron-app/src/renderer/src/recordDraft.ts, electron-app/src/renderer/src/styles.css, electron-app/src/renderer/src/terminalAppearance.test.ts, electron-app/src/renderer/src/terminalAppearance.ts, electron-app/tests/terminal-renderer/fixture.ts, electron-app/tests/terminal-renderer/index.html, electron-app/tests/terminal-renderer/main.cjs, electron-app/package-lock.json, electron-app/package.json, electron-app/scripts/build.mjs, electron-app/scripts/sign.ps1, electron-app/scripts/test-terminal.mjs, electron-app/tsconfig.json, electron-app/tsconfig.node.json, electron-app/vite.config.ts, electron-app/vitest.config.ts
- Scan context: User requested exactly one independent agent per module and security_check_result.md. docs/threat-model.md retained verbatim as supplied project security context. Native module agents had fork_turns=none; no model substitution.

Limitations and exclusions:
- One static modular pass; not the required pre-v1 Deep Scan.
- Token measurement may be unavailable for native module workers.
- Existing unrelated user changes were preserved.
- Source scope excludes legacy WPF and generated/binary assets; supporting dependency reads are not counted as full coverage.
- Excluded src/\*\*: Legacy .NET/WPF not shipped
- Excluded electron-app/node_modules/\*\*: Full dependency audit excluded; nine supporting source/doc files captured separately; dependency CVEs checked by npm audit.
- Excluded electron-app/dist/\*\*: Generated bundles; build succeeded, full bundle review not performed
- Excluded electron-app/release/\*\*: No portable candidate or signed release generated
- Excluded \*\*/\*.png: Binary artwork outside static source review
- Excluded \*\*/\*.ico: Binary icon outside static source review
- Excluded src/\*\*: Legacy .NET/WPF is not shipped

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable DSS findings | 10 |
| Report instances | 10 |
| Report severity mix | medium: 4, low: 6 |
| Report confidence mix | high: 8, medium: 2 |
| Coverage | partial |
| Validation mode | offline static analysis, independent parent validation, source-hash and line-bound checks |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Text: # PasswordManager v1 threat model ## Assets and actors The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries. ## Data flow and boundaries 1. A master password crosses the UI/process boundary and is immediately normalized and processed by Argon2id. The root-key buffer remains only in the main process and is zeroed on disposal; JavaScript cannot guarantee locked/non-pageable memory. 2. Untrusted vault bytes cross the filesystem/parser boundary. Fixed bounds are checked before KDF memory allocation or ciphertext allocation; authenticated decryption precedes JSON parsing. 3. A completed password may cross the HTTPS boundary only after per-vault consent. Only its five-character SHA-1 prefix is sent with response padding enabled. 4. The renderer requests SSH by vault-session and record identifiers only. The Electron main process reads the destination and credentials from its main-owned vault copy, requires a native confirmation before network access, and supplies credentials directly from memory to `ssh2`. The server host key must match a main-owned SHA-256 fingerprint, or first use must be explicitly confirmed in another native dialog. 5. Terminal bytes cross a bounded IPC event boundary to embedded xterm.js in the already sandboxed application renderer. CSP permits inline CSS required by xterm's generated cell, cursor, selection and truecolor styles, but blocks inline scripts, remote scripts/styles and renderer network connections. Terminal bytes are never inserted as HTML. Navigation/download blocking, disabled packaged DevTools, absence of link/host-object integration, and OSC-52 filtering restrict terminal capabilities. The main-process response header and built HTML share one policy definition. 6. A secret copied by the user crosses the Windows clipboard boundary with conditional timed clearing. Windows clipboard-history and roaming suppression is not yet implemented in this development build. 7. Release signing crosses a separate build boundary. The certificate path/password exist only as environment values and the produced executable is verified after signing. ## High-priority scenarios and controls - Offline guessing: Argon2id raises cost; a 15-character minimum and local strength feedback reduce weak choices. There is intentionally no recovery path. - Vault tampering/mix-and-match: independent GCM authentication plus AAD-bound VaultId/header fields rejects changes, truncation, cross-vault key material, and mixed saves. - Resource exhaustion: file, header, ciphertext, JSON, KDF, response, message, and folder-depth limits are enforced before allocation or recursive traversal. - Lost update/ransomware-style replacement: an exclusive sibling lock and source digest check reject concurrent change. Network reconnection revalidates both; overwrite is never automatic. - Password privacy leak: no incremental request, full hash, suffix, password, redirect, or log; padded range query only. Network failure stays indeterminate. - SSH interception/downgrade: modern allowlist by default, TOFU fingerprint confirmation, changed-key hard failure, and no external process or key file. A per-record legacy mode adds a bounded Group1/SHA-1, DSA, 3DES/AES-CBC, old-MAC, and zlib-compression compatibility set only after explicit UI activation and a native warning on every connection; it never permits RC4, Blowfish, or CAST. - UI capture: ordinary builds verify Windows content protection before any secret-bearing top-level window is usable. Failure blocks unlock and SSH. Explicitly requested screenshot diagnostic builds compile `PM_SCREENSHOT_DIAGNOSTICS=1`, allow capture, and display a persistent diagnostic badge; they are excluded from release distribution. Runtime environment, IPC, and vault data cannot enable this exception in ordinary builds. - Second-instance path injection: Electron's single-instance channel accepts only bounded, canonicalized existing `.pmvault` paths before forwarding them to the trusted renderer. - Terminal renderer escape: local embedded assets only, restrictive CSP, bounded validated IPC, blocked navigation/download/new-window/host objects, no link provider, and consumed OSC-52 sequences. ## Residual risks Valid historical vault rollback cannot be distinguished after a fresh process without an external trusted counter. SSD wear leveling prevents a physical-erasure promise. A Windows administrator, malware, debugging, unlocked-memory capture, keylogging, camera, hardware capture, malicious runtime, or compromised signing environment can defeat guarantees. Availability is not protected against file deletion or network outage. Repository: PasswordManager Version: working-tree

## Findings

| Findings | Reports | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- | --- |
| Создание сейфа может перезаписать файл, появившийся после проверки отсутствия | [occ_11b32a1e158643ad64a8e98a](#finding-1) | medium | high | occ_11b32a1e158643ad64a8e98a: inline below |
| SSH-сервер может сбрасывать таймер автоблокировки через автоматические ответы xterm | [occ_221c7be4d0d087bd0707fa00](#finding-2) | medium | high | occ_221c7be4d0d087bd0707fa00: inline below |
| После проверки temp и исходного файла сохранение заменяет пути без защиты от подмены | [occ_3f539b11871a34cd232766a2](#finding-3) | medium | high | occ_3f539b11871a34cd232766a2: inline below |
| Зависшая очистка lock-файла задерживает удаление секретов из интерфейса при автоблокировке | [occ_724dc394d06d83c590cf6d98](#finding-4) | medium | high | occ_724dc394d06d83c590cf6d98: inline below |
| Закрытие приложения до тайм-аута оставляет скопированный секрет в буфере обмена | [occ_11a76ccfb37f580d48e4f639](#finding-5) | low | high | occ_11a76ccfb37f580d48e4f639: inline below |
| Блокировка не отменяет начатое открытие сейфа и незавершённое SSH-подключение | [occ_448da7740144ac0414c3705b](#finding-6) | low | high | occ_448da7740144ac0414c3705b: inline below |
| Потеря или замена sibling lock не отзывает право записи и допускает удаление чужой блокировки | [occ_5ab9105238673d57ffee1a51](#finding-7) | low | medium | occ_5ab9105238673d57ffee1a51: inline below |
| Ошибка очистки после аутентификации оставляет скрытую сессию с освобождённой блокировкой | [occ_af3791d70f82255411d2c18d](#finding-8) | low | high | occ_af3791d70f82255411d2c18d: inline below |
| NFC-нормализация изменяет пароль, проверяемый в HIBP | [occ_c0fa4f8806fcc896b4854a19](#finding-9) | low | high | occ_c0fa4f8806fcc896b4854a19: inline below |
| Непроверенная структура JSON обходит лимиты документа и обрабатывается в main до проверки общего размера | [occ_e4112748e1387368abe312c8](#finding-10) | low | medium | occ_e4112748e1387368abe312c8: inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Создание сейфа может перезаписать файл, появившийся после проверки отсутствия

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Проверены create:51-82 и createNewAtomically:231-234. Между access и rename имеется await createMaterial. В указанном пути отсутствует условная публикация без замены. Это статический анализ; гонка на Windows не исполнялась. |
| Category | race-condition |
| CWE | CWE-367 |
| Affected lines | electron-app/src/main/vault/storage.ts:231-234, electron-app/src/main/vault/storage.ts:51-62, electron-app/src/main/vault/storage.ts:63-73, electron-app/src/main/vault/storage.ts:199-205, electron-app/src/main/vault/storage.ts:231-234, electron-app/src/main/vault/storage.test.ts:29-47, SECURITY.md:36-38, SECURITY.md:44-46, electron-app/src/main/vault/storage.ts:51-66 |

#### Summary

create проверяет отсутствие destination до получения lock и асинхронного createMaterial, но createNewAtomically использует обычный rename с заменой существующего назначения. Появившийся за это время файл не проверяется и не сохраняется.

#### Root Cause

Проверка «файл отсутствует» отделена от публикации, а примитив публикации предназначен также для замены существующего файла. Эксклюзивное создание применяется к temp и lock, но не обеспечивает отсутствие destination в момент фиксации.

**Проверка отсутствия назначения предшествует захвату lock и ожиданию создания ключевого материала.** — `electron-app/src/main/vault/storage.ts:51-62`

Проверка отсутствия назначения предшествует захвату lock и ожиданию создания ключевого материала.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
```

**Созданный файл перечитывается и аутентифицируется после createNewAtomically.** — `electron-app/src/main/vault/storage.ts:63-73`

Созданный файл перечитывается и аутентифицируется после createNewAtomically.

```
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
        } finally {
          reread.fill(0);
```

**Эксклюзивно создаётся только sibling-файл .lock.** — `electron-app/src/main/vault/storage.ts:199-205`

Эксклюзивно создаётся только sibling-файл .lock.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
```

**Публикация не использует create-if-absent.** — `electron-app/src/main/vault/storage.ts:231-234`

Публикация не использует create-if-absent.

```
async function createNewAtomically(destination: string, bytes: Buffer): Promise<void> {
  const temp = `${destination}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
  try { await writeDurably(temp, bytes); await rename(temp, destination); }
  finally { await unlink(temp).catch(() => undefined); }
```

**Существующие тесты охватывают штатное создание и второй writer, но не появление назначения во время создания.** — `electron-app/src/main/vault/storage.test.ts:29-47`

Существующие тесты охватывают штатное создание и второй writer, но не появление назначения во время создания.

```
  it('creates, saves, closes, and reopens a vault', async () => {
    const path = await testPath();
    const first = store();
    const created = await first.create(path, SYNTHETIC_PASSWORD);
    created.document.folders.push({ id: crypto.randomUUID(), parentId: created.document.rootFolderId, name: 'Synthetic folder', isDeleted: false, deletedUtc: null });
    await first.save(created.sessionId, created.document);
    await first.close(created.sessionId);

    const second = store();
    const reopened = await second.open(path, SYNTHETIC_PASSWORD);
    expect(reopened.document.folders.some((folder) => folder.name === 'Synthetic folder')).toBe(true);
  });

  it('prevents a second writer', async () => {
    const path = await testPath();
    const first = store();
    await first.create(path, SYNTHETIC_PASSWORD);
    await expect(store().open(path, SYNTHETIC_PASSWORD)).rejects.toThrow(/already open|lock/i);
  });
```

**Неизвестная версия и конфликт должны обрабатываться без изменения исходного файла.** — `SECURITY.md:36-38`

Неизвестная версия и конфликт должны обрабатываться без изменения исходного файла.

```
3. Authentication failure, unknown version, unsafe KDF setting, oversized length, or malformed input must not change the source file.
4. Real secrets never appear in logs, test fixtures, crash uploads, telemetry, command lines, MCP prompts, or temporary key files.
5. Capture-protection configuration, host-key, algorithm-policy, authentication, conflict, and signature-verification failures are fail closed. The requested capture state differs only in explicitly compiled screenshot diagnostic builds.
```

**Обход обнаружения конфликтов относится к отчётным дефектам; обычное удаление исключено.** — `SECURITY.md:44-46`

Обход обнаружения конфликтов относится к отчётным дефектам; обычное удаление исключено.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Между проверкой отсутствия и публикацией есть асинхронные операции.** — `electron-app/src/main/vault/storage.ts:51-66`

Между проверкой отсутствия и публикацией есть асинхронные операции.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
```

#### Validation

Подтверждено отдельное окно create: ENOENT проверяется до KDF, а публикация использует заменяющий rename. Сохранение требует условной проверки версии, создание — операции без замены; различие контроля и исправления сохраняет отдельную находку. Точное чередование на Windows не воспроизводилось.

Validation method: offline static source trace; independent module auditor and parent validation

**Проверка отсутствия назначения предшествует захвату lock и ожиданию создания ключевого материала.** — `electron-app/src/main/vault/storage.ts:51-62`

Проверка отсутствия назначения предшествует захвату lock и ожиданию создания ключевого материала.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
```

**Созданный файл перечитывается и аутентифицируется после createNewAtomically.** — `electron-app/src/main/vault/storage.ts:63-73`

Созданный файл перечитывается и аутентифицируется после createNewAtomically.

```
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
        } finally {
          reread.fill(0);
```

**Эксклюзивно создаётся только sibling-файл .lock.** — `electron-app/src/main/vault/storage.ts:199-205`

Эксклюзивно создаётся только sibling-файл .lock.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
```

**Публикация не использует create-if-absent.** — `electron-app/src/main/vault/storage.ts:231-234`

Публикация не использует create-if-absent.

```
async function createNewAtomically(destination: string, bytes: Buffer): Promise<void> {
  const temp = `${destination}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
  try { await writeDurably(temp, bytes); await rename(temp, destination); }
  finally { await unlink(temp).catch(() => undefined); }
```

**Существующие тесты охватывают штатное создание и второй writer, но не появление назначения во время создания.** — `electron-app/src/main/vault/storage.test.ts:29-47`

Существующие тесты охватывают штатное создание и второй writer, но не появление назначения во время создания.

```
  it('creates, saves, closes, and reopens a vault', async () => {
    const path = await testPath();
    const first = store();
    const created = await first.create(path, SYNTHETIC_PASSWORD);
    created.document.folders.push({ id: crypto.randomUUID(), parentId: created.document.rootFolderId, name: 'Synthetic folder', isDeleted: false, deletedUtc: null });
    await first.save(created.sessionId, created.document);
    await first.close(created.sessionId);

    const second = store();
    const reopened = await second.open(path, SYNTHETIC_PASSWORD);
    expect(reopened.document.folders.some((folder) => folder.name === 'Synthetic folder')).toBe(true);
  });

  it('prevents a second writer', async () => {
    const path = await testPath();
    const first = store();
    await first.create(path, SYNTHETIC_PASSWORD);
    await expect(store().open(path, SYNTHETIC_PASSWORD)).rejects.toThrow(/already open|lock/i);
  });
```

**Неизвестная версия и конфликт должны обрабатываться без изменения исходного файла.** — `SECURITY.md:36-38`

Неизвестная версия и конфликт должны обрабатываться без изменения исходного файла.

```
3. Authentication failure, unknown version, unsafe KDF setting, oversized length, or malformed input must not change the source file.
4. Real secrets never appear in logs, test fixtures, crash uploads, telemetry, command lines, MCP prompts, or temporary key files.
5. Capture-protection configuration, host-key, algorithm-policy, authentication, conflict, and signature-verification failures are fail closed. The requested capture state differs only in explicitly compiled screenshot diagnostic builds.
```

**Обход обнаружения конфликтов относится к отчётным дефектам; обычное удаление исключено.** — `SECURITY.md:44-46`

Обход обнаружения конфликтов относится к отчётным дефектам; обычное удаление исключено.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Между проверкой отсутствия и публикацией есть асинхронные операции.** — `electron-app/src/main/vault/storage.ts:51-66`

Между проверкой отсутствия и публикацией есть асинхронные операции.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
```

Assertions:
- Проверены create:51-82 и createNewAtomically:231-234. Между access и rename имеется await createMaterial. В указанном пути отсутствует условная публикация без замены. Это статический анализ; гонка на Windows не исполнялась.
- Файл, существующий во время access, отклоняется. Два клиента, соблюдающие один sibling lock и не теряющие его, обычно не дойдут до одновременной записи. Атомарность rename препятствует частичной публикации, но не заменяет требование «создать только при отсутствии». Атакующему с полным правом удаления уже доступна обычная потеря доступности; отчёт относится именно к несанкционированной фиксации приложением конкурентного назначения.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

access(destination) возвращает ENOENT → acquireLock → await createMaterial → запись случайного temp → rename(temp, destination). На последнем шаге наличие назначения повторно не проверяется и не является условием отказа; аутентификация осуществляется уже после замены.

- **Source:** Другой участник общей папки либо участник, управляющий сетевыми файловыми операциями и способный создать или переместить файл в выбранный путь назначения.

- **Sink:** Проверка «файл отсутствует» отделена от публикации, а примитив публикации предназначен также для замены существующего файла. Эксклюзивное создание применяется к temp и lock, но не обеспечивает отсутствие destination в момент фиксации.

- **Outcome:** Приложение может затереть чужую или более новую версию .pmvault при операции создания, хотя пользователь не подтвердил перезапись. Вставленный файл неизвестной версии также заменяется без проверки. Это нарушение запрета перезаписи конфликтов, а не доказательство раскрытия содержимого.

**Проверка отсутствия назначения предшествует захвату lock и ожиданию создания ключевого материала.** — `electron-app/src/main/vault/storage.ts:51-62`

Проверка отсутствия назначения предшествует захвату lock и ожиданию создания ключевого материала.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
```

**Созданный файл перечитывается и аутентифицируется после createNewAtomically.** — `electron-app/src/main/vault/storage.ts:63-73`

Созданный файл перечитывается и аутентифицируется после createNewAtomically.

```
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
        } finally {
          reread.fill(0);
```

**Эксклюзивно создаётся только sibling-файл .lock.** — `electron-app/src/main/vault/storage.ts:199-205`

Эксклюзивно создаётся только sibling-файл .lock.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
```

**Публикация не использует create-if-absent.** — `electron-app/src/main/vault/storage.ts:231-234`

Публикация не использует create-if-absent.

```
async function createNewAtomically(destination: string, bytes: Buffer): Promise<void> {
  const temp = `${destination}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
  try { await writeDurably(temp, bytes); await rename(temp, destination); }
  finally { await unlink(temp).catch(() => undefined); }
```

**Существующие тесты охватывают штатное создание и второй writer, но не появление назначения во время создания.** — `electron-app/src/main/vault/storage.test.ts:29-47`

Существующие тесты охватывают штатное создание и второй writer, но не появление назначения во время создания.

```
  it('creates, saves, closes, and reopens a vault', async () => {
    const path = await testPath();
    const first = store();
    const created = await first.create(path, SYNTHETIC_PASSWORD);
    created.document.folders.push({ id: crypto.randomUUID(), parentId: created.document.rootFolderId, name: 'Synthetic folder', isDeleted: false, deletedUtc: null });
    await first.save(created.sessionId, created.document);
    await first.close(created.sessionId);

    const second = store();
    const reopened = await second.open(path, SYNTHETIC_PASSWORD);
    expect(reopened.document.folders.some((folder) => folder.name === 'Synthetic folder')).toBe(true);
  });

  it('prevents a second writer', async () => {
    const path = await testPath();
    const first = store();
    await first.create(path, SYNTHETIC_PASSWORD);
    await expect(store().open(path, SYNTHETIC_PASSWORD)).rejects.toThrow(/already open|lock/i);
  });
```

**Неизвестная версия и конфликт должны обрабатываться без изменения исходного файла.** — `SECURITY.md:36-38`

Неизвестная версия и конфликт должны обрабатываться без изменения исходного файла.

```
3. Authentication failure, unknown version, unsafe KDF setting, oversized length, or malformed input must not change the source file.
4. Real secrets never appear in logs, test fixtures, crash uploads, telemetry, command lines, MCP prompts, or temporary key files.
5. Capture-protection configuration, host-key, algorithm-policy, authentication, conflict, and signature-verification failures are fail closed. The requested capture state differs only in explicitly compiled screenshot diagnostic builds.
```

**Обход обнаружения конфликтов относится к отчётным дефектам; обычное удаление исключено.** — `SECURITY.md:44-46`

Обход обнаружения конфликтов относится к отчётным дефектам; обычное удаление исключено.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Между проверкой отсутствия и публикацией есть асинхронные операции.** — `electron-app/src/main/vault/storage.ts:51-66`

Между проверкой отсутствия и публикацией есть асинхронные операции.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
```

#### Reachability

Пользователь начинает создание по пока отсутствующему пути. После успешной проверки ENOENT и до rename другой участник помещает туда файл. Sibling lock защищает только клиентов, добровольно соблюдающих этот протокол.

- **Attacker:** Другой участник общей папки либо участник, управляющий сетевыми файловыми операциями и способный создать или переместить файл в выбранный путь назначения.

- **Outcome:** Приложение может затереть чужую или более новую версию .pmvault при операции создания, хотя пользователь не подтвердил перезапись. Вставленный файл неизвестной версии также заменяется без проверки. Это нарушение запрета перезаписи конфликтов, а не доказательство раскрытия содержимого.

Limitations:
- Файл, существующий во время access, отклоняется. Два клиента, соблюдающие один sibling lock и не теряющие его, обычно не дойдут до одновременной записи. Атомарность rename препятствует частичной публикации, но не заменяет требование «создать только при отсутствии». Атакующему с полным правом удаления уже доступна обычная потеря доступности; отчёт относится именно к несанкционированной фиксации приложением конкурентного назначения.

#### Severity

**Medium** — Подтверждено отдельное окно create: ENOENT проверяется до KDF, а публикация использует заменяющий rename. Сохранение требует условной проверки версии, создание — операции без замены; различие контроля и исправления сохраняет отдельную находку. Точное чередование на Windows не воспроизводилось.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Публиковать новый файл проверенной атомарной операцией без замены существующего назначения. Проверять и аутентифицировать temp до публикации. При EEXIST сохранять появившийся файл и возвращать конфликт; отдельный повторный access не устраняет гонку. Добавить тест появления назначения после первоначальной проверки и тест сохранности неизвестной версии.

<a id="finding-2"></a>

### [2] SSH-сервер может сбрасывать таймер автоблокировки через автоматические ответы xterm

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Выполнена только статическая проверка. Продукт закрепляет @xterm/xterm 6.0.0 в electron-app/package.json:24 и electron-app/package-lock.json:1719-1723; локальный electron-app/node_modules/@xterm/xterm/package.json:2-6 также указывает 6.0.0 и lib/xterm.mjs. По отдельному разрешению координатора прочитан supporting исходник этой зависимости: electron-app/node_modules/@xterm/xterm/src/common/InputHandler.ts:256 регистрирует CSI n; electron-app/node_modules/@xterm/xterm/src/common/InputHandler.ts:2653-2666 отвечает на параметр 5 через triggerDataEvent(ESC\[0n). electron-app/node_modules/@xterm/xterm/src/common/services/CoreService.ts:61-81 выдаёт onData при wasUserInput=false, а electron-app/node_modules/@xterm/xterm/src/common/services/OptionsService.ts:43 задаёт disableStdin:false; electron-app/src/renderer/src/components/TerminalSession.vue:57-81 не переопределяет эту опцию. electron-app/node_modules/@xterm/xterm/src/common/CoreTerminal.ts:131 передаёт событие; electron-app/node_modules/@xterm/xterm/src/common/CoreTerminal.ts:140-146 направляет write в parser. electron-app/node_modules/@xterm/xterm/src/browser/public/Terminal.ts:74 и electron-app/node_modules/@xterm/xterm/src/browser/public/Terminal.ts:227-228 связывают публичные onData/write с core. Это замыкает цепочку без предположения о синтетическом DOM-событии. Приложение, сервер и тесты не запускались; выдержка из зависимости является статическим подтверждением поведения, а не результатом PoC. |
| Category | session-expiration |
| CWE | CWE-613 |
| Affected lines | electron-app/src/main/main.ts:261-262, electron-app/src/renderer/src/components/TerminalSession.vue:86-103, electron-app/src/preload/preload.ts:13-15, electron-app/src/main/services/ssh-terminal.ts:138-146, electron-app/src/main/services/ssh-terminal.ts:204-207, electron-app/src/main/main.ts:22-23, electron-app/src/main/main.ts:165-168, electron-app/src/main/main.ts:261-262, electron-app/src/main/main.ts:277-287, electron-app/src/main/vault/storage.ts:166-169, electron-app/src/main/vault/codec.ts:288-289, electron-app/src/main/main.ts:196-217, electron-app/src/main/main.ts:43-46, electron-app/src/main/main.ts:270-274, electron-app/src/renderer/src/App.vue:81-99, electron-app/package.json:24, electron-app/package-lock.json:1719-1723, electron-app/node_modules/@xterm/xterm/src/common/InputHandler.ts:2653-2666, electron-app/node_modules/@xterm/xterm/src/common/services/CoreService.ts:61-81, electron-app/node_modules/@xterm/xterm/src/common/CoreTerminal.ts:131, electron-app/node_modules/@xterm/xterm/src/browser/public/Terminal.ts:74, electron-app/src/renderer/src/components/TerminalSession.vue:86-97 |

#### Summary

Renderer передаёт все события terminal.onData в ssh-terminal:write. Такие события возникают не только при вводе пользователя: xterm автоматически отвечает на CSI 5 n. Общая обёртка trusted считает каждый вызов IPC активностью, поэтому регулярный запрос состояния от SSH-сервера удерживает lastActivity свежим и блокировка по бездействию не наступает.

#### Root Cause

Сигнал обмена протокольными байтами ошибочно используется как доказательство действий пользователя. TerminalSession передаёт одинаковым путём ввод клавиатуры и автоматические ответы терминала, а общий IPC wrapper безусловно обновляет lastActivity. Фильтры OSC-52 и OSC-0/1/2 не блокируют CSI-запрос состояния.

**Поглощаются только перечисленные OSC; входящий SSH-текст передаётся terminal.write, а любой onData подключённого терминала вызывает writeSshTerminal. Проверенное supporting поведение onData для автоматического CSI-ответа описано с точными dependency paths в validation.** — `electron-app/src/renderer/src/components/TerminalSession.vue:86-103`

Поглощаются только перечисленные OSC; входящий SSH-текст передаётся terminal.write, а любой onData подключённого терминала вызывает writeSshTerminal. Проверенное supporting поведение onData для автоматического CSI-ответа описано с точными dependency paths в validation.

```
  // Remote output must not be allowed to write to the local clipboard or rename UI surfaces.
  terminal.parser.registerOscHandler(52, () => true);
  terminal.parser.registerOscHandler(0, () => true);
  terminal.parser.registerOscHandler(1, () => true);
  terminal.parser.registerOscHandler(2, () => true);
  terminalDisposables.push(terminal.onData((data) => {
    if (connected) void window.passwordManager.writeSshTerminal(props.terminalId, data).catch(() => markClosed('Ошибка отправки данных.'));
  }));
  terminal.attachCustomKeyEventHandler(handleTerminalKey);
  removeDataListener = window.passwordManager.onSshTerminalData((event) => {
    if (event.terminalId === props.terminalId) terminal?.write(event.data);
  });
  removeClosedListener = window.passwordManager.onSshTerminalClosed((event) => {
    if (event.terminalId === props.terminalId) markClosed(event.reason === 'error' ? 'SSH-соединение прервано.' : 'SSH-соединение закрыто.');
  });
  removeSelectAllListener = window.passwordManager.onSshTerminalSelectAll((terminalId) => {
    if (terminalId === props.terminalId) terminal?.selectAll();
  });
```

**writeSshTerminal без признака происхождения данных вызывает ssh-terminal:write.** — `electron-app/src/preload/preload.ts:13-15`

writeSshTerminal без признака происхождения данных вызывает ssh-terminal:write.

```
  startSshTerminal: (request: SshTerminalStartRequest) => ipcRenderer.invoke('ssh-terminal:start', request),
  writeSshTerminal: (terminalId: string, data: string) => ipcRenderer.invoke('ssh-terminal:write', { terminalId, data }),
  resizeSshTerminal: (terminalId: string, cols: number, rows: number) => ipcRenderer.invoke('ssh-terminal:resize', { terminalId, cols, rows }),
```

**Байты stdout/stderr подключённого SSH-сеанса поступают в emitText.** — `electron-app/src/main/services/ssh-terminal.ts:138-146`

Байты stdout/stderr подключённого SSH-сеанса поступают в emitText.

```
          const session: TerminalSession = { vaultSessionId: request.vaultSessionId, client, stream, decoder: new StringDecoder('utf8'), closed: false };
          this.sessions.set(request.terminalId, session);
          stream.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.stderr.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.once('close', () => this.finish(request.terminalId, 'closed'));
          stream.once('error', () => this.finish(request.terminalId, 'error'));
          client.once('close', () => this.finish(request.terminalId, 'closed'));
          client.once('error', () => this.finish(request.terminalId, 'error'));
          settle({ status: 'connected', fingerprint: observedFingerprint });
```

**emitText делит входящий текст на блоки и передаёт ssh-terminal:data без удаления CSI-команд.** — `electron-app/src/main/services/ssh-terminal.ts:204-207`

emitText делит входящий текст на блоки и передаёт ssh-terminal:data без удаления CSI-команд.

```
  private emitText(terminalId: string, data: string): void {
    for (let offset = 0; offset < data.length; offset += MAXIMUM_TERMINAL_WRITE) {
      this.emit('ssh-terminal:data', { terminalId, data: data.slice(offset, offset + MAXIMUM_TERMINAL_WRITE) });
    }
```

**lastActivity является общим состоянием main-процесса, а не отдельного сейфа.** — `electron-app/src/main/main.ts:22-23`

lastActivity является общим состоянием main-процесса, а не отдельного сейфа.

```
let lastActivity = Date.now();
let idleLockRunning = false;
```

**ssh-terminal:write регистрируется через общую обёртку trusted.** — `electron-app/src/main/main.ts:165-168`

ssh-terminal:write регистрируется через общую обёртку trusted.

```
  ipcMain.handle('ssh-terminal:start', trusted(async (_event, input: unknown) => startSshTerminal(input)));
  ipcMain.handle('ssh-terminal:write', trusted(async (_event, input: unknown) => sshTerminals.write(input)));
  ipcMain.handle('ssh-terminal:resize', trusted(async (_event, input: unknown) => sshTerminals.resize(input)));
  ipcMain.handle('ssh-terminal:close', trusted(async (_event, input: unknown) => sshTerminals.close(input)));
```

**Каждый доверенный IPC автоматически обновляет общий lastActivity.** — `electron-app/src/main/main.ts:261-262`

Каждый доверенный IPC автоматически обновляет общий lastActivity.

```
function trusted<T extends unknown[], R>(handler: (event: Electron.IpcMainInvokeEvent, ...args: T) => R | Promise<R>) {
  return (event: Electron.IpcMainInvokeEvent, ...args: T) => { assertTrustedSender(event); lastActivity = Date.now(); return handler(event, ...args); };
```

**Общий lastActivity используется при выборе истёкших сеансов.** — `electron-app/src/main/main.ts:277-287`

Общий lastActivity используется при выборе истёкших сеансов.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
```

**Положительный autoLockMinutes каждого сеанса сравнивается с переданным общим временем бездействия.** — `electron-app/src/main/vault/storage.ts:166-169`

Положительный autoLockMinutes каждого сеанса сравнивается с переданным общим временем бездействия.

```
  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
```

**autoLockMinutes допускает только целые значения 0-240; минимальное включённое значение равно одной минуте.** — `electron-app/src/main/vault/codec.ts:288-289`

autoLockMinutes допускает только целые значения 0-240; минимальное включённое значение равно одной минуте.

```
  if (!document.settings || typeof document.settings !== 'object' || typeof document.settings.hibpConsent !== 'boolean' || !Number.isInteger(document.settings.clipboardClearSeconds) || document.settings.clipboardClearSeconds < 5 || document.settings.clipboardClearSeconds > 600 || !Number.isInteger(document.settings.autoLockMinutes) || document.settings.autoLockMinutes < 0 || document.settings.autoLockMinutes > 240 || !['', 'ru', 'en'].includes(document.settings.sessionLanguage)) {
    throw new VaultFormatError('Invalid vault settings.');
```

**Перед подключением проверяются main-owned профиль и пользовательские native-подтверждения, включая первое доверие ключу.** — `electron-app/src/main/main.ts:196-217`

Перед подключением проверяются main-owned профиль и пользовательские native-подтверждения, включая первое доверие ключу.

```
  let profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!(await confirmSshDestination(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  if (profile.allowLegacyAlgorithms && !(await confirmLegacySshAlgorithms(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  const approvedProfile = profile;
  profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!sameSshTarget(approvedProfile, profile)) throw new Error('SSH record changed during confirmation.');
  const runtime = { terminalId: request.terminalId, vaultSessionId: request.vaultSessionId, cols: request.cols, rows: request.rows };
  let result = await sshTerminals.start(runtime, profile);
  if (result.status === 'hostKeyRequired') {
    const confirmation = await dialog.showMessageBox(mainWindow!, {
      type: 'warning',
      title: 'Проверка ключа SSH-сервера',
      message: `Первое подключение к ${profile.host}:${profile.port}`,
      detail: `SHA-256 отпечаток ключа сервера:\n${result.fingerprint}\n\nСверьте отпечаток с администратором сервера. Сохранить его в зашифрованном сейфе и продолжить?`,
      buttons: ['Доверять и подключиться', 'Отмена'],
      defaultId: 1,
      cancelId: 1,
      noLink: true
    });
    if (confirmation.response !== 0) return { status: 'cancelled', fingerprint: result.fingerprint };
    const currentProfile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(profile, currentProfile)) throw new Error('SSH record changed during host-key confirmation.');
```

**Windows lock/suspend/shutdown вызывают lockAll отдельно от периодического idle-механизма.** — `electron-app/src/main/main.ts:43-46`

Windows lock/suspend/shutdown вызывают lockAll отдельно от периодического idle-механизма.

```
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  powerMonitor.on('shutdown', lockAll);
  setInterval(() => { void lockIdleVaults().catch(() => undefined); }, 15_000).unref();
```

**lockAll закрывает SSH и сейфы и сообщает renderer о блокировке независимо от lastActivity.** — `electron-app/src/main/main.ts:270-274`

lockAll закрывает SSH и сейфы и сообщает renderer о блокировке независимо от lastActivity.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**Renderer уже имеет отдельные pointerdown/keydown/wheel уведомления активности; данные терминала не обязаны выполнять эту роль.** — `electron-app/src/renderer/src/App.vue:81-99`

Renderer уже имеет отдельные pointerdown/keydown/wheel уведомления активности; данные терминала не обязаны выполнять эту роль.

```
const activityEvents = ['pointerdown', 'keydown', 'wheel'] as const;
const activity = (): void => window.passwordManager.notifyActivity();
const fitTerminalDockToViewport = (): void => {
  terminalViewportHeight.value = window.innerHeight;
  terminalDockHeight.value = clampTerminalHeight(terminalDockHeight.value, window.innerHeight);
};
let stopPaths = (): void => undefined;
let stopLock = (): void => undefined;
let stopVaultLock = (): void => undefined;

onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
  for (const event of activityEvents) window.addEventListener(event, activity, { passive: true });
  window.addEventListener('resize', fitTerminalDockToViewport);
```

**Продукт закрепляет версию @xterm/xterm 6.0.0, поведение которой проверено в установленном supporting исходнике.** — `electron-app/package.json:24`

Продукт закрепляет версию @xterm/xterm 6.0.0, поведение которой проверено в установленном supporting исходнике.

```
    "@xterm/xterm": "6.0.0",
```

**Lockfile закрепляет версию и integrity артефакта @xterm/xterm 6.0.0.** — `electron-app/package-lock.json:1719-1723`

Lockfile закрепляет версию и integrity артефакта @xterm/xterm 6.0.0.

```
    "node_modules/@xterm/xterm": {
      "version": "6.0.0",
      "resolved": "https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz",
      "integrity": "sha512-TQwDdQGtwwDt+2cgKDLn0IRaSxYu1tSUjgKarSDkUM0ZNiSRXFpjxEsvc/Zgc5kq5omJ+V0a8/kIM2WD3sMOYg==",
      "license": "MIT",
```

**CSI DSR вызывает автоматический triggerDataEvent.** — `electron-app/node_modules/@xterm/xterm/src/common/InputHandler.ts:2653-2666`

CSI DSR вызывает автоматический triggerDataEvent.

```
  public deviceStatus(params: IParams): boolean {
    switch (params.params[0]) {
      case 5:
        // status report
        this._coreService.triggerDataEvent(`${C0.ESC}[0n`);
        break;
      case 6:
        // cursor position
        const y = this._activeBuffer.y + 1;
        const x = this._activeBuffer.x + 1;
        this._coreService.triggerDataEvent(`${C0.ESC}[${y};${x}R`);
        break;
    }
    return true;
```

**onData выдаётся и для wasUserInput=false при включённом stdin.** — `electron-app/node_modules/@xterm/xterm/src/common/services/CoreService.ts:61-81`

onData выдаётся и для wasUserInput=false при включённом stdin.

```
  public triggerDataEvent(data: string, wasUserInput: boolean = false): void {
    // Prevents all events to pty process if stdin is disabled
    if (this._optionsService.rawOptions.disableStdin) {
      return;
    }

    // Input is being sent to the terminal, the terminal should focus the prompt.
    const buffer = this._bufferService.buffer;
    if (wasUserInput && this._optionsService.rawOptions.scrollOnUserInput && buffer.ybase !== buffer.ydisp) {
      this._onRequestScrollToBottom.fire();
    }

    // Fire onUserInput so listeners can react as well (eg. clear selection)
    if (wasUserInput) {
      this._onUserInput.fire();
    }

    // Fire onData API
    this._logService.debug(`sending data "${data}"`);
    this._logService.trace(`sending data (codes)`, () => data.split('').map(e => e.charCodeAt(0)));
    this._onData.fire(data);
```

**Событие coreService.onData пересылается в публичный канал.** — `electron-app/node_modules/@xterm/xterm/src/common/CoreTerminal.ts:131`

Событие coreService.onData пересылается в публичный канал.

```
    this._register(Event.forward(this.coreService.onData, this._onData));
```

**Публичный onData возвращает core.onData.** — `electron-app/node_modules/@xterm/xterm/src/browser/public/Terminal.ts:74`

Публичный onData возвращает core.onData.

```
  public get onData(): Event<string> { return this._core.onData; }
```

**Входной write вызывает onData; приложение пересылает каждый такой ответ через preload.** — `electron-app/src/renderer/src/components/TerminalSession.vue:86-97`

Входной write вызывает onData; приложение пересылает каждый такой ответ через preload.

```
  // Remote output must not be allowed to write to the local clipboard or rename UI surfaces.
  terminal.parser.registerOscHandler(52, () => true);
  terminal.parser.registerOscHandler(0, () => true);
  terminal.parser.registerOscHandler(1, () => true);
  terminal.parser.registerOscHandler(2, () => true);
  terminalDisposables.push(terminal.onData((data) => {
    if (connected) void window.passwordManager.writeSshTerminal(props.terminalId, data).catch(() => markClosed('Ошибка отправки данных.'));
  }));
  terminal.attachCustomKeyEventHandler(handleTerminalKey);
  removeDataListener = window.passwordManager.onSshTerminalData((event) => {
    if (event.terminalId === props.terminalId) terminal?.write(event.data);
  });
```

#### Validation

Независимо подтверждён весь путь от DSR-байтов уже разрешённого SSH endpoint до общего lastActivity. xterm генерирует onData даже при wasUserInput=false; приложение не различает происхождение этих данных. Прямой доступ сервера к другим записям не установлен, но удалённый участник действительно может обойти auto-lock всех открытых сейфов без локального кода или ввода пользователя.

Validation method: offline static source trace; independent module auditor and parent validation

**Поглощаются только перечисленные OSC; входящий SSH-текст передаётся terminal.write, а любой onData подключённого терминала вызывает writeSshTerminal. Проверенное supporting поведение onData для автоматического CSI-ответа описано с точными dependency paths в validation.** — `electron-app/src/renderer/src/components/TerminalSession.vue:86-103`

Поглощаются только перечисленные OSC; входящий SSH-текст передаётся terminal.write, а любой onData подключённого терминала вызывает writeSshTerminal. Проверенное supporting поведение onData для автоматического CSI-ответа описано с точными dependency paths в validation.

```
  // Remote output must not be allowed to write to the local clipboard or rename UI surfaces.
  terminal.parser.registerOscHandler(52, () => true);
  terminal.parser.registerOscHandler(0, () => true);
  terminal.parser.registerOscHandler(1, () => true);
  terminal.parser.registerOscHandler(2, () => true);
  terminalDisposables.push(terminal.onData((data) => {
    if (connected) void window.passwordManager.writeSshTerminal(props.terminalId, data).catch(() => markClosed('Ошибка отправки данных.'));
  }));
  terminal.attachCustomKeyEventHandler(handleTerminalKey);
  removeDataListener = window.passwordManager.onSshTerminalData((event) => {
    if (event.terminalId === props.terminalId) terminal?.write(event.data);
  });
  removeClosedListener = window.passwordManager.onSshTerminalClosed((event) => {
    if (event.terminalId === props.terminalId) markClosed(event.reason === 'error' ? 'SSH-соединение прервано.' : 'SSH-соединение закрыто.');
  });
  removeSelectAllListener = window.passwordManager.onSshTerminalSelectAll((terminalId) => {
    if (terminalId === props.terminalId) terminal?.selectAll();
  });
```

**writeSshTerminal без признака происхождения данных вызывает ssh-terminal:write.** — `electron-app/src/preload/preload.ts:13-15`

writeSshTerminal без признака происхождения данных вызывает ssh-terminal:write.

```
  startSshTerminal: (request: SshTerminalStartRequest) => ipcRenderer.invoke('ssh-terminal:start', request),
  writeSshTerminal: (terminalId: string, data: string) => ipcRenderer.invoke('ssh-terminal:write', { terminalId, data }),
  resizeSshTerminal: (terminalId: string, cols: number, rows: number) => ipcRenderer.invoke('ssh-terminal:resize', { terminalId, cols, rows }),
```

**Байты stdout/stderr подключённого SSH-сеанса поступают в emitText.** — `electron-app/src/main/services/ssh-terminal.ts:138-146`

Байты stdout/stderr подключённого SSH-сеанса поступают в emitText.

```
          const session: TerminalSession = { vaultSessionId: request.vaultSessionId, client, stream, decoder: new StringDecoder('utf8'), closed: false };
          this.sessions.set(request.terminalId, session);
          stream.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.stderr.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.once('close', () => this.finish(request.terminalId, 'closed'));
          stream.once('error', () => this.finish(request.terminalId, 'error'));
          client.once('close', () => this.finish(request.terminalId, 'closed'));
          client.once('error', () => this.finish(request.terminalId, 'error'));
          settle({ status: 'connected', fingerprint: observedFingerprint });
```

**emitText делит входящий текст на блоки и передаёт ssh-terminal:data без удаления CSI-команд.** — `electron-app/src/main/services/ssh-terminal.ts:204-207`

emitText делит входящий текст на блоки и передаёт ssh-terminal:data без удаления CSI-команд.

```
  private emitText(terminalId: string, data: string): void {
    for (let offset = 0; offset < data.length; offset += MAXIMUM_TERMINAL_WRITE) {
      this.emit('ssh-terminal:data', { terminalId, data: data.slice(offset, offset + MAXIMUM_TERMINAL_WRITE) });
    }
```

**lastActivity является общим состоянием main-процесса, а не отдельного сейфа.** — `electron-app/src/main/main.ts:22-23`

lastActivity является общим состоянием main-процесса, а не отдельного сейфа.

```
let lastActivity = Date.now();
let idleLockRunning = false;
```

**ssh-terminal:write регистрируется через общую обёртку trusted.** — `electron-app/src/main/main.ts:165-168`

ssh-terminal:write регистрируется через общую обёртку trusted.

```
  ipcMain.handle('ssh-terminal:start', trusted(async (_event, input: unknown) => startSshTerminal(input)));
  ipcMain.handle('ssh-terminal:write', trusted(async (_event, input: unknown) => sshTerminals.write(input)));
  ipcMain.handle('ssh-terminal:resize', trusted(async (_event, input: unknown) => sshTerminals.resize(input)));
  ipcMain.handle('ssh-terminal:close', trusted(async (_event, input: unknown) => sshTerminals.close(input)));
```

**Каждый доверенный IPC автоматически обновляет общий lastActivity.** — `electron-app/src/main/main.ts:261-262`

Каждый доверенный IPC автоматически обновляет общий lastActivity.

```
function trusted<T extends unknown[], R>(handler: (event: Electron.IpcMainInvokeEvent, ...args: T) => R | Promise<R>) {
  return (event: Electron.IpcMainInvokeEvent, ...args: T) => { assertTrustedSender(event); lastActivity = Date.now(); return handler(event, ...args); };
```

**Общий lastActivity используется при выборе истёкших сеансов.** — `electron-app/src/main/main.ts:277-287`

Общий lastActivity используется при выборе истёкших сеансов.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
```

**Положительный autoLockMinutes каждого сеанса сравнивается с переданным общим временем бездействия.** — `electron-app/src/main/vault/storage.ts:166-169`

Положительный autoLockMinutes каждого сеанса сравнивается с переданным общим временем бездействия.

```
  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
```

**autoLockMinutes допускает только целые значения 0-240; минимальное включённое значение равно одной минуте.** — `electron-app/src/main/vault/codec.ts:288-289`

autoLockMinutes допускает только целые значения 0-240; минимальное включённое значение равно одной минуте.

```
  if (!document.settings || typeof document.settings !== 'object' || typeof document.settings.hibpConsent !== 'boolean' || !Number.isInteger(document.settings.clipboardClearSeconds) || document.settings.clipboardClearSeconds < 5 || document.settings.clipboardClearSeconds > 600 || !Number.isInteger(document.settings.autoLockMinutes) || document.settings.autoLockMinutes < 0 || document.settings.autoLockMinutes > 240 || !['', 'ru', 'en'].includes(document.settings.sessionLanguage)) {
    throw new VaultFormatError('Invalid vault settings.');
```

**Перед подключением проверяются main-owned профиль и пользовательские native-подтверждения, включая первое доверие ключу.** — `electron-app/src/main/main.ts:196-217`

Перед подключением проверяются main-owned профиль и пользовательские native-подтверждения, включая первое доверие ключу.

```
  let profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!(await confirmSshDestination(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  if (profile.allowLegacyAlgorithms && !(await confirmLegacySshAlgorithms(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  const approvedProfile = profile;
  profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!sameSshTarget(approvedProfile, profile)) throw new Error('SSH record changed during confirmation.');
  const runtime = { terminalId: request.terminalId, vaultSessionId: request.vaultSessionId, cols: request.cols, rows: request.rows };
  let result = await sshTerminals.start(runtime, profile);
  if (result.status === 'hostKeyRequired') {
    const confirmation = await dialog.showMessageBox(mainWindow!, {
      type: 'warning',
      title: 'Проверка ключа SSH-сервера',
      message: `Первое подключение к ${profile.host}:${profile.port}`,
      detail: `SHA-256 отпечаток ключа сервера:\n${result.fingerprint}\n\nСверьте отпечаток с администратором сервера. Сохранить его в зашифрованном сейфе и продолжить?`,
      buttons: ['Доверять и подключиться', 'Отмена'],
      defaultId: 1,
      cancelId: 1,
      noLink: true
    });
    if (confirmation.response !== 0) return { status: 'cancelled', fingerprint: result.fingerprint };
    const currentProfile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(profile, currentProfile)) throw new Error('SSH record changed during host-key confirmation.');
```

**Windows lock/suspend/shutdown вызывают lockAll отдельно от периодического idle-механизма.** — `electron-app/src/main/main.ts:43-46`

Windows lock/suspend/shutdown вызывают lockAll отдельно от периодического idle-механизма.

```
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  powerMonitor.on('shutdown', lockAll);
  setInterval(() => { void lockIdleVaults().catch(() => undefined); }, 15_000).unref();
```

**lockAll закрывает SSH и сейфы и сообщает renderer о блокировке независимо от lastActivity.** — `electron-app/src/main/main.ts:270-274`

lockAll закрывает SSH и сейфы и сообщает renderer о блокировке независимо от lastActivity.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**Renderer уже имеет отдельные pointerdown/keydown/wheel уведомления активности; данные терминала не обязаны выполнять эту роль.** — `electron-app/src/renderer/src/App.vue:81-99`

Renderer уже имеет отдельные pointerdown/keydown/wheel уведомления активности; данные терминала не обязаны выполнять эту роль.

```
const activityEvents = ['pointerdown', 'keydown', 'wheel'] as const;
const activity = (): void => window.passwordManager.notifyActivity();
const fitTerminalDockToViewport = (): void => {
  terminalViewportHeight.value = window.innerHeight;
  terminalDockHeight.value = clampTerminalHeight(terminalDockHeight.value, window.innerHeight);
};
let stopPaths = (): void => undefined;
let stopLock = (): void => undefined;
let stopVaultLock = (): void => undefined;

onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
  for (const event of activityEvents) window.addEventListener(event, activity, { passive: true });
  window.addEventListener('resize', fitTerminalDockToViewport);
```

**Продукт закрепляет версию @xterm/xterm 6.0.0, поведение которой проверено в установленном supporting исходнике.** — `electron-app/package.json:24`

Продукт закрепляет версию @xterm/xterm 6.0.0, поведение которой проверено в установленном supporting исходнике.

```
    "@xterm/xterm": "6.0.0",
```

**Lockfile закрепляет версию и integrity артефакта @xterm/xterm 6.0.0.** — `electron-app/package-lock.json:1719-1723`

Lockfile закрепляет версию и integrity артефакта @xterm/xterm 6.0.0.

```
    "node_modules/@xterm/xterm": {
      "version": "6.0.0",
      "resolved": "https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz",
      "integrity": "sha512-TQwDdQGtwwDt+2cgKDLn0IRaSxYu1tSUjgKarSDkUM0ZNiSRXFpjxEsvc/Zgc5kq5omJ+V0a8/kIM2WD3sMOYg==",
      "license": "MIT",
```

**CSI DSR вызывает автоматический triggerDataEvent.** — `electron-app/node_modules/@xterm/xterm/src/common/InputHandler.ts:2653-2666`

CSI DSR вызывает автоматический triggerDataEvent.

```
  public deviceStatus(params: IParams): boolean {
    switch (params.params[0]) {
      case 5:
        // status report
        this._coreService.triggerDataEvent(`${C0.ESC}[0n`);
        break;
      case 6:
        // cursor position
        const y = this._activeBuffer.y + 1;
        const x = this._activeBuffer.x + 1;
        this._coreService.triggerDataEvent(`${C0.ESC}[${y};${x}R`);
        break;
    }
    return true;
```

**onData выдаётся и для wasUserInput=false при включённом stdin.** — `electron-app/node_modules/@xterm/xterm/src/common/services/CoreService.ts:61-81`

onData выдаётся и для wasUserInput=false при включённом stdin.

```
  public triggerDataEvent(data: string, wasUserInput: boolean = false): void {
    // Prevents all events to pty process if stdin is disabled
    if (this._optionsService.rawOptions.disableStdin) {
      return;
    }

    // Input is being sent to the terminal, the terminal should focus the prompt.
    const buffer = this._bufferService.buffer;
    if (wasUserInput && this._optionsService.rawOptions.scrollOnUserInput && buffer.ybase !== buffer.ydisp) {
      this._onRequestScrollToBottom.fire();
    }

    // Fire onUserInput so listeners can react as well (eg. clear selection)
    if (wasUserInput) {
      this._onUserInput.fire();
    }

    // Fire onData API
    this._logService.debug(`sending data "${data}"`);
    this._logService.trace(`sending data (codes)`, () => data.split('').map(e => e.charCodeAt(0)));
    this._onData.fire(data);
```

**Событие coreService.onData пересылается в публичный канал.** — `electron-app/node_modules/@xterm/xterm/src/common/CoreTerminal.ts:131`

Событие coreService.onData пересылается в публичный канал.

```
    this._register(Event.forward(this.coreService.onData, this._onData));
```

**Публичный onData возвращает core.onData.** — `electron-app/node_modules/@xterm/xterm/src/browser/public/Terminal.ts:74`

Публичный onData возвращает core.onData.

```
  public get onData(): Event<string> { return this._core.onData; }
```

**Входной write вызывает onData; приложение пересылает каждый такой ответ через preload.** — `electron-app/src/renderer/src/components/TerminalSession.vue:86-97`

Входной write вызывает onData; приложение пересылает каждый такой ответ через preload.

```
  // Remote output must not be allowed to write to the local clipboard or rename UI surfaces.
  terminal.parser.registerOscHandler(52, () => true);
  terminal.parser.registerOscHandler(0, () => true);
  terminal.parser.registerOscHandler(1, () => true);
  terminal.parser.registerOscHandler(2, () => true);
  terminalDisposables.push(terminal.onData((data) => {
    if (connected) void window.passwordManager.writeSshTerminal(props.terminalId, data).catch(() => markClosed('Ошибка отправки данных.'));
  }));
  terminal.attachCustomKeyEventHandler(handleTerminalKey);
  removeDataListener = window.passwordManager.onSshTerminalData((event) => {
    if (event.terminalId === props.terminalId) terminal?.write(event.data);
  });
```

Assertions:
- Выполнена только статическая проверка. Продукт закрепляет @xterm/xterm 6.0.0 в electron-app/package.json:24 и electron-app/package-lock.json:1719-1723; локальный electron-app/node_modules/@xterm/xterm/package.json:2-6 также указывает 6.0.0 и lib/xterm.mjs. По отдельному разрешению координатора прочитан supporting исходник этой зависимости: electron-app/node_modules/@xterm/xterm/src/common/InputHandler.ts:256 регистрирует CSI n; electron-app/node_modules/@xterm/xterm/src/common/InputHandler.ts:2653-2666 отвечает на параметр 5 через triggerDataEvent(ESC\[0n). electron-app/node_modules/@xterm/xterm/src/common/services/CoreService.ts:61-81 выдаёт onData при wasUserInput=false, а electron-app/node_modules/@xterm/xterm/src/common/services/OptionsService.ts:43 задаёт disableStdin:false; electron-app/src/renderer/src/components/TerminalSession.vue:57-81 не переопределяет эту опцию. electron-app/node_modules/@xterm/xterm/src/common/CoreTerminal.ts:131 передаёт событие; electron-app/node_modules/@xterm/xterm/src/common/CoreTerminal.ts:140-146 направляет write в parser. electron-app/node_modules/@xterm/xterm/src/browser/public/Terminal.ts:74 и electron-app/node_modules/@xterm/xterm/src/browser/public/Terminal.ts:227-228 связывают публичные onData/write с core. Это замыкает цепочку без предположения о синтетическом DOM-событии. Приложение, сервер и тесты не запускались; выдержка из зависимости является статическим подтверждением поведения, а не результатом PoC.
- Перед SSH требуются native-подтверждение назначения и проверка ключа; поэтому случайный сетевой наблюдатель без доступа к разрешённому endpoint не выполняет атаку. При заблокированном/закрытом терминале onData не пересылается, а Windows lock/suspend/shutdown идут отдельным путём lockAll и не зависят от idle таймера. OSC-52 и изменения заголовка явно поглощаются. Эти контроли не мешают уже подключённому endpoint отправлять обычный CSI 5 n, а autoLockMinutes=0 и так намеренно отключает этот механизм.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

SSH stream data/stderr → SshTerminalManager.emitText → ssh-terminal:data → TerminalSession.vue:95-96 terminal.write → xterm CSI DSR parser → автоматический onData с ESC\[0n → TerminalSession.vue:91-93 writeSshTerminal → preload.ts:14 ssh-terminal:write → main.ts:166 trusted → main.ts:261-262 lastActivity = Date.now() → main.ts:281 store.autoLockSessionIds(Date.now() - lastActivity). Один общий lastActivity применяется ко всем открытым сейфам.

- **Source:** Злонамеренный либо скомпрометированный SSH endpoint, к которому пользователь уже разрешил подключение и подтвердил соответствующий ключ. Администратор Windows, локальное внедрение кода и обход проверки ключа не требуются.

- **Sink:** Сигнал обмена протокольными байтами ошибочно используется как доказательство действий пользователя. TerminalSession передаёт одинаковым путём ввод клавиатуры и автоматические ответы терминала, а общий IPC wrapper безусловно обновляет lastActivity. Фильтры OSC-52 и OSC-0/1/2 не блокируют CSI-запрос состояния.

- **Outcome:** Удалённый SSH endpoint может неограниченно продлевать время, в течение которого все открытые сейфы и их сеансы остаются разблокированными после прекращения ввода. Это обход обещанного ограничения времени сеанса; сам по себе путь не предоставляет серверу чтение других записей и не доказывает эксфильтрацию. Учитывая необходимое заранее разрешённое SSH-соединение и ограниченный непосредственный ущерб, серьёзность medium.

**Поглощаются только перечисленные OSC; входящий SSH-текст передаётся terminal.write, а любой onData подключённого терминала вызывает writeSshTerminal. Проверенное supporting поведение onData для автоматического CSI-ответа описано с точными dependency paths в validation.** — `electron-app/src/renderer/src/components/TerminalSession.vue:86-103`

Поглощаются только перечисленные OSC; входящий SSH-текст передаётся terminal.write, а любой onData подключённого терминала вызывает writeSshTerminal. Проверенное supporting поведение onData для автоматического CSI-ответа описано с точными dependency paths в validation.

```
  // Remote output must not be allowed to write to the local clipboard or rename UI surfaces.
  terminal.parser.registerOscHandler(52, () => true);
  terminal.parser.registerOscHandler(0, () => true);
  terminal.parser.registerOscHandler(1, () => true);
  terminal.parser.registerOscHandler(2, () => true);
  terminalDisposables.push(terminal.onData((data) => {
    if (connected) void window.passwordManager.writeSshTerminal(props.terminalId, data).catch(() => markClosed('Ошибка отправки данных.'));
  }));
  terminal.attachCustomKeyEventHandler(handleTerminalKey);
  removeDataListener = window.passwordManager.onSshTerminalData((event) => {
    if (event.terminalId === props.terminalId) terminal?.write(event.data);
  });
  removeClosedListener = window.passwordManager.onSshTerminalClosed((event) => {
    if (event.terminalId === props.terminalId) markClosed(event.reason === 'error' ? 'SSH-соединение прервано.' : 'SSH-соединение закрыто.');
  });
  removeSelectAllListener = window.passwordManager.onSshTerminalSelectAll((terminalId) => {
    if (terminalId === props.terminalId) terminal?.selectAll();
  });
```

**writeSshTerminal без признака происхождения данных вызывает ssh-terminal:write.** — `electron-app/src/preload/preload.ts:13-15`

writeSshTerminal без признака происхождения данных вызывает ssh-terminal:write.

```
  startSshTerminal: (request: SshTerminalStartRequest) => ipcRenderer.invoke('ssh-terminal:start', request),
  writeSshTerminal: (terminalId: string, data: string) => ipcRenderer.invoke('ssh-terminal:write', { terminalId, data }),
  resizeSshTerminal: (terminalId: string, cols: number, rows: number) => ipcRenderer.invoke('ssh-terminal:resize', { terminalId, cols, rows }),
```

**Байты stdout/stderr подключённого SSH-сеанса поступают в emitText.** — `electron-app/src/main/services/ssh-terminal.ts:138-146`

Байты stdout/stderr подключённого SSH-сеанса поступают в emitText.

```
          const session: TerminalSession = { vaultSessionId: request.vaultSessionId, client, stream, decoder: new StringDecoder('utf8'), closed: false };
          this.sessions.set(request.terminalId, session);
          stream.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.stderr.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.once('close', () => this.finish(request.terminalId, 'closed'));
          stream.once('error', () => this.finish(request.terminalId, 'error'));
          client.once('close', () => this.finish(request.terminalId, 'closed'));
          client.once('error', () => this.finish(request.terminalId, 'error'));
          settle({ status: 'connected', fingerprint: observedFingerprint });
```

**emitText делит входящий текст на блоки и передаёт ssh-terminal:data без удаления CSI-команд.** — `electron-app/src/main/services/ssh-terminal.ts:204-207`

emitText делит входящий текст на блоки и передаёт ssh-terminal:data без удаления CSI-команд.

```
  private emitText(terminalId: string, data: string): void {
    for (let offset = 0; offset < data.length; offset += MAXIMUM_TERMINAL_WRITE) {
      this.emit('ssh-terminal:data', { terminalId, data: data.slice(offset, offset + MAXIMUM_TERMINAL_WRITE) });
    }
```

**lastActivity является общим состоянием main-процесса, а не отдельного сейфа.** — `electron-app/src/main/main.ts:22-23`

lastActivity является общим состоянием main-процесса, а не отдельного сейфа.

```
let lastActivity = Date.now();
let idleLockRunning = false;
```

**ssh-terminal:write регистрируется через общую обёртку trusted.** — `electron-app/src/main/main.ts:165-168`

ssh-terminal:write регистрируется через общую обёртку trusted.

```
  ipcMain.handle('ssh-terminal:start', trusted(async (_event, input: unknown) => startSshTerminal(input)));
  ipcMain.handle('ssh-terminal:write', trusted(async (_event, input: unknown) => sshTerminals.write(input)));
  ipcMain.handle('ssh-terminal:resize', trusted(async (_event, input: unknown) => sshTerminals.resize(input)));
  ipcMain.handle('ssh-terminal:close', trusted(async (_event, input: unknown) => sshTerminals.close(input)));
```

**Каждый доверенный IPC автоматически обновляет общий lastActivity.** — `electron-app/src/main/main.ts:261-262`

Каждый доверенный IPC автоматически обновляет общий lastActivity.

```
function trusted<T extends unknown[], R>(handler: (event: Electron.IpcMainInvokeEvent, ...args: T) => R | Promise<R>) {
  return (event: Electron.IpcMainInvokeEvent, ...args: T) => { assertTrustedSender(event); lastActivity = Date.now(); return handler(event, ...args); };
```

**Общий lastActivity используется при выборе истёкших сеансов.** — `electron-app/src/main/main.ts:277-287`

Общий lastActivity используется при выборе истёкших сеансов.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
```

**Положительный autoLockMinutes каждого сеанса сравнивается с переданным общим временем бездействия.** — `electron-app/src/main/vault/storage.ts:166-169`

Положительный autoLockMinutes каждого сеанса сравнивается с переданным общим временем бездействия.

```
  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
```

**autoLockMinutes допускает только целые значения 0-240; минимальное включённое значение равно одной минуте.** — `electron-app/src/main/vault/codec.ts:288-289`

autoLockMinutes допускает только целые значения 0-240; минимальное включённое значение равно одной минуте.

```
  if (!document.settings || typeof document.settings !== 'object' || typeof document.settings.hibpConsent !== 'boolean' || !Number.isInteger(document.settings.clipboardClearSeconds) || document.settings.clipboardClearSeconds < 5 || document.settings.clipboardClearSeconds > 600 || !Number.isInteger(document.settings.autoLockMinutes) || document.settings.autoLockMinutes < 0 || document.settings.autoLockMinutes > 240 || !['', 'ru', 'en'].includes(document.settings.sessionLanguage)) {
    throw new VaultFormatError('Invalid vault settings.');
```

**Перед подключением проверяются main-owned профиль и пользовательские native-подтверждения, включая первое доверие ключу.** — `electron-app/src/main/main.ts:196-217`

Перед подключением проверяются main-owned профиль и пользовательские native-подтверждения, включая первое доверие ключу.

```
  let profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!(await confirmSshDestination(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  if (profile.allowLegacyAlgorithms && !(await confirmLegacySshAlgorithms(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  const approvedProfile = profile;
  profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!sameSshTarget(approvedProfile, profile)) throw new Error('SSH record changed during confirmation.');
  const runtime = { terminalId: request.terminalId, vaultSessionId: request.vaultSessionId, cols: request.cols, rows: request.rows };
  let result = await sshTerminals.start(runtime, profile);
  if (result.status === 'hostKeyRequired') {
    const confirmation = await dialog.showMessageBox(mainWindow!, {
      type: 'warning',
      title: 'Проверка ключа SSH-сервера',
      message: `Первое подключение к ${profile.host}:${profile.port}`,
      detail: `SHA-256 отпечаток ключа сервера:\n${result.fingerprint}\n\nСверьте отпечаток с администратором сервера. Сохранить его в зашифрованном сейфе и продолжить?`,
      buttons: ['Доверять и подключиться', 'Отмена'],
      defaultId: 1,
      cancelId: 1,
      noLink: true
    });
    if (confirmation.response !== 0) return { status: 'cancelled', fingerprint: result.fingerprint };
    const currentProfile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(profile, currentProfile)) throw new Error('SSH record changed during host-key confirmation.');
```

**Windows lock/suspend/shutdown вызывают lockAll отдельно от периодического idle-механизма.** — `electron-app/src/main/main.ts:43-46`

Windows lock/suspend/shutdown вызывают lockAll отдельно от периодического idle-механизма.

```
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  powerMonitor.on('shutdown', lockAll);
  setInterval(() => { void lockIdleVaults().catch(() => undefined); }, 15_000).unref();
```

**lockAll закрывает SSH и сейфы и сообщает renderer о блокировке независимо от lastActivity.** — `electron-app/src/main/main.ts:270-274`

lockAll закрывает SSH и сейфы и сообщает renderer о блокировке независимо от lastActivity.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**Renderer уже имеет отдельные pointerdown/keydown/wheel уведомления активности; данные терминала не обязаны выполнять эту роль.** — `electron-app/src/renderer/src/App.vue:81-99`

Renderer уже имеет отдельные pointerdown/keydown/wheel уведомления активности; данные терминала не обязаны выполнять эту роль.

```
const activityEvents = ['pointerdown', 'keydown', 'wheel'] as const;
const activity = (): void => window.passwordManager.notifyActivity();
const fitTerminalDockToViewport = (): void => {
  terminalViewportHeight.value = window.innerHeight;
  terminalDockHeight.value = clampTerminalHeight(terminalDockHeight.value, window.innerHeight);
};
let stopPaths = (): void => undefined;
let stopLock = (): void => undefined;
let stopVaultLock = (): void => undefined;

onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
  for (const event of activityEvents) window.addEventListener(event, activity, { passive: true });
  window.addEventListener('resize', fitTerminalDockToViewport);
```

**Продукт закрепляет версию @xterm/xterm 6.0.0, поведение которой проверено в установленном supporting исходнике.** — `electron-app/package.json:24`

Продукт закрепляет версию @xterm/xterm 6.0.0, поведение которой проверено в установленном supporting исходнике.

```
    "@xterm/xterm": "6.0.0",
```

**Lockfile закрепляет версию и integrity артефакта @xterm/xterm 6.0.0.** — `electron-app/package-lock.json:1719-1723`

Lockfile закрепляет версию и integrity артефакта @xterm/xterm 6.0.0.

```
    "node_modules/@xterm/xterm": {
      "version": "6.0.0",
      "resolved": "https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz",
      "integrity": "sha512-TQwDdQGtwwDt+2cgKDLn0IRaSxYu1tSUjgKarSDkUM0ZNiSRXFpjxEsvc/Zgc5kq5omJ+V0a8/kIM2WD3sMOYg==",
      "license": "MIT",
```

**CSI DSR вызывает автоматический triggerDataEvent.** — `electron-app/node_modules/@xterm/xterm/src/common/InputHandler.ts:2653-2666`

CSI DSR вызывает автоматический triggerDataEvent.

```
  public deviceStatus(params: IParams): boolean {
    switch (params.params[0]) {
      case 5:
        // status report
        this._coreService.triggerDataEvent(`${C0.ESC}[0n`);
        break;
      case 6:
        // cursor position
        const y = this._activeBuffer.y + 1;
        const x = this._activeBuffer.x + 1;
        this._coreService.triggerDataEvent(`${C0.ESC}[${y};${x}R`);
        break;
    }
    return true;
```

**onData выдаётся и для wasUserInput=false при включённом stdin.** — `electron-app/node_modules/@xterm/xterm/src/common/services/CoreService.ts:61-81`

onData выдаётся и для wasUserInput=false при включённом stdin.

```
  public triggerDataEvent(data: string, wasUserInput: boolean = false): void {
    // Prevents all events to pty process if stdin is disabled
    if (this._optionsService.rawOptions.disableStdin) {
      return;
    }

    // Input is being sent to the terminal, the terminal should focus the prompt.
    const buffer = this._bufferService.buffer;
    if (wasUserInput && this._optionsService.rawOptions.scrollOnUserInput && buffer.ybase !== buffer.ydisp) {
      this._onRequestScrollToBottom.fire();
    }

    // Fire onUserInput so listeners can react as well (eg. clear selection)
    if (wasUserInput) {
      this._onUserInput.fire();
    }

    // Fire onData API
    this._logService.debug(`sending data "${data}"`);
    this._logService.trace(`sending data (codes)`, () => data.split('').map(e => e.charCodeAt(0)));
    this._onData.fire(data);
```

**Событие coreService.onData пересылается в публичный канал.** — `electron-app/node_modules/@xterm/xterm/src/common/CoreTerminal.ts:131`

Событие coreService.onData пересылается в публичный канал.

```
    this._register(Event.forward(this.coreService.onData, this._onData));
```

**Публичный onData возвращает core.onData.** — `electron-app/node_modules/@xterm/xterm/src/browser/public/Terminal.ts:74`

Публичный onData возвращает core.onData.

```
  public get onData(): Event<string> { return this._core.onData; }
```

**Входной write вызывает onData; приложение пересылает каждый такой ответ через preload.** — `electron-app/src/renderer/src/components/TerminalSession.vue:86-97`

Входной write вызывает onData; приложение пересылает каждый такой ответ через preload.

```
  // Remote output must not be allowed to write to the local clipboard or rename UI surfaces.
  terminal.parser.registerOscHandler(52, () => true);
  terminal.parser.registerOscHandler(0, () => true);
  terminal.parser.registerOscHandler(1, () => true);
  terminal.parser.registerOscHandler(2, () => true);
  terminalDisposables.push(terminal.onData((data) => {
    if (connected) void window.passwordManager.writeSshTerminal(props.terminalId, data).catch(() => markClosed('Ошибка отправки данных.'));
  }));
  terminal.attachCustomKeyEventHandler(handleTerminalKey);
  removeDataListener = window.passwordManager.onSshTerminalData((event) => {
    if (event.terminalId === props.terminalId) terminal?.write(event.data);
  });
```

#### Reachability

Установлен хотя бы один встроенный SSH-сеанс; открыт сейф с autoLockMinutes \> 0; пользователь прекращает ввод, оставив приложение работающим. После установления соединения endpoint отправляет ESC\[5n, например каждые 10 секунд. Это короче минимального положительного порога автоблокировки в одну минуту.

- **Attacker:** Злонамеренный либо скомпрометированный SSH endpoint, к которому пользователь уже разрешил подключение и подтвердил соответствующий ключ. Администратор Windows, локальное внедрение кода и обход проверки ключа не требуются.

- **Outcome:** Удалённый SSH endpoint может неограниченно продлевать время, в течение которого все открытые сейфы и их сеансы остаются разблокированными после прекращения ввода. Это обход обещанного ограничения времени сеанса; сам по себе путь не предоставляет серверу чтение других записей и не доказывает эксфильтрацию. Учитывая необходимое заранее разрешённое SSH-соединение и ограниченный непосредственный ущерб, серьёзность medium.

Limitations:
- Перед SSH требуются native-подтверждение назначения и проверка ключа; поэтому случайный сетевой наблюдатель без доступа к разрешённому endpoint не выполняет атаку. При заблокированном/закрытом терминале onData не пересылается, а Windows lock/suspend/shutdown идут отдельным путём lockAll и не зависят от idle таймера. OSC-52 и изменения заголовка явно поглощаются. Эти контроли не мешают уже подключённому endpoint отправлять обычный CSI 5 n, а autoLockMinutes=0 и так намеренно отключает этот механизм.

#### Severity

**Medium** — Независимо подтверждён весь путь от DSR-байтов уже разрешённого SSH endpoint до общего lastActivity. xterm генерирует onData даже при wasUserInput=false; приложение не различает происхождение этих данных. Прямой доступ сервера к другим записям не установлен, но удалённый участник действительно может обойти auto-lock всех открытых сейфов без локального кода или ввода пользователя.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Не обновлять пользовательский таймер в общей обёртке trusted и при ssh-terminal:write/resize/close, поскольку эти IPC могут возникать без ввода. Считать активностью отдельные события реального взаимодействия с интерфейсом; отделить протокольные ответы xterm от пользовательского ввода. Добавить регрессионную проверку: подключённый синтетический сервер регулярно посылает CSI 5 n без действий пользователя; все сейфы с истёкшим autoLockMinutes должны закрыться. Отдельно проверить, что настоящий ввод корректно продлевает сеанс, а Windows lock/suspend по-прежнему закрывает его.

<a id="finding-3"></a>

### [3] После проверки temp и исходного файла сохранение заменяет пути без защиты от подмены

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Статически прослежены save:85-120, readBounded:213-218 и writeDurably:221-228. Допустимое чередование следует из раздельных await и закрытия дескриптора перед повторным открытием/rename. Тест storage.test.ts:49-65 меняет исходник до вызова save и не воспроизводит окно между последней проверкой и заменой. Приложение и тесты не запускались. |
| Category | race-condition |
| CWE | CWE-367 |
| Affected lines | electron-app/src/main/vault/storage.ts:105-116, electron-app/src/main/vault/storage.ts:85-101, electron-app/src/main/vault/storage.ts:102-116, electron-app/src/main/vault/storage.ts:213-218, electron-app/src/main/vault/storage.ts:221-228, electron-app/src/main/vault/storage.test.ts:49-65, docs/threat-model.md:5, SECURITY.md:29, SECURITY.md:44-46, electron-app/src/main/vault/storage.ts:95-116 |

#### Summary

save аутентифицирует прочитанный temp и сравнивает его хеш с подготовленными байтами, затем отдельно читает и проверяет исходный файл. До rename оба файловых дескриптора уже закрыты. Изменение temp либо исходного пути после соответствующей проверки не проверяется перед публикацией; успешное сохранение может опубликовать другие байты или затереть конкурентное изменение.

#### Root Cause

Проверки целостности привязаны к прошлым чтениям по имени, а операция фиксации не сохраняет неизменность проверенного temp и исходного объекта. Между проверкой версии и заменой отсутствует защищённая операция сравнения и замены.

**Сохранение готовит шифротекст, пишет temp и проверяет аутентичность и хеш отдельно прочитанной копии.** — `electron-app/src/main/vault/storage.ts:85-101`

Сохранение готовит шифротекст, пишет temp и проверяет аутентичность и хеш отдельно прочитанной копии.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
```

**После завершения проверки temp отдельно читается источник, сравнивается sourceHash, затем выполняется rename; новый sourceHash берётся из bytes.** — `electron-app/src/main/vault/storage.ts:102-116`

После завершения проверки temp отдельно читается источник, сравнивается sourceHash, затем выполняется rename; новый sourceHash берётся из bytes.

```
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

**readBounded выполняет stat и readFile по имени и возвращает Buffer, а не удерживаемый дескриптор.** — `electron-app/src/main/vault/storage.ts:213-218`

readBounded выполняет stat и readFile по имени и возвращает Buffer, а не удерживаемый дескриптор.

```
async function readBounded(path: string): Promise<Buffer> {
  const info = await stat(path);
  if (!info.isFile() || info.size < HEADER_SIZE || info.size > MAXIMUM_FILE_SIZE) throw new Error('Invalid vault size.');
  const bytes = await readFile(path);
  if (bytes.length !== info.size) { bytes.fill(0); throw new Error('Vault changed while being read.'); }
  return bytes;
```

**Дескриптор temp закрывается до его публикации.** — `electron-app/src/main/vault/storage.ts:221-228`

Дескриптор temp закрывается до его публикации.

```
async function writeDurably(path: string, bytes: Buffer): Promise<void> {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
```

**Имеющийся тест проверяет сохранность источника, изменённого до начала save.** — `electron-app/src/main/vault/storage.test.ts:49-65`

Имеющийся тест проверяет сохранность источника, изменённого до начала save.

```
  it('does not overwrite a source changed outside the session', async () => {
    const path = await testPath();
    const vaultStore = store();
    const snapshot = await vaultStore.create(path, SYNTHETIC_PASSWORD);
    const externalBytes = await readFile(path);
    externalBytes[externalBytes.length - 1] = externalBytes[externalBytes.length - 1]! ^ 0x40;
    await writeFile(path, externalBytes);
    const changedHash = Buffer.from(externalBytes);
    externalBytes.fill(0);

    snapshot.document.settings.sessionLanguage = 'ru';
    await expect(vaultStore.save(snapshot.sessionId, snapshot.document)).rejects.toThrow(/conflict/i);
    const after = await readFile(path);
    expect(after.equals(changedHash)).toBe(true);
    after.fill(0);
    changedHash.fill(0);
  });
```

**В модель входят участник, контролирующий сетевую папку, и участник, изменяющий байты сейфа.** — `docs/threat-model.md:5`

В модель входят участник, контролирующий сетевую папку, и участник, изменяющий байты сейфа.

```
The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries.
```

**Граница хранения обещает аутентифицированный temp, проверку версии и отсутствие перезаписи конфликтов.** — `SECURITY.md:29`

Граница хранения обещает аутентифицированный temp, проверку версии и отсутствие перезаписи конфликтов.

```
- The storage boundary uses a writer lock, authenticated encrypted temp, durable flush, authenticated reread, source-version hash check, and atomic replacement. Conflicts are never overwritten.
```

**Обход writer/conflict относится к отчётным дефектам; простая потеря доступности от удаления файла исключена.** — `SECURITY.md:44-46`

Обход writer/conflict относится к отчётным дефектам; простая потеря доступности от удаления файла исключена.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Проверенные копии temp и source отделены от последующего rename.** — `electron-app/src/main/vault/storage.ts:95-116`

Проверенные копии temp и source отделены от последующего rename.

```
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

#### Validation

Подтверждены окна между проверкой temp/источника и pathname rename. Проверки обнаруживают предшествующую подмену, но не связывают проверенный файловый объект с публикацией. Отчёт ограничен нарушением гарантий конфликта/фиксации при праве изменять общую папку; раскрытие plaintext и обход GCM не утверждаются.

Validation method: offline static source trace; independent module auditor and parent validation

**Сохранение готовит шифротекст, пишет temp и проверяет аутентичность и хеш отдельно прочитанной копии.** — `electron-app/src/main/vault/storage.ts:85-101`

Сохранение готовит шифротекст, пишет temp и проверяет аутентичность и хеш отдельно прочитанной копии.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
```

**После завершения проверки temp отдельно читается источник, сравнивается sourceHash, затем выполняется rename; новый sourceHash берётся из bytes.** — `electron-app/src/main/vault/storage.ts:102-116`

После завершения проверки temp отдельно читается источник, сравнивается sourceHash, затем выполняется rename; новый sourceHash берётся из bytes.

```
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

**readBounded выполняет stat и readFile по имени и возвращает Buffer, а не удерживаемый дескриптор.** — `electron-app/src/main/vault/storage.ts:213-218`

readBounded выполняет stat и readFile по имени и возвращает Buffer, а не удерживаемый дескриптор.

```
async function readBounded(path: string): Promise<Buffer> {
  const info = await stat(path);
  if (!info.isFile() || info.size < HEADER_SIZE || info.size > MAXIMUM_FILE_SIZE) throw new Error('Invalid vault size.');
  const bytes = await readFile(path);
  if (bytes.length !== info.size) { bytes.fill(0); throw new Error('Vault changed while being read.'); }
  return bytes;
```

**Дескриптор temp закрывается до его публикации.** — `electron-app/src/main/vault/storage.ts:221-228`

Дескриптор temp закрывается до его публикации.

```
async function writeDurably(path: string, bytes: Buffer): Promise<void> {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
```

**Имеющийся тест проверяет сохранность источника, изменённого до начала save.** — `electron-app/src/main/vault/storage.test.ts:49-65`

Имеющийся тест проверяет сохранность источника, изменённого до начала save.

```
  it('does not overwrite a source changed outside the session', async () => {
    const path = await testPath();
    const vaultStore = store();
    const snapshot = await vaultStore.create(path, SYNTHETIC_PASSWORD);
    const externalBytes = await readFile(path);
    externalBytes[externalBytes.length - 1] = externalBytes[externalBytes.length - 1]! ^ 0x40;
    await writeFile(path, externalBytes);
    const changedHash = Buffer.from(externalBytes);
    externalBytes.fill(0);

    snapshot.document.settings.sessionLanguage = 'ru';
    await expect(vaultStore.save(snapshot.sessionId, snapshot.document)).rejects.toThrow(/conflict/i);
    const after = await readFile(path);
    expect(after.equals(changedHash)).toBe(true);
    after.fill(0);
    changedHash.fill(0);
  });
```

**В модель входят участник, контролирующий сетевую папку, и участник, изменяющий байты сейфа.** — `docs/threat-model.md:5`

В модель входят участник, контролирующий сетевую папку, и участник, изменяющий байты сейфа.

```
The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries.
```

**Граница хранения обещает аутентифицированный temp, проверку версии и отсутствие перезаписи конфликтов.** — `SECURITY.md:29`

Граница хранения обещает аутентифицированный temp, проверку версии и отсутствие перезаписи конфликтов.

```
- The storage boundary uses a writer lock, authenticated encrypted temp, durable flush, authenticated reread, source-version hash check, and atomic replacement. Conflicts are never overwritten.
```

**Обход writer/conflict относится к отчётным дефектам; простая потеря доступности от удаления файла исключена.** — `SECURITY.md:44-46`

Обход writer/conflict относится к отчётным дефектам; простая потеря доступности от удаления файла исключена.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Проверенные копии temp и source отделены от последующего rename.** — `electron-app/src/main/vault/storage.ts:95-116`

Проверенные копии temp и source отделены от последующего rename.

```
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

Assertions:
- Статически прослежены save:85-120, readBounded:213-218 и writeDurably:221-228. Допустимое чередование следует из раздельных await и закрытия дескриптора перед повторным открытием/rename. Тест storage.test.ts:49-65 меняет исходник до вызова save и не воспроизводит окно между последней проверкой и заменой. Приложение и тесты не запускались.
- Случайное 128-битное имя и wx предотвращают обычное предварительное захватывание temp; verifyAndDecode и сравнение хешей отклоняют подмену, произошедшую до чтения. Изменение исходника до проверки обнаруживается, что явно проверяет существующий тест. Обычный второй экземпляр с неизменённым sibling lock блокируется. Эти меры не удерживают проверенные файловые объекты неизменными до rename. Возможность выиграть гонку на конкретной Windows/SMB-конфигурации динамически не измерялась.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

Вариант A: writeDurably закрывает temp → readBounded возвращает его байты → verifyAndDecode и сравнение хешей проходят → пока читается исходный файл, атакующий меняет temp → rename публикует непроверенное содержимое. Вариант B: проверка исходного хеша проходит → другой участник заменяет исходник → rename затирает эту новую версию. После rename sourceHash вычисляется из прежнего bytes, а не фактически опубликованного файла.

- **Source:** Участник, способный изменять файлы в каталоге сетевого сейфа или управлять ответами сетевого хранилища; такой участник входит в модель угроз. Не требуется доступ к памяти разблокированного процесса или мастер-пароль.

- **Sink:** Проверки целостности привязаны к прошлым чтениям по имени, а операция фиксации не сохраняет неизменность проверенного temp и исходного объекта. Между проверкой версии и заменой отсутствует защищённая операция сравнения и замены.

- **Outcome:** Нарушаются обнаружение изменений в текущей сессии и гарантия публикации только проверенного шифротекста. Возможны успешный ответ при повреждённом либо подменённом файле и потеря конкурентной версии. Это обход границы фиксации, а не доказательство расшифрования или обхода AES-GCM.

**Сохранение готовит шифротекст, пишет temp и проверяет аутентичность и хеш отдельно прочитанной копии.** — `electron-app/src/main/vault/storage.ts:85-101`

Сохранение готовит шифротекст, пишет temp и проверяет аутентичность и хеш отдельно прочитанной копии.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
```

**После завершения проверки temp отдельно читается источник, сравнивается sourceHash, затем выполняется rename; новый sourceHash берётся из bytes.** — `electron-app/src/main/vault/storage.ts:102-116`

После завершения проверки temp отдельно читается источник, сравнивается sourceHash, затем выполняется rename; новый sourceHash берётся из bytes.

```
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

**readBounded выполняет stat и readFile по имени и возвращает Buffer, а не удерживаемый дескриптор.** — `electron-app/src/main/vault/storage.ts:213-218`

readBounded выполняет stat и readFile по имени и возвращает Buffer, а не удерживаемый дескриптор.

```
async function readBounded(path: string): Promise<Buffer> {
  const info = await stat(path);
  if (!info.isFile() || info.size < HEADER_SIZE || info.size > MAXIMUM_FILE_SIZE) throw new Error('Invalid vault size.');
  const bytes = await readFile(path);
  if (bytes.length !== info.size) { bytes.fill(0); throw new Error('Vault changed while being read.'); }
  return bytes;
```

**Дескриптор temp закрывается до его публикации.** — `electron-app/src/main/vault/storage.ts:221-228`

Дескриптор temp закрывается до его публикации.

```
async function writeDurably(path: string, bytes: Buffer): Promise<void> {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
```

**Имеющийся тест проверяет сохранность источника, изменённого до начала save.** — `electron-app/src/main/vault/storage.test.ts:49-65`

Имеющийся тест проверяет сохранность источника, изменённого до начала save.

```
  it('does not overwrite a source changed outside the session', async () => {
    const path = await testPath();
    const vaultStore = store();
    const snapshot = await vaultStore.create(path, SYNTHETIC_PASSWORD);
    const externalBytes = await readFile(path);
    externalBytes[externalBytes.length - 1] = externalBytes[externalBytes.length - 1]! ^ 0x40;
    await writeFile(path, externalBytes);
    const changedHash = Buffer.from(externalBytes);
    externalBytes.fill(0);

    snapshot.document.settings.sessionLanguage = 'ru';
    await expect(vaultStore.save(snapshot.sessionId, snapshot.document)).rejects.toThrow(/conflict/i);
    const after = await readFile(path);
    expect(after.equals(changedHash)).toBe(true);
    after.fill(0);
    changedHash.fill(0);
  });
```

**В модель входят участник, контролирующий сетевую папку, и участник, изменяющий байты сейфа.** — `docs/threat-model.md:5`

В модель входят участник, контролирующий сетевую папку, и участник, изменяющий байты сейфа.

```
The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries.
```

**Граница хранения обещает аутентифицированный temp, проверку версии и отсутствие перезаписи конфликтов.** — `SECURITY.md:29`

Граница хранения обещает аутентифицированный temp, проверку версии и отсутствие перезаписи конфликтов.

```
- The storage boundary uses a writer lock, authenticated encrypted temp, durable flush, authenticated reread, source-version hash check, and atomic replacement. Conflicts are never overwritten.
```

**Обход writer/conflict относится к отчётным дефектам; простая потеря доступности от удаления файла исключена.** — `SECURITY.md:44-46`

Обход writer/conflict относится к отчётным дефектам; простая потеря доступности от удаления файла исключена.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Проверенные копии temp и source отделены от последующего rename.** — `electron-app/src/main/vault/storage.ts:95-116`

Проверенные копии temp и source отделены от последующего rename.

```
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

#### Reachability

Пользователь выполняет сохранение доступного ему сейфа; атакующий может изменить temp или исходный файл в интервале после чтения для проверки и до rename. Для локального каталога требуются соответствующие файловые права; доступ на защищённом локальном NTFS-каталоге не предполагается автоматически.

- **Attacker:** Участник, способный изменять файлы в каталоге сетевого сейфа или управлять ответами сетевого хранилища; такой участник входит в модель угроз. Не требуется доступ к памяти разблокированного процесса или мастер-пароль.

- **Outcome:** Нарушаются обнаружение изменений в текущей сессии и гарантия публикации только проверенного шифротекста. Возможны успешный ответ при повреждённом либо подменённом файле и потеря конкурентной версии. Это обход границы фиксации, а не доказательство расшифрования или обхода AES-GCM.

Limitations:
- Случайное 128-битное имя и wx предотвращают обычное предварительное захватывание temp; verifyAndDecode и сравнение хешей отклоняют подмену, произошедшую до чтения. Изменение исходника до проверки обнаруживается, что явно проверяет существующий тест. Обычный второй экземпляр с неизменённым sibling lock блокируется. Эти меры не удерживают проверенные файловые объекты неизменными до rename. Возможность выиграть гонку на конкретной Windows/SMB-конфигурации динамически не измерялась.

#### Severity

**Medium** — Подтверждены окна между проверкой temp/источника и pathname rename. Проверки обнаруживают предшествующую подмену, но не связывают проверенный файловый объект с публикацией. Отчёт ограничен нарушением гарантий конфликта/фиксации при праве изменять общую папку; раскрытие plaintext и обход GCM не утверждаются.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Обеспечить неизменность проверенного temp до публикации и сериализовать операции сессии. Использовать проверенные механизмы Windows/поддерживаемой SMB-системы, связывающие проверенную идентичность и версию источника с атомарной заменой; сохранять необходимые дескрипторы и запреты совместной записи/удаления. Если требуемые свойства недоступны, запрещать сохранение в таком режиме. Добавить управляемые точки остановки для подмены temp и исходника непосредственно перед фиксацией.

<a id="finding-4"></a>

### [4] Зависшая очистка lock-файла задерживает удаление секретов из интерфейса при автоблокировке

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Статически проверена зависимость каждой отправки события от releaseLock. Достаточно незавершённого Promise close/unlink, чтобы управление не дошло до webContents.send; код не задаёт тайм-аут и не уведомляет renderer раньше. Реальные SMB timeout и UI на Windows не запускались. Синтетический проверочный сценарий: задержать releaseLock после удаления сессии, вызвать idle lock и проверить немедленное исчезновение вкладки. |
| Category | improper-cleanup |
| CWE | CWE-459 |
| Affected lines | electron-app/src/main/main.ts:284-287, electron-app/src/main/main.ts:270-274, electron-app/src/main/main.ts:277-294, electron-app/src/main/vault/storage.ts:152-163, electron-app/src/main/vault/storage.ts:185-202, electron-app/src/main/vault/storage.ts:208-210, electron-app/src/renderer/src/App.vue:91-97, electron-app/src/renderer/src/App.vue:464-466, docs/threat-model.md:5, electron-app/src/main/main.ts:277-293, electron-app/src/main/vault/storage.ts:152-159 |

#### Summary

И lockAll, и lockIdleVaults отправляют уведомление об очистке renderer только после await store.close/closeAll. Эти методы ожидают закрытие дескриптора и unlink соседнего lock-файла. Медленная или зависшая SMB-операция оставляет открытый документ в интерфейсе после наступления блокировки.

#### Root Cause

Операция немедленной визуальной блокировки поставлена в зависимость от потенциально неограниченной очистки внешнего filesystem-ресурса. finally защищает от завершившегося исключения, но не от незавершённого await.

**Глобальное событие app:lock и clipboard.clear находятся после await store.closeAll.** — `electron-app/src/main/main.ts:270-274`

Глобальное событие app:lock и clipboard.clear находятся после await store.closeAll.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**При inactivity событие app:vault-locked находится после await store.close; idleLockRunning снимается только при завершении всего обработчика.** — `electron-app/src/main/main.ts:277-294`

При inactivity событие app:vault-locked находится после await store.close; idleLockRunning снимается только при завершении всего обработчика.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
  } finally {
    idleLockRunning = false;
  }
```

**close очищает main-сессию, но его Promise завершается лишь после releaseLock; closeAll ожидает все close.** — `electron-app/src/main/vault/storage.ts:152-163`

close очищает main-сессию, но его Promise завершается лишь после releaseLock; closeAll ожидает все close.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
```

**Сейф и sibling lock используют выбранный файловый путь; ограничения не исключают сетевые папки.** — `electron-app/src/main/vault/storage.ts:185-202`

Сейф и sibling lock используют выбранный файловый путь; ограничения не исключают сетевые папки.

```
async function canonicalVaultPath(path: string, mustExist: boolean): Promise<string> {
  if (typeof path !== 'string' || path.length < 1 || path.length > 32_768) throw new Error('Invalid vault path.');
  let result = resolve(path);
  if (extname(result).toLowerCase() !== '.pmvault') result += '.pmvault';
  const parent = dirname(result);
  const parentStats = await stat(parent);
  if (!parentStats.isDirectory()) throw new Error('Vault parent is not a directory.');
  if (mustExist) {
    const vaultStats = await stat(result);
    if (!vaultStats.isFile() || vaultStats.size < HEADER_SIZE || vaultStats.size > MAXIMUM_FILE_SIZE) throw new Error('Invalid vault file.');
  }
  return result;
}

async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
```

**close и unlink не ограничены временем.** — `electron-app/src/main/vault/storage.ts:208-210`

close и unlink не ограничены временем.

```
async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
```

**Именно событие main запускает скрытие renderer.** — `electron-app/src/renderer/src/App.vue:91-97`

Именно событие main запускает скрытие renderer.

```
onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
```

**clearRendererSecrets очищает текущие секреты и удаляет вкладки; без уведомления эта операция не вызывается.** — `electron-app/src/renderer/src/App.vue:464-466`

clearRendererSecrets очищает текущие секреты и удаляет вкладки; без уведомления эта операция не вызывается.

```
function clearRecordSecrets(record: VaultRecord): void { record.password = ''; if (record.ssh) { record.ssh.password = ''; record.ssh.privateKeyPem = ''; record.ssh.privateKeyPassphrase = ''; } for (const field of record.customFields) if (field.isSecret) field.value = ''; }
function clearTabSecrets(tab: UiTab): void { for (const record of tab.document.records) clearRecordSecrets(record); }
function clearRendererSecrets(): void { terminalTabs.value = []; activeTerminalId.value = null; for (const tab of tabs.value) clearTabSecrets(tab); if (draft.value) clearRecordSecrets(draft.value); tabs.value = []; activeId.value = null; draft.value = null; dialogState.value = null; settingsDialog.value = null; dialogError.value = ''; }
```

**Сторона, контролирующая сетевую папку, входит в перечень атакующих.** — `docs/threat-model.md:5`

Сторона, контролирующая сетевую папку, входит в перечень атакующих.

```
The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries.
```

**UI уведомляется после await store.close.** — `electron-app/src/main/main.ts:277-293`

UI уведомляется после await store.close.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
  } finally {
    idleLockRunning = false;
```

**Удаление main-сессии предшествует файловому ожиданию.** — `electron-app/src/main/vault/storage.ts:152-159`

Удаление main-сессии предшествует файловому ожиданию.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
```

#### Validation

Подтверждена зависимость скрытия данных от внешнего файлового I/O. Очистка ключей main происходит до await, но renderer удаляет открытые данные только после завершения releaseLock. Контролирующая задержки общая папка может отложить обещанную автоблокировку интерфейса; конкретные Windows/SMB сроки не измерялись.

Validation method: offline static source trace; independent module auditor and parent validation

**Глобальное событие app:lock и clipboard.clear находятся после await store.closeAll.** — `electron-app/src/main/main.ts:270-274`

Глобальное событие app:lock и clipboard.clear находятся после await store.closeAll.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**При inactivity событие app:vault-locked находится после await store.close; idleLockRunning снимается только при завершении всего обработчика.** — `electron-app/src/main/main.ts:277-294`

При inactivity событие app:vault-locked находится после await store.close; idleLockRunning снимается только при завершении всего обработчика.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
  } finally {
    idleLockRunning = false;
  }
```

**close очищает main-сессию, но его Promise завершается лишь после releaseLock; closeAll ожидает все close.** — `electron-app/src/main/vault/storage.ts:152-163`

close очищает main-сессию, но его Promise завершается лишь после releaseLock; closeAll ожидает все close.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
```

**Сейф и sibling lock используют выбранный файловый путь; ограничения не исключают сетевые папки.** — `electron-app/src/main/vault/storage.ts:185-202`

Сейф и sibling lock используют выбранный файловый путь; ограничения не исключают сетевые папки.

```
async function canonicalVaultPath(path: string, mustExist: boolean): Promise<string> {
  if (typeof path !== 'string' || path.length < 1 || path.length > 32_768) throw new Error('Invalid vault path.');
  let result = resolve(path);
  if (extname(result).toLowerCase() !== '.pmvault') result += '.pmvault';
  const parent = dirname(result);
  const parentStats = await stat(parent);
  if (!parentStats.isDirectory()) throw new Error('Vault parent is not a directory.');
  if (mustExist) {
    const vaultStats = await stat(result);
    if (!vaultStats.isFile() || vaultStats.size < HEADER_SIZE || vaultStats.size > MAXIMUM_FILE_SIZE) throw new Error('Invalid vault file.');
  }
  return result;
}

async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
```

**close и unlink не ограничены временем.** — `electron-app/src/main/vault/storage.ts:208-210`

close и unlink не ограничены временем.

```
async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
```

**Именно событие main запускает скрытие renderer.** — `electron-app/src/renderer/src/App.vue:91-97`

Именно событие main запускает скрытие renderer.

```
onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
```

**clearRendererSecrets очищает текущие секреты и удаляет вкладки; без уведомления эта операция не вызывается.** — `electron-app/src/renderer/src/App.vue:464-466`

clearRendererSecrets очищает текущие секреты и удаляет вкладки; без уведомления эта операция не вызывается.

```
function clearRecordSecrets(record: VaultRecord): void { record.password = ''; if (record.ssh) { record.ssh.password = ''; record.ssh.privateKeyPem = ''; record.ssh.privateKeyPassphrase = ''; } for (const field of record.customFields) if (field.isSecret) field.value = ''; }
function clearTabSecrets(tab: UiTab): void { for (const record of tab.document.records) clearRecordSecrets(record); }
function clearRendererSecrets(): void { terminalTabs.value = []; activeTerminalId.value = null; for (const tab of tabs.value) clearTabSecrets(tab); if (draft.value) clearRecordSecrets(draft.value); tabs.value = []; activeId.value = null; draft.value = null; dialogState.value = null; settingsDialog.value = null; dialogError.value = ''; }
```

**Сторона, контролирующая сетевую папку, входит в перечень атакующих.** — `docs/threat-model.md:5`

Сторона, контролирующая сетевую папку, входит в перечень атакующих.

```
The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries.
```

**UI уведомляется после await store.close.** — `electron-app/src/main/main.ts:277-293`

UI уведомляется после await store.close.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
  } finally {
    idleLockRunning = false;
```

**Удаление main-сессии предшествует файловому ожиданию.** — `electron-app/src/main/vault/storage.ts:152-159`

Удаление main-сессии предшествует файловому ожиданию.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
```

Assertions:
- Статически проверена зависимость каждой отправки события от releaseLock. Достаточно незавершённого Promise close/unlink, чтобы управление не дошло до webContents.send; код не задаёт тайм-аут и не уведомляет renderer раньше. Реальные SMB timeout и UI на Windows не запускались. Синтетический проверочный сценарий: задержать releaseLock после удаления сессии, вызвать idle lock и проверить немедленное исчезновение вкладки.
- VaultStore.close сначала удаляет сессию и очищает ключевой материал, поэтому этот дефект не сохраняет действующий rootKey main. releaseLock подавляет завершившиеся ошибки close/unlink, а finally в lockIdleVaults в итоге отправляет событие даже при ошибке. Эти меры не ограничивают ожидание. Защита захвата окна остаётся включённой; атаки через камеры/администратора не заявляются.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

Таймер → autoLockSessionIds → await store.close → sessions.delete/clearDocument/disposeMaterial → await releaseLock → await handle.close/unlink → только после завершения app:vault-locked/app:lock → renderer удаляет вкладки и секреты. При ожидании I/O последний переход не происходит; глобальный idleLockRunning остаётся true.

- **Source:** Сторона, управляющая сервером сетевой папки либо задержкой его файловых ответов. Дальнейшее случайное раскрытие возможно человеку, которому пользователь показывает экран или содержимое приложения после ожидаемой автоблокировки; удалённое извлечение самим SMB-сервером не доказано.

- **Sink:** Операция немедленной визуальной блокировки поставлена в зависимость от потенциально неограниченной очистки внешнего filesystem-ресурса. finally защищает от завершившегося исключения, но не от незавершённого await.

- **Outcome:** Автоблокировка удаляет ключи main, но оставляет копию открытого документа и видимые секреты в renderer до ответа файловой системы. Проблема не ограничивается потерей доступности файлов: обещанное скрытие уже открытых данных откладывается. Само раскрытие удалённому владельцу SMB или обход Windows lock не установлены.

**Глобальное событие app:lock и clipboard.clear находятся после await store.closeAll.** — `electron-app/src/main/main.ts:270-274`

Глобальное событие app:lock и clipboard.clear находятся после await store.closeAll.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**При inactivity событие app:vault-locked находится после await store.close; idleLockRunning снимается только при завершении всего обработчика.** — `electron-app/src/main/main.ts:277-294`

При inactivity событие app:vault-locked находится после await store.close; idleLockRunning снимается только при завершении всего обработчика.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
  } finally {
    idleLockRunning = false;
  }
```

**close очищает main-сессию, но его Promise завершается лишь после releaseLock; closeAll ожидает все close.** — `electron-app/src/main/vault/storage.ts:152-163`

close очищает main-сессию, но его Promise завершается лишь после releaseLock; closeAll ожидает все close.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
```

**Сейф и sibling lock используют выбранный файловый путь; ограничения не исключают сетевые папки.** — `electron-app/src/main/vault/storage.ts:185-202`

Сейф и sibling lock используют выбранный файловый путь; ограничения не исключают сетевые папки.

```
async function canonicalVaultPath(path: string, mustExist: boolean): Promise<string> {
  if (typeof path !== 'string' || path.length < 1 || path.length > 32_768) throw new Error('Invalid vault path.');
  let result = resolve(path);
  if (extname(result).toLowerCase() !== '.pmvault') result += '.pmvault';
  const parent = dirname(result);
  const parentStats = await stat(parent);
  if (!parentStats.isDirectory()) throw new Error('Vault parent is not a directory.');
  if (mustExist) {
    const vaultStats = await stat(result);
    if (!vaultStats.isFile() || vaultStats.size < HEADER_SIZE || vaultStats.size > MAXIMUM_FILE_SIZE) throw new Error('Invalid vault file.');
  }
  return result;
}

async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
```

**close и unlink не ограничены временем.** — `electron-app/src/main/vault/storage.ts:208-210`

close и unlink не ограничены временем.

```
async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
```

**Именно событие main запускает скрытие renderer.** — `electron-app/src/renderer/src/App.vue:91-97`

Именно событие main запускает скрытие renderer.

```
onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
```

**clearRendererSecrets очищает текущие секреты и удаляет вкладки; без уведомления эта операция не вызывается.** — `electron-app/src/renderer/src/App.vue:464-466`

clearRendererSecrets очищает текущие секреты и удаляет вкладки; без уведомления эта операция не вызывается.

```
function clearRecordSecrets(record: VaultRecord): void { record.password = ''; if (record.ssh) { record.ssh.password = ''; record.ssh.privateKeyPem = ''; record.ssh.privateKeyPassphrase = ''; } for (const field of record.customFields) if (field.isSecret) field.value = ''; }
function clearTabSecrets(tab: UiTab): void { for (const record of tab.document.records) clearRecordSecrets(record); }
function clearRendererSecrets(): void { terminalTabs.value = []; activeTerminalId.value = null; for (const tab of tabs.value) clearTabSecrets(tab); if (draft.value) clearRecordSecrets(draft.value); tabs.value = []; activeId.value = null; draft.value = null; dialogState.value = null; settingsDialog.value = null; dialogError.value = ''; }
```

**Сторона, контролирующая сетевую папку, входит в перечень атакующих.** — `docs/threat-model.md:5`

Сторона, контролирующая сетевую папку, входит в перечень атакующих.

```
The primary user is the signed-in Windows account owner. Relevant attackers are: a thief with a copied locked vault; a party controlling a network share or modifying vault bytes; a party observing HIBP/SSH traffic; a malicious or changed SSH endpoint; another local process under a different Windows account; and an attacker who compromises the release channel. The Windows kernel/account, unlocked process, and trusted release worker are privileged dependencies rather than adversarial isolation boundaries.
```

**UI уведомляется после await store.close.** — `electron-app/src/main/main.ts:277-293`

UI уведомляется после await store.close.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
  } finally {
    idleLockRunning = false;
```

**Удаление main-сессии предшествует файловому ожиданию.** — `electron-app/src/main/vault/storage.ts:152-159`

Удаление main-сессии предшествует файловому ожиданию.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
```

#### Reachability

Открытый сейф расположен на сетевой папке. Наступает inactivity auto-lock либо lock-screen/suspend, а close/unlink sibling lock-файла не завершается своевременно. Для видимого эффекта существует открытая вкладка с данными.

- **Attacker:** Сторона, управляющая сервером сетевой папки либо задержкой его файловых ответов. Дальнейшее случайное раскрытие возможно человеку, которому пользователь показывает экран или содержимое приложения после ожидаемой автоблокировки; удалённое извлечение самим SMB-сервером не доказано.

- **Outcome:** Автоблокировка удаляет ключи main, но оставляет копию открытого документа и видимые секреты в renderer до ответа файловой системы. Проблема не ограничивается потерей доступности файлов: обещанное скрытие уже открытых данных откладывается. Само раскрытие удалённому владельцу SMB или обход Windows lock не установлены.

Limitations:
- VaultStore.close сначала удаляет сессию и очищает ключевой материал, поэтому этот дефект не сохраняет действующий rootKey main. releaseLock подавляет завершившиеся ошибки close/unlink, а finally в lockIdleVaults в итоге отправляет событие даже при ошибке. Эти меры не ограничивают ожидание. Защита захвата окна остаётся включённой; атаки через камеры/администратора не заявляются.

#### Severity

**Medium** — Подтверждена зависимость скрытия данных от внешнего файлового I/O. Очистка ключей main происходит до await, но renderer удаляет открытые данные только после завершения releaseLock. Контролирующая задержки общая папка может отложить обещанную автоблокировку интерфейса; конкретные Windows/SMB сроки не измерялись.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

В момент начала блокировки синхронно отозвать доступ к сессии и немедленно уведомить renderer, очистить принадлежащий приложению clipboard и отменить pending-операции. Освобождение файловых ресурсов выполнять отдельно от скрытия данных; ограничить/наблюдать его время и запретить повторное открытие до безопасного разрешения владения lock. Не ослаблять единственного writer ради тайм-аута.

<a id="finding-5"></a>

### [5] Закрытие приложения до тайм-аута оставляет скопированный секрет в буфере обмена

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Статически сопоставлены все записи/очистки clipboard с полными обработчиками before-quit и closed. Оба пути выхода не вызывают clearClipboardIfUnchanged/clipboard.clear и не дожидаются таймера. Windows clipboard persistence и реальное закрытие не проверялись исполнением; требуется синтетический ручной либо интеграционный сценарий copy → quit до тайм-аута → paste после срока. |
| Category | improper-cleanup |
| CWE | CWE-459 |
| Affected lines | electron-app/src/main/main.ts:49-50, electron-app/src/preload/preload.ts:12, electron-app/src/main/main.ts:161-164, electron-app/src/main/main.ts:309-327, electron-app/src/main/main.ts:49-50, electron-app/src/main/main.ts:120, electron-app/src/main/main.ts:270-291, electron-app/src/renderer/src/App.vue:263-266, docs/threat-model.md:14, electron-app/src/main/main.ts:309-328 |

#### Summary

copySecret устанавливает таймер условной очистки, но before-quit и closed закрывают только SSH и VaultStore. Если пользователь выходит раньше выбранного срока, процесс и его таймер прекращаются, а очистка системного clipboard больше не выполняется.

#### Root Cause

Срок хранения секрета реализован только таймером процесса; очистка принадлежащего приложению clipboard не включена в штатный жизненный цикл выхода. Ожидаемый digest хранится внутри замыкания таймера и недоступен обработчику shutdown.

**copySecret предоставляет штатный путь записи секрета через main IPC.** — `electron-app/src/preload/preload.ts:12`

copySecret предоставляет штатный путь записи секрета через main IPC.

```
  copySecret: (value: string, clearSeconds: number) => ipcRenderer.invoke('clipboard:copy', { value, clearSeconds }),
```

**clipboard:copy принимает clearSeconds от 5 до 600 и вызывает условную очистку.** — `electron-app/src/main/main.ts:161-164`

clipboard:copy принимает clearSeconds от 5 до 600 и вызывает условную очистку.

```
  ipcMain.handle('clipboard:copy', trusted(async (_event, input) => {
    const value = z.object({ value: z.string().max(16 * 1024 * 1024), clearSeconds: z.number().int().min(5).max(600) }).strict().parse(input);
    await writeClipboardWithConditionalClear(value.value, value.clearSeconds);
  }));
```

**Запись clipboard планирует только unref-таймер; hash buffers очищаются внутри будущей проверки.** — `electron-app/src/main/main.ts:309-327`

Запись clipboard планирует только unref-таймер; hash buffers очищаются внутри будущей проверки.

```
async function writeClipboardWithConditionalClear(value: string, clearSeconds: number): Promise<void> {
  const expected = createHash('sha256').update(value, 'utf8').digest();
  try {
    await clipboard.writeText(value);
    setTimeout(() => { void clearClipboardIfUnchanged(expected); }, clearSeconds * 1000).unref();
  } catch (error) {
    expected.fill(0);
    throw error;
  }
}

async function clearClipboardIfUnchanged(expected: Buffer): Promise<void> {
  let actual: Buffer | null = null;
  try {
    actual = createHash('sha256').update(await clipboard.readText(), 'utf8').digest();
    if (timingSafeEqual(actual, expected)) await clipboard.clear();
  } finally {
    actual?.fill(0);
    expected.fill(0);
```

**При выходе закрываются только менеджеры SSH и vault.** — `electron-app/src/main/main.ts:49-50`

При выходе закрываются только менеджеры SSH и vault.

```
app.on('before-quit', () => { quitting = true; void sshTerminals.closeAll(); void store.closeAll(); });
app.on('window-all-closed', () => app.quit());
```

**Обработчик closed также закрывает только SSH/store.** — `electron-app/src/main/main.ts:120`

Обработчик closed также закрывает только SSH/store.

```
  mainWindow.on('closed', () => { mainWindow = null; if (!quitting) { void sshTerminals.closeAll(); void store.closeAll(); } });
```

**Очистка clipboard есть в lockAll и при завершённом idle lock — это ограничивает, но не покрывает normal quit.** — `electron-app/src/main/main.ts:270-291`

Очистка clipboard есть в lockAll и при завершённом idle lock — это ограничивает, но не покрывает normal quit.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
}

async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
```

**После копирования UI сообщает пользователю, через сколько секунд clipboard будет очищен.** — `electron-app/src/renderer/src/App.vue:263-266`

После копирования UI сообщает пользователю, через сколько секунд clipboard будет очищен.

```
async function copy(value: string): Promise<void> {
  if (!activeTab.value || !value) return;
  await window.passwordManager.copySecret(value, activeTab.value.document.settings.clipboardClearSeconds);
  message.value = `Скопировано. Буфер будет очищен через ${activeTab.value.document.settings.clipboardClearSeconds} секунд.`;
```

**Модель обещает conditional timed clearing; отсутствие clipboard-history/roaming suppression указано отдельно.** — `docs/threat-model.md:14`

Модель обещает conditional timed clearing; отсутствие clipboard-history/roaming suppression указано отдельно.

```
6. A secret copied by the user crosses the Windows clipboard boundary with conditional timed clearing. Windows clipboard-history and roaming suppression is not yet implemented in this development build.
```

**Единственная условная очистка после copy выполняется отложенным unref-таймером.** — `electron-app/src/main/main.ts:309-328`

Единственная условная очистка после copy выполняется отложенным unref-таймером.

```
async function writeClipboardWithConditionalClear(value: string, clearSeconds: number): Promise<void> {
  const expected = createHash('sha256').update(value, 'utf8').digest();
  try {
    await clipboard.writeText(value);
    setTimeout(() => { void clearClipboardIfUnchanged(expected); }, clearSeconds * 1000).unref();
  } catch (error) {
    expected.fill(0);
    throw error;
  }
}

async function clearClipboardIfUnchanged(expected: Buffer): Promise<void> {
  let actual: Buffer | null = null;
  try {
    actual = createHash('sha256').update(await clipboard.readText(), 'utf8').digest();
    if (timingSafeEqual(actual, expected)) await clipboard.clear();
  } finally {
    actual?.fill(0);
    expected.fill(0);
  }
```

#### Validation

Подтверждено отсутствие условной очистки clipboard при нормальном выходе. Таймер привязан к процессу, тогда как скопированное значение принадлежит системному clipboard. Возможен последующий случайный paste; гарантированное чтение третьей стороной не утверждается.

Validation method: offline static source trace; independent module auditor and parent validation

**copySecret предоставляет штатный путь записи секрета через main IPC.** — `electron-app/src/preload/preload.ts:12`

copySecret предоставляет штатный путь записи секрета через main IPC.

```
  copySecret: (value: string, clearSeconds: number) => ipcRenderer.invoke('clipboard:copy', { value, clearSeconds }),
```

**clipboard:copy принимает clearSeconds от 5 до 600 и вызывает условную очистку.** — `electron-app/src/main/main.ts:161-164`

clipboard:copy принимает clearSeconds от 5 до 600 и вызывает условную очистку.

```
  ipcMain.handle('clipboard:copy', trusted(async (_event, input) => {
    const value = z.object({ value: z.string().max(16 * 1024 * 1024), clearSeconds: z.number().int().min(5).max(600) }).strict().parse(input);
    await writeClipboardWithConditionalClear(value.value, value.clearSeconds);
  }));
```

**Запись clipboard планирует только unref-таймер; hash buffers очищаются внутри будущей проверки.** — `electron-app/src/main/main.ts:309-327`

Запись clipboard планирует только unref-таймер; hash buffers очищаются внутри будущей проверки.

```
async function writeClipboardWithConditionalClear(value: string, clearSeconds: number): Promise<void> {
  const expected = createHash('sha256').update(value, 'utf8').digest();
  try {
    await clipboard.writeText(value);
    setTimeout(() => { void clearClipboardIfUnchanged(expected); }, clearSeconds * 1000).unref();
  } catch (error) {
    expected.fill(0);
    throw error;
  }
}

async function clearClipboardIfUnchanged(expected: Buffer): Promise<void> {
  let actual: Buffer | null = null;
  try {
    actual = createHash('sha256').update(await clipboard.readText(), 'utf8').digest();
    if (timingSafeEqual(actual, expected)) await clipboard.clear();
  } finally {
    actual?.fill(0);
    expected.fill(0);
```

**При выходе закрываются только менеджеры SSH и vault.** — `electron-app/src/main/main.ts:49-50`

При выходе закрываются только менеджеры SSH и vault.

```
app.on('before-quit', () => { quitting = true; void sshTerminals.closeAll(); void store.closeAll(); });
app.on('window-all-closed', () => app.quit());
```

**Обработчик closed также закрывает только SSH/store.** — `electron-app/src/main/main.ts:120`

Обработчик closed также закрывает только SSH/store.

```
  mainWindow.on('closed', () => { mainWindow = null; if (!quitting) { void sshTerminals.closeAll(); void store.closeAll(); } });
```

**Очистка clipboard есть в lockAll и при завершённом idle lock — это ограничивает, но не покрывает normal quit.** — `electron-app/src/main/main.ts:270-291`

Очистка clipboard есть в lockAll и при завершённом idle lock — это ограничивает, но не покрывает normal quit.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
}

async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
```

**После копирования UI сообщает пользователю, через сколько секунд clipboard будет очищен.** — `electron-app/src/renderer/src/App.vue:263-266`

После копирования UI сообщает пользователю, через сколько секунд clipboard будет очищен.

```
async function copy(value: string): Promise<void> {
  if (!activeTab.value || !value) return;
  await window.passwordManager.copySecret(value, activeTab.value.document.settings.clipboardClearSeconds);
  message.value = `Скопировано. Буфер будет очищен через ${activeTab.value.document.settings.clipboardClearSeconds} секунд.`;
```

**Модель обещает conditional timed clearing; отсутствие clipboard-history/roaming suppression указано отдельно.** — `docs/threat-model.md:14`

Модель обещает conditional timed clearing; отсутствие clipboard-history/roaming suppression указано отдельно.

```
6. A secret copied by the user crosses the Windows clipboard boundary with conditional timed clearing. Windows clipboard-history and roaming suppression is not yet implemented in this development build.
```

**Единственная условная очистка после copy выполняется отложенным unref-таймером.** — `electron-app/src/main/main.ts:309-328`

Единственная условная очистка после copy выполняется отложенным unref-таймером.

```
async function writeClipboardWithConditionalClear(value: string, clearSeconds: number): Promise<void> {
  const expected = createHash('sha256').update(value, 'utf8').digest();
  try {
    await clipboard.writeText(value);
    setTimeout(() => { void clearClipboardIfUnchanged(expected); }, clearSeconds * 1000).unref();
  } catch (error) {
    expected.fill(0);
    throw error;
  }
}

async function clearClipboardIfUnchanged(expected: Buffer): Promise<void> {
  let actual: Buffer | null = null;
  try {
    actual = createHash('sha256').update(await clipboard.readText(), 'utf8').digest();
    if (timingSafeEqual(actual, expected)) await clipboard.clear();
  } finally {
    actual?.fill(0);
    expected.fill(0);
  }
```

Assertions:
- Статически сопоставлены все записи/очистки clipboard с полными обработчиками before-quit и closed. Оба пути выхода не вызывают clearClipboardIfUnchanged/clipboard.clear и не дожидаются таймера. Windows clipboard persistence и реальное закрытие не проверялись исполнением; требуется синтетический ручной либо интеграционный сценарий copy → quit до тайм-аута → paste после срока.
- При работающем приложении содержимое сравнивается по SHA-256 и стирается только при совпадении; lockAll и успешная inactivity-блокировка очищают clipboard. Если таймер успел сработать до выхода, проблемы нет. Доступ malware к clipboard разблокированного пользователя вне модели; пользовательская копия секрета изначально является явным действием.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

renderer copySecret → clipboard:copy → clipboard.writeText → setTimeout(...).unref() → закрытие последнего окна/app.quit → before-quit закрывает SSH/store без clipboard cleanup → таймер больше не живёт, скопированное значение остаётся в системном clipboard.

- **Source:** Получатель последующей случайной вставки в другое приложение или переписку после закрытия PasswordManager. Отдельный вредоносный процесс на разблокированном хосте не требуется и не используется как обоснование.

- **Sink:** Срок хранения секрета реализован только таймером процесса; очистка принадлежащего приложению clipboard не включена в штатный жизненный цикл выхода. Ожидаемый digest хранится внутри замыкания таймера и недоступен обработчику shutdown.

- **Outcome:** Скопированный секрет остаётся доступен для последующей вставки после заявленного интервала, увеличивая риск случайного раскрытия. Это относится к текущему буферу обмена, отдельно от уже документированного отсутствия suppression истории/roaming.

**copySecret предоставляет штатный путь записи секрета через main IPC.** — `electron-app/src/preload/preload.ts:12`

copySecret предоставляет штатный путь записи секрета через main IPC.

```
  copySecret: (value: string, clearSeconds: number) => ipcRenderer.invoke('clipboard:copy', { value, clearSeconds }),
```

**clipboard:copy принимает clearSeconds от 5 до 600 и вызывает условную очистку.** — `electron-app/src/main/main.ts:161-164`

clipboard:copy принимает clearSeconds от 5 до 600 и вызывает условную очистку.

```
  ipcMain.handle('clipboard:copy', trusted(async (_event, input) => {
    const value = z.object({ value: z.string().max(16 * 1024 * 1024), clearSeconds: z.number().int().min(5).max(600) }).strict().parse(input);
    await writeClipboardWithConditionalClear(value.value, value.clearSeconds);
  }));
```

**Запись clipboard планирует только unref-таймер; hash buffers очищаются внутри будущей проверки.** — `electron-app/src/main/main.ts:309-327`

Запись clipboard планирует только unref-таймер; hash buffers очищаются внутри будущей проверки.

```
async function writeClipboardWithConditionalClear(value: string, clearSeconds: number): Promise<void> {
  const expected = createHash('sha256').update(value, 'utf8').digest();
  try {
    await clipboard.writeText(value);
    setTimeout(() => { void clearClipboardIfUnchanged(expected); }, clearSeconds * 1000).unref();
  } catch (error) {
    expected.fill(0);
    throw error;
  }
}

async function clearClipboardIfUnchanged(expected: Buffer): Promise<void> {
  let actual: Buffer | null = null;
  try {
    actual = createHash('sha256').update(await clipboard.readText(), 'utf8').digest();
    if (timingSafeEqual(actual, expected)) await clipboard.clear();
  } finally {
    actual?.fill(0);
    expected.fill(0);
```

**При выходе закрываются только менеджеры SSH и vault.** — `electron-app/src/main/main.ts:49-50`

При выходе закрываются только менеджеры SSH и vault.

```
app.on('before-quit', () => { quitting = true; void sshTerminals.closeAll(); void store.closeAll(); });
app.on('window-all-closed', () => app.quit());
```

**Обработчик closed также закрывает только SSH/store.** — `electron-app/src/main/main.ts:120`

Обработчик closed также закрывает только SSH/store.

```
  mainWindow.on('closed', () => { mainWindow = null; if (!quitting) { void sshTerminals.closeAll(); void store.closeAll(); } });
```

**Очистка clipboard есть в lockAll и при завершённом idle lock — это ограничивает, но не покрывает normal quit.** — `electron-app/src/main/main.ts:270-291`

Очистка clipboard есть в lockAll и при завершённом idle lock — это ограничивает, но не покрывает normal quit.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
}

async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
    }
    if (sessionIds.length > 0) await clipboard.clear();
```

**После копирования UI сообщает пользователю, через сколько секунд clipboard будет очищен.** — `electron-app/src/renderer/src/App.vue:263-266`

После копирования UI сообщает пользователю, через сколько секунд clipboard будет очищен.

```
async function copy(value: string): Promise<void> {
  if (!activeTab.value || !value) return;
  await window.passwordManager.copySecret(value, activeTab.value.document.settings.clipboardClearSeconds);
  message.value = `Скопировано. Буфер будет очищен через ${activeTab.value.document.settings.clipboardClearSeconds} секунд.`;
```

**Модель обещает conditional timed clearing; отсутствие clipboard-history/roaming suppression указано отдельно.** — `docs/threat-model.md:14`

Модель обещает conditional timed clearing; отсутствие clipboard-history/roaming suppression указано отдельно.

```
6. A secret copied by the user crosses the Windows clipboard boundary with conditional timed clearing. Windows clipboard-history and roaming suppression is not yet implemented in this development build.
```

**Единственная условная очистка после copy выполняется отложенным unref-таймером.** — `electron-app/src/main/main.ts:309-328`

Единственная условная очистка после copy выполняется отложенным unref-таймером.

```
async function writeClipboardWithConditionalClear(value: string, clearSeconds: number): Promise<void> {
  const expected = createHash('sha256').update(value, 'utf8').digest();
  try {
    await clipboard.writeText(value);
    setTimeout(() => { void clearClipboardIfUnchanged(expected); }, clearSeconds * 1000).unref();
  } catch (error) {
    expected.fill(0);
    throw error;
  }
}

async function clearClipboardIfUnchanged(expected: Buffer): Promise<void> {
  let actual: Buffer | null = null;
  try {
    actual = createHash('sha256').update(await clipboard.readText(), 'utf8').digest();
    if (timingSafeEqual(actual, expected)) await clipboard.clear();
  } finally {
    actual?.fill(0);
    expected.fill(0);
  }
```

#### Reachability

Пользователь копирует секрет штатной кнопкой и закрывает приложение в течение clearSeconds; clipboard ещё содержит именно скопированное значение.

- **Attacker:** Получатель последующей случайной вставки в другое приложение или переписку после закрытия PasswordManager. Отдельный вредоносный процесс на разблокированном хосте не требуется и не используется как обоснование.

- **Outcome:** Скопированный секрет остаётся доступен для последующей вставки после заявленного интервала, увеличивая риск случайного раскрытия. Это относится к текущему буферу обмена, отдельно от уже документированного отсутствия suppression истории/roaming.

Limitations:
- При работающем приложении содержимое сравнивается по SHA-256 и стирается только при совпадении; lockAll и успешная inactivity-блокировка очищают clipboard. Если таймер успел сработать до выхода, проблемы нет. Доступ malware к clipboard разблокированного пользователя вне модели; пользовательская копия секрета изначально является явным действием.

#### Severity

**Low** — Подтверждено отсутствие условной очистки clipboard при нормальном выходе. Таймер привязан к процессу, тогда как скопированное значение принадлежит системному clipboard. Возможен последующий случайный paste; гарантированное чтение третьей стороной не утверждается.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Отслеживать digest текущего значения, записанного приложением, и условно очищать его при штатном закрытии/выходе до завершения процесса. Сохранить правило, что более новое содержимое другого приложения не стирается. Отменять связанные таймеры и обнулять digest после проверки.

<a id="finding-6"></a>

### [6] Блокировка не отменяет начатое открытие сейфа и незавершённое SSH-подключение

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Статически прослежено допустимое чередование: остановить open перед addSession на чтении сетевого файла; выполнить lockAll с пустой Map; завершить чтение и аутентификацию; addSession и addTab выполнятся после app:lock. Проверены весь main.ts, методы store и фактический обработчик результата в App.vue. Для SSH проверены момент регистрации и поздняя компенсация renderer. Сценарии не исполнялись; длительность окна и поведение Windows при suspend требуют отдельного синтетического интеграционного теста. |
| Category | lifecycle |
| CWE | CWE-362 |
| Affected lines | electron-app/src/main/main.ts:270-274, electron-app/src/main/main.ts:43-46, electron-app/src/main/main.ts:135-136, electron-app/src/main/main.ts:270-274, electron-app/src/main/vault/storage.ts:32-41, electron-app/src/main/vault/storage.ts:60-71, electron-app/src/main/vault/storage.ts:152-175, electron-app/src/renderer/src/App.vue:91-97, electron-app/src/renderer/src/App.vue:128-163, electron-app/src/main/main.ts:196-225, electron-app/src/main/services/ssh-terminal.ts:98-109, electron-app/src/main/services/ssh-terminal.ts:112-146, electron-app/src/main/services/ssh-terminal.ts:168-194, electron-app/src/renderer/src/components/TerminalSession.vue:126-168, electron-app/src/renderer/src/App.vue:143-146, electron-app/src/main/vault/storage.ts:51-71, electron-app/src/main/vault/codec.ts:81-86, electron-app/src/renderer/src/App.vue:128-155, electron-app/src/renderer/src/App.vue:158-163, electron-app/src/renderer/src/App.vue:464-466, docs/vault-format.md:56, SECURITY.md:19-25 |

#### Summary

lockAll закрывает только уже зарегистрированные сессии. Открытие или создание, начавшееся до события блокировки и находящееся на await, затем может зарегистрировать новую сессию и вернуть её открытый документ. Renderer безусловно добавляет поздний результат после ранее обработанного app:lock. Аналогично начатое SSH-подключение не учитывается closeAll до создания shell.

#### Root Cause

Нет поколения блокировки, состояния отмены или реестра незавершённых операций, проверяемого перед регистрацией сессии и публикацией результата. Закрытие текущей Map ошибочно используется как завершённый переход в заблокированное состояние.

**События lock-screen/suspend/shutdown вызывают lockAll.** — `electron-app/src/main/main.ts:43-46`

События lock-screen/suspend/shutdown вызывают lockAll.

```
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  powerMonitor.on('shutdown', lockAll);
  setInterval(() => { void lockIdleVaults().catch(() => undefined); }, 15_000).unref();
```

**IPC open/create непосредственно возвращает асинхронный результат store без маркера поколения блокировки.** — `electron-app/src/main/main.ts:135-136`

IPC open/create непосредственно возвращает асинхронный результат store без маркера поколения блокировки.

```
  ipcMain.handle('vault:open', trusted(async (_event, input) => { const value = credentials.parse(input); return store.open(value.path, value.password); }));
  ipcMain.handle('vault:create', trusted(async (_event, input) => { const value = credentials.parse(input); return store.create(value.path, value.password); }));
```

**lockAll закрывает имеющиеся сессии и затем отправляет app:lock.** — `electron-app/src/main/main.ts:270-274`

lockAll закрывает имеющиеся сессии и затем отправляет app:lock.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**open ожидает чтение и decodeVault до регистрации сессии, а затем возвращает snapshot без проверки отмены.** — `electron-app/src/main/vault/storage.ts:32-41`

open ожидает чтение и decodeVault до регистрации сессии, а затем возвращает snapshot без проверки отмены.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
```

**Создание ожидает получение material и файловые операции до addSession.** — `electron-app/src/main/vault/storage.ts:60-71`

Создание ожидает получение material и файловые операции до addSession.

```
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
```

**closeAll перечисляет только уже зарегистрированные IDs, addSession безусловно добавляет новую сессию; таймер допускает отключение при 0.** — `electron-app/src/main/vault/storage.ts:152-175`

closeAll перечисляет только уже зарегистрированные IDs, addSession безусловно добавляет новую сессию; таймер допускает отключение при 0.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }

  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
  }

  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**Обработчик app:lock очищает renderer.** — `electron-app/src/renderer/src/App.vue:91-97`

Обработчик app:lock очищает renderer.

```
onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
```

**После await open/create результат без проверки блокировки передаётся в addTab и добавляется в tabs.** — `electron-app/src/renderer/src/App.vue:128-163`

После await open/create результат без проверки блокировки передаётся в addTab и добавляется в tabs.

```
async function submitVaultDialog(): Promise<void> {
  const state = dialogState.value;
  if (!state || busy.value) return;
  if (state.kind === 'create' && state.password.length < 15) {
    dialogError.value = 'Мастер-пароль должен содержать не менее 15 символов.';
    return;
  }
  if (state.kind === 'create' && state.password !== state.confirmation) {
    dialogError.value = 'Пароль и подтверждение не совпадают.';
    return;
  }
  busy.value = true;
  dialogError.value = '';
  message.value = '';
  try {
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
  finally { busy.value = false; }
}

function addTab(snapshot: VaultSnapshot): void {
  const existing = tabs.value.find((tab) => tab.path.toLocaleLowerCase() === snapshot.path.toLocaleLowerCase());
  if (existing) { activeId.value = existing.sessionId; return; }
  tabs.value.push({ ...snapshot, selectedFolderId: snapshot.document.rootFolderId, selectedRecordId: null });
  activeId.value = snapshot.sessionId;
  draft.value = null;
```

**SSH-профиль перепроверяется вокруг подтверждений, но после await start отсутствует проверка отмены либо блокировки.** — `electron-app/src/main/main.ts:196-225`

SSH-профиль перепроверяется вокруг подтверждений, но после await start отсутствует проверка отмены либо блокировки.

```
  let profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!(await confirmSshDestination(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  if (profile.allowLegacyAlgorithms && !(await confirmLegacySshAlgorithms(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  const approvedProfile = profile;
  profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!sameSshTarget(approvedProfile, profile)) throw new Error('SSH record changed during confirmation.');
  const runtime = { terminalId: request.terminalId, vaultSessionId: request.vaultSessionId, cols: request.cols, rows: request.rows };
  let result = await sshTerminals.start(runtime, profile);
  if (result.status === 'hostKeyRequired') {
    const confirmation = await dialog.showMessageBox(mainWindow!, {
      type: 'warning',
      title: 'Проверка ключа SSH-сервера',
      message: `Первое подключение к ${profile.host}:${profile.port}`,
      detail: `SHA-256 отпечаток ключа сервера:\n${result.fingerprint}\n\nСверьте отпечаток с администратором сервера. Сохранить его в зашифрованном сейфе и продолжить?`,
      buttons: ['Доверять и подключиться', 'Отмена'],
      defaultId: 1,
      cancelId: 1,
      noLink: true
    });
    if (confirmation.response !== 0) return { status: 'cancelled', fingerprint: result.fingerprint };
    const currentProfile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(profile, currentProfile)) throw new Error('SSH record changed during host-key confirmation.');
    await store.setSshHostKey(request.vaultSessionId, request.recordId, result.fingerprint);
    const approvedPinnedProfile: SshProfile = { ...profile, hostKeySha256: result.fingerprint };
    profile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(approvedPinnedProfile, profile)) throw new Error('SSH record changed while the host key was being saved.');
    result = await sshTerminals.start(runtime, profile);
  }
  if (result.status === 'hostKeyRequired') throw new Error('SSH host key was not persisted.');
  return result;
```

**closeAll/closeByVault закрывают только элементы sessions.** — `electron-app/src/main/services/ssh-terminal.ts:98-109`

closeAll/closeByVault закрывают только элементы sessions.

```
  async close(input: unknown): Promise<void> {
    const terminalId = idSchema.parse(typeof input === 'object' && input && 'terminalId' in input ? input.terminalId : input);
    this.finish(terminalId, 'closed');
  }

  async closeAll(): Promise<void> {
    for (const terminalId of [...this.sessions.keys()]) this.finish(terminalId, 'closed');
  }

  async closeByVault(vaultSessionId: string): Promise<void> {
    const id = idSchema.parse(vaultSessionId);
    for (const [terminalId, session] of this.sessions) if (session.vaultSessionId === id) this.finish(terminalId, 'closed');
```

**SSH-клиент и временные credentials существуют до добавления sessions, которое происходит только после ready и shell.** — `electron-app/src/main/services/ssh-terminal.ts:112-146`

SSH-клиент и временные credentials существуют до добавления sessions, которое происходит только после ready и shell.

```
  private connect(request: RuntimeRequest, profile: SshProfile): Promise<InternalSshStartResult> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      const expectedFingerprint = profile.hostKeySha256 || null;
      let observedFingerprint: string | null = null;
      let fingerprintRejected = false;
      let keyboardPasswordSent = false;
      let settled = false;
      const privateKey = profile.authenticationKind === 1 ? Buffer.from(profile.privateKeyPem, 'utf8') : null;
      const settle = (result: InternalSshStartResult | Error): void => {
        if (settled) return;
        settled = true;
        privateKey?.fill(0);
        profile.password = '';
        profile.privateKeyPem = '';
        profile.privateKeyPassphrase = '';
        if (result instanceof Error) reject(result); else resolve(result);
      };

      client.once('ready', () => {
        client.shell({ term: 'xterm-256color', cols: request.cols, rows: request.rows, width: 0, height: 0 }, (error, stream) => {
          if (error || !observedFingerprint) {
            client.end();
            settle({ status: 'failed', reason: 'shell' });
            return;
          }
          const session: TerminalSession = { vaultSessionId: request.vaultSessionId, client, stream, decoder: new StringDecoder('utf8'), closed: false };
          this.sessions.set(request.terminalId, session);
          stream.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.stderr.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.once('close', () => this.finish(request.terminalId, 'closed'));
          stream.once('error', () => this.finish(request.terminalId, 'error'));
          client.once('close', () => this.finish(request.terminalId, 'closed'));
          client.once('error', () => this.finish(request.terminalId, 'error'));
          settle({ status: 'connected', fingerprint: observedFingerprint });
```

**Подключение содержит credentials и hostVerifier, но не состояние отмены сессии сейфа.** — `electron-app/src/main/services/ssh-terminal.ts:168-194`

Подключение содержит credentials и hostVerifier, но не состояние отмены сессии сейфа.

```
      const config: ConnectConfig = {
        host: profile.host,
        port: profile.port,
        username: profile.userName,
        readyTimeout: 15_000,
        keepaliveInterval: 15_000,
        keepaliveCountMax: 3,
        strictVendor: true,
        tryKeyboard: profile.authenticationKind === 0,
        algorithms: profile.allowLegacyAlgorithms ? SSH_COMPATIBILITY_ALGORITHMS : SSH_ALGORITHMS,
        authHandler: profile.authenticationKind === 0 ? ['password', 'keyboard-interactive'] : ['publickey'],
        hostVerifier: (key: Buffer) => {
          observedFingerprint = hostKeyFingerprintSha256(key);
          const accepted = expectedFingerprint !== null && observedFingerprint === expectedFingerprint;
          fingerprintRejected = !accepted;
          return accepted;
        }
      };
      if (profile.authenticationKind === 0) config.password = profile.password;
      else {
        try { assertModernPrivateKey(privateKey!, profile.privateKeyPassphrase); }
        catch { client.end(); settle({ status: 'failed', reason: 'privateKey' }); return; }
        config.privateKey = privateKey!;
        if (profile.privateKeyPassphrase) config.passphrase = profile.privateKeyPassphrase;
      }
      try { client.connect(config); }
      catch (error) { client.end(); settle({ status: 'failed', reason: classifyConnectionFailure(error) }); }
```

**Renderer посылает close при unmount и повторяет его при позднем connected; это ограничивает эффект, но происходит после сетевой аутентификации.** — `electron-app/src/renderer/src/components/TerminalSession.vue:126-168`

Renderer посылает close при unmount и повторяет его при позднем connected; это ограничивает эффект, но происходит после сетевой аутентификации.

```
onBeforeUnmount(() => {
  disposed = true;
  connected = false;
  removeDataListener();
  removeClosedListener();
  removeSelectAllListener();
  resizeObserver?.disconnect();
  for (const disposable of terminalDisposables) disposable.dispose();
  void window.passwordManager.closeSshTerminal(props.terminalId).catch(() => undefined);
  terminal?.dispose();
  terminal = null;
  fitAddon = null;
});

async function connect(): Promise<void> {
  if (!terminal || disposed) return;
  try {
    const result = await window.passwordManager.startSshTerminal({
      terminalId: props.terminalId,
      vaultSessionId: props.vaultSessionId,
      recordId: props.recordId,
      cols: terminal.cols,
      rows: terminal.rows
    });
    if (result.status === 'cancelled') {
      markClosed('Подключение отменено пользователем.');
      return;
    }
    if (result.status === 'hostKeyMismatch') {
      markClosed(`Подключение заблокировано: ключ сервера изменился (${result.fingerprint}).`);
      return;
    }
    if (result.status === 'failed') {
      markClosed(connectionFailureText(result.reason));
      return;
    }
    if (result.status !== 'connected') {
      markClosed('Не удалось подтвердить ключ SSH-сервера.');
      return;
    }
    if (disposed) {
      await window.passwordManager.closeSshTerminal(props.terminalId).catch(() => undefined);
      return;
```

**Поздний snapshot без проверки эпохи возвращается в tabs.** — `electron-app/src/renderer/src/App.vue:143-146`

Поздний snapshot без проверки эпохи возвращается в tabs.

```
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
```

**create ожидает создание материала и файловые операции до addSession.** — `electron-app/src/main/vault/storage.ts:51-71`

create ожидает создание материала и файловые операции до addSession.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
```

**decodeVault ожидает deriveRootKey перед возвратом material/document.** — `electron-app/src/main/vault/codec.ts:81-86`

decodeVault ожидает deriveRootKey перед возвратом material/document.

```
export async function decodeVault(fileBytes: Buffer, password: string): Promise<DecodedVault> {
  const parsed = parseHeader(fileBytes);
  const rootKey = await deriveRootKey(password, parsed.kdfSalt, parsed.parameters);
  const material = { vaultId: parsed.vaultId, kdfSalt: parsed.kdfSalt, parameters: parsed.parameters, rootKey };
  try {
    return { material, document: decryptDocument(fileBytes, material) };
```

**Форма ожидает openVault/createVault и затем без проверки актуальности попытки вызывает addTab.** — `electron-app/src/renderer/src/App.vue:128-155`

Форма ожидает openVault/createVault и затем без проверки актуальности попытки вызывает addTab.

```
async function submitVaultDialog(): Promise<void> {
  const state = dialogState.value;
  if (!state || busy.value) return;
  if (state.kind === 'create' && state.password.length < 15) {
    dialogError.value = 'Мастер-пароль должен содержать не менее 15 символов.';
    return;
  }
  if (state.kind === 'create' && state.password !== state.confirmation) {
    dialogError.value = 'Пароль и подтверждение не совпадают.';
    return;
  }
  busy.value = true;
  dialogError.value = '';
  message.value = '';
  try {
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
  finally { busy.value = false; }
```

**addTab помещает возвращённый snapshot в tabs и делает его активным.** — `electron-app/src/renderer/src/App.vue:158-163`

addTab помещает возвращённый snapshot в tabs и делает его активным.

```
function addTab(snapshot: VaultSnapshot): void {
  const existing = tabs.value.find((tab) => tab.path.toLocaleLowerCase() === snapshot.path.toLocaleLowerCase());
  if (existing) { activeId.value = existing.sessionId; return; }
  tabs.value.push({ ...snapshot, selectedFolderId: snapshot.document.rootFolderId, selectedRecordId: null });
  activeId.value = snapshot.sessionId;
  draft.value = null;
```

**clearRendererSecrets удаляет вкладки/диалог, но не отменяет уже выполняющуюся асинхронную submitVaultDialog.** — `electron-app/src/renderer/src/App.vue:464-466`

clearRendererSecrets удаляет вкладки/диалог, но не отменяет уже выполняющуюся асинхронную submitVaultDialog.

```
function clearRecordSecrets(record: VaultRecord): void { record.password = ''; if (record.ssh) { record.ssh.password = ''; record.ssh.privateKeyPem = ''; record.ssh.privateKeyPassphrase = ''; } for (const field of record.customFields) if (field.isSecret) field.value = ''; }
function clearTabSecrets(tab: UiTab): void { for (const record of tab.document.records) clearRecordSecrets(record); }
function clearRendererSecrets(): void { terminalTabs.value = []; activeTerminalId.value = null; for (const tab of tabs.value) clearTabSecrets(tab); if (draft.value) clearRecordSecrets(draft.value); tabs.value = []; activeId.value = null; draft.value = null; dialogState.value = null; settingsDialog.value = null; dialogError.value = ''; }
```

**Отключение таймера не должно отключать блокировку при Windows lock, suspend, shutdown и закрытии.** — `docs/vault-format.md:56`

Отключение таймера не должно отключать блокировку при Windows lock, suspend, shutdown и закрытии.

```
`settings.autoLockMinutes` is an authenticated integer in the inclusive range 0-240. `0` disables inactivity auto-lock for that vault; it does not disable locking on Windows lock, suspend, shutdown, explicit close, or application exit. Older v1 payloads remain compatible because their existing positive value retains the same meaning.
```

**ОС и разблокированный локальный процесс доверены; сетевые ошибки и файловые входы недоверенны.** — `SECURITY.md:19-25`

ОС и разблокированный локальный процесс доверены; сетевые ошибки и файловые входы недоверенны.

```
The product does not claim to protect an unlocked process against malware, keyloggers, an OS administrator, a debugger, process or kernel dumps, physical cameras, or hardware capture. Availability attacks, deletion, and rollback to an older valid copy remain possible; the application detects in-session conflicts but has no trusted monotonic counter.

## Protected assets and trust boundaries

- Master passwords, derived root keys, data keys, record fields, SSH credentials and private keys, folder and record names, vault settings, HIBP consent, and SSH fingerprints are confidential.
- The local Windows account and kernel, Electron/Chromium/Node runtime, Node cryptographic implementation, Windows RNG, destination filesystem, HTTPS PKI, HIBP range endpoint, SSH server, and release-signing environment are explicit trust dependencies.
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
```

#### Validation

Подтверждён поздний addSession/addTab после lockAll: начатые open/create не инвалидируются. Severity снижен до low: нужен уже авторизованный ввод пароля и определённое чередование; удалённое чтение данных или обход Windows lock не установлены. Pending SSH — связанный пробел отмены, ограниченный поздним close renderer.

Validation method: offline static source trace; independent module auditor and parent validation

**События lock-screen/suspend/shutdown вызывают lockAll.** — `electron-app/src/main/main.ts:43-46`

События lock-screen/suspend/shutdown вызывают lockAll.

```
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  powerMonitor.on('shutdown', lockAll);
  setInterval(() => { void lockIdleVaults().catch(() => undefined); }, 15_000).unref();
```

**IPC open/create непосредственно возвращает асинхронный результат store без маркера поколения блокировки.** — `electron-app/src/main/main.ts:135-136`

IPC open/create непосредственно возвращает асинхронный результат store без маркера поколения блокировки.

```
  ipcMain.handle('vault:open', trusted(async (_event, input) => { const value = credentials.parse(input); return store.open(value.path, value.password); }));
  ipcMain.handle('vault:create', trusted(async (_event, input) => { const value = credentials.parse(input); return store.create(value.path, value.password); }));
```

**lockAll закрывает имеющиеся сессии и затем отправляет app:lock.** — `electron-app/src/main/main.ts:270-274`

lockAll закрывает имеющиеся сессии и затем отправляет app:lock.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**open ожидает чтение и decodeVault до регистрации сессии, а затем возвращает snapshot без проверки отмены.** — `electron-app/src/main/vault/storage.ts:32-41`

open ожидает чтение и decodeVault до регистрации сессии, а затем возвращает snapshot без проверки отмены.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
```

**Создание ожидает получение material и файловые операции до addSession.** — `electron-app/src/main/vault/storage.ts:60-71`

Создание ожидает получение material и файловые операции до addSession.

```
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
```

**closeAll перечисляет только уже зарегистрированные IDs, addSession безусловно добавляет новую сессию; таймер допускает отключение при 0.** — `electron-app/src/main/vault/storage.ts:152-175`

closeAll перечисляет только уже зарегистрированные IDs, addSession безусловно добавляет новую сессию; таймер допускает отключение при 0.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }

  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
  }

  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**Обработчик app:lock очищает renderer.** — `electron-app/src/renderer/src/App.vue:91-97`

Обработчик app:lock очищает renderer.

```
onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
```

**После await open/create результат без проверки блокировки передаётся в addTab и добавляется в tabs.** — `electron-app/src/renderer/src/App.vue:128-163`

После await open/create результат без проверки блокировки передаётся в addTab и добавляется в tabs.

```
async function submitVaultDialog(): Promise<void> {
  const state = dialogState.value;
  if (!state || busy.value) return;
  if (state.kind === 'create' && state.password.length < 15) {
    dialogError.value = 'Мастер-пароль должен содержать не менее 15 символов.';
    return;
  }
  if (state.kind === 'create' && state.password !== state.confirmation) {
    dialogError.value = 'Пароль и подтверждение не совпадают.';
    return;
  }
  busy.value = true;
  dialogError.value = '';
  message.value = '';
  try {
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
  finally { busy.value = false; }
}

function addTab(snapshot: VaultSnapshot): void {
  const existing = tabs.value.find((tab) => tab.path.toLocaleLowerCase() === snapshot.path.toLocaleLowerCase());
  if (existing) { activeId.value = existing.sessionId; return; }
  tabs.value.push({ ...snapshot, selectedFolderId: snapshot.document.rootFolderId, selectedRecordId: null });
  activeId.value = snapshot.sessionId;
  draft.value = null;
```

**SSH-профиль перепроверяется вокруг подтверждений, но после await start отсутствует проверка отмены либо блокировки.** — `electron-app/src/main/main.ts:196-225`

SSH-профиль перепроверяется вокруг подтверждений, но после await start отсутствует проверка отмены либо блокировки.

```
  let profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!(await confirmSshDestination(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  if (profile.allowLegacyAlgorithms && !(await confirmLegacySshAlgorithms(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  const approvedProfile = profile;
  profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!sameSshTarget(approvedProfile, profile)) throw new Error('SSH record changed during confirmation.');
  const runtime = { terminalId: request.terminalId, vaultSessionId: request.vaultSessionId, cols: request.cols, rows: request.rows };
  let result = await sshTerminals.start(runtime, profile);
  if (result.status === 'hostKeyRequired') {
    const confirmation = await dialog.showMessageBox(mainWindow!, {
      type: 'warning',
      title: 'Проверка ключа SSH-сервера',
      message: `Первое подключение к ${profile.host}:${profile.port}`,
      detail: `SHA-256 отпечаток ключа сервера:\n${result.fingerprint}\n\nСверьте отпечаток с администратором сервера. Сохранить его в зашифрованном сейфе и продолжить?`,
      buttons: ['Доверять и подключиться', 'Отмена'],
      defaultId: 1,
      cancelId: 1,
      noLink: true
    });
    if (confirmation.response !== 0) return { status: 'cancelled', fingerprint: result.fingerprint };
    const currentProfile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(profile, currentProfile)) throw new Error('SSH record changed during host-key confirmation.');
    await store.setSshHostKey(request.vaultSessionId, request.recordId, result.fingerprint);
    const approvedPinnedProfile: SshProfile = { ...profile, hostKeySha256: result.fingerprint };
    profile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(approvedPinnedProfile, profile)) throw new Error('SSH record changed while the host key was being saved.');
    result = await sshTerminals.start(runtime, profile);
  }
  if (result.status === 'hostKeyRequired') throw new Error('SSH host key was not persisted.');
  return result;
```

**closeAll/closeByVault закрывают только элементы sessions.** — `electron-app/src/main/services/ssh-terminal.ts:98-109`

closeAll/closeByVault закрывают только элементы sessions.

```
  async close(input: unknown): Promise<void> {
    const terminalId = idSchema.parse(typeof input === 'object' && input && 'terminalId' in input ? input.terminalId : input);
    this.finish(terminalId, 'closed');
  }

  async closeAll(): Promise<void> {
    for (const terminalId of [...this.sessions.keys()]) this.finish(terminalId, 'closed');
  }

  async closeByVault(vaultSessionId: string): Promise<void> {
    const id = idSchema.parse(vaultSessionId);
    for (const [terminalId, session] of this.sessions) if (session.vaultSessionId === id) this.finish(terminalId, 'closed');
```

**SSH-клиент и временные credentials существуют до добавления sessions, которое происходит только после ready и shell.** — `electron-app/src/main/services/ssh-terminal.ts:112-146`

SSH-клиент и временные credentials существуют до добавления sessions, которое происходит только после ready и shell.

```
  private connect(request: RuntimeRequest, profile: SshProfile): Promise<InternalSshStartResult> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      const expectedFingerprint = profile.hostKeySha256 || null;
      let observedFingerprint: string | null = null;
      let fingerprintRejected = false;
      let keyboardPasswordSent = false;
      let settled = false;
      const privateKey = profile.authenticationKind === 1 ? Buffer.from(profile.privateKeyPem, 'utf8') : null;
      const settle = (result: InternalSshStartResult | Error): void => {
        if (settled) return;
        settled = true;
        privateKey?.fill(0);
        profile.password = '';
        profile.privateKeyPem = '';
        profile.privateKeyPassphrase = '';
        if (result instanceof Error) reject(result); else resolve(result);
      };

      client.once('ready', () => {
        client.shell({ term: 'xterm-256color', cols: request.cols, rows: request.rows, width: 0, height: 0 }, (error, stream) => {
          if (error || !observedFingerprint) {
            client.end();
            settle({ status: 'failed', reason: 'shell' });
            return;
          }
          const session: TerminalSession = { vaultSessionId: request.vaultSessionId, client, stream, decoder: new StringDecoder('utf8'), closed: false };
          this.sessions.set(request.terminalId, session);
          stream.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.stderr.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.once('close', () => this.finish(request.terminalId, 'closed'));
          stream.once('error', () => this.finish(request.terminalId, 'error'));
          client.once('close', () => this.finish(request.terminalId, 'closed'));
          client.once('error', () => this.finish(request.terminalId, 'error'));
          settle({ status: 'connected', fingerprint: observedFingerprint });
```

**Подключение содержит credentials и hostVerifier, но не состояние отмены сессии сейфа.** — `electron-app/src/main/services/ssh-terminal.ts:168-194`

Подключение содержит credentials и hostVerifier, но не состояние отмены сессии сейфа.

```
      const config: ConnectConfig = {
        host: profile.host,
        port: profile.port,
        username: profile.userName,
        readyTimeout: 15_000,
        keepaliveInterval: 15_000,
        keepaliveCountMax: 3,
        strictVendor: true,
        tryKeyboard: profile.authenticationKind === 0,
        algorithms: profile.allowLegacyAlgorithms ? SSH_COMPATIBILITY_ALGORITHMS : SSH_ALGORITHMS,
        authHandler: profile.authenticationKind === 0 ? ['password', 'keyboard-interactive'] : ['publickey'],
        hostVerifier: (key: Buffer) => {
          observedFingerprint = hostKeyFingerprintSha256(key);
          const accepted = expectedFingerprint !== null && observedFingerprint === expectedFingerprint;
          fingerprintRejected = !accepted;
          return accepted;
        }
      };
      if (profile.authenticationKind === 0) config.password = profile.password;
      else {
        try { assertModernPrivateKey(privateKey!, profile.privateKeyPassphrase); }
        catch { client.end(); settle({ status: 'failed', reason: 'privateKey' }); return; }
        config.privateKey = privateKey!;
        if (profile.privateKeyPassphrase) config.passphrase = profile.privateKeyPassphrase;
      }
      try { client.connect(config); }
      catch (error) { client.end(); settle({ status: 'failed', reason: classifyConnectionFailure(error) }); }
```

**Renderer посылает close при unmount и повторяет его при позднем connected; это ограничивает эффект, но происходит после сетевой аутентификации.** — `electron-app/src/renderer/src/components/TerminalSession.vue:126-168`

Renderer посылает close при unmount и повторяет его при позднем connected; это ограничивает эффект, но происходит после сетевой аутентификации.

```
onBeforeUnmount(() => {
  disposed = true;
  connected = false;
  removeDataListener();
  removeClosedListener();
  removeSelectAllListener();
  resizeObserver?.disconnect();
  for (const disposable of terminalDisposables) disposable.dispose();
  void window.passwordManager.closeSshTerminal(props.terminalId).catch(() => undefined);
  terminal?.dispose();
  terminal = null;
  fitAddon = null;
});

async function connect(): Promise<void> {
  if (!terminal || disposed) return;
  try {
    const result = await window.passwordManager.startSshTerminal({
      terminalId: props.terminalId,
      vaultSessionId: props.vaultSessionId,
      recordId: props.recordId,
      cols: terminal.cols,
      rows: terminal.rows
    });
    if (result.status === 'cancelled') {
      markClosed('Подключение отменено пользователем.');
      return;
    }
    if (result.status === 'hostKeyMismatch') {
      markClosed(`Подключение заблокировано: ключ сервера изменился (${result.fingerprint}).`);
      return;
    }
    if (result.status === 'failed') {
      markClosed(connectionFailureText(result.reason));
      return;
    }
    if (result.status !== 'connected') {
      markClosed('Не удалось подтвердить ключ SSH-сервера.');
      return;
    }
    if (disposed) {
      await window.passwordManager.closeSshTerminal(props.terminalId).catch(() => undefined);
      return;
```

**Поздний snapshot без проверки эпохи возвращается в tabs.** — `electron-app/src/renderer/src/App.vue:143-146`

Поздний snapshot без проверки эпохи возвращается в tabs.

```
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
```

**create ожидает создание материала и файловые операции до addSession.** — `electron-app/src/main/vault/storage.ts:51-71`

create ожидает создание материала и файловые операции до addSession.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
```

**decodeVault ожидает deriveRootKey перед возвратом material/document.** — `electron-app/src/main/vault/codec.ts:81-86`

decodeVault ожидает deriveRootKey перед возвратом material/document.

```
export async function decodeVault(fileBytes: Buffer, password: string): Promise<DecodedVault> {
  const parsed = parseHeader(fileBytes);
  const rootKey = await deriveRootKey(password, parsed.kdfSalt, parsed.parameters);
  const material = { vaultId: parsed.vaultId, kdfSalt: parsed.kdfSalt, parameters: parsed.parameters, rootKey };
  try {
    return { material, document: decryptDocument(fileBytes, material) };
```

**Форма ожидает openVault/createVault и затем без проверки актуальности попытки вызывает addTab.** — `electron-app/src/renderer/src/App.vue:128-155`

Форма ожидает openVault/createVault и затем без проверки актуальности попытки вызывает addTab.

```
async function submitVaultDialog(): Promise<void> {
  const state = dialogState.value;
  if (!state || busy.value) return;
  if (state.kind === 'create' && state.password.length < 15) {
    dialogError.value = 'Мастер-пароль должен содержать не менее 15 символов.';
    return;
  }
  if (state.kind === 'create' && state.password !== state.confirmation) {
    dialogError.value = 'Пароль и подтверждение не совпадают.';
    return;
  }
  busy.value = true;
  dialogError.value = '';
  message.value = '';
  try {
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
  finally { busy.value = false; }
```

**addTab помещает возвращённый snapshot в tabs и делает его активным.** — `electron-app/src/renderer/src/App.vue:158-163`

addTab помещает возвращённый snapshot в tabs и делает его активным.

```
function addTab(snapshot: VaultSnapshot): void {
  const existing = tabs.value.find((tab) => tab.path.toLocaleLowerCase() === snapshot.path.toLocaleLowerCase());
  if (existing) { activeId.value = existing.sessionId; return; }
  tabs.value.push({ ...snapshot, selectedFolderId: snapshot.document.rootFolderId, selectedRecordId: null });
  activeId.value = snapshot.sessionId;
  draft.value = null;
```

**clearRendererSecrets удаляет вкладки/диалог, но не отменяет уже выполняющуюся асинхронную submitVaultDialog.** — `electron-app/src/renderer/src/App.vue:464-466`

clearRendererSecrets удаляет вкладки/диалог, но не отменяет уже выполняющуюся асинхронную submitVaultDialog.

```
function clearRecordSecrets(record: VaultRecord): void { record.password = ''; if (record.ssh) { record.ssh.password = ''; record.ssh.privateKeyPem = ''; record.ssh.privateKeyPassphrase = ''; } for (const field of record.customFields) if (field.isSecret) field.value = ''; }
function clearTabSecrets(tab: UiTab): void { for (const record of tab.document.records) clearRecordSecrets(record); }
function clearRendererSecrets(): void { terminalTabs.value = []; activeTerminalId.value = null; for (const tab of tabs.value) clearTabSecrets(tab); if (draft.value) clearRecordSecrets(draft.value); tabs.value = []; activeId.value = null; draft.value = null; dialogState.value = null; settingsDialog.value = null; dialogError.value = ''; }
```

**Отключение таймера не должно отключать блокировку при Windows lock, suspend, shutdown и закрытии.** — `docs/vault-format.md:56`

Отключение таймера не должно отключать блокировку при Windows lock, suspend, shutdown и закрытии.

```
`settings.autoLockMinutes` is an authenticated integer in the inclusive range 0-240. `0` disables inactivity auto-lock for that vault; it does not disable locking on Windows lock, suspend, shutdown, explicit close, or application exit. Older v1 payloads remain compatible because their existing positive value retains the same meaning.
```

**ОС и разблокированный локальный процесс доверены; сетевые ошибки и файловые входы недоверенны.** — `SECURITY.md:19-25`

ОС и разблокированный локальный процесс доверены; сетевые ошибки и файловые входы недоверенны.

```
The product does not claim to protect an unlocked process against malware, keyloggers, an OS administrator, a debugger, process or kernel dumps, physical cameras, or hardware capture. Availability attacks, deletion, and rollback to an older valid copy remain possible; the application detects in-session conflicts but has no trusted monotonic counter.

## Protected assets and trust boundaries

- Master passwords, derived root keys, data keys, record fields, SSH credentials and private keys, folder and record names, vault settings, HIBP consent, and SSH fingerprints are confidential.
- The local Windows account and kernel, Electron/Chromium/Node runtime, Node cryptographic implementation, Windows RNG, destination filesystem, HTTPS PKI, HIBP range endpoint, SSH server, and release-signing environment are explicit trust dependencies.
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
```

Assertions:
- Статически прослежено допустимое чередование: остановить open перед addSession на чтении сетевого файла; выполнить lockAll с пустой Map; завершить чтение и аутентификацию; addSession и addTab выполнятся после app:lock. Проверены весь main.ts, методы store и фактический обработчик результата в App.vue. Для SSH проверены момент регистрации и поздняя компенсация renderer. Сценарии не исполнялись; длительность окна и поведение Windows при suspend требуют отдельного синтетического интеграционного теста.
- Существующие VaultSession удаляются и их material очищается синхронно до освобождения lock-файла. Открытие всё ещё требует правильной аутентификации. Native SSH confirmations и повторные getSshProfile защищают изменения во время диалогов. TerminalSession.vue проверяет disposed после успешного соединения и посылает close, поэтому длительно живущий осиротевший SSH-сеанс при исправном renderer не доказан; однако эта проверка происходит после аутентификации. Windows lock сам по себе продолжает защищать рабочий стол. Извлечение данных через процесс-дамп вне модели не заявляется.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

vault:open/create → асинхронные canonicalVaultPath/readBounded/decodeVault/createMaterial → параллельно lockAll → closeAll обходит текущую Map и отправляет app:lock → операция продолжается, addSession помещает ключ и документ в Map → snapshot возвращается через IPC → submitVaultDialog вызывает addTab. Для SSH main ожидает sshTerminals.start, пока closeAll видит только уже готовые sessions; поздний shell добавляется без повторной проверки состояния сейфа.

- **Source:** Сторона, управляющая задержками сетевой папки с выбранным пользователем сейфом; для SSH-варианта — ранее подтверждённый SSH-сервер с закреплённым ключом. Доступ администратора или исполнение кода на локальном хосте не требуется для создания задержки.

- **Sink:** Нет поколения блокировки, состояния отмены или реестра незавершённых операций, проверяемого перед регистрацией сессии и публикацией результата. Закрытие текущей Map ошибочно используется как завершённый переход в заблокированное состояние.

- **Outcome:** Сейф вновь оказывается открыт после уведомления о блокировке без нового ввода мастер-пароля; в main снова имеется rootKey, а в renderer — документ. SSH может продолжать аутентификацию после блокировки до позднего закрытия интерфейсом. Это нарушение жизненного цикла блокировки, а не обход шифрования либо закрепления ключа SSH.

**События lock-screen/suspend/shutdown вызывают lockAll.** — `electron-app/src/main/main.ts:43-46`

События lock-screen/suspend/shutdown вызывают lockAll.

```
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  powerMonitor.on('shutdown', lockAll);
  setInterval(() => { void lockIdleVaults().catch(() => undefined); }, 15_000).unref();
```

**IPC open/create непосредственно возвращает асинхронный результат store без маркера поколения блокировки.** — `electron-app/src/main/main.ts:135-136`

IPC open/create непосредственно возвращает асинхронный результат store без маркера поколения блокировки.

```
  ipcMain.handle('vault:open', trusted(async (_event, input) => { const value = credentials.parse(input); return store.open(value.path, value.password); }));
  ipcMain.handle('vault:create', trusted(async (_event, input) => { const value = credentials.parse(input); return store.create(value.path, value.password); }));
```

**lockAll закрывает имеющиеся сессии и затем отправляет app:lock.** — `electron-app/src/main/main.ts:270-274`

lockAll закрывает имеющиеся сессии и затем отправляет app:lock.

```
async function lockAll(): Promise<void> {
  await sshTerminals.closeAll();
  await store.closeAll();
  mainWindow?.webContents.send('app:lock');
  await clipboard.clear();
```

**open ожидает чтение и decodeVault до регистрации сессии, а затем возвращает snapshot без проверки отмены.** — `electron-app/src/main/vault/storage.ts:32-41`

open ожидает чтение и decodeVault до регистрации сессии, а затем возвращает snapshot без проверки отмены.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
```

**Создание ожидает получение material и файловые операции до addSession.** — `electron-app/src/main/vault/storage.ts:60-71`

Создание ожидает получение material и файловые операции до addSession.

```
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
```

**closeAll перечисляет только уже зарегистрированные IDs, addSession безусловно добавляет новую сессию; таймер допускает отключение при 0.** — `electron-app/src/main/vault/storage.ts:152-175`

closeAll перечисляет только уже зарегистрированные IDs, addSession безусловно добавляет новую сессию; таймер допускает отключение при 0.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }

  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
  }

  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**Обработчик app:lock очищает renderer.** — `electron-app/src/renderer/src/App.vue:91-97`

Обработчик app:lock очищает renderer.

```
onMounted(() => {
  stopPaths = window.passwordManager.onOpenPaths((paths) => enqueuePaths(paths));
  stopLock = window.passwordManager.onLock(() => {
    clearRendererSecrets();
    message.value = 'Все сейфы заблокированы.';
  });
  stopVaultLock = window.passwordManager.onVaultLocked((sessionId) => removeLockedVault(sessionId));
```

**После await open/create результат без проверки блокировки передаётся в addTab и добавляется в tabs.** — `electron-app/src/renderer/src/App.vue:128-163`

После await open/create результат без проверки блокировки передаётся в addTab и добавляется в tabs.

```
async function submitVaultDialog(): Promise<void> {
  const state = dialogState.value;
  if (!state || busy.value) return;
  if (state.kind === 'create' && state.password.length < 15) {
    dialogError.value = 'Мастер-пароль должен содержать не менее 15 символов.';
    return;
  }
  if (state.kind === 'create' && state.password !== state.confirmation) {
    dialogError.value = 'Пароль и подтверждение не совпадают.';
    return;
  }
  busy.value = true;
  dialogError.value = '';
  message.value = '';
  try {
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
  finally { busy.value = false; }
}

function addTab(snapshot: VaultSnapshot): void {
  const existing = tabs.value.find((tab) => tab.path.toLocaleLowerCase() === snapshot.path.toLocaleLowerCase());
  if (existing) { activeId.value = existing.sessionId; return; }
  tabs.value.push({ ...snapshot, selectedFolderId: snapshot.document.rootFolderId, selectedRecordId: null });
  activeId.value = snapshot.sessionId;
  draft.value = null;
```

**SSH-профиль перепроверяется вокруг подтверждений, но после await start отсутствует проверка отмены либо блокировки.** — `electron-app/src/main/main.ts:196-225`

SSH-профиль перепроверяется вокруг подтверждений, но после await start отсутствует проверка отмены либо блокировки.

```
  let profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!(await confirmSshDestination(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  if (profile.allowLegacyAlgorithms && !(await confirmLegacySshAlgorithms(profile))) return { status: 'cancelled', fingerprint: profile.hostKeySha256 || null };
  const approvedProfile = profile;
  profile = store.getSshProfile(request.vaultSessionId, request.recordId);
  if (!sameSshTarget(approvedProfile, profile)) throw new Error('SSH record changed during confirmation.');
  const runtime = { terminalId: request.terminalId, vaultSessionId: request.vaultSessionId, cols: request.cols, rows: request.rows };
  let result = await sshTerminals.start(runtime, profile);
  if (result.status === 'hostKeyRequired') {
    const confirmation = await dialog.showMessageBox(mainWindow!, {
      type: 'warning',
      title: 'Проверка ключа SSH-сервера',
      message: `Первое подключение к ${profile.host}:${profile.port}`,
      detail: `SHA-256 отпечаток ключа сервера:\n${result.fingerprint}\n\nСверьте отпечаток с администратором сервера. Сохранить его в зашифрованном сейфе и продолжить?`,
      buttons: ['Доверять и подключиться', 'Отмена'],
      defaultId: 1,
      cancelId: 1,
      noLink: true
    });
    if (confirmation.response !== 0) return { status: 'cancelled', fingerprint: result.fingerprint };
    const currentProfile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(profile, currentProfile)) throw new Error('SSH record changed during host-key confirmation.');
    await store.setSshHostKey(request.vaultSessionId, request.recordId, result.fingerprint);
    const approvedPinnedProfile: SshProfile = { ...profile, hostKeySha256: result.fingerprint };
    profile = store.getSshProfile(request.vaultSessionId, request.recordId);
    if (!sameSshTarget(approvedPinnedProfile, profile)) throw new Error('SSH record changed while the host key was being saved.');
    result = await sshTerminals.start(runtime, profile);
  }
  if (result.status === 'hostKeyRequired') throw new Error('SSH host key was not persisted.');
  return result;
```

**closeAll/closeByVault закрывают только элементы sessions.** — `electron-app/src/main/services/ssh-terminal.ts:98-109`

closeAll/closeByVault закрывают только элементы sessions.

```
  async close(input: unknown): Promise<void> {
    const terminalId = idSchema.parse(typeof input === 'object' && input && 'terminalId' in input ? input.terminalId : input);
    this.finish(terminalId, 'closed');
  }

  async closeAll(): Promise<void> {
    for (const terminalId of [...this.sessions.keys()]) this.finish(terminalId, 'closed');
  }

  async closeByVault(vaultSessionId: string): Promise<void> {
    const id = idSchema.parse(vaultSessionId);
    for (const [terminalId, session] of this.sessions) if (session.vaultSessionId === id) this.finish(terminalId, 'closed');
```

**SSH-клиент и временные credentials существуют до добавления sessions, которое происходит только после ready и shell.** — `electron-app/src/main/services/ssh-terminal.ts:112-146`

SSH-клиент и временные credentials существуют до добавления sessions, которое происходит только после ready и shell.

```
  private connect(request: RuntimeRequest, profile: SshProfile): Promise<InternalSshStartResult> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      const expectedFingerprint = profile.hostKeySha256 || null;
      let observedFingerprint: string | null = null;
      let fingerprintRejected = false;
      let keyboardPasswordSent = false;
      let settled = false;
      const privateKey = profile.authenticationKind === 1 ? Buffer.from(profile.privateKeyPem, 'utf8') : null;
      const settle = (result: InternalSshStartResult | Error): void => {
        if (settled) return;
        settled = true;
        privateKey?.fill(0);
        profile.password = '';
        profile.privateKeyPem = '';
        profile.privateKeyPassphrase = '';
        if (result instanceof Error) reject(result); else resolve(result);
      };

      client.once('ready', () => {
        client.shell({ term: 'xterm-256color', cols: request.cols, rows: request.rows, width: 0, height: 0 }, (error, stream) => {
          if (error || !observedFingerprint) {
            client.end();
            settle({ status: 'failed', reason: 'shell' });
            return;
          }
          const session: TerminalSession = { vaultSessionId: request.vaultSessionId, client, stream, decoder: new StringDecoder('utf8'), closed: false };
          this.sessions.set(request.terminalId, session);
          stream.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.stderr.on('data', (chunk: Buffer) => this.emitText(request.terminalId, session.decoder.write(chunk)));
          stream.once('close', () => this.finish(request.terminalId, 'closed'));
          stream.once('error', () => this.finish(request.terminalId, 'error'));
          client.once('close', () => this.finish(request.terminalId, 'closed'));
          client.once('error', () => this.finish(request.terminalId, 'error'));
          settle({ status: 'connected', fingerprint: observedFingerprint });
```

**Подключение содержит credentials и hostVerifier, но не состояние отмены сессии сейфа.** — `electron-app/src/main/services/ssh-terminal.ts:168-194`

Подключение содержит credentials и hostVerifier, но не состояние отмены сессии сейфа.

```
      const config: ConnectConfig = {
        host: profile.host,
        port: profile.port,
        username: profile.userName,
        readyTimeout: 15_000,
        keepaliveInterval: 15_000,
        keepaliveCountMax: 3,
        strictVendor: true,
        tryKeyboard: profile.authenticationKind === 0,
        algorithms: profile.allowLegacyAlgorithms ? SSH_COMPATIBILITY_ALGORITHMS : SSH_ALGORITHMS,
        authHandler: profile.authenticationKind === 0 ? ['password', 'keyboard-interactive'] : ['publickey'],
        hostVerifier: (key: Buffer) => {
          observedFingerprint = hostKeyFingerprintSha256(key);
          const accepted = expectedFingerprint !== null && observedFingerprint === expectedFingerprint;
          fingerprintRejected = !accepted;
          return accepted;
        }
      };
      if (profile.authenticationKind === 0) config.password = profile.password;
      else {
        try { assertModernPrivateKey(privateKey!, profile.privateKeyPassphrase); }
        catch { client.end(); settle({ status: 'failed', reason: 'privateKey' }); return; }
        config.privateKey = privateKey!;
        if (profile.privateKeyPassphrase) config.passphrase = profile.privateKeyPassphrase;
      }
      try { client.connect(config); }
      catch (error) { client.end(); settle({ status: 'failed', reason: classifyConnectionFailure(error) }); }
```

**Renderer посылает close при unmount и повторяет его при позднем connected; это ограничивает эффект, но происходит после сетевой аутентификации.** — `electron-app/src/renderer/src/components/TerminalSession.vue:126-168`

Renderer посылает close при unmount и повторяет его при позднем connected; это ограничивает эффект, но происходит после сетевой аутентификации.

```
onBeforeUnmount(() => {
  disposed = true;
  connected = false;
  removeDataListener();
  removeClosedListener();
  removeSelectAllListener();
  resizeObserver?.disconnect();
  for (const disposable of terminalDisposables) disposable.dispose();
  void window.passwordManager.closeSshTerminal(props.terminalId).catch(() => undefined);
  terminal?.dispose();
  terminal = null;
  fitAddon = null;
});

async function connect(): Promise<void> {
  if (!terminal || disposed) return;
  try {
    const result = await window.passwordManager.startSshTerminal({
      terminalId: props.terminalId,
      vaultSessionId: props.vaultSessionId,
      recordId: props.recordId,
      cols: terminal.cols,
      rows: terminal.rows
    });
    if (result.status === 'cancelled') {
      markClosed('Подключение отменено пользователем.');
      return;
    }
    if (result.status === 'hostKeyMismatch') {
      markClosed(`Подключение заблокировано: ключ сервера изменился (${result.fingerprint}).`);
      return;
    }
    if (result.status === 'failed') {
      markClosed(connectionFailureText(result.reason));
      return;
    }
    if (result.status !== 'connected') {
      markClosed('Не удалось подтвердить ключ SSH-сервера.');
      return;
    }
    if (disposed) {
      await window.passwordManager.closeSshTerminal(props.terminalId).catch(() => undefined);
      return;
```

**Поздний snapshot без проверки эпохи возвращается в tabs.** — `electron-app/src/renderer/src/App.vue:143-146`

Поздний snapshot без проверки эпохи возвращается в tabs.

```
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
```

**create ожидает создание материала и файловые операции до addSession.** — `electron-app/src/main/vault/storage.ts:51-71`

create ожидает создание материала и файловые операции до addSession.

```
  async create(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, false);
    try {
      await access(vaultPath, constants.F_OK);
      throw new Error('The destination vault already exists.');
    } catch (error) {
      if (error instanceof Error && error.message === 'The destination vault already exists.') throw error;
      if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    }
    const lock = await acquireLock(vaultPath);
    const document = createEmptyDocument();
    const material = await createMaterial(password);
    try {
      const bytes = encodeVault(document, material);
      try {
        await createNewAtomically(vaultPath, bytes);
        const reread = await readBounded(vaultPath);
        try {
          verifyAndDecode(reread, material);
          const session = this.addSession(vaultPath, lock, createHash('sha256').update(reread).digest(), material, document);
          return snapshot(session);
```

**decodeVault ожидает deriveRootKey перед возвратом material/document.** — `electron-app/src/main/vault/codec.ts:81-86`

decodeVault ожидает deriveRootKey перед возвратом material/document.

```
export async function decodeVault(fileBytes: Buffer, password: string): Promise<DecodedVault> {
  const parsed = parseHeader(fileBytes);
  const rootKey = await deriveRootKey(password, parsed.kdfSalt, parsed.parameters);
  const material = { vaultId: parsed.vaultId, kdfSalt: parsed.kdfSalt, parameters: parsed.parameters, rootKey };
  try {
    return { material, document: decryptDocument(fileBytes, material) };
```

**Форма ожидает openVault/createVault и затем без проверки актуальности попытки вызывает addTab.** — `electron-app/src/renderer/src/App.vue:128-155`

Форма ожидает openVault/createVault и затем без проверки актуальности попытки вызывает addTab.

```
async function submitVaultDialog(): Promise<void> {
  const state = dialogState.value;
  if (!state || busy.value) return;
  if (state.kind === 'create' && state.password.length < 15) {
    dialogError.value = 'Мастер-пароль должен содержать не менее 15 символов.';
    return;
  }
  if (state.kind === 'create' && state.password !== state.confirmation) {
    dialogError.value = 'Пароль и подтверждение не совпадают.';
    return;
  }
  busy.value = true;
  dialogError.value = '';
  message.value = '';
  try {
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
  finally { busy.value = false; }
```

**addTab помещает возвращённый snapshot в tabs и делает его активным.** — `electron-app/src/renderer/src/App.vue:158-163`

addTab помещает возвращённый snapshot в tabs и делает его активным.

```
function addTab(snapshot: VaultSnapshot): void {
  const existing = tabs.value.find((tab) => tab.path.toLocaleLowerCase() === snapshot.path.toLocaleLowerCase());
  if (existing) { activeId.value = existing.sessionId; return; }
  tabs.value.push({ ...snapshot, selectedFolderId: snapshot.document.rootFolderId, selectedRecordId: null });
  activeId.value = snapshot.sessionId;
  draft.value = null;
```

**clearRendererSecrets удаляет вкладки/диалог, но не отменяет уже выполняющуюся асинхронную submitVaultDialog.** — `electron-app/src/renderer/src/App.vue:464-466`

clearRendererSecrets удаляет вкладки/диалог, но не отменяет уже выполняющуюся асинхронную submitVaultDialog.

```
function clearRecordSecrets(record: VaultRecord): void { record.password = ''; if (record.ssh) { record.ssh.password = ''; record.ssh.privateKeyPem = ''; record.ssh.privateKeyPassphrase = ''; } for (const field of record.customFields) if (field.isSecret) field.value = ''; }
function clearTabSecrets(tab: UiTab): void { for (const record of tab.document.records) clearRecordSecrets(record); }
function clearRendererSecrets(): void { terminalTabs.value = []; activeTerminalId.value = null; for (const tab of tabs.value) clearTabSecrets(tab); if (draft.value) clearRecordSecrets(draft.value); tabs.value = []; activeId.value = null; draft.value = null; dialogState.value = null; settingsDialog.value = null; dialogError.value = ''; }
```

**Отключение таймера не должно отключать блокировку при Windows lock, suspend, shutdown и закрытии.** — `docs/vault-format.md:56`

Отключение таймера не должно отключать блокировку при Windows lock, suspend, shutdown и закрытии.

```
`settings.autoLockMinutes` is an authenticated integer in the inclusive range 0-240. `0` disables inactivity auto-lock for that vault; it does not disable locking on Windows lock, suspend, shutdown, explicit close, or application exit. Older v1 payloads remain compatible because their existing positive value retains the same meaning.
```

**ОС и разблокированный локальный процесс доверены; сетевые ошибки и файловые входы недоверенны.** — `SECURITY.md:19-25`

ОС и разблокированный локальный процесс доверены; сетевые ошибки и файловые входы недоверенны.

```
The product does not claim to protect an unlocked process against malware, keyloggers, an OS administrator, a debugger, process or kernel dumps, physical cameras, or hardware capture. Availability attacks, deletion, and rollback to an older valid copy remain possible; the application detects in-session conflicts but has no trusted monotonic counter.

## Protected assets and trust boundaries

- Master passwords, derived root keys, data keys, record fields, SSH credentials and private keys, folder and record names, vault settings, HIBP consent, and SSH fingerprints are confidential.
- The local Windows account and kernel, Electron/Chromium/Node runtime, Node cryptographic implementation, Windows RNG, destination filesystem, HTTPS PKI, HIBP range endpoint, SSH server, and release-signing environment are explicit trust dependencies.
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
```

#### Reachability

Пользователь уже передал правильный мастер-пароль и начал открытие/создание; lock-screen или suspend происходит до регистрации сессии. Для SSH пользователь предварительно подтвердил адрес, а соединение ещё устанавливается. Злоумышленник не получает возможность открыть произвольный сейф без пароля.

- **Attacker:** Сторона, управляющая задержками сетевой папки с выбранным пользователем сейфом; для SSH-варианта — ранее подтверждённый SSH-сервер с закреплённым ключом. Доступ администратора или исполнение кода на локальном хосте не требуется для создания задержки.

- **Outcome:** Сейф вновь оказывается открыт после уведомления о блокировке без нового ввода мастер-пароля; в main снова имеется rootKey, а в renderer — документ. SSH может продолжать аутентификацию после блокировки до позднего закрытия интерфейсом. Это нарушение жизненного цикла блокировки, а не обход шифрования либо закрепления ключа SSH.

Limitations:
- Существующие VaultSession удаляются и их material очищается синхронно до освобождения lock-файла. Открытие всё ещё требует правильной аутентификации. Native SSH confirmations и повторные getSshProfile защищают изменения во время диалогов. TerminalSession.vue проверяет disposed после успешного соединения и посылает close, поэтому длительно живущий осиротевший SSH-сеанс при исправном renderer не доказан; однако эта проверка происходит после аутентификации. Windows lock сам по себе продолжает защищать рабочий стол. Извлечение данных через процесс-дамп вне модели не заявляется.

#### Severity

**Low** — Подтверждён поздний addSession/addTab после lockAll: начатые open/create не инвалидируются. Severity снижен до low: нужен уже авторизованный ввод пароля и определённое чередование; удалённое чтение данных или обход Windows lock не установлены. Pending SSH — связанный пробел отмены, ограниченный поздним close renderer.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Ввести main-owned поколение блокировки и отмену незавершённых операций. При lock/close инвалидировать соответствующие операции до await; перед addSession и возвратом snapshot сравнивать поколение, уничтожая полученные material/document при отмене. Отслеживать pending SSH-клиенты с момента создания, закрывать их при lock/close и проверять действительность vault-сессии перед аутентификацией/регистрацией. Renderer также должен отбрасывать поздние результаты прежнего поколения.

<a id="finding-7"></a>

### [7] Потеря или замена sibling lock не отзывает право записи и допускает удаление чужой блокировки

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | medium |
| Confidence rationale | Прослежены создание lock, поля VaultSession, полный save и releaseLock. Найдено, что lockHandle/lockPath используются для хранения и закрытия, а не для подтверждения владения перед записью. Последовательность L1/L2 является статическим контрпримером при указанной файловой предпосылке; сетевой reconnect и удаление открытого файла не исполнялись. |
| Category | improper-locking |
| CWE | CWE-667 |
| Affected lines | electron-app/src/main/vault/storage.ts:208-210, electron-app/src/main/vault/storage.ts:19-26, electron-app/src/main/vault/storage.ts:85-120, electron-app/src/main/vault/storage.ts:152-164, electron-app/src/main/vault/storage.ts:199-211, electron-app/src/main/vault/storage.test.ts:42-47, docs/threat-model.md:22, SECURITY.md:25-29, SECURITY.md:44-46, electron-app/src/main/vault/storage.ts:199-210, electron-app/src/main/vault/storage.ts:85-116 |

#### Summary

Writer lock представлен дескриптором пустого файла, созданного с wx. В дальнейших save наличие, идентичность и владение lock не проверяются. releaseLock безусловно удаляет текущее имя после закрытия старого дескриптора. Если lock исчез или был заменён, старый writer продолжает считать себя владельцем и при закрытии может удалить lock нового writer.

#### Root Cause

Эксклюзивность создания файла используется как непрерывное владение блокировкой, но не существует проверки идентичности текущего lock, сигнала потери владения или привязки удаления к собственному lock. Обещанная повторная проверка блокировки после сетевого переподключения отсутствует на пути save.

**Сессия хранит путь и дескриптор lock; отдельного состояния поколения/утраты владения нет.** — `electron-app/src/main/vault/storage.ts:19-26`

Сессия хранит путь и дескриптор lock; отдельного состояния поколения/утраты владения нет.

```
interface VaultSession {
  id: string;
  path: string;
  lockPath: string;
  lockHandle: FileHandle;
  sourceHash: Buffer;
  material: VaultMaterial;
  document: VaultDocument;
```

**Полный путь save не читает и не проверяет lockHandle/lockPath.** — `electron-app/src/main/vault/storage.ts:85-120`

Полный путь save не читает и не проверяет lockHandle/lockPath.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
    } finally {
      bytes.fill(0);
      await unlink(tempPath).catch(() => undefined);
    }
```

**Закрытие сессии вызывает releaseLock с ранее сохранённым дескриптором и путём.** — `electron-app/src/main/vault/storage.ts:152-164`

Закрытие сессии вызывает releaseLock с ранее сохранённым дескриптором и путём.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }
```

**Lock получается открытием имени с wx; освобождение закрывает handle и удаляет имя без проверки его текущего владельца.** — `electron-app/src/main/vault/storage.ts:199-211`

Lock получается открытием имени с wx; освобождение закрывает handle и удаляет имя без проверки его текущего владельца.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
}

async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
}
```

**Проверен только второй writer при сохранившемся первоначальном lock.** — `electron-app/src/main/vault/storage.test.ts:42-47`

Проверен только второй writer при сохранившемся первоначальном lock.

```
  it('prevents a second writer', async () => {
    const path = await testPath();
    const first = store();
    await first.create(path, SYNTHETIC_PASSWORD);
    await expect(store().open(path, SYNTHETIC_PASSWORD)).rejects.toThrow(/already open|lock/i);
  });
```

**Модель обещает повторную проверку lock и исходного хеша после переподключения.** — `docs/threat-model.md:22`

Модель обещает повторную проверку lock и исходного хеша после переподключения.

```
- Lost update/ransomware-style replacement: an exclusive sibling lock and source digest check reject concurrent change. Network reconnection revalidates both; overwrite is never automatic.
```

**Sibling lock/temp и файловые метаданные объявлены недоверенными, а writer lock является частью границы хранения.** — `SECURITY.md:25-29`

Sibling lock/temp и файловые метаданные объявлены недоверенными, а writer lock является частью границы хранения.

```
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
- A vault is authenticated before JSON parsing. Resource limits are enforced before allocations. Ordinary builds verify screen-capture exclusion before any secret-bearing window is usable.
- The HIBP boundary receives only a five-character uppercase SHA-1 prefix after explicit consent and only for a completed password. A failure is reported as “not checked”, never “safe”.
- The SSH boundary uses an explicit modern algorithm policy by default and a pinned SHA-256 host fingerprint. Per-record legacy compatibility requires explicit UI activation and a native warning on every connection, and permits only the documented bounded Group1/SHA-1, DSA, 3DES/AES-CBC, old-MAC, and zlib-compression set. RC4, Blowfish, and CAST remain prohibited. A changed key is a hard failure.
- The storage boundary uses a writer lock, authenticated encrypted temp, durable flush, authenticated reread, source-version hash check, and atomic replacement. Conflicts are never overwritten.
```

**Writer/conflict bypass является отчётным, при этом обычная потеря доступности исключена.** — `SECURITY.md:44-46`

Writer/conflict bypass является отчётным, при этом обычная потеря доступности исключена.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**wx устанавливает начальную эксклюзивность, release удаляет имя без проверки владельца.** — `electron-app/src/main/vault/storage.ts:199-210`

wx устанавливает начальную эксклюзивность, release удаляет имя без проверки владельца.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
}

async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
```

**save не использует lockHandle/lockPath для проверки сохранённого владения.** — `electron-app/src/main/vault/storage.ts:85-116`

save не использует lockHandle/lockPath для проверки сохранённого владения.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

#### Validation

Подтверждено отсутствие повторной проверки владения lock и удаление текущего имени по старому handle. Severity/confidence откалиброваны до low/medium: нужны права или SMB-семантика, позволяющие заменить lock; конкретная локальная конфигурация не исследована. Стабильный lock и sourceHash ограничивают обычного второго writer.

Validation method: offline static source trace; independent module auditor and parent validation

**Сессия хранит путь и дескриптор lock; отдельного состояния поколения/утраты владения нет.** — `electron-app/src/main/vault/storage.ts:19-26`

Сессия хранит путь и дескриптор lock; отдельного состояния поколения/утраты владения нет.

```
interface VaultSession {
  id: string;
  path: string;
  lockPath: string;
  lockHandle: FileHandle;
  sourceHash: Buffer;
  material: VaultMaterial;
  document: VaultDocument;
```

**Полный путь save не читает и не проверяет lockHandle/lockPath.** — `electron-app/src/main/vault/storage.ts:85-120`

Полный путь save не читает и не проверяет lockHandle/lockPath.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
    } finally {
      bytes.fill(0);
      await unlink(tempPath).catch(() => undefined);
    }
```

**Закрытие сессии вызывает releaseLock с ранее сохранённым дескриптором и путём.** — `electron-app/src/main/vault/storage.ts:152-164`

Закрытие сессии вызывает releaseLock с ранее сохранённым дескриптором и путём.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }
```

**Lock получается открытием имени с wx; освобождение закрывает handle и удаляет имя без проверки его текущего владельца.** — `electron-app/src/main/vault/storage.ts:199-211`

Lock получается открытием имени с wx; освобождение закрывает handle и удаляет имя без проверки его текущего владельца.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
}

async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
}
```

**Проверен только второй writer при сохранившемся первоначальном lock.** — `electron-app/src/main/vault/storage.test.ts:42-47`

Проверен только второй writer при сохранившемся первоначальном lock.

```
  it('prevents a second writer', async () => {
    const path = await testPath();
    const first = store();
    await first.create(path, SYNTHETIC_PASSWORD);
    await expect(store().open(path, SYNTHETIC_PASSWORD)).rejects.toThrow(/already open|lock/i);
  });
```

**Модель обещает повторную проверку lock и исходного хеша после переподключения.** — `docs/threat-model.md:22`

Модель обещает повторную проверку lock и исходного хеша после переподключения.

```
- Lost update/ransomware-style replacement: an exclusive sibling lock and source digest check reject concurrent change. Network reconnection revalidates both; overwrite is never automatic.
```

**Sibling lock/temp и файловые метаданные объявлены недоверенными, а writer lock является частью границы хранения.** — `SECURITY.md:25-29`

Sibling lock/temp и файловые метаданные объявлены недоверенными, а writer lock является частью границы хранения.

```
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
- A vault is authenticated before JSON parsing. Resource limits are enforced before allocations. Ordinary builds verify screen-capture exclusion before any secret-bearing window is usable.
- The HIBP boundary receives only a five-character uppercase SHA-1 prefix after explicit consent and only for a completed password. A failure is reported as “not checked”, never “safe”.
- The SSH boundary uses an explicit modern algorithm policy by default and a pinned SHA-256 host fingerprint. Per-record legacy compatibility requires explicit UI activation and a native warning on every connection, and permits only the documented bounded Group1/SHA-1, DSA, 3DES/AES-CBC, old-MAC, and zlib-compression set. RC4, Blowfish, and CAST remain prohibited. A changed key is a hard failure.
- The storage boundary uses a writer lock, authenticated encrypted temp, durable flush, authenticated reread, source-version hash check, and atomic replacement. Conflicts are never overwritten.
```

**Writer/conflict bypass является отчётным, при этом обычная потеря доступности исключена.** — `SECURITY.md:44-46`

Writer/conflict bypass является отчётным, при этом обычная потеря доступности исключена.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**wx устанавливает начальную эксклюзивность, release удаляет имя без проверки владельца.** — `electron-app/src/main/vault/storage.ts:199-210`

wx устанавливает начальную эксклюзивность, release удаляет имя без проверки владельца.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
}

async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
```

**save не использует lockHandle/lockPath для проверки сохранённого владения.** — `electron-app/src/main/vault/storage.ts:85-116`

save не использует lockHandle/lockPath для проверки сохранённого владения.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

Assertions:
- Прослежены создание lock, поля VaultSession, полный save и releaseLock. Найдено, что lockHandle/lockPath используются для хранения и закрытия, а не для подтверждения владения перед записью. Последовательность L1/L2 является статическим контрпримером при указанной файловой предпосылке; сетевой reconnect и удаление открытого файла не исполнялись.
- wx отклоняет второго writer при неизменённом имени lock, что проверяет тест. sourceHash блокирует сохранение, если другой writer уже успел зафиксировать отличающиеся байты до чтения источника. Код не удаляет stale lock по таймеру, поэтому один только старый оставшийся lock не разрешает двух writers. Непрерывная защита зависит от файловых прав/шаринга и недоказанных здесь свойств SMB; code-level проверки владения нет.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

A создаёт path.lock и хранит FileHandle → имя L1 исчезает → B создаёт path.lock заново и открывает тот же шифротекст → A.save использует только document/material/sourceHash, не lock → A.close закрывает старый handle и unlink(path.lock) удаляет L2. После этого возможен ещё один writer, пока B остаётся активным.

- **Source:** Участник с правом удаления/переименования lock в общей папке либо участник, управляющий сетевой папкой и её переподключением. Локальный администратор или вредоносный код в доверенной учётной записи не требуются и не используются как основание находки.

- **Sink:** Эксклюзивность создания файла используется как непрерывное владение блокировкой, но не существует проверки идентичности текущего lock, сигнала потери владения или привязки удаления к собственному lock. Обещанная повторная проверка блокировки после сетевого переподключения отсутствует на пути save.

- **Outcome:** Несколько сессий могут одновременно считаться писателями; старый владелец может снять блокировку действующего владельца. Это нарушение writer boundary. Обычная последовательная запись второй версии всё ещё может быть остановлена хешем источника; неизбежная потеря данных или расшифрование не утверждаются.

**Сессия хранит путь и дескриптор lock; отдельного состояния поколения/утраты владения нет.** — `electron-app/src/main/vault/storage.ts:19-26`

Сессия хранит путь и дескриптор lock; отдельного состояния поколения/утраты владения нет.

```
interface VaultSession {
  id: string;
  path: string;
  lockPath: string;
  lockHandle: FileHandle;
  sourceHash: Buffer;
  material: VaultMaterial;
  document: VaultDocument;
```

**Полный путь save не читает и не проверяет lockHandle/lockPath.** — `electron-app/src/main/vault/storage.ts:85-120`

Полный путь save не читает и не проверяет lockHandle/lockPath.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
    } finally {
      bytes.fill(0);
      await unlink(tempPath).catch(() => undefined);
    }
```

**Закрытие сессии вызывает releaseLock с ранее сохранённым дескриптором и путём.** — `electron-app/src/main/vault/storage.ts:152-164`

Закрытие сессии вызывает releaseLock с ранее сохранённым дескриптором и путём.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }
```

**Lock получается открытием имени с wx; освобождение закрывает handle и удаляет имя без проверки его текущего владельца.** — `electron-app/src/main/vault/storage.ts:199-211`

Lock получается открытием имени с wx; освобождение закрывает handle и удаляет имя без проверки его текущего владельца.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
}

async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
}
```

**Проверен только второй writer при сохранившемся первоначальном lock.** — `electron-app/src/main/vault/storage.test.ts:42-47`

Проверен только второй writer при сохранившемся первоначальном lock.

```
  it('prevents a second writer', async () => {
    const path = await testPath();
    const first = store();
    await first.create(path, SYNTHETIC_PASSWORD);
    await expect(store().open(path, SYNTHETIC_PASSWORD)).rejects.toThrow(/already open|lock/i);
  });
```

**Модель обещает повторную проверку lock и исходного хеша после переподключения.** — `docs/threat-model.md:22`

Модель обещает повторную проверку lock и исходного хеша после переподключения.

```
- Lost update/ransomware-style replacement: an exclusive sibling lock and source digest check reject concurrent change. Network reconnection revalidates both; overwrite is never automatic.
```

**Sibling lock/temp и файловые метаданные объявлены недоверенными, а writer lock является частью границы хранения.** — `SECURITY.md:25-29`

Sibling lock/temp и файловые метаданные объявлены недоверенными, а writer lock является частью границы хранения.

```
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
- A vault is authenticated before JSON parsing. Resource limits are enforced before allocations. Ordinary builds verify screen-capture exclusion before any secret-bearing window is usable.
- The HIBP boundary receives only a five-character uppercase SHA-1 prefix after explicit consent and only for a completed password. A failure is reported as “not checked”, never “safe”.
- The SSH boundary uses an explicit modern algorithm policy by default and a pinned SHA-256 host fingerprint. Per-record legacy compatibility requires explicit UI activation and a native warning on every connection, and permits only the documented bounded Group1/SHA-1, DSA, 3DES/AES-CBC, old-MAC, and zlib-compression set. RC4, Blowfish, and CAST remain prohibited. A changed key is a hard failure.
- The storage boundary uses a writer lock, authenticated encrypted temp, durable flush, authenticated reread, source-version hash check, and atomic replacement. Conflicts are never overwritten.
```

**Writer/conflict bypass является отчётным, при этом обычная потеря доступности исключена.** — `SECURITY.md:44-46`

Writer/conflict bypass является отчётным, при этом обычная потеря доступности исключена.

```
Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**wx устанавливает начальную эксклюзивность, release удаляет имя без проверки владельца.** — `electron-app/src/main/vault/storage.ts:199-210`

wx устанавливает начальную эксклюзивность, release удаляет имя без проверки владельца.

```
async function acquireLock(vaultPath: string): Promise<{ handle: FileHandle; path: string }> {
  const lockPath = `${vaultPath}.lock`;
  try {
    return { handle: await open(lockPath, 'wx', 0o600), path: lockPath };
  } catch (error) {
    throw new Error('Vault is already open for writing or its lock is unavailable.', { cause: error });
  }
}

async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
```

**save не использует lockHandle/lockPath для проверки сохранённого владения.** — `electron-app/src/main/vault/storage.ts:85-116`

save не использует lockHandle/lockPath для проверки сохранённого владения.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
    const tempPath = `${session.path}.${randomBytes(16).toString('hex').toUpperCase()}.tmp`;
    try {
      await writeDurably(tempPath, bytes);
      const reread = await readBounded(tempPath);
      try {
        verifyAndDecode(reread, session.material);
        if (!timingSafeEqual(createHash('sha256').update(reread).digest(), createHash('sha256').update(bytes).digest())) {
          throw new Error('Encrypted temporary file verification failed.');
        }
      } finally {
        reread.fill(0);
      }
      const current = await readBounded(session.path);
      try {
        if (!timingSafeEqual(createHash('sha256').update(current).digest(), session.sourceHash)) {
          throw new Error('Vault conflict: the source changed and was not overwritten.');
        }
      } finally {
        current.fill(0);
      }
      await rename(tempPath, session.path);
      session.sourceHash.fill(0);
      session.sourceHash = createHash('sha256').update(bytes).digest();
      session.document = safeDocument;
```

#### Reachability

Активная сессия уже держит дескриптор L1. Файловая система/SMB-папка позволяет удалить или заменить имя lock, либо после потери соединения имя больше не относится к L1. Новая легитимная сессия может открыть неизменённый сейф и создать L2. Поддержка конкретного сценария удаления открытого файла локальной конфигурацией не проверялась; утверждение не распространяется на каталоги, где права/шаринг это исключают.

- **Attacker:** Участник с правом удаления/переименования lock в общей папке либо участник, управляющий сетевой папкой и её переподключением. Локальный администратор или вредоносный код в доверенной учётной записи не требуются и не используются как основание находки.

- **Outcome:** Несколько сессий могут одновременно считаться писателями; старый владелец может снять блокировку действующего владельца. Это нарушение writer boundary. Обычная последовательная запись второй версии всё ещё может быть остановлена хешем источника; неизбежная потеря данных или расшифрование не утверждаются.

Limitations:
- wx отклоняет второго writer при неизменённом имени lock, что проверяет тест. sourceHash блокирует сохранение, если другой writer уже успел зафиксировать отличающиеся байты до чтения источника. Код не удаляет stale lock по таймеру, поэтому один только старый оставшийся lock не разрешает двух writers. Непрерывная защита зависит от файловых прав/шаринга и недоказанных здесь свойств SMB; code-level проверки владения нет.

#### Severity

**Low** — Подтверждено отсутствие повторной проверки владения lock и удаление текущего имени по старому handle. Severity/confidence откалиброваны до low/medium: нужны права или SMB-семантика, позволяющие заменить lock; конкретная локальная конфигурация не исследована. Стабильный lock и sourceHash ограничивают обычного второго writer.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Использовать механизм блокировки с проверяемым непрерывным владением и безопасным поведением при потере SMB-соединения; блокировать дальнейшие сохранения при потере владения. Не удалять lock, идентичность которого не соответствует собственному объекту/токену. Проверить механизм на поддерживаемых Windows/SMB-конфигурациях, включая reconnect, замену lock и закрытие старого владельца после повторного открытия.

<a id="finding-8"></a>

### [8] Ошибка очистки после аутентификации оставляет скрытую сессию с освобождённой блокировкой

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Проверены порядок open:32-48, addSession:172-175, падающие await cleanupEncryptedTemps:237-256 и close/autoLockSessionIds:152-169. По статическому потоку catch не вызывает ни sessions.delete, ни disposeMaterial для уже зарегистрированной сессии. Сценарий ошибки readdir после успешной аутентификации не исполнялся. |
| Category | improper-cleanup |
| CWE | CWE-459 |
| Affected lines | electron-app/src/main/vault/storage.ts:38-47, electron-app/src/main/vault/storage.ts:32-48, electron-app/src/main/vault/storage.ts:237-255, electron-app/src/main/vault/storage.ts:152-175, electron-app/src/main/vault/storage.ts:208-211, electron-app/src/main/vault/codec.ts:81-91, electron-app/src/main/vault/codec.ts:148-151, electron-app/src/renderer/src/App.vue:143-154, electron-app/src/renderer/src/App.vue:415-428, electron-app/src/main/main.ts:277-289, SECURITY.md:19-25, electron-app/src/main/vault/storage.ts:38-47 |

#### Summary

open добавляет расшифрованную сессию в sessions до await cleanupEncryptedTemps. Если перечисление каталога или чтение temp завершается ошибкой, catch освобождает lock и сообщает об ошибке, но не удаляет сессию и не очищает её rootKey/document. При последующей очистке скрытая сессия также может удалить блокировку повторного открытия.

#### Root Cause

Публикация сессии в глобальной коллекции происходит до завершения потенциально падающего этапа открытия, а rollback обрабатывает только дескриптор lock, не уже переданное владение ключевым материалом и документом.

**addSession вызывается перед cleanupEncryptedTemps; внешний catch освобождает только lock и повторно бросает ошибку.** — `electron-app/src/main/vault/storage.ts:32-48`

addSession вызывается перед cleanupEncryptedTemps; внешний catch освобождает только lock и повторно бросает ошибку.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
    }
```

**readdir/read являются падающими await.** — `electron-app/src/main/vault/storage.ts:237-255`

readdir/read являются падающими await.

```
async function cleanupEncryptedTemps(vaultPath: string): Promise<void> {
  const { readdir } = await import('node:fs/promises');
  const directory = dirname(vaultPath);
  const prefix = `${basename(vaultPath)}.`;
  const entries = (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.startsWith(prefix) && entry.name.endsWith('.tmp')).slice(0, 32);
  for (const entry of entries) {
    const candidate = join(directory, entry.name);
    const handle = await open(candidate, 'r').catch(() => null);
    if (!handle) continue;
    try {
      const magic = Buffer.alloc(8);
      await handle.read(magic, 0, 8, 0);
      if (magic.equals(Buffer.from('PMVAULT1'))) {
        await handle.close();
        await unlink(candidate).catch(() => undefined);
      }
    } finally {
      await handle.close().catch(() => undefined);
    }
```

**Скрытая сессия остаётся в коллекции и позднее закрывается по старому пути lock.** — `electron-app/src/main/vault/storage.ts:152-175`

Скрытая сессия остаётся в коллекции и позднее закрывается по старому пути lock.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }

  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
  }

  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**Освобождение старой сессии удаляет текущее имя lock без проверки идентичности.** — `electron-app/src/main/vault/storage.ts:208-211`

Освобождение старой сессии удаляет текущее имя lock без проверки идентичности.

```
async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
}
```

**Ошибка дешифрования до регистрации сессии вызывает disposeMaterial.** — `electron-app/src/main/vault/codec.ts:81-91`

Ошибка дешифрования до регистрации сессии вызывает disposeMaterial.

```
export async function decodeVault(fileBytes: Buffer, password: string): Promise<DecodedVault> {
  const parsed = parseHeader(fileBytes);
  const rootKey = await deriveRootKey(password, parsed.kdfSalt, parsed.parameters);
  const material = { vaultId: parsed.vaultId, kdfSalt: parsed.kdfSalt, parameters: parsed.parameters, rootKey };
  try {
    return { material, document: decryptDocument(fileBytes, material) };
  } catch (error) {
    disposeMaterial(material);
    if (error instanceof VaultFormatError) throw error;
    throw new VaultAuthenticationError('Wrong password or vault authentication failed.');
  }
```

**disposeMaterial обнуляет rootKey, kdfSalt и vaultId.** — `electron-app/src/main/vault/codec.ts:148-151`

disposeMaterial обнуляет rootKey, kdfSalt и vaultId.

```
export function disposeMaterial(material: VaultMaterial): void {
  material.rootKey.fill(0);
  material.kdfSalt.fill(0);
  material.vaultId.fill(0);
```

**При отказе open вкладка не создаётся и UI сообщает о невозможности открытия.** — `electron-app/src/renderer/src/App.vue:143-154`

При отказе open вкладка не создаётся и UI сообщает о невозможности открытия.

```
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
```

**Настройки действующей вкладки позволяют отключить или изменить её срок авто-блокировки.** — `electron-app/src/renderer/src/App.vue:415-428`

Настройки действующей вкладки позволяют отключить или изменить её срок авто-блокировки.

```
async function saveSettings(): Promise<void> {
  const state = settingsDialog.value;
  const tab = tabs.value.find((item) => item.sessionId === state?.sessionId);
  if (!state || !tab || !Number.isInteger(state.autoLockMinutes) || state.autoLockMinutes < 0 || state.autoLockMinutes > 240) {
    message.value = 'Автоблокировка должна быть целым числом от 0 до 240 минут.';
    return;
  }
  const previous = tab.document.settings.autoLockMinutes;
  tab.document.settings.autoLockMinutes = state.autoLockMinutes;
  if (await persistVault(tab)) {
    settingsDialog.value = null;
    message.value = state.autoLockMinutes === 0 ? 'Автоблокировка по бездействию отключена.' : `Автоблокировка: ${state.autoLockMinutes} мин.`;
  } else {
    tab.document.settings.autoLockMinutes = previous;
```

**Таймер закрывает только выбранные по своим настройкам сессии.** — `electron-app/src/main/main.ts:277-289`

Таймер закрывает только выбранные по своим настройкам сессии.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
```

**Извлечение памяти привилегированного процесса исключено; root keys/document являются активами, а сетевые ошибки и lock-файлы недоверенны.** — `SECURITY.md:19-25`

Извлечение памяти привилегированного процесса исключено; root keys/document являются активами, а сетевые ошибки и lock-файлы недоверенны.

```
The product does not claim to protect an unlocked process against malware, keyloggers, an OS administrator, a debugger, process or kernel dumps, physical cameras, or hardware capture. Availability attacks, deletion, and rollback to an older valid copy remain possible; the application detects in-session conflicts but has no trusted monotonic counter.

## Protected assets and trust boundaries

- Master passwords, derived root keys, data keys, record fields, SSH credentials and private keys, folder and record names, vault settings, HIBP consent, and SSH fingerprints are confidential.
- The local Windows account and kernel, Electron/Chromium/Node runtime, Node cryptographic implementation, Windows RNG, destination filesystem, HTTPS PKI, HIBP range endpoint, SSH server, and release-signing environment are explicit trust dependencies.
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
```

**После публикации сессии cleanup может бросить ошибку; rollback освобождает только lock.** — `electron-app/src/main/vault/storage.ts:38-47`

После публикации сессии cleanup может бросить ошибку; rollback освобождает только lock.

```
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
```

#### Validation

Подтверждён незавершённый rollback открытия: addSession предшествует cleanup, catch освобождает lock, но оставляет session/material. Прямой доступ к скрытому случайному ID не установлен; отчёт ограничен остаточным состоянием и влиянием старой сессии на владение lock при повторном открытии.

Validation method: offline static source trace; independent module auditor and parent validation

**addSession вызывается перед cleanupEncryptedTemps; внешний catch освобождает только lock и повторно бросает ошибку.** — `electron-app/src/main/vault/storage.ts:32-48`

addSession вызывается перед cleanupEncryptedTemps; внешний catch освобождает только lock и повторно бросает ошибку.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
    }
```

**readdir/read являются падающими await.** — `electron-app/src/main/vault/storage.ts:237-255`

readdir/read являются падающими await.

```
async function cleanupEncryptedTemps(vaultPath: string): Promise<void> {
  const { readdir } = await import('node:fs/promises');
  const directory = dirname(vaultPath);
  const prefix = `${basename(vaultPath)}.`;
  const entries = (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.startsWith(prefix) && entry.name.endsWith('.tmp')).slice(0, 32);
  for (const entry of entries) {
    const candidate = join(directory, entry.name);
    const handle = await open(candidate, 'r').catch(() => null);
    if (!handle) continue;
    try {
      const magic = Buffer.alloc(8);
      await handle.read(magic, 0, 8, 0);
      if (magic.equals(Buffer.from('PMVAULT1'))) {
        await handle.close();
        await unlink(candidate).catch(() => undefined);
      }
    } finally {
      await handle.close().catch(() => undefined);
    }
```

**Скрытая сессия остаётся в коллекции и позднее закрывается по старому пути lock.** — `electron-app/src/main/vault/storage.ts:152-175`

Скрытая сессия остаётся в коллекции и позднее закрывается по старому пути lock.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }

  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
  }

  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**Освобождение старой сессии удаляет текущее имя lock без проверки идентичности.** — `electron-app/src/main/vault/storage.ts:208-211`

Освобождение старой сессии удаляет текущее имя lock без проверки идентичности.

```
async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
}
```

**Ошибка дешифрования до регистрации сессии вызывает disposeMaterial.** — `electron-app/src/main/vault/codec.ts:81-91`

Ошибка дешифрования до регистрации сессии вызывает disposeMaterial.

```
export async function decodeVault(fileBytes: Buffer, password: string): Promise<DecodedVault> {
  const parsed = parseHeader(fileBytes);
  const rootKey = await deriveRootKey(password, parsed.kdfSalt, parsed.parameters);
  const material = { vaultId: parsed.vaultId, kdfSalt: parsed.kdfSalt, parameters: parsed.parameters, rootKey };
  try {
    return { material, document: decryptDocument(fileBytes, material) };
  } catch (error) {
    disposeMaterial(material);
    if (error instanceof VaultFormatError) throw error;
    throw new VaultAuthenticationError('Wrong password or vault authentication failed.');
  }
```

**disposeMaterial обнуляет rootKey, kdfSalt и vaultId.** — `electron-app/src/main/vault/codec.ts:148-151`

disposeMaterial обнуляет rootKey, kdfSalt и vaultId.

```
export function disposeMaterial(material: VaultMaterial): void {
  material.rootKey.fill(0);
  material.kdfSalt.fill(0);
  material.vaultId.fill(0);
```

**При отказе open вкладка не создаётся и UI сообщает о невозможности открытия.** — `electron-app/src/renderer/src/App.vue:143-154`

При отказе open вкладка не создаётся и UI сообщает о невозможности открытия.

```
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
```

**Настройки действующей вкладки позволяют отключить или изменить её срок авто-блокировки.** — `electron-app/src/renderer/src/App.vue:415-428`

Настройки действующей вкладки позволяют отключить или изменить её срок авто-блокировки.

```
async function saveSettings(): Promise<void> {
  const state = settingsDialog.value;
  const tab = tabs.value.find((item) => item.sessionId === state?.sessionId);
  if (!state || !tab || !Number.isInteger(state.autoLockMinutes) || state.autoLockMinutes < 0 || state.autoLockMinutes > 240) {
    message.value = 'Автоблокировка должна быть целым числом от 0 до 240 минут.';
    return;
  }
  const previous = tab.document.settings.autoLockMinutes;
  tab.document.settings.autoLockMinutes = state.autoLockMinutes;
  if (await persistVault(tab)) {
    settingsDialog.value = null;
    message.value = state.autoLockMinutes === 0 ? 'Автоблокировка по бездействию отключена.' : `Автоблокировка: ${state.autoLockMinutes} мин.`;
  } else {
    tab.document.settings.autoLockMinutes = previous;
```

**Таймер закрывает только выбранные по своим настройкам сессии.** — `electron-app/src/main/main.ts:277-289`

Таймер закрывает только выбранные по своим настройкам сессии.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
```

**Извлечение памяти привилегированного процесса исключено; root keys/document являются активами, а сетевые ошибки и lock-файлы недоверенны.** — `SECURITY.md:19-25`

Извлечение памяти привилегированного процесса исключено; root keys/document являются активами, а сетевые ошибки и lock-файлы недоверенны.

```
The product does not claim to protect an unlocked process against malware, keyloggers, an OS administrator, a debugger, process or kernel dumps, physical cameras, or hardware capture. Availability attacks, deletion, and rollback to an older valid copy remain possible; the application detects in-session conflicts but has no trusted monotonic counter.

## Protected assets and trust boundaries

- Master passwords, derived root keys, data keys, record fields, SSH credentials and private keys, folder and record names, vault settings, HIBP consent, and SSH fingerprints are confidential.
- The local Windows account and kernel, Electron/Chromium/Node runtime, Node cryptographic implementation, Windows RNG, destination filesystem, HTTPS PKI, HIBP range endpoint, SSH server, and release-signing environment are explicit trust dependencies.
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
```

**После публикации сессии cleanup может бросить ошибку; rollback освобождает только lock.** — `electron-app/src/main/vault/storage.ts:38-47`

После публикации сессии cleanup может бросить ошибку; rollback освобождает только lock.

```
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
```

Assertions:
- Проверены порядок open:32-48, addSession:172-175, падающие await cleanupEncryptedTemps:237-256 и close/autoLockSessionIds:152-169. По статическому потоку catch не вызывает ни sessions.delete, ни disposeMaterial для уже зарегистрированной сессии. Сценарий ошибки readdir после успешной аутентификации не исполнялся.
- Ошибка дешифрования в decodeVault очищает material до addSession. Обычные close/closeAll очищают document и material, а global lockAll в конечном счёте также удалит скрытую сессию. Её случайный sessionId не возвращается renderer при ошибке; прямой доступ к данным через неизвестный ID не показан. Для снятия нового lock дополнительно нужны повторное открытие и подходящее время закрытия.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

decodeVault → addSession(S1) → cleanupEncryptedTemps бросает ошибку → releaseLock(L1) и ошибка в UI, без close(S1). Повторный open создаёт S2/L2. S1 остаётся в sessions с прежними настройками; по её таймеру close(S1) вызывает unlink по тому же пути и может снять L2, пока S2 ещё работает.

- **Source:** Участник сетевой папки, способный вызвать ошибку её перечисления или чтения подходящего temp при сохранении доступности корректного сейфа; реальный мастер-пароль вводит пользователь.

- **Sink:** Публикация сессии в глобальной коллекции происходит до завершения потенциально падающего этапа открытия, а rollback обрабатывает только дескриптор lock, не уже переданное владение ключевым материалом и документом.

- **Outcome:** После сообщения о неудачном открытии в main остаются расшифрованный документ и rootKey без видимой вкладки и без принадлежащего им lock. Последующая очистка может нарушить блокировку повторно открытой сессии. Извлечение этих секретов внешним атакующим не доказано; низкая тяжесть учитывает ограничения модели доверенного процесса.

**addSession вызывается перед cleanupEncryptedTemps; внешний catch освобождает только lock и повторно бросает ошибку.** — `electron-app/src/main/vault/storage.ts:32-48`

addSession вызывается перед cleanupEncryptedTemps; внешний catch освобождает только lock и повторно бросает ошибку.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
    }
```

**readdir/read являются падающими await.** — `electron-app/src/main/vault/storage.ts:237-255`

readdir/read являются падающими await.

```
async function cleanupEncryptedTemps(vaultPath: string): Promise<void> {
  const { readdir } = await import('node:fs/promises');
  const directory = dirname(vaultPath);
  const prefix = `${basename(vaultPath)}.`;
  const entries = (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.startsWith(prefix) && entry.name.endsWith('.tmp')).slice(0, 32);
  for (const entry of entries) {
    const candidate = join(directory, entry.name);
    const handle = await open(candidate, 'r').catch(() => null);
    if (!handle) continue;
    try {
      const magic = Buffer.alloc(8);
      await handle.read(magic, 0, 8, 0);
      if (magic.equals(Buffer.from('PMVAULT1'))) {
        await handle.close();
        await unlink(candidate).catch(() => undefined);
      }
    } finally {
      await handle.close().catch(() => undefined);
    }
```

**Скрытая сессия остаётся в коллекции и позднее закрывается по старому пути lock.** — `electron-app/src/main/vault/storage.ts:152-175`

Скрытая сессия остаётся в коллекции и позднее закрывается по старому пути lock.

```
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearDocument(session.document);
    disposeMaterial(session.material);
    session.sourceHash.fill(0);
    await releaseLock(session.lockHandle, session.lockPath);
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.keys()].map((id) => this.close(id)));
  }

  autoLockSessionIds(idleMilliseconds: number): string[] {
    return [...this.sessions.values()]
      .filter((session) => session.document.settings.autoLockMinutes > 0 && idleMilliseconds >= session.document.settings.autoLockMinutes * 60_000)
      .map((session) => session.id);
  }

  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**Освобождение старой сессии удаляет текущее имя lock без проверки идентичности.** — `electron-app/src/main/vault/storage.ts:208-211`

Освобождение старой сессии удаляет текущее имя lock без проверки идентичности.

```
async function releaseLock(handle: FileHandle, lockPath: string): Promise<void> {
  await handle.close().catch(() => undefined);
  await unlink(lockPath).catch(() => undefined);
}
```

**Ошибка дешифрования до регистрации сессии вызывает disposeMaterial.** — `electron-app/src/main/vault/codec.ts:81-91`

Ошибка дешифрования до регистрации сессии вызывает disposeMaterial.

```
export async function decodeVault(fileBytes: Buffer, password: string): Promise<DecodedVault> {
  const parsed = parseHeader(fileBytes);
  const rootKey = await deriveRootKey(password, parsed.kdfSalt, parsed.parameters);
  const material = { vaultId: parsed.vaultId, kdfSalt: parsed.kdfSalt, parameters: parsed.parameters, rootKey };
  try {
    return { material, document: decryptDocument(fileBytes, material) };
  } catch (error) {
    disposeMaterial(material);
    if (error instanceof VaultFormatError) throw error;
    throw new VaultAuthenticationError('Wrong password or vault authentication failed.');
  }
```

**disposeMaterial обнуляет rootKey, kdfSalt и vaultId.** — `electron-app/src/main/vault/codec.ts:148-151`

disposeMaterial обнуляет rootKey, kdfSalt и vaultId.

```
export function disposeMaterial(material: VaultMaterial): void {
  material.rootKey.fill(0);
  material.kdfSalt.fill(0);
  material.vaultId.fill(0);
```

**При отказе open вкладка не создаётся и UI сообщает о невозможности открытия.** — `electron-app/src/renderer/src/App.vue:143-154`

При отказе open вкладка не создаётся и UI сообщает о невозможности открытия.

```
    const snapshot = state.kind === 'open'
      ? await window.passwordManager.openVault(state.path, state.password)
      : await window.passwordManager.createVault(state.path, state.password);
    addTab(snapshot);
    state.password = ''; state.confirmation = '';
    dialogState.value = null;
    openNextQueuedPath();
  } catch {
    dialogError.value = state.kind === 'create'
      ? 'Не удалось создать сейф. Проверьте доступ к выбранной папке, отсутствие файла с таким именем и повторите попытку.'
      : 'Не удалось открыть сейф. Проверьте мастер-пароль, целостность файла и отсутствие активной блокировки.';
  }
```

**Настройки действующей вкладки позволяют отключить или изменить её срок авто-блокировки.** — `electron-app/src/renderer/src/App.vue:415-428`

Настройки действующей вкладки позволяют отключить или изменить её срок авто-блокировки.

```
async function saveSettings(): Promise<void> {
  const state = settingsDialog.value;
  const tab = tabs.value.find((item) => item.sessionId === state?.sessionId);
  if (!state || !tab || !Number.isInteger(state.autoLockMinutes) || state.autoLockMinutes < 0 || state.autoLockMinutes > 240) {
    message.value = 'Автоблокировка должна быть целым числом от 0 до 240 минут.';
    return;
  }
  const previous = tab.document.settings.autoLockMinutes;
  tab.document.settings.autoLockMinutes = state.autoLockMinutes;
  if (await persistVault(tab)) {
    settingsDialog.value = null;
    message.value = state.autoLockMinutes === 0 ? 'Автоблокировка по бездействию отключена.' : `Автоблокировка: ${state.autoLockMinutes} мин.`;
  } else {
    tab.document.settings.autoLockMinutes = previous;
```

**Таймер закрывает только выбранные по своим настройкам сессии.** — `electron-app/src/main/main.ts:277-289`

Таймер закрывает только выбранные по своим настройкам сессии.

```
async function lockIdleVaults(): Promise<void> {
  if (idleLockRunning) return;
  idleLockRunning = true;
  try {
    const sessionIds = store.autoLockSessionIds(Date.now() - lastActivity);
    for (const sessionId of sessionIds) {
      try {
        try { await sshTerminals.closeByVault(sessionId); }
        finally {
          try { await store.close(sessionId); }
          finally { mainWindow?.webContents.send('app:vault-locked', sessionId); }
        }
      } catch { /* Secret-bearing UI is still removed even if lock-file cleanup reports an error. */ }
```

**Извлечение памяти привилегированного процесса исключено; root keys/document являются активами, а сетевые ошибки и lock-файлы недоверенны.** — `SECURITY.md:19-25`

Извлечение памяти привилегированного процесса исключено; root keys/document являются активами, а сетевые ошибки и lock-файлы недоверенны.

```
The product does not claim to protect an unlocked process against malware, keyloggers, an OS administrator, a debugger, process or kernel dumps, physical cameras, or hardware capture. Availability attacks, deletion, and rollback to an older valid copy remain possible; the application detects in-session conflicts but has no trusted monotonic counter.

## Protected assets and trust boundaries

- Master passwords, derived root keys, data keys, record fields, SSH credentials and private keys, folder and record names, vault settings, HIBP consent, and SSH fingerprints are confidential.
- The local Windows account and kernel, Electron/Chromium/Node runtime, Node cryptographic implementation, Windows RNG, destination filesystem, HTTPS PKI, HIBP range endpoint, SSH server, and release-signing environment are explicit trust dependencies.
- `.pmvault` bytes, sibling lock/temp files, command-line paths, IPC messages, HIBP responses, SSH banners/output, renderer messages, filesystem metadata, and all network errors are untrusted inputs.
```

**После публикации сессии cleanup может бросить ошибку; rollback освобождает только lock.** — `electron-app/src/main/vault/storage.ts:38-47`

После публикации сессии cleanup может бросить ошибку; rollback освобождает только lock.

```
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
```

#### Reachability

Аутентификация исходного сейфа успешно завершается. Затем readdir или handle.read в cleanupEncryptedTemps отклоняется. Для вторичного снятия активного lock нужен повторный успешный open того же пути и закрытие скрытой старой сессии раньше новой; например, новая сессия меняет авто-блокировку на 0 или более длительный срок.

- **Attacker:** Участник сетевой папки, способный вызвать ошибку её перечисления или чтения подходящего temp при сохранении доступности корректного сейфа; реальный мастер-пароль вводит пользователь.

- **Outcome:** После сообщения о неудачном открытии в main остаются расшифрованный документ и rootKey без видимой вкладки и без принадлежащего им lock. Последующая очистка может нарушить блокировку повторно открытой сессии. Извлечение этих секретов внешним атакующим не доказано; низкая тяжесть учитывает ограничения модели доверенного процесса.

Limitations:
- Ошибка дешифрования в decodeVault очищает material до addSession. Обычные close/closeAll очищают document и material, а global lockAll в конечном счёте также удалит скрытую сессию. Её случайный sessionId не возвращается renderer при ошибке; прямой доступ к данным через неизвестный ID не показан. Для снятия нового lock дополнительно нужны повторное открытие и подходящее время закрытия.

#### Severity

**Low** — Подтверждён незавершённый rollback открытия: addSession предшествует cleanup, catch освобождает lock, но оставляет session/material. Прямой доступ к скрытому случайному ID не установлен; отчёт ограничен остаточным состоянием и влиянием старой сессии на владение lock при повторном открытии.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Завершать падающую очистку до передачи material/document во владение sessions либо при любой последующей ошибке атомарно удалять зарегистрированную сессию и очищать весь материал. Исключить повторное освобождение lock по чужому текущему имени. Добавить failure-injection тест ошибок readdir/handle.read после аутентификации, повторного открытия и закрытия старой сессии.

<a id="finding-9"></a>

### [9] NFC-нормализация изменяет пароль, проверяемый в HIBP

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Статически прослежены вход, преобразование и потребители. Для синтетического значения с последовательностью U+0065 U+0301 NFC заменяет эту часть на U+00E9 до хеширования в hibp.ts:8-10; App.vue:554 копирует исходную строку, а ssh-terminal.ts:160-164 передаёт исходный profile.password для keyboard-interactive. Это подтверждает несовпадение проверяемого и используемого значения. Приложение, тесты и сетевые запросы не запускались; утверждение о конкретном содержимом HIBP не делается. |
| Category | incorrect-normalization |
| CWE | CWE-20 |
| Affected lines | electron-app/src/main/services/hibp.ts:7-10, electron-app/src/main/services/hibp.ts:7-13, electron-app/src/main/services/hibp.ts:18-27, electron-app/src/renderer/src/App.vue:269-277, electron-app/src/main/main.ts:143-159, electron-app/src/renderer/src/App.vue:283-288, electron-app/src/renderer/src/App.vue:215-225, electron-app/src/renderer/src/App.vue:554-556, electron-app/src/main/services/ssh-terminal.ts:160-164, docs/vault-format.md:5-8, electron-app/src/main/services/hibp.ts:34-37 |

#### Summary

checkPwnedPassword хеширует password.normalize('NFC'), хотя вызывающая сторона передаёт пароль обычной или SSH-записи и продолжает использовать исходное значение. Для пароля в ненормализованной Unicode-форме проверяется другой набор UTF-8 байтов. Если исходная форма присутствует в базе утечек, а нормализованная отсутствует, результат будет notFound для фактически непроверенного пароля.

#### Root Cause

Нормализация, определённая форматом для мастер-пароля, применяется к произвольному паролю внешней записи без соответствующего изменения его потребителей. В результате объект проверки не совпадает с используемым секретом.

**SHA-1 вычисляется после изменения Unicode-последовательности.** — `electron-app/src/main/services/hibp.ts:7-13`

SHA-1 вычисляется после изменения Unicode-последовательности.

```
export async function checkPwnedPassword(password: string): Promise<HibpResult> {
  const normalized = Buffer.from(password.normalize('NFC'), 'utf8');
  let hash = '';
  try { hash = createHash('sha1').update(normalized).digest('hex').toUpperCase(); }
  finally { normalized.fill(0); }
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
```

**Совпадение ищется только с суффиксом преобразованного хеша; отсутствие совпадения становится notFound.** — `electron-app/src/main/services/hibp.ts:18-27`

Совпадение ищется только с суффиксом преобразованного хеша; отсутствие совпадения становится notFound.

```
      for (const rawLine of body.toString('ascii').split(/\r?\n/u)) {
        if (rawLine.length > 64 || rawLine[35] !== ':') continue;
        if (rawLine.slice(0, 35).toUpperCase() !== suffix) continue;
        const countText = rawLine.slice(36);
        if (!/^\d+$/u.test(countText)) return { status: 'failed', occurrenceCount: 0, reason: 'MalformedResponse' };
        const count = Number(countText);
        if (!Number.isSafeInteger(count)) return { status: 'failed', occurrenceCount: 0, reason: 'MalformedResponse' };
        return count === 0 ? { status: 'notFound', occurrenceCount: 0 } : { status: 'compromised', occurrenceCount: count };
      }
      return { status: 'notFound', occurrenceCount: 0 };
```

**В HIBP направляется пароль записи.** — `electron-app/src/renderer/src/App.vue:269-277`

В HIBP направляется пароль записи.

```
async function checkBreach(): Promise<void> {
  const tab = activeTab.value;
  const checkedDraft = draft.value;
  if (!tab || !checkedDraft) return;
  const password = checkedDraft.type === 4 ? checkedDraft.ssh?.password ?? '' : checkedDraft.password;
  if (!password) return;
  busy.value = true;
  try {
    const result = await window.passwordManager.checkPassword(tab.sessionId, password);
```

**IPC проверяет форму и размер запроса и согласие, затем передаёт value.password в модуль без изменения значения.** — `electron-app/src/main/main.ts:143-159`

IPC проверяет форму и размер запроса и согласие, затем передаёт value.password в модуль без изменения значения.

```
  ipcMain.handle('hibp:check', trusted(async (_event, input) => {
    const value = z.object({ sessionId, password: z.string().min(1).max(1_000_000) }).strict().parse(input);
    if (!store.hasHibpConsent(value.sessionId)) {
      const consent = await dialog.showMessageBox(mainWindow!, {
        type: 'question',
        title: 'Проверка пароля в Have I Been Pwned',
        message: 'Разрешить сетевую проверку завершённого пароля?',
        detail: 'Будут отправлены только первые 5 символов SHA-1. Сам пароль и полный хеш не передаются. Согласие сохранится внутри зашифрованного сейфа.',
        buttons: ['Разрешить проверку', 'Отмена'],
        defaultId: 1,
        cancelId: 1,
        noLink: true
      });
      if (consent.response !== 0) return { status: 'failed', occurrenceCount: 0, reason: 'ConsentDeclined' } as const;
      await store.grantHibpConsent(value.sessionId);
    }
    return checkPwnedPassword(value.password);
```

**notFound присваивает исходной записи статус 1 и отображается как отсутствие пароля в HIBP на момент проверки.** — `electron-app/src/renderer/src/App.vue:283-288`

notFound присваивает исходной записи статус 1 и отображается как отсутствие пароля в HIBP на момент проверки.

```
    tab.document.settings.hibpConsent = true;
    checkedDraft.breach.status = result.status === 'compromised' ? 2 : result.status === 'notFound' ? 1 : 3;
    checkedDraft.breach.occurrenceCount = result.occurrenceCount;
    checkedDraft.breach.checkedUtc = new Date().toISOString();
    checkedDraft.breach.compromisedSaveConfirmed = false;
    breachMessage.value = result.status === 'compromised' ? `Этот пароль скомпрометирован — ${result.occurrenceCount.toLocaleString('ru-RU')} совпадений в Have I Been Pwned.` : result.status === 'notFound' ? 'Не найден в HIBP на момент проверки.' : 'Не проверено: сеть или сервис недоступны.';
```

**Подтверждение риска требуется только при статусе 2; сохраняется клон исходной записи без нормализации её пароля.** — `electron-app/src/renderer/src/App.vue:215-225`

Подтверждение риска требуется только при статусе 2; сохраняется клон исходной записи без нормализации её пароля.

```
async function saveDraft(): Promise<boolean> {
  const tab = activeTab.value;
  if (!tab || !draft.value || !draft.value.name.trim()) { message.value = 'Введите имя записи.'; return false; }
  if (draft.value.breach.status === 2 && !draft.value.breach.compromisedSaveConfirmed) {
    message.value = 'Пароль найден в утечках. Отметьте явное подтверждение перед сохранением.'; return false;
  }
  const saved = clone(draft.value);
  saved.name = saved.name.trim(); saved.modifiedUtc = new Date().toISOString();
  const index = tab.document.records.findIndex((record) => record.id === saved.id);
  const previous = index >= 0 ? tab.document.records[index] : null;
  if (index >= 0) tab.document.records[index] = saved; else tab.document.records.push(saved);
```

**Копируется исходное значение draft.password.** — `electron-app/src/renderer/src/App.vue:554-556`

Копируется исходное значение draft.password.

```
              <label>Пароль<div class="field-with-action"><input v-model="draft.password" :type="revealPassword ? 'text' : 'password'" autocomplete="new-password" /><button @click="revealPassword = !revealPassword">{{ revealPassword ? 'Скрыть' : 'Показать' }}</button><button title="Копировать" @click="copy(draft.password)"><FluentIcon name="copy" :size="16" /></button></div></label>
              <div class="breach-actions"><button class="secondary-button compact" @click="checkBreach">Проверить в HIBP</button><span :class="{ danger: draft.breach.status === 2 }">{{ breachMessage }}</span></div>
              <label v-if="draft.breach.status === 2" class="danger-confirm"><input v-model="draft.breach.compromisedSaveConfirmed" type="checkbox" /> Я понимаю риск и всё равно сохраняю пароль</label>
```

**SSH keyboard-interactive использует исходный profile.password без NFC-преобразования.** — `electron-app/src/main/services/ssh-terminal.ts:160-164`

SSH keyboard-interactive использует исходный profile.password без NFC-преобразования.

```
      if (profile.authenticationKind === 0) {
        client.on('keyboard-interactive', (_name, _instructions, _language, prompts, finish) => {
          const isSingleHiddenPasswordPrompt = !keyboardPasswordSent && prompts.length === 1 && prompts[0]?.echo === false;
          if (isSingleHiddenPasswordPrompt) keyboardPasswordSent = true;
          finish(isSingleHiddenPasswordPrompt ? [profile.password] : []);
```

**Требование NFC относится к мастер-паролю криптографического формата.** — `docs/vault-format.md:5-8`

Требование NFC относится к мастер-паролю криптографического формата.

```
## Cryptographic suite 1

- Master-password normalization: Unicode NFC, then strict UTF-8.
- Root derivation: Argon2id v1.3, 64 MiB, 3 iterations, 4 lanes, 16-byte random salt, 32-byte output.
```

**Даже для изменённого значения сетевой запрос содержит только префикс, использует фиксированный HTTPS endpoint и Add-Padding.** — `electron-app/src/main/services/hibp.ts:34-37`

Даже для изменённого значения сетевой запрос содержит только префикс, использует фиксированный HTTPS endpoint и Add-Padding.

```
function requestRange(prefix: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: 'api.pwnedpasswords.com', port: 443, method: 'GET', path: `/range/${prefix}`, headers: { 'Add-Padding': 'true', Accept: 'text/plain', 'User-Agent': 'PasswordManager/1.0' }, timeout: 10_000 }, (response) => {
      if (response.statusCode !== 200 || response.headers.location) { response.resume(); reject(new Error('HIBP rejected.')); return; }
```

#### Validation

Подтверждено несовпадение проверяемого значения с используемым паролем: NFC применяется только в HIBP-пути, тогда как запись/копирование используют исходную строку. Условие присутствия конкретной формы в реальном корпусе HIBP не проверялось, поэтому не заявляется подтверждённый случай утёкшего пользовательского пароля.

Validation method: offline static source trace; independent module auditor and parent validation

**SHA-1 вычисляется после изменения Unicode-последовательности.** — `electron-app/src/main/services/hibp.ts:7-13`

SHA-1 вычисляется после изменения Unicode-последовательности.

```
export async function checkPwnedPassword(password: string): Promise<HibpResult> {
  const normalized = Buffer.from(password.normalize('NFC'), 'utf8');
  let hash = '';
  try { hash = createHash('sha1').update(normalized).digest('hex').toUpperCase(); }
  finally { normalized.fill(0); }
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
```

**Совпадение ищется только с суффиксом преобразованного хеша; отсутствие совпадения становится notFound.** — `electron-app/src/main/services/hibp.ts:18-27`

Совпадение ищется только с суффиксом преобразованного хеша; отсутствие совпадения становится notFound.

```
      for (const rawLine of body.toString('ascii').split(/\r?\n/u)) {
        if (rawLine.length > 64 || rawLine[35] !== ':') continue;
        if (rawLine.slice(0, 35).toUpperCase() !== suffix) continue;
        const countText = rawLine.slice(36);
        if (!/^\d+$/u.test(countText)) return { status: 'failed', occurrenceCount: 0, reason: 'MalformedResponse' };
        const count = Number(countText);
        if (!Number.isSafeInteger(count)) return { status: 'failed', occurrenceCount: 0, reason: 'MalformedResponse' };
        return count === 0 ? { status: 'notFound', occurrenceCount: 0 } : { status: 'compromised', occurrenceCount: count };
      }
      return { status: 'notFound', occurrenceCount: 0 };
```

**В HIBP направляется пароль записи.** — `electron-app/src/renderer/src/App.vue:269-277`

В HIBP направляется пароль записи.

```
async function checkBreach(): Promise<void> {
  const tab = activeTab.value;
  const checkedDraft = draft.value;
  if (!tab || !checkedDraft) return;
  const password = checkedDraft.type === 4 ? checkedDraft.ssh?.password ?? '' : checkedDraft.password;
  if (!password) return;
  busy.value = true;
  try {
    const result = await window.passwordManager.checkPassword(tab.sessionId, password);
```

**IPC проверяет форму и размер запроса и согласие, затем передаёт value.password в модуль без изменения значения.** — `electron-app/src/main/main.ts:143-159`

IPC проверяет форму и размер запроса и согласие, затем передаёт value.password в модуль без изменения значения.

```
  ipcMain.handle('hibp:check', trusted(async (_event, input) => {
    const value = z.object({ sessionId, password: z.string().min(1).max(1_000_000) }).strict().parse(input);
    if (!store.hasHibpConsent(value.sessionId)) {
      const consent = await dialog.showMessageBox(mainWindow!, {
        type: 'question',
        title: 'Проверка пароля в Have I Been Pwned',
        message: 'Разрешить сетевую проверку завершённого пароля?',
        detail: 'Будут отправлены только первые 5 символов SHA-1. Сам пароль и полный хеш не передаются. Согласие сохранится внутри зашифрованного сейфа.',
        buttons: ['Разрешить проверку', 'Отмена'],
        defaultId: 1,
        cancelId: 1,
        noLink: true
      });
      if (consent.response !== 0) return { status: 'failed', occurrenceCount: 0, reason: 'ConsentDeclined' } as const;
      await store.grantHibpConsent(value.sessionId);
    }
    return checkPwnedPassword(value.password);
```

**notFound присваивает исходной записи статус 1 и отображается как отсутствие пароля в HIBP на момент проверки.** — `electron-app/src/renderer/src/App.vue:283-288`

notFound присваивает исходной записи статус 1 и отображается как отсутствие пароля в HIBP на момент проверки.

```
    tab.document.settings.hibpConsent = true;
    checkedDraft.breach.status = result.status === 'compromised' ? 2 : result.status === 'notFound' ? 1 : 3;
    checkedDraft.breach.occurrenceCount = result.occurrenceCount;
    checkedDraft.breach.checkedUtc = new Date().toISOString();
    checkedDraft.breach.compromisedSaveConfirmed = false;
    breachMessage.value = result.status === 'compromised' ? `Этот пароль скомпрометирован — ${result.occurrenceCount.toLocaleString('ru-RU')} совпадений в Have I Been Pwned.` : result.status === 'notFound' ? 'Не найден в HIBP на момент проверки.' : 'Не проверено: сеть или сервис недоступны.';
```

**Подтверждение риска требуется только при статусе 2; сохраняется клон исходной записи без нормализации её пароля.** — `electron-app/src/renderer/src/App.vue:215-225`

Подтверждение риска требуется только при статусе 2; сохраняется клон исходной записи без нормализации её пароля.

```
async function saveDraft(): Promise<boolean> {
  const tab = activeTab.value;
  if (!tab || !draft.value || !draft.value.name.trim()) { message.value = 'Введите имя записи.'; return false; }
  if (draft.value.breach.status === 2 && !draft.value.breach.compromisedSaveConfirmed) {
    message.value = 'Пароль найден в утечках. Отметьте явное подтверждение перед сохранением.'; return false;
  }
  const saved = clone(draft.value);
  saved.name = saved.name.trim(); saved.modifiedUtc = new Date().toISOString();
  const index = tab.document.records.findIndex((record) => record.id === saved.id);
  const previous = index >= 0 ? tab.document.records[index] : null;
  if (index >= 0) tab.document.records[index] = saved; else tab.document.records.push(saved);
```

**Копируется исходное значение draft.password.** — `electron-app/src/renderer/src/App.vue:554-556`

Копируется исходное значение draft.password.

```
              <label>Пароль<div class="field-with-action"><input v-model="draft.password" :type="revealPassword ? 'text' : 'password'" autocomplete="new-password" /><button @click="revealPassword = !revealPassword">{{ revealPassword ? 'Скрыть' : 'Показать' }}</button><button title="Копировать" @click="copy(draft.password)"><FluentIcon name="copy" :size="16" /></button></div></label>
              <div class="breach-actions"><button class="secondary-button compact" @click="checkBreach">Проверить в HIBP</button><span :class="{ danger: draft.breach.status === 2 }">{{ breachMessage }}</span></div>
              <label v-if="draft.breach.status === 2" class="danger-confirm"><input v-model="draft.breach.compromisedSaveConfirmed" type="checkbox" /> Я понимаю риск и всё равно сохраняю пароль</label>
```

**SSH keyboard-interactive использует исходный profile.password без NFC-преобразования.** — `electron-app/src/main/services/ssh-terminal.ts:160-164`

SSH keyboard-interactive использует исходный profile.password без NFC-преобразования.

```
      if (profile.authenticationKind === 0) {
        client.on('keyboard-interactive', (_name, _instructions, _language, prompts, finish) => {
          const isSingleHiddenPasswordPrompt = !keyboardPasswordSent && prompts.length === 1 && prompts[0]?.echo === false;
          if (isSingleHiddenPasswordPrompt) keyboardPasswordSent = true;
          finish(isSingleHiddenPasswordPrompt ? [profile.password] : []);
```

**Требование NFC относится к мастер-паролю криптографического формата.** — `docs/vault-format.md:5-8`

Требование NFC относится к мастер-паролю криптографического формата.

```
## Cryptographic suite 1

- Master-password normalization: Unicode NFC, then strict UTF-8.
- Root derivation: Argon2id v1.3, 64 MiB, 3 iterations, 4 lanes, 16-byte random salt, 32-byte output.
```

**Даже для изменённого значения сетевой запрос содержит только префикс, использует фиксированный HTTPS endpoint и Add-Padding.** — `electron-app/src/main/services/hibp.ts:34-37`

Даже для изменённого значения сетевой запрос содержит только префикс, использует фиксированный HTTPS endpoint и Add-Padding.

```
function requestRange(prefix: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: 'api.pwnedpasswords.com', port: 443, method: 'GET', path: `/range/${prefix}`, headers: { 'Add-Padding': 'true', Accept: 'text/plain', 'User-Agent': 'PasswordManager/1.0' }, timeout: 10_000 }, (response) => {
      if (response.statusCode !== 200 || response.headers.location) { response.resume(); reject(new Error('HIBP rejected.')); return; }
```

Assertions:
- Статически прослежены вход, преобразование и потребители. Для синтетического значения с последовательностью U+0065 U+0301 NFC заменяет эту часть на U+00E9 до хеширования в hibp.ts:8-10; App.vue:554 копирует исходную строку, а ssh-terminal.ts:160-164 передаёт исходный profile.password для keyboard-interactive. Это подтверждает несовпадение проверяемого и используемого значения. Приложение, тесты и сетевые запросы не запускались; утверждение о конкретном содержимом HIBP не делается.
- ASCII и уже NFC-нормализованные пароли не меняются. docs/vault-format.md:7 действительно требует NFC для мастер-пароля, однако текущий вызывающий путь App.vue:269-277 передаёт пароли записей, не мастер-пароль. UI формулирует результат как отсутствие в HIBP на момент проверки, а не абсолютную безопасность. HTTPS-запрос по-прежнему содержит только пятисимвольный префикс. Реальная распространённость затронутых хешей не установлена.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

App.vue:269-277 берёт checkedDraft.password либо checkedDraft.ssh.password и передаёт значение через IPC. main.ts:143-159 после проверки параметров и согласия вызывает checkPwnedPassword(value.password). hibp.ts:8-13 нормализует значение перед SHA-1 и делит уже изменённый хеш на prefix/suffix; hibp.ts:18-27 ищет только этот suffix. App.vue:284-288 записывает отрицательный результат в состояние исходной записи, а App.vue:554 копирует исходный draft.password.

- **Source:** Сторона, уже располагающая утёкшим исходным паролем внешнего аккаунта, может продолжать его использовать, пока пользователь получает отрицательный результат проверки другой формы. Контроль HIBP, TLS или процесса приложения не требуется; это пропуск предупреждения, а не новая возможность узнать пароль из сейфа.

- **Sink:** Нормализация, определённая форматом для мастер-пароля, применяется к произвольному паролю внешней записи без соответствующего изменения его потребителей. В результате объект проверки не совпадает с используемым секретом.

- **Outcome:** Пользователь может получить «Не найден в HIBP» для уже утёкшего пароля в ненормализованной форме. При notFound не включается предупреждение и требование подтверждения сохранения, зависящее от breach.status === 2. Влияние ограничено достоверностью дополнительной проверки; обход шифрования или новая утечка через сеть не установлены.

**SHA-1 вычисляется после изменения Unicode-последовательности.** — `electron-app/src/main/services/hibp.ts:7-13`

SHA-1 вычисляется после изменения Unicode-последовательности.

```
export async function checkPwnedPassword(password: string): Promise<HibpResult> {
  const normalized = Buffer.from(password.normalize('NFC'), 'utf8');
  let hash = '';
  try { hash = createHash('sha1').update(normalized).digest('hex').toUpperCase(); }
  finally { normalized.fill(0); }
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
```

**Совпадение ищется только с суффиксом преобразованного хеша; отсутствие совпадения становится notFound.** — `electron-app/src/main/services/hibp.ts:18-27`

Совпадение ищется только с суффиксом преобразованного хеша; отсутствие совпадения становится notFound.

```
      for (const rawLine of body.toString('ascii').split(/\r?\n/u)) {
        if (rawLine.length > 64 || rawLine[35] !== ':') continue;
        if (rawLine.slice(0, 35).toUpperCase() !== suffix) continue;
        const countText = rawLine.slice(36);
        if (!/^\d+$/u.test(countText)) return { status: 'failed', occurrenceCount: 0, reason: 'MalformedResponse' };
        const count = Number(countText);
        if (!Number.isSafeInteger(count)) return { status: 'failed', occurrenceCount: 0, reason: 'MalformedResponse' };
        return count === 0 ? { status: 'notFound', occurrenceCount: 0 } : { status: 'compromised', occurrenceCount: count };
      }
      return { status: 'notFound', occurrenceCount: 0 };
```

**В HIBP направляется пароль записи.** — `electron-app/src/renderer/src/App.vue:269-277`

В HIBP направляется пароль записи.

```
async function checkBreach(): Promise<void> {
  const tab = activeTab.value;
  const checkedDraft = draft.value;
  if (!tab || !checkedDraft) return;
  const password = checkedDraft.type === 4 ? checkedDraft.ssh?.password ?? '' : checkedDraft.password;
  if (!password) return;
  busy.value = true;
  try {
    const result = await window.passwordManager.checkPassword(tab.sessionId, password);
```

**IPC проверяет форму и размер запроса и согласие, затем передаёт value.password в модуль без изменения значения.** — `electron-app/src/main/main.ts:143-159`

IPC проверяет форму и размер запроса и согласие, затем передаёт value.password в модуль без изменения значения.

```
  ipcMain.handle('hibp:check', trusted(async (_event, input) => {
    const value = z.object({ sessionId, password: z.string().min(1).max(1_000_000) }).strict().parse(input);
    if (!store.hasHibpConsent(value.sessionId)) {
      const consent = await dialog.showMessageBox(mainWindow!, {
        type: 'question',
        title: 'Проверка пароля в Have I Been Pwned',
        message: 'Разрешить сетевую проверку завершённого пароля?',
        detail: 'Будут отправлены только первые 5 символов SHA-1. Сам пароль и полный хеш не передаются. Согласие сохранится внутри зашифрованного сейфа.',
        buttons: ['Разрешить проверку', 'Отмена'],
        defaultId: 1,
        cancelId: 1,
        noLink: true
      });
      if (consent.response !== 0) return { status: 'failed', occurrenceCount: 0, reason: 'ConsentDeclined' } as const;
      await store.grantHibpConsent(value.sessionId);
    }
    return checkPwnedPassword(value.password);
```

**notFound присваивает исходной записи статус 1 и отображается как отсутствие пароля в HIBP на момент проверки.** — `electron-app/src/renderer/src/App.vue:283-288`

notFound присваивает исходной записи статус 1 и отображается как отсутствие пароля в HIBP на момент проверки.

```
    tab.document.settings.hibpConsent = true;
    checkedDraft.breach.status = result.status === 'compromised' ? 2 : result.status === 'notFound' ? 1 : 3;
    checkedDraft.breach.occurrenceCount = result.occurrenceCount;
    checkedDraft.breach.checkedUtc = new Date().toISOString();
    checkedDraft.breach.compromisedSaveConfirmed = false;
    breachMessage.value = result.status === 'compromised' ? `Этот пароль скомпрометирован — ${result.occurrenceCount.toLocaleString('ru-RU')} совпадений в Have I Been Pwned.` : result.status === 'notFound' ? 'Не найден в HIBP на момент проверки.' : 'Не проверено: сеть или сервис недоступны.';
```

**Подтверждение риска требуется только при статусе 2; сохраняется клон исходной записи без нормализации её пароля.** — `electron-app/src/renderer/src/App.vue:215-225`

Подтверждение риска требуется только при статусе 2; сохраняется клон исходной записи без нормализации её пароля.

```
async function saveDraft(): Promise<boolean> {
  const tab = activeTab.value;
  if (!tab || !draft.value || !draft.value.name.trim()) { message.value = 'Введите имя записи.'; return false; }
  if (draft.value.breach.status === 2 && !draft.value.breach.compromisedSaveConfirmed) {
    message.value = 'Пароль найден в утечках. Отметьте явное подтверждение перед сохранением.'; return false;
  }
  const saved = clone(draft.value);
  saved.name = saved.name.trim(); saved.modifiedUtc = new Date().toISOString();
  const index = tab.document.records.findIndex((record) => record.id === saved.id);
  const previous = index >= 0 ? tab.document.records[index] : null;
  if (index >= 0) tab.document.records[index] = saved; else tab.document.records.push(saved);
```

**Копируется исходное значение draft.password.** — `electron-app/src/renderer/src/App.vue:554-556`

Копируется исходное значение draft.password.

```
              <label>Пароль<div class="field-with-action"><input v-model="draft.password" :type="revealPassword ? 'text' : 'password'" autocomplete="new-password" /><button @click="revealPassword = !revealPassword">{{ revealPassword ? 'Скрыть' : 'Показать' }}</button><button title="Копировать" @click="copy(draft.password)"><FluentIcon name="copy" :size="16" /></button></div></label>
              <div class="breach-actions"><button class="secondary-button compact" @click="checkBreach">Проверить в HIBP</button><span :class="{ danger: draft.breach.status === 2 }">{{ breachMessage }}</span></div>
              <label v-if="draft.breach.status === 2" class="danger-confirm"><input v-model="draft.breach.compromisedSaveConfirmed" type="checkbox" /> Я понимаю риск и всё равно сохраняю пароль</label>
```

**SSH keyboard-interactive использует исходный profile.password без NFC-преобразования.** — `electron-app/src/main/services/ssh-terminal.ts:160-164`

SSH keyboard-interactive использует исходный profile.password без NFC-преобразования.

```
      if (profile.authenticationKind === 0) {
        client.on('keyboard-interactive', (_name, _instructions, _language, prompts, finish) => {
          const isSingleHiddenPasswordPrompt = !keyboardPasswordSent && prompts.length === 1 && prompts[0]?.echo === false;
          if (isSingleHiddenPasswordPrompt) keyboardPasswordSent = true;
          finish(isSingleHiddenPasswordPrompt ? [profile.password] : []);
```

**Требование NFC относится к мастер-паролю криптографического формата.** — `docs/vault-format.md:5-8`

Требование NFC относится к мастер-паролю криптографического формата.

```
## Cryptographic suite 1

- Master-password normalization: Unicode NFC, then strict UTF-8.
- Root derivation: Argon2id v1.3, 64 MiB, 3 iterations, 4 lanes, 16-byte random salt, 32-byte output.
```

**Даже для изменённого значения сетевой запрос содержит только префикс, использует фиксированный HTTPS endpoint и Add-Padding.** — `electron-app/src/main/services/hibp.ts:34-37`

Даже для изменённого значения сетевой запрос содержит только префикс, использует фиксированный HTTPS endpoint и Add-Padding.

```
function requestRange(prefix: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: 'api.pwnedpasswords.com', port: 443, method: 'GET', path: `/range/${prefix}`, headers: { 'Add-Padding': 'true', Accept: 'text/plain', 'User-Agent': 'PasswordManager/1.0' }, timeout: 10_000 }, (response) => {
      if (response.statusCode !== 200 || response.headers.location) { response.resume(); reject(new Error('HIBP rejected.')); return; }
```

#### Reachability

Пользователь хранит и явно проверяет пароль, для которого NFC меняет последовательность символов; внешний сервис использует исходную последовательность. Для ложного отрицательного результата дополнительно требуется наличие исходного хеша в HIBP при отсутствии хеша NFC-версии. Наличие такой записи в реальной базе в этом офлайн-аудите не проверялось.

- **Attacker:** Сторона, уже располагающая утёкшим исходным паролем внешнего аккаунта, может продолжать его использовать, пока пользователь получает отрицательный результат проверки другой формы. Контроль HIBP, TLS или процесса приложения не требуется; это пропуск предупреждения, а не новая возможность узнать пароль из сейфа.

- **Outcome:** Пользователь может получить «Не найден в HIBP» для уже утёкшего пароля в ненормализованной форме. При notFound не включается предупреждение и требование подтверждения сохранения, зависящее от breach.status === 2. Влияние ограничено достоверностью дополнительной проверки; обход шифрования или новая утечка через сеть не установлены.

Limitations:
- ASCII и уже NFC-нормализованные пароли не меняются. docs/vault-format.md:7 действительно требует NFC для мастер-пароля, однако текущий вызывающий путь App.vue:269-277 передаёт пароли записей, не мастер-пароль. UI формулирует результат как отсутствие в HIBP на момент проверки, а не абсолютную безопасность. HTTPS-запрос по-прежнему содержит только пятисимвольный префикс. Реальная распространённость затронутых хешей не установлена.

#### Severity

**Low** — Подтверждено несовпадение проверяемого значения с используемым паролем: NFC применяется только в HIBP-пути, тогда как запись/копирование используют исходную строку. Условие присутствия конкретной формы в реальном корпусе HIBP не проверялось, поэтому не заявляется подтверждённый случай утёкшего пользовательского пароля.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

В checkPwnedPassword вычислять SHA-1 от точных UTF-8 байтов переданного пароля записи без NFC-нормализации. Нормализацию мастер-пароля оставить в его собственном пути. Добавить изолированный тест с явно синтетическим паролем в decomposed Unicode-форме и подставленным range-ответом, подтверждающий поиск исходного хеша.

<a id="finding-10"></a>

### [10] Непроверенная структура JSON обходит лимиты документа и обрабатывается в main до проверки общего размера

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | medium |
| Confidence rationale | Статически прослежены оба входа и все вызовы validateDocument/encodeVault/decodeVault. Контрпример структуры: обычные обязательные поля VaultDocument плюс дополнительный ключ с массивами произвольной глубины; ни одна проверка validateDocument не читает этот ключ, а JSON.parse, structuredClone и JSON.stringify обрабатывают его. В storage.open addSession предшествует потенциально ошибочному snapshot, а catch не вызывает close/disposeMaterial. Эксплуатационный файл, приложение и тесты не запускались; фактический crash/OOM не утверждается как воспроизведённый. |
| Category | resource-exhaustion |
| CWE | CWE-400 |
| Affected lines | electron-app/src/main/vault/codec.ts:271-291, electron-app/src/main/vault/codec.ts:198-204, electron-app/src/main/vault/codec.ts:271-291, electron-app/src/main/vault/codec.ts:293-324, electron-app/src/main/vault/codec.ts:326-336, electron-app/src/main/vault/codec.ts:106-113, electron-app/src/main/main.ts:135-141, electron-app/src/main/vault/storage.ts:85-92, electron-app/src/main/vault/storage.ts:32-47, electron-app/src/main/vault/storage.ts:172-175, electron-app/src/main/vault/storage.ts:263-265, electron-app/src/main/vault/codec.ts:154-168, SECURITY.md:42-46, AGENTS.md:27-30, electron-app/src/main/vault/codec.ts:106-111 |

#### Summary

validateDocument проверяет только известные поля, но не запрещает дополнительные свойства и не ограничивает их глубину или число узлов. При открытии JSON.parse создаёт весь граф объектов до этой проверки; при сохранении JSON.stringify обходит весь документ до проверки размера 64 MiB. Таким образом, небольшой корректный VaultDocument может содержать дополнительное поле с крайне глубокой или разветвлённой структурой, которое минует установленные ограничения и заставит main выполнять дорогое выделение памяти, клонирование или сериализацию.

#### Root Cause

Лимит 64 MiB применяется к строке JSON после выделения памяти при сохранении; при чтении он ограничивает только число байтов до JSON.parse. Нет предварительного бюджета глубины, числа JSON-узлов и совокупного размера, а проверка схемы не отклоняет неизвестные поля. Ограничение глубины 64 распространяется только на связи parentId в известном массиве folders, а не на фактический граф входного документа.

**JSON.parse предшествует проверке структуры.** — `electron-app/src/main/vault/codec.ts:198-204`

JSON.parse предшествует проверке структуры.

```
    plaintext = Buffer.concat([payloadCipher.update(fileBytes.subarray(HEADER_SIZE)), payloadCipher.final()]);
    const jsonLength = plaintext.readInt32LE(0);
    if (jsonLength < 2 || jsonLength > MAXIMUM_JSON_SIZE || jsonLength > plaintext.length - 4) throw new VaultFormatError('Invalid authenticated JSON length.');
    const json = new TextDecoder('utf-8', { fatal: true }).decode(plaintext.subarray(4, 4 + jsonLength));
    const document = JSON.parse(json) as VaultDocument;
    validateDocument(document);
    return document;
```

**Неизвестные поля и общий граф не ограничены.** — `electron-app/src/main/vault/codec.ts:271-291`

Неизвестные поля и общий граф не ограничены.

```
export function validateDocument(document: VaultDocument): void {
  if (!document || typeof document !== 'object' || !isUuid(document.rootFolderId) || !Array.isArray(document.folders) || !Array.isArray(document.records) || document.folders.length < 1 || document.folders.length > 100_000 || document.records.length > 1_000_000) {
    throw new VaultFormatError('Invalid vault document.');
  }
  validateUtc(document.modifiedUtc, false);
  const folders = new Map<string, VaultFolder>();
  for (const folder of document.folders) {
    validateName(folder.name);
    if (!isUuid(folder.id) || folders.has(folder.id) || (folder.parentId !== null && !isUuid(folder.parentId)) || typeof folder.isDeleted !== 'boolean') throw new VaultFormatError('Invalid folder identifier.');
    validateUtc(folder.deletedUtc, true);
    folders.set(folder.id, folder);
  }
  const root = folders.get(document.rootFolderId);
  if (!root || root.parentId !== null) throw new VaultFormatError('Invalid root folder.');
  for (const folder of document.folders) validateAncestry(folder, folders);
  const records = new Set<string>();
  for (const record of document.records) validateRecord(record, records, folders);
  if (!document.settings || typeof document.settings !== 'object' || typeof document.settings.hibpConsent !== 'boolean' || !Number.isInteger(document.settings.clipboardClearSeconds) || document.settings.clipboardClearSeconds < 5 || document.settings.clipboardClearSeconds > 600 || !Number.isInteger(document.settings.autoLockMinutes) || document.settings.autoLockMinutes < 0 || document.settings.autoLockMinutes > 240 || !['', 'ru', 'en'].includes(document.settings.sessionLanguage)) {
    throw new VaultFormatError('Invalid vault settings.');
  }
}
```

**Вложенные записи, customFields, breach и ssh проверяются по отдельным полям без запрета дополнительных ключей и общего бюджета документа.** — `electron-app/src/main/vault/codec.ts:293-324`

Вложенные записи, customFields, breach и ssh проверяются по отдельным полям без запрета дополнительных ключей и общего бюджета документа.

```
function validateRecord(record: VaultRecord, records: Set<string>, folders: Map<string, VaultFolder>): void {
  if (!isUuid(record.id) || records.has(record.id) || !folders.has(record.folderId) || !Number.isInteger(record.type) || record.type < 0 || record.type > 4) throw new VaultFormatError('Invalid record.');
  records.add(record.id);
  validateName(record.name);
  for (const value of [record.userName, record.email, record.password, record.url, record.notes]) validateField(value);
  if (typeof record.isDeleted !== 'boolean') throw new VaultFormatError('Invalid record state.');
  validateUtc(record.deletedUtc, true);
  validateUtc(record.modifiedUtc, false);
  if (!Array.isArray(record.customFields) || record.customFields.length > 256) throw new VaultFormatError('Too many custom fields.');
  for (const field of record.customFields) {
    validateName(field.name);
    validateField(field.value);
    if (typeof field.isSecret !== 'boolean') throw new VaultFormatError('Invalid custom field.');
  }
  if (!record.breach || !Number.isInteger(record.breach.status) || record.breach.status < 0 || record.breach.status > 3 || !Number.isSafeInteger(record.breach.occurrenceCount) || record.breach.occurrenceCount < 0 || typeof record.breach.compromisedSaveConfirmed !== 'boolean') {
    throw new VaultFormatError('Invalid breach-check state.');
  }
  validateUtc(record.breach.checkedUtc, true);
  if ((record.type === 4) !== (record.ssh !== null)) throw new VaultFormatError('SSH profile does not match record type.');
  if (record.ssh) {
    if (!Object.hasOwn(record.ssh, 'allowLegacyAlgorithms')) record.ssh.allowLegacyAlgorithms = false;
    if (typeof record.ssh.host !== 'string' || record.ssh.host.trim().length === 0 || record.ssh.host.length > 253 || /[\u0000-\u001F\u007F]/u.test(record.ssh.host) ||
        typeof record.ssh.userName !== 'string' || record.ssh.userName.length < 1 || record.ssh.userName.length > 512 || /[\u0000-\u001F\u007F]/u.test(record.ssh.userName) ||
        typeof record.ssh.password !== 'string' || record.ssh.password.length > 1_000_000 ||
        typeof record.ssh.privateKeyPem !== 'string' || record.ssh.privateKeyPem.length > 4 * 1024 * 1024 ||
        typeof record.ssh.privateKeyPassphrase !== 'string' || record.ssh.privateKeyPassphrase.length > 1_000_000 ||
        !Number.isInteger(record.ssh.port) || record.ssh.port < 1 || record.ssh.port > 65535 ||
        (record.ssh.authenticationKind !== 0 && record.ssh.authenticationKind !== 1) ||
        typeof record.ssh.allowLegacyAlgorithms !== 'boolean' ||
        (record.ssh.hostKeySha256 !== '' && !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(record.ssh.hostKeySha256))) throw new VaultFormatError('Invalid SSH profile.');
  }
}
```

**Предел 64 относится только к цепочке parentId папок, а не к синтаксической глубине JSON.** — `electron-app/src/main/vault/codec.ts:326-336`

Предел 64 относится только к цепочке parentId папок, а не к синтаксической глубине JSON.

```
function validateAncestry(folder: VaultFolder, folders: Map<string, VaultFolder>): void {
  const visited = new Set<string>();
  let current = folder;
  let depth = 0;
  while (current.parentId !== null) {
    if (visited.has(current.id) || ++depth > 64) throw new VaultFormatError('Folder cycle or excessive depth.');
    visited.add(current.id);
    const parent = folders.get(current.parentId);
    if (!parent) throw new VaultFormatError('Missing parent folder.');
    current = parent;
  }
```

**JSON.stringify и Buffer.from выполняются до проверки MAXIMUM_JSON_SIZE и выделения padded plaintext.** — `electron-app/src/main/vault/codec.ts:106-113`

JSON.stringify и Buffer.from выполняются до проверки MAXIMUM_JSON_SIZE и выделения padded plaintext.

```
export function encodeVault(document: VaultDocument, material: VaultMaterial): Buffer {
  validateDocument(document);
  const json = Buffer.from(JSON.stringify(document), 'utf8');
  if (json.length > MAXIMUM_JSON_SIZE) throw new VaultFormatError('Vault JSON is too large.');
  const plaintextLength = Math.max(4096, Math.ceil((json.length + 4) / 4096) * 4096);
  if (HEADER_SIZE + plaintextLength > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Vault is too large.');

  const plaintext = Buffer.allocUnsafe(plaintextLength);
```

**IPC открывает vault и передаёт document сохранения в VaultStore после проверки sessionId без самостоятельного структурного бюджета.** — `electron-app/src/main/main.ts:135-141`

IPC открывает vault и передаёт document сохранения в VaultStore после проверки sessionId без самостоятельного структурного бюджета.

```
  ipcMain.handle('vault:open', trusted(async (_event, input) => { const value = credentials.parse(input); return store.open(value.path, value.password); }));
  ipcMain.handle('vault:create', trusted(async (_event, input) => { const value = credentials.parse(input); return store.create(value.path, value.password); }));
  ipcMain.handle('vault:save', trusted(async (_event, input: unknown) => {
    if (!input || typeof input !== 'object' || !('sessionId' in input) || !('document' in input)) throw new Error('Invalid save request.');
    const id = sessionId.parse(input.sessionId);
    await store.save(id, input.document as never);
  }));
```

**Входной документ целиком клонируется и кодируется.** — `electron-app/src/main/vault/storage.ts:85-92`

Входной документ целиком клонируется и кодируется.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
```

**open добавляет сессию до snapshot; catch освобождает lock и повторно выбрасывает ошибку без удаления добавленной сессии.** — `electron-app/src/main/vault/storage.ts:32-47`

open добавляет сессию до snapshot; catch освобождает lock и повторно выбрасывает ошибку без удаления добавленной сессии.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
```

**addSession сохраняет material и полный document в долгоживущей Map.** — `electron-app/src/main/vault/storage.ts:172-175`

addSession сохраняет material и полный document в долгоживущей Map.

```
  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**snapshot клонирует весь session.document, включая неизвестные поля.** — `electron-app/src/main/vault/storage.ts:263-265`

snapshot клонирует весь session.document, включая неизвестные поля.

```
function snapshot(session: VaultSession): VaultSnapshot {
  return { sessionId: session.id, path: session.path, displayName: basename(session.path, '.pmvault'), document: structuredClone(session.document) };
}
```

**До KDF действуют предел файла 256 MiB, фиксированный заголовок и точное соответствие длины ciphertext; это ограничивает файловый вход, но не число создаваемых JSON-объектов.** — `electron-app/src/main/vault/codec.ts:154-168`

До KDF действуют предел файла 256 MiB, фиксированный заголовок и точное соответствие длины ciphertext; это ограничивает файловый вход, но не число создаваемых JSON-объектов.

```
function parseHeader(fileBytes: Buffer): { vaultId: Buffer; kdfSalt: Buffer; parameters: KdfParameters; ciphertextLength: number } {
  if (fileBytes.length < HEADER_SIZE || fileBytes.length > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Invalid vault size.');
  const header = fileBytes.subarray(0, HEADER_SIZE);
  if (!header.subarray(0, 8).equals(MAGIC)) throw new VaultFormatError('Not a PasswordManager vault.');
  if (header.readUInt16LE(OFFSETS.version) !== 1 || header.readUInt16LE(OFFSETS.suite) !== 1 || header.readInt32LE(OFFSETS.headerLength) !== HEADER_SIZE) {
    throw new VaultFormatError('Unsupported vault version or cipher suite.');
  }
  const digest = createHash('sha256').update(header.subarray(0, OFFSETS.headerDigest)).digest();
  if (!timingSafeEqual(digest, header.subarray(OFFSETS.headerDigest, HEADER_SIZE))) throw new VaultFormatError('Corrupt vault header.');
  const ciphertextLengthBig = header.readBigInt64LE(OFFSETS.ciphertextLength);
  if (ciphertextLengthBig < 4096n || ciphertextLengthBig > BigInt(MAXIMUM_FILE_SIZE - HEADER_SIZE) || ciphertextLengthBig % 4096n !== 0n) {
    throw new VaultFormatError('Invalid ciphertext length.');
  }
  const ciphertextLength = Number(ciphertextLengthBig);
  if (ciphertextLength !== fileBytes.length - HEADER_SIZE) throw new VaultFormatError('Truncated or trailing vault bytes.');
```

**Политика явно включает parser memory exhaustion внутри поддерживаемого file cap в reportable issues и исключает обычную авторизованную активность пользователя.** — `SECURITY.md:42-46`

Политика явно включает parser memory exhaustion внутри поддерживаемого file cap в reportable issues и исключает обычную авторизованную активность пользователя.

```
## Reportable issues

Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Renderer объявлен недоверенным; main обязан проверять каждый IPC payload.** — `AGENTS.md:27-30`

Renderer объявлен недоверенным; main обязан проверять каждый IPC payload.

```
- The renderer is untrusted presentation code: keep `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, `webviewTag: false`, and `webSecurity: true`.
- Serve packaged UI only through the `pmapp://local` protocol with a restrictive CSP. Deny permissions, navigation, popups, downloads, external content, DevTools in packaged builds, and arbitrary IPC.
- Expose only narrow frozen preload methods. Validate the sender frame and every IPC payload in the main process; never expose `ipcRenderer`, filesystem, shell, crypto keys, or network primitives to Vue.
- Do not use `v-html`, dynamic code execution, remote scripts/styles, frontend persistence, or secret-bearing URLs.
```

**Проверка размера следует за JSON.stringify и Buffer.from.** — `electron-app/src/main/vault/codec.ts:106-111`

Проверка размера следует за JSON.stringify и Buffer.from.

```
export function encodeVault(document: VaultDocument, material: VaultMaterial): Buffer {
  validateDocument(document);
  const json = Buffer.from(JSON.stringify(document), 'utf8');
  if (json.length > MAXIMUM_JSON_SIZE) throw new VaultFormatError('Vault JSON is too large.');
  const plaintextLength = Math.max(4096, Math.ceil((json.length + 4) / 4096) * 4096);
  if (HEADER_SIZE + plaintextLength > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Vault is too large.');
```

#### Validation

Подтверждены отсутствие общей структурной квоты и принятие неизвестных полей до structuredClone/JSON.stringify. Файловый вход требует валидной аутентификации созданного атакующим vault; IPC-вариант требует контроля renderer. Severity снижен до low из-за ограниченного воздействия на доступность, существенных предпосылок и неизмеренного OOM-порога. Обход GCM не обнаружен.

Validation method: offline static source trace; independent module auditor and parent validation

**JSON.parse предшествует проверке структуры.** — `electron-app/src/main/vault/codec.ts:198-204`

JSON.parse предшествует проверке структуры.

```
    plaintext = Buffer.concat([payloadCipher.update(fileBytes.subarray(HEADER_SIZE)), payloadCipher.final()]);
    const jsonLength = plaintext.readInt32LE(0);
    if (jsonLength < 2 || jsonLength > MAXIMUM_JSON_SIZE || jsonLength > plaintext.length - 4) throw new VaultFormatError('Invalid authenticated JSON length.');
    const json = new TextDecoder('utf-8', { fatal: true }).decode(plaintext.subarray(4, 4 + jsonLength));
    const document = JSON.parse(json) as VaultDocument;
    validateDocument(document);
    return document;
```

**Неизвестные поля и общий граф не ограничены.** — `electron-app/src/main/vault/codec.ts:271-291`

Неизвестные поля и общий граф не ограничены.

```
export function validateDocument(document: VaultDocument): void {
  if (!document || typeof document !== 'object' || !isUuid(document.rootFolderId) || !Array.isArray(document.folders) || !Array.isArray(document.records) || document.folders.length < 1 || document.folders.length > 100_000 || document.records.length > 1_000_000) {
    throw new VaultFormatError('Invalid vault document.');
  }
  validateUtc(document.modifiedUtc, false);
  const folders = new Map<string, VaultFolder>();
  for (const folder of document.folders) {
    validateName(folder.name);
    if (!isUuid(folder.id) || folders.has(folder.id) || (folder.parentId !== null && !isUuid(folder.parentId)) || typeof folder.isDeleted !== 'boolean') throw new VaultFormatError('Invalid folder identifier.');
    validateUtc(folder.deletedUtc, true);
    folders.set(folder.id, folder);
  }
  const root = folders.get(document.rootFolderId);
  if (!root || root.parentId !== null) throw new VaultFormatError('Invalid root folder.');
  for (const folder of document.folders) validateAncestry(folder, folders);
  const records = new Set<string>();
  for (const record of document.records) validateRecord(record, records, folders);
  if (!document.settings || typeof document.settings !== 'object' || typeof document.settings.hibpConsent !== 'boolean' || !Number.isInteger(document.settings.clipboardClearSeconds) || document.settings.clipboardClearSeconds < 5 || document.settings.clipboardClearSeconds > 600 || !Number.isInteger(document.settings.autoLockMinutes) || document.settings.autoLockMinutes < 0 || document.settings.autoLockMinutes > 240 || !['', 'ru', 'en'].includes(document.settings.sessionLanguage)) {
    throw new VaultFormatError('Invalid vault settings.');
  }
}
```

**Вложенные записи, customFields, breach и ssh проверяются по отдельным полям без запрета дополнительных ключей и общего бюджета документа.** — `electron-app/src/main/vault/codec.ts:293-324`

Вложенные записи, customFields, breach и ssh проверяются по отдельным полям без запрета дополнительных ключей и общего бюджета документа.

```
function validateRecord(record: VaultRecord, records: Set<string>, folders: Map<string, VaultFolder>): void {
  if (!isUuid(record.id) || records.has(record.id) || !folders.has(record.folderId) || !Number.isInteger(record.type) || record.type < 0 || record.type > 4) throw new VaultFormatError('Invalid record.');
  records.add(record.id);
  validateName(record.name);
  for (const value of [record.userName, record.email, record.password, record.url, record.notes]) validateField(value);
  if (typeof record.isDeleted !== 'boolean') throw new VaultFormatError('Invalid record state.');
  validateUtc(record.deletedUtc, true);
  validateUtc(record.modifiedUtc, false);
  if (!Array.isArray(record.customFields) || record.customFields.length > 256) throw new VaultFormatError('Too many custom fields.');
  for (const field of record.customFields) {
    validateName(field.name);
    validateField(field.value);
    if (typeof field.isSecret !== 'boolean') throw new VaultFormatError('Invalid custom field.');
  }
  if (!record.breach || !Number.isInteger(record.breach.status) || record.breach.status < 0 || record.breach.status > 3 || !Number.isSafeInteger(record.breach.occurrenceCount) || record.breach.occurrenceCount < 0 || typeof record.breach.compromisedSaveConfirmed !== 'boolean') {
    throw new VaultFormatError('Invalid breach-check state.');
  }
  validateUtc(record.breach.checkedUtc, true);
  if ((record.type === 4) !== (record.ssh !== null)) throw new VaultFormatError('SSH profile does not match record type.');
  if (record.ssh) {
    if (!Object.hasOwn(record.ssh, 'allowLegacyAlgorithms')) record.ssh.allowLegacyAlgorithms = false;
    if (typeof record.ssh.host !== 'string' || record.ssh.host.trim().length === 0 || record.ssh.host.length > 253 || /[\u0000-\u001F\u007F]/u.test(record.ssh.host) ||
        typeof record.ssh.userName !== 'string' || record.ssh.userName.length < 1 || record.ssh.userName.length > 512 || /[\u0000-\u001F\u007F]/u.test(record.ssh.userName) ||
        typeof record.ssh.password !== 'string' || record.ssh.password.length > 1_000_000 ||
        typeof record.ssh.privateKeyPem !== 'string' || record.ssh.privateKeyPem.length > 4 * 1024 * 1024 ||
        typeof record.ssh.privateKeyPassphrase !== 'string' || record.ssh.privateKeyPassphrase.length > 1_000_000 ||
        !Number.isInteger(record.ssh.port) || record.ssh.port < 1 || record.ssh.port > 65535 ||
        (record.ssh.authenticationKind !== 0 && record.ssh.authenticationKind !== 1) ||
        typeof record.ssh.allowLegacyAlgorithms !== 'boolean' ||
        (record.ssh.hostKeySha256 !== '' && !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(record.ssh.hostKeySha256))) throw new VaultFormatError('Invalid SSH profile.');
  }
}
```

**Предел 64 относится только к цепочке parentId папок, а не к синтаксической глубине JSON.** — `electron-app/src/main/vault/codec.ts:326-336`

Предел 64 относится только к цепочке parentId папок, а не к синтаксической глубине JSON.

```
function validateAncestry(folder: VaultFolder, folders: Map<string, VaultFolder>): void {
  const visited = new Set<string>();
  let current = folder;
  let depth = 0;
  while (current.parentId !== null) {
    if (visited.has(current.id) || ++depth > 64) throw new VaultFormatError('Folder cycle or excessive depth.');
    visited.add(current.id);
    const parent = folders.get(current.parentId);
    if (!parent) throw new VaultFormatError('Missing parent folder.');
    current = parent;
  }
```

**JSON.stringify и Buffer.from выполняются до проверки MAXIMUM_JSON_SIZE и выделения padded plaintext.** — `electron-app/src/main/vault/codec.ts:106-113`

JSON.stringify и Buffer.from выполняются до проверки MAXIMUM_JSON_SIZE и выделения padded plaintext.

```
export function encodeVault(document: VaultDocument, material: VaultMaterial): Buffer {
  validateDocument(document);
  const json = Buffer.from(JSON.stringify(document), 'utf8');
  if (json.length > MAXIMUM_JSON_SIZE) throw new VaultFormatError('Vault JSON is too large.');
  const plaintextLength = Math.max(4096, Math.ceil((json.length + 4) / 4096) * 4096);
  if (HEADER_SIZE + plaintextLength > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Vault is too large.');

  const plaintext = Buffer.allocUnsafe(plaintextLength);
```

**IPC открывает vault и передаёт document сохранения в VaultStore после проверки sessionId без самостоятельного структурного бюджета.** — `electron-app/src/main/main.ts:135-141`

IPC открывает vault и передаёт document сохранения в VaultStore после проверки sessionId без самостоятельного структурного бюджета.

```
  ipcMain.handle('vault:open', trusted(async (_event, input) => { const value = credentials.parse(input); return store.open(value.path, value.password); }));
  ipcMain.handle('vault:create', trusted(async (_event, input) => { const value = credentials.parse(input); return store.create(value.path, value.password); }));
  ipcMain.handle('vault:save', trusted(async (_event, input: unknown) => {
    if (!input || typeof input !== 'object' || !('sessionId' in input) || !('document' in input)) throw new Error('Invalid save request.');
    const id = sessionId.parse(input.sessionId);
    await store.save(id, input.document as never);
  }));
```

**Входной документ целиком клонируется и кодируется.** — `electron-app/src/main/vault/storage.ts:85-92`

Входной документ целиком клонируется и кодируется.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
```

**open добавляет сессию до snapshot; catch освобождает lock и повторно выбрасывает ошибку без удаления добавленной сессии.** — `electron-app/src/main/vault/storage.ts:32-47`

open добавляет сессию до snapshot; catch освобождает lock и повторно выбрасывает ошибку без удаления добавленной сессии.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
```

**addSession сохраняет material и полный document в долгоживущей Map.** — `electron-app/src/main/vault/storage.ts:172-175`

addSession сохраняет material и полный document в долгоживущей Map.

```
  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**snapshot клонирует весь session.document, включая неизвестные поля.** — `electron-app/src/main/vault/storage.ts:263-265`

snapshot клонирует весь session.document, включая неизвестные поля.

```
function snapshot(session: VaultSession): VaultSnapshot {
  return { sessionId: session.id, path: session.path, displayName: basename(session.path, '.pmvault'), document: structuredClone(session.document) };
}
```

**До KDF действуют предел файла 256 MiB, фиксированный заголовок и точное соответствие длины ciphertext; это ограничивает файловый вход, но не число создаваемых JSON-объектов.** — `electron-app/src/main/vault/codec.ts:154-168`

До KDF действуют предел файла 256 MiB, фиксированный заголовок и точное соответствие длины ciphertext; это ограничивает файловый вход, но не число создаваемых JSON-объектов.

```
function parseHeader(fileBytes: Buffer): { vaultId: Buffer; kdfSalt: Buffer; parameters: KdfParameters; ciphertextLength: number } {
  if (fileBytes.length < HEADER_SIZE || fileBytes.length > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Invalid vault size.');
  const header = fileBytes.subarray(0, HEADER_SIZE);
  if (!header.subarray(0, 8).equals(MAGIC)) throw new VaultFormatError('Not a PasswordManager vault.');
  if (header.readUInt16LE(OFFSETS.version) !== 1 || header.readUInt16LE(OFFSETS.suite) !== 1 || header.readInt32LE(OFFSETS.headerLength) !== HEADER_SIZE) {
    throw new VaultFormatError('Unsupported vault version or cipher suite.');
  }
  const digest = createHash('sha256').update(header.subarray(0, OFFSETS.headerDigest)).digest();
  if (!timingSafeEqual(digest, header.subarray(OFFSETS.headerDigest, HEADER_SIZE))) throw new VaultFormatError('Corrupt vault header.');
  const ciphertextLengthBig = header.readBigInt64LE(OFFSETS.ciphertextLength);
  if (ciphertextLengthBig < 4096n || ciphertextLengthBig > BigInt(MAXIMUM_FILE_SIZE - HEADER_SIZE) || ciphertextLengthBig % 4096n !== 0n) {
    throw new VaultFormatError('Invalid ciphertext length.');
  }
  const ciphertextLength = Number(ciphertextLengthBig);
  if (ciphertextLength !== fileBytes.length - HEADER_SIZE) throw new VaultFormatError('Truncated or trailing vault bytes.');
```

**Политика явно включает parser memory exhaustion внутри поддерживаемого file cap в reportable issues и исключает обычную авторизованную активность пользователя.** — `SECURITY.md:42-46`

Политика явно включает parser memory exhaustion внутри поддерживаемого file cap в reportable issues и исключает обычную авторизованную активность пользователя.

```
## Reportable issues

Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Renderer объявлен недоверенным; main обязан проверять каждый IPC payload.** — `AGENTS.md:27-30`

Renderer объявлен недоверенным; main обязан проверять каждый IPC payload.

```
- The renderer is untrusted presentation code: keep `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, `webviewTag: false`, and `webSecurity: true`.
- Serve packaged UI only through the `pmapp://local` protocol with a restrictive CSP. Deny permissions, navigation, popups, downloads, external content, DevTools in packaged builds, and arbitrary IPC.
- Expose only narrow frozen preload methods. Validate the sender frame and every IPC payload in the main process; never expose `ipcRenderer`, filesystem, shell, crypto keys, or network primitives to Vue.
- Do not use `v-html`, dynamic code execution, remote scripts/styles, frontend persistence, or secret-bearing URLs.
```

**Проверка размера следует за JSON.stringify и Buffer.from.** — `electron-app/src/main/vault/codec.ts:106-111`

Проверка размера следует за JSON.stringify и Buffer.from.

```
export function encodeVault(document: VaultDocument, material: VaultMaterial): Buffer {
  validateDocument(document);
  const json = Buffer.from(JSON.stringify(document), 'utf8');
  if (json.length > MAXIMUM_JSON_SIZE) throw new VaultFormatError('Vault JSON is too large.');
  const plaintextLength = Math.max(4096, Math.ceil((json.length + 4) / 4096) * 4096);
  if (HEADER_SIZE + plaintextLength > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Vault is too large.');
```

Assertions:
- Статически прослежены оба входа и все вызовы validateDocument/encodeVault/decodeVault. Контрпример структуры: обычные обязательные поля VaultDocument плюс дополнительный ключ с массивами произвольной глубины; ни одна проверка validateDocument не читает этот ключ, а JSON.parse, structuredClone и JSON.stringify обрабатывают его. В storage.open addSession предшествует потенциально ошибочному snapshot, а catch не вызывает close/disposeMaterial. Эксплуатационный файл, приложение и тесты не запускались; фактический crash/OOM не утверждается как воспроизведённый.
- GCM проверяется до JSON.parse, JsonLength ограничен 64 MiB, весь файл ограничен 256 MiB; известные массивы, строки и ancestry также имеют лимиты. Поэтому обычное изменение украденного locked vault без пароля не достигает JSON-парсера. Ошибки разбора/клонирования обычно возвращаются как отказ открытия или сохранения, а не обязательно завершают процесс. Политика исключает обычные атаки удаления/доступности, но отдельно относит parser memory exhaustion внутри поддерживаемого размера к reportable issues. Вероятность и точный размер воздействия зависят от пользовательского открытия подготовленного файла или компрометации renderer и от лимитов V8.

Limitations:
- No dynamic exploit or Windows/SMB reproduction; repository tests were run independently of static review.

#### Dataflow

Файл: vault:open → VaultStore.open → decodeVault → успешный GCM final → JSON.parse → validateDocument, игнорирующий дополнительные поля → addSession → snapshot/structuredClone. IPC: vault:save → VaultStore.save → validateDocument → structuredClone → encodeVault → JSON.stringify/Buffer.from → лишь затем проверка json.length. Дополнительное свойство с глубоко вложенными массивами не относится к folders и потому не ограничивается validateAncestry. Разделяемые ссылки в входном графе дополнительно опасны для JSON.stringify, который должен материализовать повторяющиеся ветви; этот вариант зависит от сохранения ссылок при передаче через Electron и не является единственным основанием находки.

- **Source:** Автор внешнего .pmvault, который передаёт пользователю свой корректно зашифрованный файл и пароль, либо код в недоверенном renderer при наличии открытой сессии. Доступ к rootKey жертвы и административные права для этих входов не требуются.

- **Sink:** Лимит 64 MiB применяется к строке JSON после выделения памяти при сохранении; при чтении он ограничивает только число байтов до JSON.parse. Нет предварительного бюджета глубины, числа JSON-узлов и совокупного размера, а проверка схемы не отклоняет неизвестные поля. Ограничение глубины 64 распространяется только на связи parentId в известном массиве folders, а не на фактический граф входного документа.

- **Outcome:** Исчерпание памяти и/или длительная блокировка главного процесса при обработке данных, не прошедших полный структурный контроль. Файловый путь усиливается порядком операций storage: сессия добавляется в Map до snapshot; при ошибке последующего клонирования внешний catch освобождает lock, но не удаляет уже добавленную сессию, сохраняя её большой документ. Повторные попытки открытия могут накапливать такие документы. Точные пороги OOM и длительность блокировки в целевом Electron не измерены; утечка plaintext, обход GCM и выполнение кода из JSON не заявляются.

**JSON.parse предшествует проверке структуры.** — `electron-app/src/main/vault/codec.ts:198-204`

JSON.parse предшествует проверке структуры.

```
    plaintext = Buffer.concat([payloadCipher.update(fileBytes.subarray(HEADER_SIZE)), payloadCipher.final()]);
    const jsonLength = plaintext.readInt32LE(0);
    if (jsonLength < 2 || jsonLength > MAXIMUM_JSON_SIZE || jsonLength > plaintext.length - 4) throw new VaultFormatError('Invalid authenticated JSON length.');
    const json = new TextDecoder('utf-8', { fatal: true }).decode(plaintext.subarray(4, 4 + jsonLength));
    const document = JSON.parse(json) as VaultDocument;
    validateDocument(document);
    return document;
```

**Неизвестные поля и общий граф не ограничены.** — `electron-app/src/main/vault/codec.ts:271-291`

Неизвестные поля и общий граф не ограничены.

```
export function validateDocument(document: VaultDocument): void {
  if (!document || typeof document !== 'object' || !isUuid(document.rootFolderId) || !Array.isArray(document.folders) || !Array.isArray(document.records) || document.folders.length < 1 || document.folders.length > 100_000 || document.records.length > 1_000_000) {
    throw new VaultFormatError('Invalid vault document.');
  }
  validateUtc(document.modifiedUtc, false);
  const folders = new Map<string, VaultFolder>();
  for (const folder of document.folders) {
    validateName(folder.name);
    if (!isUuid(folder.id) || folders.has(folder.id) || (folder.parentId !== null && !isUuid(folder.parentId)) || typeof folder.isDeleted !== 'boolean') throw new VaultFormatError('Invalid folder identifier.');
    validateUtc(folder.deletedUtc, true);
    folders.set(folder.id, folder);
  }
  const root = folders.get(document.rootFolderId);
  if (!root || root.parentId !== null) throw new VaultFormatError('Invalid root folder.');
  for (const folder of document.folders) validateAncestry(folder, folders);
  const records = new Set<string>();
  for (const record of document.records) validateRecord(record, records, folders);
  if (!document.settings || typeof document.settings !== 'object' || typeof document.settings.hibpConsent !== 'boolean' || !Number.isInteger(document.settings.clipboardClearSeconds) || document.settings.clipboardClearSeconds < 5 || document.settings.clipboardClearSeconds > 600 || !Number.isInteger(document.settings.autoLockMinutes) || document.settings.autoLockMinutes < 0 || document.settings.autoLockMinutes > 240 || !['', 'ru', 'en'].includes(document.settings.sessionLanguage)) {
    throw new VaultFormatError('Invalid vault settings.');
  }
}
```

**Вложенные записи, customFields, breach и ssh проверяются по отдельным полям без запрета дополнительных ключей и общего бюджета документа.** — `electron-app/src/main/vault/codec.ts:293-324`

Вложенные записи, customFields, breach и ssh проверяются по отдельным полям без запрета дополнительных ключей и общего бюджета документа.

```
function validateRecord(record: VaultRecord, records: Set<string>, folders: Map<string, VaultFolder>): void {
  if (!isUuid(record.id) || records.has(record.id) || !folders.has(record.folderId) || !Number.isInteger(record.type) || record.type < 0 || record.type > 4) throw new VaultFormatError('Invalid record.');
  records.add(record.id);
  validateName(record.name);
  for (const value of [record.userName, record.email, record.password, record.url, record.notes]) validateField(value);
  if (typeof record.isDeleted !== 'boolean') throw new VaultFormatError('Invalid record state.');
  validateUtc(record.deletedUtc, true);
  validateUtc(record.modifiedUtc, false);
  if (!Array.isArray(record.customFields) || record.customFields.length > 256) throw new VaultFormatError('Too many custom fields.');
  for (const field of record.customFields) {
    validateName(field.name);
    validateField(field.value);
    if (typeof field.isSecret !== 'boolean') throw new VaultFormatError('Invalid custom field.');
  }
  if (!record.breach || !Number.isInteger(record.breach.status) || record.breach.status < 0 || record.breach.status > 3 || !Number.isSafeInteger(record.breach.occurrenceCount) || record.breach.occurrenceCount < 0 || typeof record.breach.compromisedSaveConfirmed !== 'boolean') {
    throw new VaultFormatError('Invalid breach-check state.');
  }
  validateUtc(record.breach.checkedUtc, true);
  if ((record.type === 4) !== (record.ssh !== null)) throw new VaultFormatError('SSH profile does not match record type.');
  if (record.ssh) {
    if (!Object.hasOwn(record.ssh, 'allowLegacyAlgorithms')) record.ssh.allowLegacyAlgorithms = false;
    if (typeof record.ssh.host !== 'string' || record.ssh.host.trim().length === 0 || record.ssh.host.length > 253 || /[\u0000-\u001F\u007F]/u.test(record.ssh.host) ||
        typeof record.ssh.userName !== 'string' || record.ssh.userName.length < 1 || record.ssh.userName.length > 512 || /[\u0000-\u001F\u007F]/u.test(record.ssh.userName) ||
        typeof record.ssh.password !== 'string' || record.ssh.password.length > 1_000_000 ||
        typeof record.ssh.privateKeyPem !== 'string' || record.ssh.privateKeyPem.length > 4 * 1024 * 1024 ||
        typeof record.ssh.privateKeyPassphrase !== 'string' || record.ssh.privateKeyPassphrase.length > 1_000_000 ||
        !Number.isInteger(record.ssh.port) || record.ssh.port < 1 || record.ssh.port > 65535 ||
        (record.ssh.authenticationKind !== 0 && record.ssh.authenticationKind !== 1) ||
        typeof record.ssh.allowLegacyAlgorithms !== 'boolean' ||
        (record.ssh.hostKeySha256 !== '' && !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(record.ssh.hostKeySha256))) throw new VaultFormatError('Invalid SSH profile.');
  }
}
```

**Предел 64 относится только к цепочке parentId папок, а не к синтаксической глубине JSON.** — `electron-app/src/main/vault/codec.ts:326-336`

Предел 64 относится только к цепочке parentId папок, а не к синтаксической глубине JSON.

```
function validateAncestry(folder: VaultFolder, folders: Map<string, VaultFolder>): void {
  const visited = new Set<string>();
  let current = folder;
  let depth = 0;
  while (current.parentId !== null) {
    if (visited.has(current.id) || ++depth > 64) throw new VaultFormatError('Folder cycle or excessive depth.');
    visited.add(current.id);
    const parent = folders.get(current.parentId);
    if (!parent) throw new VaultFormatError('Missing parent folder.');
    current = parent;
  }
```

**JSON.stringify и Buffer.from выполняются до проверки MAXIMUM_JSON_SIZE и выделения padded plaintext.** — `electron-app/src/main/vault/codec.ts:106-113`

JSON.stringify и Buffer.from выполняются до проверки MAXIMUM_JSON_SIZE и выделения padded plaintext.

```
export function encodeVault(document: VaultDocument, material: VaultMaterial): Buffer {
  validateDocument(document);
  const json = Buffer.from(JSON.stringify(document), 'utf8');
  if (json.length > MAXIMUM_JSON_SIZE) throw new VaultFormatError('Vault JSON is too large.');
  const plaintextLength = Math.max(4096, Math.ceil((json.length + 4) / 4096) * 4096);
  if (HEADER_SIZE + plaintextLength > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Vault is too large.');

  const plaintext = Buffer.allocUnsafe(plaintextLength);
```

**IPC открывает vault и передаёт document сохранения в VaultStore после проверки sessionId без самостоятельного структурного бюджета.** — `electron-app/src/main/main.ts:135-141`

IPC открывает vault и передаёт document сохранения в VaultStore после проверки sessionId без самостоятельного структурного бюджета.

```
  ipcMain.handle('vault:open', trusted(async (_event, input) => { const value = credentials.parse(input); return store.open(value.path, value.password); }));
  ipcMain.handle('vault:create', trusted(async (_event, input) => { const value = credentials.parse(input); return store.create(value.path, value.password); }));
  ipcMain.handle('vault:save', trusted(async (_event, input: unknown) => {
    if (!input || typeof input !== 'object' || !('sessionId' in input) || !('document' in input)) throw new Error('Invalid save request.');
    const id = sessionId.parse(input.sessionId);
    await store.save(id, input.document as never);
  }));
```

**Входной документ целиком клонируется и кодируется.** — `electron-app/src/main/vault/storage.ts:85-92`

Входной документ целиком клонируется и кодируется.

```
  async save(sessionId: string, document: VaultDocument): Promise<void> {
    const session = this.requireSession(sessionId);
    validateDocument(document);
    const safeDocument = structuredClone(document);
    constrainSshFingerprints(safeDocument, session.document);
    safeDocument.settings.hibpConsent = session.document.settings.hibpConsent;
    safeDocument.modifiedUtc = new Date().toISOString();
    const bytes = encodeVault(safeDocument, session.material);
```

**open добавляет сессию до snapshot; catch освобождает lock и повторно выбрасывает ошибку без удаления добавленной сессии.** — `electron-app/src/main/vault/storage.ts:32-47`

open добавляет сессию до snapshot; catch освобождает lock и повторно выбрасывает ошибку без удаления добавленной сессии.

```
  async open(path: string, password: string): Promise<VaultSnapshot> {
    const vaultPath = await canonicalVaultPath(path, true);
    const lock = await acquireLock(vaultPath);
    try {
      const bytes = await readBounded(vaultPath);
      try {
        const decoded = await decodeVault(bytes, password);
        const session = this.addSession(vaultPath, lock, createHash('sha256').update(bytes).digest(), decoded.material, decoded.document);
        await cleanupEncryptedTemps(vaultPath);
        return snapshot(session);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      await releaseLock(lock.handle, lock.path);
      throw error;
```

**addSession сохраняет material и полный document в долгоживущей Map.** — `electron-app/src/main/vault/storage.ts:172-175`

addSession сохраняет material и полный document в долгоживущей Map.

```
  private addSession(path: string, lock: { handle: FileHandle; path: string }, sourceHash: Buffer, material: VaultMaterial, document: VaultDocument): VaultSession {
    const session = { id: randomUUID(), path, lockPath: lock.path, lockHandle: lock.handle, sourceHash, material, document };
    this.sessions.set(session.id, session);
    return session;
```

**snapshot клонирует весь session.document, включая неизвестные поля.** — `electron-app/src/main/vault/storage.ts:263-265`

snapshot клонирует весь session.document, включая неизвестные поля.

```
function snapshot(session: VaultSession): VaultSnapshot {
  return { sessionId: session.id, path: session.path, displayName: basename(session.path, '.pmvault'), document: structuredClone(session.document) };
}
```

**До KDF действуют предел файла 256 MiB, фиксированный заголовок и точное соответствие длины ciphertext; это ограничивает файловый вход, но не число создаваемых JSON-объектов.** — `electron-app/src/main/vault/codec.ts:154-168`

До KDF действуют предел файла 256 MiB, фиксированный заголовок и точное соответствие длины ciphertext; это ограничивает файловый вход, но не число создаваемых JSON-объектов.

```
function parseHeader(fileBytes: Buffer): { vaultId: Buffer; kdfSalt: Buffer; parameters: KdfParameters; ciphertextLength: number } {
  if (fileBytes.length < HEADER_SIZE || fileBytes.length > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Invalid vault size.');
  const header = fileBytes.subarray(0, HEADER_SIZE);
  if (!header.subarray(0, 8).equals(MAGIC)) throw new VaultFormatError('Not a PasswordManager vault.');
  if (header.readUInt16LE(OFFSETS.version) !== 1 || header.readUInt16LE(OFFSETS.suite) !== 1 || header.readInt32LE(OFFSETS.headerLength) !== HEADER_SIZE) {
    throw new VaultFormatError('Unsupported vault version or cipher suite.');
  }
  const digest = createHash('sha256').update(header.subarray(0, OFFSETS.headerDigest)).digest();
  if (!timingSafeEqual(digest, header.subarray(OFFSETS.headerDigest, HEADER_SIZE))) throw new VaultFormatError('Corrupt vault header.');
  const ciphertextLengthBig = header.readBigInt64LE(OFFSETS.ciphertextLength);
  if (ciphertextLengthBig < 4096n || ciphertextLengthBig > BigInt(MAXIMUM_FILE_SIZE - HEADER_SIZE) || ciphertextLengthBig % 4096n !== 0n) {
    throw new VaultFormatError('Invalid ciphertext length.');
  }
  const ciphertextLength = Number(ciphertextLengthBig);
  if (ciphertextLength !== fileBytes.length - HEADER_SIZE) throw new VaultFormatError('Truncated or trailing vault bytes.');
```

**Политика явно включает parser memory exhaustion внутри поддерживаемого file cap в reportable issues и исключает обычную авторизованную активность пользователя.** — `SECURITY.md:42-46`

Политика явно включает parser memory exhaustion внутри поддерживаемого file cap в reportable issues и исключает обычную авторизованную активность пользователя.

```
## Reportable issues

Reportable security defects include vault plaintext disclosure; authentication or AAD bypass; nonce/key reuse; unsafe KDF allocation; parser memory exhaustion within the supported file cap; path or temp-file attacks that can expose or overwrite unrelated data; writer/conflict bypass; password or full-hash disclosure to HIBP; navigation or code execution in the terminal WebView; SSH algorithm downgrade or host-key bypass; capture-gate bypass; cross-user named-pipe access; secrets in logs or release artifacts; or release-signature bypass.

Ordinary authorized access by the signed-in user, availability loss from deleting a vault, observation by an already privileged administrator, and weaknesses explicitly outside the threat model are not vulnerabilities unless they cross another stated boundary.
```

**Renderer объявлен недоверенным; main обязан проверять каждый IPC payload.** — `AGENTS.md:27-30`

Renderer объявлен недоверенным; main обязан проверять каждый IPC payload.

```
- The renderer is untrusted presentation code: keep `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, `webviewTag: false`, and `webSecurity: true`.
- Serve packaged UI only through the `pmapp://local` protocol with a restrictive CSP. Deny permissions, navigation, popups, downloads, external content, DevTools in packaged builds, and arbitrary IPC.
- Expose only narrow frozen preload methods. Validate the sender frame and every IPC payload in the main process; never expose `ipcRenderer`, filesystem, shell, crypto keys, or network primitives to Vue.
- Do not use `v-html`, dynamic code execution, remote scripts/styles, frontend persistence, or secret-bearing URLs.
```

**Проверка размера следует за JSON.stringify и Buffer.from.** — `electron-app/src/main/vault/codec.ts:106-111`

Проверка размера следует за JSON.stringify и Buffer.from.

```
export function encodeVault(document: VaultDocument, material: VaultMaterial): Buffer {
  validateDocument(document);
  const json = Buffer.from(JSON.stringify(document), 'utf8');
  if (json.length > MAXIMUM_JSON_SIZE) throw new VaultFormatError('Vault JSON is too large.');
  const plaintextLength = Math.max(4096, Math.ceil((json.length + 4) / 4096) * 4096);
  if (HEADER_SIZE + plaintextLength > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Vault is too large.');
```

#### Reachability

Для файлового пути пользователь должен самостоятельно открыть подготовленный атакующим vault с известным паролем: изменение чужого ciphertext без ключа не проходит GCM. Для IPC-пути необходимы выполнение кода в renderer и действующий sessionId; самостоятельная возможность получить такое выполнение в данном модуле не установлена.

- **Attacker:** Автор внешнего .pmvault, который передаёт пользователю свой корректно зашифрованный файл и пароль, либо код в недоверенном renderer при наличии открытой сессии. Доступ к rootKey жертвы и административные права для этих входов не требуются.

- **Outcome:** Исчерпание памяти и/или длительная блокировка главного процесса при обработке данных, не прошедших полный структурный контроль. Файловый путь усиливается порядком операций storage: сессия добавляется в Map до snapshot; при ошибке последующего клонирования внешний catch освобождает lock, но не удаляет уже добавленную сессию, сохраняя её большой документ. Повторные попытки открытия могут накапливать такие документы. Точные пороги OOM и длительность блокировки в целевом Electron не измерены; утечка plaintext, обход GCM и выполнение кода из JSON не заявляются.

Limitations:
- GCM проверяется до JSON.parse, JsonLength ограничен 64 MiB, весь файл ограничен 256 MiB; известные массивы, строки и ancestry также имеют лимиты. Поэтому обычное изменение украденного locked vault без пароля не достигает JSON-парсера. Ошибки разбора/клонирования обычно возвращаются как отказ открытия или сохранения, а не обязательно завершают процесс. Политика исключает обычные атаки удаления/доступности, но отдельно относит parser memory exhaustion внутри поддерживаемого размера к reportable issues. Вероятность и точный размер воздействия зависят от пользовательского открытия подготовленного файла или компрометации renderer и от лимитов V8.

#### Severity

**Low** — Подтверждены отсутствие общей структурной квоты и принятие неизвестных полей до structuredClone/JSON.stringify. Файловый вход требует валидной аутентификации созданного атакующим vault; IPC-вариант требует контроля renderer. Severity снижен до low из-за ограниченного воздействия на доступность, существенных предпосылок и неизмеренного OOM-порога. Обход GCM не обнаружен.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Отклонять неизвестные поля на каждом уровне и принимать только явно построенный документ из разрешённых скалярных полей. Перед JSON.parse применять ограничивающий потоковый разбор либо предварительный проход с лимитами глубины, числа узлов и длины строк; перед JSON.stringify проверять совокупный бюджет и недопустимые циклы/разделяемые структуры без разворачивания графа. При любой ошибке после addSession удалять сессию и обнулять material. Добавить синтетические отрицательные тесты для глубокого дополнительного поля, чрезмерного количества JSON-узлов, чрезмерного суммарного размера, повторных ссылок IPC и очистки сессии при ошибке snapshot.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| electron-boundary | not recorded | Reported | Полностью прочитаны пять назначенных файлов и проверены связанные потребители. Выявлены три дефекта жизненного цикла: незавершённые операции могут пережить блокировку; очистка интерфейса ожидает файловую очистку; выход отменяет таймер очистки буфера обмена. Два вывода имеют уровень medium, один low. Установлены действующие границы main/preload/renderer, локального протокола, сетевых запросов и защиты от захвата. Проверка статическая, без исполнения приложения. Как фактически разделены доверие и владение секретами между процессами? Main владеет VaultStore и SshTerminalManager. Preload передаёт конкретные команды и данные событий через замороженный API, не экспортируя ipcRenderer/event. RootKey остаётся в material main, но полная копия VaultDocument, включая поля записей/SSH, передаётся в renderer после открытия и нужна для редактирования. Поэтому доверие к renderer как к месту представления раскрытых данных не равно праву управлять сетевыми направлениями, ключами main или произвольными системными API. electron-app/src/main/main.ts:19-20 — Main создаёт единственные менеджеры vault и SSH; SSH события направляет mainWindow.; electron-app/src/preload/preload.ts:4-34 — Замороженный API содержит фиксированные invoke/send и подписки; callback получает payload без IpcRendererEvent.; electron-app/src/main/vault/storage.ts:19-26 — Root material и document находятся в VaultSession main.; electron-app/src/main/vault/storage.ts:263-264 — snapshot возвращает structuredClone(document), не material.; electron-app/src/shared/contracts.ts:9-18 — SshProfile включает поля credentials, которые входят в документ.; electron-app/src/main/main.ts:188-203 — SSH start принимает identifiers и размеры; профиль получает main из своего VaultStore. Доказан ли обход IPC sender validation или sandbox? Нет. Окно использует contextIsolation, sandbox, webSecurity, отключённые Node/webview и packaged DevTools. Все invoke handlers обёрнуты trusted; activity также проверяет отправителя. Проверка senderFrame ограничена protocol/hostname и не сверяет event.sender с mainWindow.webContents, mainFrame и точным index.html. Это неполнота дополнительной защиты, но достижимый чужой pmapp-frame с bridge в текущей архитектуре не установлен: имеется одно окно, frame-src none и запрет новых окон/webview. В уязвимость без источника чужого кадра не повышено. electron-app/src/main/main.ts:79-100 — Единственное создаваемое BrowserWindow имеет требуемые webPreferences.; electron-app/src/main/main.ts:112-114 — Навигация, создание новых окон и attach webview блокируются.; electron-app/src/main/main.ts:124-185 — Регистрация фиксированного набора IPC handlers использует trusted; activity отдельно вызывает assertTrustedSender.; electron-app/src/main/main.ts:261-268 — trusted проверяет senderFrame URL только по pmapp: и hostname local.; electron-app/src/shared/content-security-policy.ts:6-6 — CSP запрещает frame-src. Какие правила действуют на границе packaged assets / browser network и доказан ли traversal? pmapp регистрируется как standard/secure; обработчик принимает GET для local, декодирует и нормализует путь, проверяет relative/isAbsolute и затем читает локальный asset. Очевидный выход за rendererRoot через .. отвергается; обход или чтение произвольного файла не доказаны. CSP задаёт только self scripts/styles/fonts, допускает inline CSS и data images, запрещает renderer connect/object/base/form/frame. Политика общая для HTTP-подобного header и HTML meta. Отдельного will-download deny нет в полном main.ts, несмотря на текст модели; достижимая цепочка создания загрузки из неисполняемого SSH/vault контента статически не найдена, поэтому это остаётся вопросом browser integration, не подтверждённым exploit. electron-app/src/main/main.ts:14-14 — Схема регистрируется с standard/secure/supportFetchAPI.; electron-app/src/main/main.ts:52-62 — Handler проверяет host/method и относительный путь до net.fetch file URL.; electron-app/src/main/main.ts:65-74 — Permissions отвергаются, CSP и nosniff добавляются к ответам.; electron-app/src/main/main.ts:77-121 — Полная конфигурация окна содержит navigation/window/webview blockers, но не обработчик downloads.; electron-app/src/shared/content-security-policy.ts:1-6 — Общая политика явно разрешает inline CSS для xterm и запрещает сетевые соединения renderer.; electron-app/vite.config.ts:4-15 — Vite импортирует ту же политику и вставляет meta в head.; docs/threat-model.md:13-13 — Модель заявляет download blocking; код этой отдельной меры не найден. Можно ли отключить capture protection runtime-переменной или IPC в обычной сборке? В проверенном пути сборки нет. Build script подставляет литерал для main/preload, Vite отдельно подставляет compile-time флаг renderer. Окно создаётся скрытым, конфигурируется защита, и при несоответствии isContentProtected либо исключении окно уничтожается до load/show. В диагностическом renderer есть видимый badge. Тесты покрывают обычный и диагностический режимы, mismatch и исключение setter. Реальное выполнение Windows API/невозможность screen capture и release gating этим статическим модульным аудитом не подтверждаются. electron-app/src/main/main.ts:84-121 — show:false предшествует configureCaptureProtection; loadURL/ready-to-show регистрируются после успешной проверки.; electron-app/src/main/services/capture-protection.ts:7-17 — Состояние запрашивается, читается обратно; ошибка уничтожает окно.; electron-app/src/main/services/capture-protection.test.ts:9-39 — Unit tests охватывают normal/diagnostic, mismatch и setter exception.; electron-app/scripts/build.mjs:10-20 — esbuild заменяет process.env.PM_SCREENSHOT_DIAGNOSTICS строковым литералом при сборке entrypoints.; electron-app/vite.config.ts:17-18 — Диагностический флаг renderer заменяется булевым литералом.; electron-app/src/renderer/src/App.vue:473-476 — При флаге renderer показывает диагностический badge. Какие IPC payload проходят проверку main и кому принадлежит сетевое согласие? Credentials, UUID, размеры terminal, clipboard bounds и тема проверяются в main. save не является strict wrapper schema, но его document проходит validateDocument в VaultStore до encode; дополнительные поля wrapper сами по себе не потребляются. HIBP consent хранится main и не перезаписывается входящим renderer document; при отсутствии согласия используется native диалог с отменой по умолчанию. Отдельный полный аудит HIBP/codec не заявляется. electron-app/src/main/main.ts:125-164 — IPC schemas задают bounds для path/password/sessionId/clipboard и native HIBP consent.; electron-app/src/main/main.ts:179-195 — Theme enum и strict SSH start payload проверяются main.; electron-app/src/main/vault/storage.ts:85-92 — save валидирует document, клонирует его, ограничивает fingerprints и восстанавливает consent из main.; electron-app/src/main/vault/storage.ts:140-149 — Consent читается из существующей main сессии и меняется через отдельный метод.; electron-app/src/main/services/ssh-terminal.ts:51-59 — Terminal write/resize используют строгие schemas с bounds.; electron-app/src/main/vault/storage.test.ts:101-115 — Тесты проверяют, что save из renderer не может включить/выключить main-owned consent. Что предотвращает передачу SSH credentials произвольному адресу из renderer? Start принимает только identifiers и размеры; main получает сохранённый профиль, показывает native destination confirmation и отдельное legacy warning, заново получает профиль после ожиданий и сравнивает target. TOFU требует native approval, сохранения fingerprint и повторного сравнения. HostVerifier принимает только совпадение закреплённого SHA-256. Терминальные bytes проходят bounded main events в xterm.write; OSC 52 и изменение заголовка потребляются обработчиками. Эти меры не отменяют race блокировки из electron-boundary-001. electron-app/src/main/main.ts:188-229 — Native approvals и проверки target/host-key persistence происходят на main-owned профиле.; electron-app/src/main/main.ts:232-258 — Оба native диалога используют cancel/defaultId=1.; electron-app/src/main/services/ssh-terminal.ts:179-183 — HostVerifier допускает только ненулевой expectedFingerprint, совпадающий с наблюдённым.; electron-app/src/main/services/ssh-terminal.ts:204-206 — Выход SSH делится на сообщения ограниченного размера.; electron-app/src/renderer/src/components/TerminalSession.vue:86-97 — OSC 52/0/1/2 поглощаются, SSH data передаются xterm.write. Является ли void store.closeAll при выходе доказанным сохранением rootKey? Нет. closeAll вызывает close для всех имеющихся ключей Map сразу; close удаляет сессию, очищает document/material/sourceHash до первого await releaseLock. Поэтому отсутствие await в before-quit само по себе не доказывает сохранение rootKey существующей сессии. Оно не решает pending-операции и clipboard, описанные отдельно. Невозможность гарантированно стереть строки/копии V8 остаётся документированным ограничением. electron-app/src/main/main.ts:49-49 — before-quit запускает closeAll без ожидания.; electron-app/src/main/vault/storage.ts:152-163 — Синхронное удаление и очистка существующих сессий происходят до ожидания файловой очистки.; electron-app/src/main/vault/codec.ts:148-151 — disposeMaterial обнуляет rootKey и buffers метаданных.; docs/threat-model.md:9-9 — Модель признаёт ограничение памяти JavaScript. Как фактически работают second-instance и inactivity? Пути командной строки/second-instance ограничены 32 элементами, отбрасывают --, проходят resolve, length/extension/existence check и только помещаются в очередь диалога открытия; авторазблокировки по пути нет. Это lexical normalization, не realpath, а existence check делает filesystem I/O. Таймер бездействия общий для приложения, обновляется доверенным IPC и activity событиями; у каждого сейфа собственный timeout, 0 исключает его из inactivity. Здесь не установлены отдельные path injection или spoofed-input exploit. electron-app/src/main/main.ts:27-35 — second-instance фильтрует типы и отправляет safeVaultPaths в renderer.; electron-app/src/main/main.ts:331-338 — Пути ограничены 32 аргументами, нормализованы resolve и проверены по extension/length/existence.; electron-app/src/renderer/src/App.vue:455-462 — Полученные пути помещаются в очередь диалога с пустым паролем.; electron-app/src/main/main.ts:261-262 — Каждый trusted invoke обновляет общую lastActivity.; electron-app/src/main/main.ts:277-291 — Периодический handler выбирает истекшие sessions и блокирует их.; electron-app/src/main/vault/storage.ts:166-169 — autoLockSessionIds исключает timeout=0 и сравнивает положительные значения.; electron-app/src/renderer/src/App.vue:81-98 — Физические UI события pointerdown/keydown/wheel передаются как activity. |
| vault-codec | not recorded | Reported | Полностью прочитаны три назначенных файла и прослежены потребители codec в storage, IPC и SSH. Найден один дефект ограничения ресурсов: неизвестные поля и произвольная структура JSON проходят проверку документа и попадают в обработку main без структурного или совокупного бюджета. Обход аутентификации, повтор nonce под одним ключом и снижение KDF через неподтверждённый заголовок не установлены. Проверка статическая; приложение и тесты не запускались. Как устроена архитектура codec и где проходят границы доверия? Codec работает в main. VaultMaterial содержит rootKey, salt и VaultId; storage хранит material отдельно от документа в сессии. Renderer получает VaultSnapshot с документом и идентификатором сессии, но контракт снимка не содержит material. На вход codec поступают недоверенные байты файлов и документы сохранения из IPC. Preload предоставляет фиксированный API, а main проверяет origin отправителя и форму внешней операции; полнота document validation рассматривается в vault-codec-001. electron-app/src/main/vault/codec.ts:43-53 — VaultMaterial включает rootKey, а DecodedVault возвращает его отдельно от document.; electron-app/src/main/vault/storage.ts:19-30 — VaultSession и private Map хранят document и material в main.; electron-app/src/shared/contracts.ts:65-70 — VaultSnapshot содержит sessionId, path, displayName и document без rootKey/material.; electron-app/src/shared/contracts.ts:123-145 — Общий интерфейс задаёт операции vault/SSH/clipboard и не предоставляет renderer прямой filesystem или crypto API.; electron-app/src/preload/preload.ts:4-13 — Фиксированный API заморожен; открытие, создание и сохранение передаются через выделенные IPC-каналы.; electron-app/src/main/main.ts:261-268 — Обёртка trusted проверяет protocol pmapp и hostname local перед вызовом обработчика; проверка не заменяет валидацию документа. Можно ли получить plaintext или ослабить криптографию изменением незаверенного заголовка? Такой путь не установлен. Фиксированная длина/версия/suite/длина ciphertext и диапазоны KDF проверяются до derivation. SHA-256 заголовка служит только ранней проверкой: изменение digest не заменяет GCM-теги. Wrap AAD покрывает начало заголовка до WrappedDataKey; payload AAD включает остальной релевантный заголовок с документированными обнулёнными полями. Wrap final предшествует использованию dataKey, payload final предшествует чтению JsonLength и JSON.parse. Для reread дополнительно проверяются VaultId, KDF salt и параметры. electron-app/src/main/vault/codec.ts:81-90 — parseHeader предшествует deriveRootKey; при ошибке последующей аутентификации материал обнуляется.; electron-app/src/main/vault/codec.ts:94-103 — verifyAndDecode сравнивает VaultId, salt и все параметры KDF с материалом открытой сессии.; electron-app/src/main/vault/codec.ts:154-179 — Заголовок, digest, точная длина и диапазоны KDF проверяются до возврата параметров для derivation.; electron-app/src/main/vault/codec.ts:190-204 — Оба AES-256-GCM используют 16-byte tags и AAD; обе final завершаются до разбора JSON.; electron-app/src/main/vault/codec.ts:232-237 — Payload AAD копирует заголовок до digest и обнуляет WrappedDataKey, WrapTag и PayloadTag.; docs/vault-format.md:38-42 — Спецификация считает digest ранней проверкой повреждения и определяет те же два диапазона AAD. Соответствуют ли KDF и ротация ключевого материала заявленному формату? В проверенном исходнике создаются Argon2id с 65536 KiB, 3 проходами, 4 lanes, salt 16 bytes и результатом 32 bytes; библиотечный исходник локально установленного hash-wasm фиксирует version 0x13 и тип id. При чтении допускаются только документированные ограниченные диапазоны; бинарное чтение даёт целые числа. Для каждой encodeVault генерируются новый 32-byte dataKey, 32-byte wrap salt и два 12-byte nonce, а KEK выводится HKDF-SHA-256 с доменным info. Argon2 выполняется hash-wasm, а AES/HKDF/RNG — node:crypto: требование использовать только крипто реализации pinned runtime соблюдается не буквально для Argon2; доказательств слабости самой выбранной реализации не найдено, внешний аудит зависимости и соответствие её установленного содержимого lock integrity не выполнялись. electron-app/src/main/vault/codec.ts:1-17 — AES/HKDF/RNG импортируются из node:crypto, argon2id — из hash-wasm; WRAP_INFO содержит домен v1/data-key-wrap.; electron-app/src/main/vault/codec.ts:69-77 — createMaterial создаёт 16-byte salt и фиксированные параметры 65536/3/4.; electron-app/src/main/vault/codec.ts:114-125 — Каждое сохранение генерирует новый dataKey и выводит 32-byte KEK через HKDF-SHA-256.; electron-app/src/main/vault/codec.ts:226-229 — initializeHeader генерирует новый wrap salt и отдельные wrap/payload nonce при каждом вызове.; electron-app/src/main/vault/codec.ts:240-263 — Пароль нормализуется NFC, Argon2id получает 32-byte output и ограниченные memory/iterations/parallelism.; electron-app/node_modules/hash-wasm/lib/argon2.ts:132-159 — Прочитанный локальный исходник зависимости задаёт version 0x13 и включает его в initVector.; electron-app/node_modules/hash-wasm/lib/argon2.ts:291-299 — Экспорт argon2id выбирает hashType id.; electron-app/package-lock.json:3457-3461 — lock закрепляет hash-wasm 4.12.0 и integrity; проверка фактических байтов пакета не выполнялась.; AGENTS.md:35-38 — Политика требует reviewed primitives из pinned runtime, конкретный Argon2id/AES набор и новую генерацию материала каждого save.; docs/vault-format.md:24-26 — Разрешённые при чтении диапазоны KDF совпадают с границами в validateKdf. Какие гарантии очистки секретных Buffer действительно следуют из кода? Явно удерживаемые passwordBytes/derived, KEK/dataKey/plaintext и rootKey имеют очистку. disposeMaterial вызывается при ошибке decode и обычном закрытии storage-сессии. Полного обнуления всех временных копий нет: encode создаёт временный результат HKDF без отдельной очистки; decrypt копирует результат Buffer.concat unwrap и результаты decipher.update, не сохраняя их для fill(0); при final failure присваивание plaintext не выполняется. Кроме того, json при oversized encode выбрасывается до finally. Это отклонения от строгого правила временных Buffer, но самостоятельный доступ к остаткам требует способности читать память доверенного unlocked host; в данной модели это hardening/ограничение, а не установленная утечка через файл или renderer. Строки JSON и пароля также не имеют гарантированного стирания. electron-app/src/main/vault/codec.ts:106-118 — json создаётся и проверяется на размер до входа в finally, поэтому ранний throw не вызывает его fill(0).; electron-app/src/main/vault/codec.ts:123-123 — Результат HKDF копируется во второй Buffer KEK; промежуточный результат не сохраняется для очистки.; electron-app/src/main/vault/codec.ts:138-151 — encode finally обнуляет именованные временные Buffer; disposeMaterial обнуляет rootKey, salt и VaultId.; electron-app/src/main/vault/codec.ts:190-211 — unwrap и payload используют временные update/concat Buffer, тогда как finally очищает только kek, dataKey и присвоенный plaintext.; electron-app/src/main/vault/codec.ts:254-258 — deriveRootKey возвращает отдельный rootKey Buffer и в finally обнуляет derived и passwordBytes.; electron-app/src/main/vault/codec.ts:85-90 — decodeVault при ошибке после derivation вызывает disposeMaterial.; electron-app/src/main/vault/storage.ts:152-159 — Обычное закрытие удаляет сессию, очищает документ, material и sourceHash до освобождения lock.; AGENTS.md:41-42 — Требуется finally/fill(0) для временных Buffer и детерминированное уничтожение rootKey; строки явно не гарантируются стираемыми.; SECURITY.md:19-19 — Политика исключает malware, debugger и process dumps доверенного unlocked процесса. Что гарантирует валидация документа и где обнаружены несоответствия без отдельного доказанного security impact? Известные поля проверяются на UUID, ссылки папок, циклы, глубину, диапазоны enum, длины строк, bool/settings и parseable timestamps. Отсутствующий allowLegacyAlgorithms мигрирует в false, не-булевое значение отвергается. Полная строгая схема отсутствует (ресурсное следствие отражено в finding). JSON.parse не обнаруживает duplicate keys вопреки спецификации; временные метки принимают Date.parse-совместимые строки без требования канонического UTC. hasUnpairedSurrogate пропускает последний одиночный high surrogate: charCodeAt за концом даёт NaN, а обе проверки диапазона с NaN ложны; к master password этот helper вообще не применяется. Это подтверждённые отклонения формата/валидации, но в просмотренных потребителях не установлен обход аутентификации или иной отдельный переход границы доверия за их счёт. electron-app/src/main/vault/codec.ts:271-322 — Перечислены проверки известных полей, enum, timestamps, settings и миграция SSH allowLegacyAlgorithms в false.; electron-app/src/main/vault/codec.ts:326-369 — Проверяются ancestry и длины строк; validateUtc использует Date.parse, а hasUnpairedSurrogate не проверяет наличие второго code unit перед сравнением.; electron-app/src/main/vault/codec.ts:199-203 — UTF-8 декодируется fatal, затем используется обычный JSON.parse без проверки повторяющихся ключей.; electron-app/src/main/vault/codec.ts:240-242 — Master password кодируется Buffer.from после NFC без проверки непарных surrogate.; docs/vault-format.md:3-8 — Спецификация требует отказа для duplicate/unknown fields и invalid UTF-8/JSON, а для пароля — NFC и strict UTF-8.; docs/vault-format.md:56-58 — 0 для autoLockMinutes документирован как отключение inactivity; отсутствующий legacy SSH boolean документирован как false. Обеспечивает ли проверка SSH-полей в codec заявленное исключение управляющих символов? Нет: regexp в codec содержит двойное экранирование backslash перед u и поэтому не обозначает ожидаемый диапазон управляющих кодов Unicode. Аналогичный regexp повторён в SSH-service. Это подтверждённый дефект проверки строк, способный также отклонять обычные символы имени. Отдельная security-находка не заявлена: просмотренный потребитель передаёт host/username в структурированный ConnectConfig, требует native confirmation и проверяет SHA-256 host key; инъекция shell-команд, конкретный обход DNS/hostVerifier либо воспроизведённый обман native dialog не установлены. Для исправления нужны корректный regexp и негативные тесты, включая NUL/newline и отображение native confirmation. electron-app/src/main/vault/codec.ts:314-315 — Regexp host и userName использует двойные backslash перед u в классе символов вместо Unicode escape ожидаемого control range.; electron-app/src/main/services/ssh-terminal.ts:13-14 — SSH-service определяет такой же CONTROL_CHARACTER regexp.; electron-app/src/main/services/ssh-terminal.ts:36-49 — Потребитель повторно проверяет профиль строгой Zod-схемой, используя этот regexp.; electron-app/src/main/main.ts:196-203 — Перед start SSH main требует подтверждение назначения и повторно сравнивает профиль.; electron-app/src/main/main.ts:246-258 — host и userName отображаются в native destination confirmation; эффект control characters на целевой Windows dialog не проверялся.; electron-app/src/main/services/ssh-terminal.ts:168-194 — Назначение и username передаются как поля ConnectConfig; hostVerifier сравнивает наблюдаемый SHA-256 с сохранённым fingerprint перед аутентификацией. Что подтверждают назначенные тесты и какие проверки они не устанавливают? Прочитаны round-trip, отличающийся ciphertext каждого save, wrong password, короткий новый пароль, диапазон auto-lock и SSH migration/type tests. Mutation tests изменяют заголовок без пересчёта его SHA-256, поэтому большинство таких мутаций отвергаются уже digest-проверкой и не доказывают независимо AAD/GCM-защиту. Сам код AAD проверен отдельно. В назначенном тестовом файле нет независимых vectors Argon2/AES, header tamper с заново вычисленным digest, truncation/unsafe-KDF cases, глубоких/неизвестных JSON-полей и key-disposal failure tests. Отсутствие теста само по себе не считается уязвимостью; существующие тесты не запускались. electron-app/src/main/vault/codec.test.ts:45-67 — Тесты проверяют padded round-trip и различие ciphertext двух сохранений.; electron-app/src/main/vault/codec.test.ts:69-90 — Mutation cases XOR один байт без пересчёта digest; отдельно проверяются wrong password и короткий новый пароль.; electron-app/src/main/vault/codec.test.ts:92-136 — Оставшиеся тесты охватывают auto-lock и legacy SSH migration/type, но не структурный бюджет или отказные пути очистки.; electron-app/src/main/vault/codec.ts:161-162 — Header digest проверяется до GCM, поэтому обычная header mutation может остановиться на этой ранней проверке. Является ли открытие старого валидного vault или наличие публичных параметров в заголовке обходом защиты? Нет в принятой модели. Формат намеренно оставляет публичные suite/VaultId/KDF/salts/nonces/length в заголовке, а имена, settings и records находятся в зашифрованном VaultDocument. Свежий процесс не отличает старую корректно аутентифицированную копию без доверенного монотонного счётчика; это явно документированный остаточный риск. In-session digest conflict относится к storage и не заявляется как глобальная anti-rollback защита codec. docs/vault-format.md:19-36 — Бинарная схема явно задаёт публичный криптографический заголовок и ciphertext.; electron-app/src/shared/contracts.ts:21-63 — Имена, records, SSH-поля и settings входят в VaultDocument.; electron-app/src/main/vault/codec.ts:119-137 — Сериализованный document помещается в padded plaintext и шифруется payload AES-256-GCM до формирования файла.; docs/threat-model.md:29-31 — Threat model прямо указывает невозможность различить исторический валидный rollback после нового процесса без внешнего счётчика. |
| vault-storage | not recorded | Reported | Полностью статически проверены оба назначенных файла и необходимые вызывающие пути. Выявлены пять дефектов: разрыв между проверкой и заменой при сохранении; перезапись возникшего назначения при создании; отсутствие проверки актуального владения writer lock; сохранение скрытой сессии при ошибке очистки; завершение начатого открытия после общей блокировки. Критических и высоких находок нет. Эксплуатационные предпосылки, контрдоказательства и отсутствие динамического подтверждения указаны отдельно. Пишет ли обычный путь хранения plaintext или принимает неаутентифицированный документ? В назначенном коде такого пути не найдено: запись получает результат encodeVault, temp содержит шифротекст, декодирование проверяет GCM перед JSON.parse. При успешном save temp дополнительно сравнивается с подготовленным bytes. Это эффективные меры против подмены до проверки; проблемы между проверкой и фиксацией выделены отдельно. electron-app/src/main/vault/storage.ts:64-76 — Создание пишет результат encodeVault и аутентифицирует перечитанный файл.; electron-app/src/main/vault/storage.ts:85-104 — Сохранение валидирует документ, шифрует, перечитывает temp, аутентифицирует и сравнивает хеши.; electron-app/src/main/vault/storage.ts:221-228 — Файловая запись получает только переданный Buffer шифротекста и синхронизирует его.; electron-app/src/main/vault/codec.ts:106-137 — encodeVault сериализует и шифрует содержимое в памяти, возвращая header+ciphertext.; electron-app/src/main/vault/codec.ts:183-211 — Дешифрование завершает обе GCM-проверки перед разбором JSON и очищает временные ключевые буферы. Может ли обычное сохранение напрямую назначить SSH fingerprint или HIBP consent из renderer? Прямое назначение этих полей подавляется: safeDocument получает HIBP consent из текущей main-сессии, а SSH pin переносится из прежней записи только при совпадении host/port; новый адрес очищает pin. Отдельные main-методы изменяют авторитетное состояние. Имеются положительные и отрицательные тесты этих правил; здесь они только прочитаны. electron-app/src/main/vault/storage.ts:85-90 — save перезаписывает переданные renderer HIBP consent и SSH fingerprint правилами main.; electron-app/src/main/vault/storage.ts:129-149 — setSshHostKey и grantHibpConsent меняют main-owned состояние и откатывают его при ошибке save.; electron-app/src/main/vault/storage.ts:278-287 — Fingerprint сохраняется только у той же записи/адреса/порта; иначе очищается.; electron-app/src/main/vault/storage.test.ts:67-99 — Тест показывает отклонение renderer pin и очистку pin при смене host.; electron-app/src/main/vault/storage.test.ts:101-115 — Тест показывает невозможность изменить consent обычным save. Есть ли реальные проверки обычного второго writer, конфликтов и очистки ключей при штатном закрытии? Да. Неизменённый sibling lock отклоняет второй open, исходный хеш останавливает изменение, случившееся до его чтения, а close удаляет сессию и обнуляет material. Эти результаты подтверждаются исходником и наличием тестов, а не выполнением тестов в данном аудите. electron-app/src/main/vault/storage.ts:105-119 — При несовпадении sourceHash фиксация не выполняется, temp удаляется в finally.; electron-app/src/main/vault/storage.ts:152-164 — Штатное закрытие удаляет сессию, очищает документ/material/hash и освобождает lock.; electron-app/src/main/vault/storage.ts:199-211 — Первоначальная эксклюзивность создаваемого sibling lock обеспечивается wx.; electron-app/src/main/vault/codec.ts:148-151 — disposeMaterial обнуляет rootKey и вспомогательные буферы.; electron-app/src/main/vault/storage.test.ts:29-65 — Тесты покрывают создание/сохранение/повторное открытие, второй writer и заранее изменённый источник.; electron-app/src/main/vault/storage.test.ts:118-130 — Тесты покрывают включённый срок авто-блокировки и допустимое отключение таймера. Достаточно ли stat перед readFile для ограничения выделения памяти на недоверенном изменяемом пути? Нет абсолютной гарантии: readBounded проверяет размер через stat, затем читает заново по имени и сравнивает длину только после readFile. Между ними возможна подмена более крупным файлом; аналогично readdir перечисляет каталог целиком перед slice(0,32). Отдельная уязвимость не заявлена: динамический рост памяти не измерялся, а конкретная эксплуатация через файл в пределах разрешённого размера не установлена; общие availability-атаки исключены политикой. Рекомендуется ограниченное чтение через один FileHandle и ограниченное перечисление. electron-app/src/main/vault/storage.ts:213-218 — Предварительный stat не ограничивает непосредственно последующий readFile; сравнение длины выполняется после чтения.; electron-app/src/main/vault/storage.ts:237-241 — readdir возвращает весь каталог, затем filter и slice ограничивают только число обрабатываемых кандидатов.; electron-app/src/main/vault/codec.ts:13-15 — Размер файла ограничен 256 МиБ, JSON — 64 МиБ.; electron-app/src/main/vault/codec.ts:154-168 — Codec повторно ограничивает Buffer/длину payload, но уже после файлового чтения.; SECURITY.md:19-19 — Availability-атаки и удаление остаются возможными.; SECURITY.md:44-44 — Политика отдельно считает отчётным parser memory exhaustion внутри поддерживаемого ограничения файла. Создаёт ли отказ createMaterial самостоятельный обход writer lock? Обнаружен незавершённый путь очистки: lock получается до createMaterial, а try/catch начинается после него; короткий мастер-пароль или ошибка KDF могут оставить lock/handle. Самостоятельный security finding не заявлен: это удержание/отказ доступности, а не разрешение второго writer; UI предварительно проверяет длину, и зависание из-за неподходящего пароля является действием самого клиента. Требуется failure-injection тест и перенос acquisition/material в единый finally. electron-app/src/main/vault/storage.ts:60-80 — createMaterial вызывается после acquireLock, но до try/catch, освобождающего lock.; electron-app/src/main/vault/codec.ts:69-78 — createMaterial сначала валидирует новый пароль, затем ожидает derivation.; electron-app/src/main/vault/codec.ts:267-269 — Слишком короткий пароль вызывает исключение.; electron-app/src/renderer/src/App.vue:128-138 — Штатная форма создания проверяет длину и совпадение пароля.; SECURITY.md:19-19 — Потеря доступности исключена из основных гарантий. Доказаны ли атаки через алиасы путей или удаление произвольного чужого файла при уборке temp? Нет. canonicalVaultPath выполняет лексический resolve/stat, но не проверяет устойчивую идентичность файла. Уборка удаляет кандидаты с подходящими prefix/suffix и только восьмибайтовой сигнатурой, без аутентификации или строгого формата случайного имени. Это требует отдельной платформенной проверки: не доказано, что алиас ведёт к двум успешным заменам одного объекта на поддерживаемой Windows, либо что cleanup пересекает границу произвольного защищённого чужого пути. Простое удаление подходящего файла/старого lock и восстановление после аварии относятся к ограничениям доступности; спекулятивные уязвимости не добавлены. electron-app/src/main/vault/storage.ts:185-196 — canonicalVaultPath нормализует путь и использует stat, но не realpath/идентичность файла.; electron-app/src/main/vault/storage.ts:237-255 — Кандидат cleanup определяется prefix/suffix/isFile; удаление разрешается только по совпадению magic PMVAULT1.; electron-app/src/main/vault/storage.ts:199-205 — Наличие любого существующего sibling lock приводит к отказу, автоматического удаления stale lock здесь нет.; SECURITY.md:24-25 — Файловая система доверена как зависимость, но файловые метаданные и sibling-файлы являются недоверенными входами.; SECURITY.md:44-46 — Отчётность path/temp атак требует раскрытия или перезаписи чужих данных; обычное удаление исключено. |
| hibp | not recorded | Reported | Полностью проверен hibp.ts и прослежены его вызывающие пути. Найден один дефект низкой серьёзности: проверка NFC-нормализованного значения вместо фактического пароля записи. Передача полного пароля или полного хеша, обход согласия через сохранение документа и перенаправление запроса по коду не подтверждены. Некорректные успешные ответы и отсутствие абсолютного срока запроса отдельно отмечены с учётом доверия к HIBP/HTTPS PKI. Можно ли вызвать сетевую проверку без согласия или подменить согласие при сохранении документа из renderer? Штатный вызов привязан к кнопкам проверки. Основной процесс валидирует sessionId/password и перед первым запросом показывает нативный диалог с отменой по умолчанию, сохраняет согласие и только затем вызывает сервис. Сохранение документа заменяет переданное renderer значение hibpConsent на основное значение сессии. Тест этого контроля присутствует, но не запускался. electron-app/src/renderer/src/App.vue:554-555 — Для обычной записи checkBreach привязан к явной кнопке, а не вводу пароля.; electron-app/src/renderer/src/App.vue:565-567 — Проверка пароля SSH также вызывается отдельной кнопкой.; electron-app/src/main/main.ts:143-159 — Строгая IPC-схема ограничивает пароль одним миллионом символов, требует UUID сессии и выполняет проверку только после согласия.; electron-app/src/main/main.ts:261-268 — Обёртка trusted требует senderFrame с протоколом pmapp: и hostname local.; electron-app/src/main/vault/storage.ts:85-92 — При сохранении поле hibpConsent из renderer заменяется значением основной сессии до шифрования.; electron-app/src/main/vault/storage.ts:140-149 — Согласие читается из основной сессии и откатывается при ошибке сохранения.; electron-app/src/main/vault/storage.test.ts:101-115 — Имеющийся тест проверяет невозможность менять согласие через переданный документ. Раскрывает ли запрос пароль, полный SHA-1, суффикс или пользовательские метаданные; можно ли перенаправить его? В проверенном пути запрос содержит лишь первые пять uppercase hex-символов вычисленного SHA-1. Адрес, метод и заголовки фиксированы, Add-Padding установлен в true. Ответ с не-200 статусом либо Location отклоняется; модуль не выполняет второй запрос по Location. Операций логирования нет, ошибки наружу преобразуются в постоянный reason. Буфер UTF-8 пароля очищается в finally; гарантированное стирание строк этим не обеспечивается. electron-app/src/main/services/hibp.ts:7-14 — SHA-1 преобразуется в uppercase, префикс имеет длину 5, буфер нормализованного пароля очищается в finally.; electron-app/src/main/services/hibp.ts:15-31 — requestRange получает только prefix; наружу возвращаются статусы, счётчик и постоянные причины ошибки, без логирования секрета.; electron-app/src/main/services/hibp.ts:34-53 — Единственный HTTPS-запрос использует фиксированный hostname и prefix-only path, padding; Location и не-200 отклоняются, логирования и перехода по Location нет. Ограничены ли объём успешного ответа и обработка сетевых ошибок? Успешный ответ ограничен 2 МиБ по объявленному и фактически полученному размеру. Превышение фактического размера уничтожает response; ошибки запроса/ответа отвергают promise, после чего возвращается failed/NetworkFailure. Таймаут инициирует destroy запроса. UI отображает failed как непроведённую проверку. Эти контроли не доказывают полноценную валидацию содержимого HTTP 200 или абсолютный срок всей операции. electron-app/src/main/services/hibp.ts:5-5 — Максимум успешного ответа установлен в 2 МиБ.; electron-app/src/main/services/hibp.ts:38-51 — Проверяются Content-Length и накопленный размер; error приводит к reject, timeout уничтожает request.; electron-app/src/main/services/hibp.ts:29-30 — Отклонённый сетевой promise преобразуется в failed/NetworkFailure.; electron-app/src/renderer/src/App.vue:284-288 — failed сохраняется как статус 3 и показывается как непроведённая проверка. Всегда ли некорректный HTTP 200 остаётся неопределённым результатом? Нет: пустое тело, HTML вместо range-данных или строки с неверной структурой пропускаются, а отсутствие совпадения становится notFound. MalformedResponse возвращается только при некорректном счётчике уже совпавшего суффикса. Это подтверждённое ограничение обработки отказов, для исправления которого следует валидировать весь формат ответа и трактовать отсутствие корректного range-ответа как failed. Отдельная атакуемая уязвимость не заявляется: фиксированный HTTPS endpoint и HTTPS PKI являются явными доверенными зависимостями, а источник поддельного успешного ответа в пределах модели не установлен. Обрыв транспортного ответа не приравнивается здесь к нормальному end без проверки поведения runtime. electron-app/src/main/services/hibp.ts:18-27 — Неподходящие строки пропускаются, некорректный счётчик проверяется только при совпадении suffix, общий fallthrough возвращает notFound.; electron-app/src/main/services/hibp.ts:36-48 — У ответа HTTP 200 нет проверки Content-Type или структуры до resolve; транспортные error отклоняются отдельно.; SECURITY.md:24-27 — HIBP endpoint и HTTPS PKI доверены, но ответы объявлены недоверенными входами, а сбой должен означать непроведённую проверку. Есть ли гарантированный общий срок запроса и одинаковые лимиты для отвергнутых HTTP-ответов? В коде есть timeout: 10000 и обработчик timeout, но отсутствует отдельный абсолютный таймер или AbortSignal на всю операцию. Не-200/Location ответ отклоняется для вызывающей стороны сразу, затем response.resume продолжает его дренировать вне счётчика 2 МиБ. Это отмечено как ограничение ресурсов; атака на доверенный endpoint либо локальную доверенную среду не заявляется. Для усиления можно добавить абсолютный deadline и уничтожать отвергнутые ответы вместо их дренирования. electron-app/src/main/services/hibp.ts:34-53 — Полный requestRange содержит только request timeout и обработчик timeout; ветка отклонения статуса вызывает resume до установки счётчика data.; SECURITY.md:19-25 — Доступность не является гарантией, а HIBP/HTTPS PKI и локальная среда указаны доверенными зависимостями. |
| ssh-terminal | not recorded | No issue found | Оба назначенных файла полностью прочитаны; проверены вызывающий main-процесс, потребитель терминальных событий и соответствующие участки установленного ssh2/xterm. Подтверждённых уязвимостей в заявленной модели угроз не установлено. Обнаруженные пробелы отмены незавершённых подключений, управления потоком и очистки обработчиков сохранены отдельно от уязвимостей. Проверка границ параметров DH group exchange в криптографическом runtime остаётся открытым вопросом. Может ли входящий запрос произвольно подменить SSH-адрес или передать параметры запуска внешней команды? В проверенном пути запрос содержит только идентификаторы сейфа/записи/терминала и размеры. Main получает отдельную копию профиля из открытого сейфа, показывает нативное подтверждение и повторно сравнивает адрес, пользователя, тип аутентификации, fingerprint и режим совместимости после подтверждения. Модуль проверяет форму и пределы профиля, затем передаёт host/port/username прямо в ssh2; shell открывается с фиксированным типом терминала. Пути запуска дочернего процесса или сохранения ключа в файл здесь нет. electron-app/src/main/main.ts:188-203 — Строгий IPC-запрос содержит идентификаторы и размеры; профиль читается из store до и после нативного подтверждения.; electron-app/src/main/main.ts:228-229 — sameSshTarget сравнивает адрес, порт, пользователя, тип аутентификации, fingerprint и allowLegacyAlgorithms.; electron-app/src/main/main.ts:246-258 — Нативный диалог показывает пользователя, адрес, порт и закреплённый fingerprint; действие по умолчанию — отмена.; electron-app/src/main/vault/storage.ts:123-126 — SSH-профиль возвращается через structuredClone только для существующей неудалённой SSH-записи открытой сессии.; electron-app/src/main/services/ssh-terminal.ts:36-59 — Строгие схемы ограничивают host, port, username, секретные поля, fingerprint, UUID и размеры; управляющие символы host/username запрещены.; electron-app/src/main/services/ssh-terminal.ts:131-132 — Создаётся встроенный SSH shell с фиксированным term=xterm-256color и проверенными размерами.; electron-app/src/main/services/ssh-terminal.ts:168-194 — Адрес и учётные данные передаются Client.connect в памяти; конфигурация не содержит команды, файла ключа, агента или внешнего терминала. Можно ли автоматически согласовать запрещённые устаревшие алгоритмы? Современный и совместимый наборы заданы явными массивами; автоматического перехода к совместимости нет. RC4, Blowfish и CAST отсутствуют в обоих наборах. Совместимость выбирается сохранённым флагом и сопровождается отдельным нативным предупреждением перед подключением. Пароли не используются для других методов, кроме password/keyboard-interactive; закрытые ключи ограничены Ed25519/ECDSA, поэтому RSA user authentication с возможным SHA-1 fallback отклоняется. Это подтверждает политику имён алгоритмов; вопрос фактических параметров DH рассмотрен отдельно. electron-app/src/main/services/ssh-terminal.ts:17-34 — Определены два явных набора kex/cipher/serverHostKey/hmac/compress; запрещённые RC4, Blowfish и CAST в них не включены.; electron-app/src/main/services/ssh-terminal.ts:176-178 — Набор выбирается только по allowLegacyAlgorithms, authHandler явно ограничен password/keyboard-interactive либо publickey.; electron-app/src/main/services/ssh-terminal.ts:186-194 — Проверка типа закрытого ключа предшествует connect; ошибка завершает запрос без fallback.; electron-app/src/main/services/ssh-terminal.ts:230-234 — assertModernPrivateKey допускает только приватные ключи Ed25519 и перечисленные ECDSA-типы.; electron-app/src/main/main.ts:196-201 — Совместимый профиль требует нативного предупреждения и повторной проверки профиля перед подключением.; electron-app/src/main/main.ts:232-243 — Предупреждение перечисляет разрешённые устаревшие алгоритмы, имеет отмену по умолчанию и вызывается для каждого совместимого подключения.; electron-app/src/renderer/src/App.vue:324-330 — Обычный UI требует отдельного явного подтверждения перед установкой флага совместимости.; electron-app/src/main/services/ssh-terminal.test.ts:17-30 — Тесты проверяют современный/совместимый наборы и отклонение RSA private key.; electron-app/src/main/services/ssh-terminal.test.ts:151-198 — Синтетический сервер Group1/3DES/ssh-rsa/MD5/zlib используется для теста отказа современного режима и успеха явно включённой совместимости. Можно ли отправить пароль до проверки host key либо обойти изменившийся закреплённый ключ через TOFU? В проверенном пути нет: verifier возвращает true только при непустом ожидаемом SHA-256 fingerprint и точном совпадении. Неизвестный ключ отклоняется на первой попытке; main предлагает нативное подтверждение, сохраняет fingerprint и перепроверяет профиль перед повтором. Изменившийся ключ возвращает hostKeyMismatch и не попадает в ветку TOFU. Дополнительно ssh2 проверяет подпись обмена, поэтому одного предъявления публичного ключа недостаточно для успешного подключения. Отдельного интеграционного теста mismatch в назначенном файле нет; вывод основан на статическом пути, а не заявленном запуске тестов. electron-app/src/main/services/ssh-terminal.ts:115-117 — Ожидаемый fingerprint фиксируется из профиля при создании попытки подключения.; electron-app/src/main/services/ssh-terminal.ts:150-154 — Неизвестный fingerprint и несовпадение уже закреплённого fingerprint возвращают разные статусы.; electron-app/src/main/services/ssh-terminal.ts:179-184 — Host verifier принимает только точное совпадение с непустым ожидаемым fingerprint.; electron-app/src/main/services/ssh-terminal.ts:226-227 — Fingerprint вычисляется SHA-256 по байтам host key и кодируется base64 без padding.; electron-app/src/main/main.ts:204-225 — Только hostKeyRequired вызывает TOFU; перед сохранением и повтором проверяется актуальный профиль, mismatch возвращается без перепривязки.; electron-app/node_modules/ssh2/lib/client.js:281-287 — ssh2 передаёт возвращённое приложением логическое значение в проверку host key.; electron-app/node_modules/ssh2/lib/protocol/kex.js:1200-1213 — Отказ host verifier приводит к фатальной ошибке key exchange.; electron-app/node_modules/ssh2/lib/protocol/kex.js:688-714 — Подпись exchange hash проверяется host public key с SHA-2 для RSA-SHA2; неверная подпись завершает handshake.; electron-app/src/main/services/ssh-terminal.test.ts:88-100 — Синтетический тест проверяет первый отказ TOFU и успешный shell после явного закрепления fingerprint. Раскрывают ли обработчики аутентификации или ошибок секреты через UI и сообщения? Обработчик keyboard-interactive отправляет пароль только один раз и только на единственный скрытый prompt; остальные запросы получают пустой ответ. Обычные сетевые ошибки сводятся к фиксированным категориям. Локальный Buffer PEM обнуляется при settle, строки профиля заменяются пустыми. Это не доказывает стирание всех копий внутри ssh2/V8 и не устраняет удержание данных при незавершённом shell; такие гарантии не приписываются реализации. electron-app/src/main/services/ssh-terminal.ts:120-128 — settle обнуляет созданный модулем privateKey Buffer и очищает строковые поля копии профиля.; electron-app/src/main/services/ssh-terminal.ts:160-165 — Пароль передаётся максимум в один одиночный prompt с echo=false.; electron-app/src/main/services/ssh-terminal.ts:237-257 — classifyConnectionFailure возвращает фиксированную категорию вместо исходного текста сетевой ошибки.; electron-app/src/main/services/ssh-terminal.test.ts:33-49 — Тесты перечисляют ожидаемую классификацию синтетических ошибок.; electron-app/src/main/services/ssh-terminal.test.ts:103-148 — Есть положительный синтетический тест единственного скрытого keyboard-interactive prompt.; AGENTS.md:41-41 — Политика прямо признаёт невозможность гарантированного стирания строк JavaScript и копий V8. Закрываются ли попытки подключения при блокировке сейфа или закрытии вкладки? Подтверждён пробел жизненного цикла, отдельно от доказанной уязвимости: sessions содержит клиент только после успешного открытия shell; close/closeAll/closeByVault обходят лишь этот Map. Поэтому pending handshake или shell не отменяется закрытием вкладки/сейфа. readyTimeout заканчивается после USERAUTH_SUCCESS, а отдельного срока ожидания shell нет; отвечающий на keepalive сервер может удерживать попытку. Сильное контрдоказательство против постоянного живого терминала после позднего успеха: размонтированный renderer повторно закрывает терминал при результате connected. Сохранение сетевой попытки и её копий данных подтверждено, но доступ иного атакующего к секретам не установлен; сбор дампов и availability прямо ограничены моделью. Нужны регистрация pending-клиента до сети, отмена по terminalId/vaultSessionId, срок ожидания shell и проверка отмены перед публикацией успешной сессии. electron-app/src/main/services/ssh-terminal.ts:79-83 — start проверяет только уже зарегистрированный terminalId и затем начинает connect.; electron-app/src/main/services/ssh-terminal.ts:98-110 — closeAll/closeByVault обходят только sessions; close вызывает finish по идентификатору.; electron-app/src/main/services/ssh-terminal.ts:112-146 — Клиент и секретная копия существуют до shell callback; запись в sessions появляется лишь после успешного callback.; electron-app/src/main/services/ssh-terminal.ts:168-174 — Заданы readyTimeout=15000 и keepalive, отдельный shell timeout отсутствует в конфигурации.; electron-app/node_modules/ssh2/lib/client.js:364-370 — ssh2 сбрасывает readyTimeout при USERAUTH_SUCCESS до вызова обработчика ready приложения.; electron-app/node_modules/ssh2/lib/client.js:1826-1841 — Shell ожидает ответа в очереди callback без самостоятельного таймера на этом пути.; electron-app/src/main/main.ts:270-274 — Глобальная блокировка закрывает известные терминалы, затем vault store и уведомляет renderer.; electron-app/src/main/main.ts:281-287 — Автоблокировка по сейфу вызывает closeByVault и закрывает store с уведомлением renderer.; electron-app/src/renderer/src/components/TerminalSession.vue:126-138 — Размонтирование ставит disposed, удаляет подписки и запрашивает закрытие terminalId.; electron-app/src/renderer/src/components/TerminalSession.vue:162-168 — Поздний connected для disposed-компонента вызывает повторное закрытие терминала.; SECURITY.md:19-19 — Модель не гарантирует защиту от дампов/привилегированного доступа к unlocked process и availability-атак. Образует ли terminalId отдельную границу между пользователями или сейфами? Методы write/resize проверяют существование terminalId, а не повторную принадлежность открытому сейфу; UUID выбирает renderer. Однако проверенный продукт использует одно окно и один renderer для всех открытых сейфов, поэтому отдельная межпользовательская граница здесь не установлена. Одновременные start с одинаковым UUID могут пройти проверку до регистрации и перезаписать Map; обычный UI создаёт разные идентификаторы, а атакующий сервер не задаёт terminalId. Это остаётся пробелом устойчивости менеджера; pending-регистрация также устранит дубликаты. electron-app/src/main/services/ssh-terminal.ts:79-95 — Проверка дубликата start и операции write/resize используют terminalId.; electron-app/src/main/services/ssh-terminal.ts:138-139 — Map.set выполняется после асинхронного открытия shell без повторной проверки дубликата.; electron-app/src/main/services/ssh-terminal.ts:198-201 — requireSession проверяет только наличие и closed-флаг терминала.; electron-app/src/main/main.ts:19-21 — В приложении один менеджер терминалов, отправляющий события единственному mainWindow.; electron-app/src/main/main.ts:165-168 — Операции терминала проходят общий trusted wrapper.; electron-app/src/main/main.ts:261-267 — IPC wrapper проверяет pmapp://local sender URL; дополнительной привязки terminalId к отдельному sender в этом пути нет.; electron-app/src/renderer/src/App.vue:311-320 — Обычный UI создаёт TerminalTab с новым crypto.randomUUID и привязкой к vaultSessionId/recordId. Ограничивают ли размеры IPC-сообщений совокупную нагрузку от удалённого вывода? Ограничен размер одного исходящего фрагмента и одной записи в терминал, но не суммарная очередь. data/stdout и stderr сразу пересылаются renderer, тот вызывает terminal.write без callback подтверждения обработки. Обратного давления до SSH-канала нет. Контрдоказательства: scrollback ограничен 5000 строками, а xterm отбрасывает новые записи после примерно 50 миллионов ожидающих символов. Эти меры не равны общему лимиту IPC, но аварийное исчерпание памяти всего приложения в данной статической проверке не воспроизводилось. Это пробел управления потоком с риском зависания/потери вывода; не заявлена утечка или выполнение кода. Для усиления нужны подтверждения обработанных байтов, pause/resume SSH stream, общий предел очереди и обработка отказа xterm. electron-app/src/main/services/ssh-terminal.ts:15-15 — Максимальный фрагмент терминала равен 64\*1024 символам.; electron-app/src/main/services/ssh-terminal.ts:58-59 — Входящие write ограничены по длине; resize ограничен по размерам.; electron-app/src/main/services/ssh-terminal.ts:86-90 — Возвращаемое stream.write значение обратного давления не используется.; electron-app/src/main/services/ssh-terminal.ts:138-141 — Обработчики data обоих потоков немедленно декодируют и отправляют вывод.; electron-app/src/main/services/ssh-terminal.ts:204-207 — emitText только делит строку на фрагменты, без счётчика очереди или ожидания потребителя.; electron-app/src/main/main.ts:20-20 — Emitter сразу вызывает webContents.send.; electron-app/src/renderer/src/components/TerminalSession.vue:76-76 — Scrollback xterm установлен в 5000 строк.; electron-app/src/renderer/src/components/TerminalSession.vue:95-97 — Получатель вызывает terminal.write без callback и без обработки исключения в этом обработчике.; electron-app/node_modules/@xterm/xterm/src/common/input/WriteBuffer.ts:13-20 — xterm содержит аварийный watermark=50000000 и поясняет необходимость flow control.; electron-app/node_modules/@xterm/xterm/src/common/input/WriteBuffer.ts:103-105 — При превышении watermark write выбрасывает исключение до добавления новой записи.; SECURITY.md:19-19 — Availability-атаки явно указаны как возможный остаточный риск. Может ли терминальный вывод писать в clipboard, открывать внешние ссылки или исполняться как HTML? В проверенном потребителе вывод передаётся xterm.write, OSC-52 и команды изменения заголовка поглощаются. Renderer работает с sandbox/contextIsolation без Node; main блокирует навигацию, новые окна и webview. Эти контрмеры исключают прямой путь из произвольных SSH-байтов в HTML или clipboard в изученном коде; эксплуатация неизвестной ошибки самого xterm не предполагается. electron-app/src/renderer/src/components/TerminalSession.vue:82-97 — Подключён FitAddon; OSC 52/0/1/2 поглощаются, данные передаются xterm.write.; electron-app/src/main/main.ts:91-100 — Окно использует sandbox, contextIsolation, webSecurity, отключённый Node и запрещённый webview; packaged DevTools выключены.; electron-app/src/main/main.ts:112-114 — Навигация, открытие новых окон и подключение webview блокируются обработчиками main. Безопасно ли удалять все error listeners до полного закрытия SSH-транспорта? Есть отдельный риск надёжности: finish удаляет все listeners клиента и потока, затем вызывает end, которое инициирует завершение TCP без немедленного destroy. ssh2 ещё может переслать socket error в Client.error; после снятия обработчиков такая ошибка способна стать необработанной. Сетевой сценарий и точное поведение Electron без запуска не подтверждены, поэтому это не выдано за воспроизведённую уязвимость. При усилении следует сохранять безопасный error listener до фактического close и не удалять внутренние обработчики зависимости без необходимости. electron-app/src/main/services/ssh-terminal.ts:210-222 — finish удаляет сессию, снимает все stream/stderr/client listeners и вызывает end.; electron-app/node_modules/ssh2/lib/client.js:798-805 — Socket error преобразуется в Client.emit('error').; electron-app/node_modules/ssh2/lib/client.js:1179-1188 — Client.end отправляет DISCONNECT и вызывает socket.end; уничтожение сокета реализовано отдельно в destroy. Проверяются ли фактические размеры и свойства присланной DH group exchange группы? Открытый вопрос для проверки runtime. Современный набор допускает diffie-hellman-group-exchange-sha256. Установленный ssh2 запрашивает диапазон 2048–8192 бит, но в разобранном JS-пути проверяет лишь тип Buffer для p/g и передаёт их в Node createDiffieHellman/generateKeys; локальной проверки полученной длины и verifyError не найдено. Это не доказательство принятия слабой группы: отказ может обеспечивать pinned Node/OpenSSL, а подпись обмена остаётся обязательной. Без разрешённой динамической проверки нельзя утверждать downgrade, восстановление секрета или конкретную стоимость DoS. Следует отдельно проверить малые/чрезмерные/небезопасные синтетические группы на поставляемом Electron либо исключить GEX до подтверждения нужных ограничений. electron-app/src/main/services/ssh-terminal.ts:17-18 — В современном allowlist есть diffie-hellman-group-exchange-sha256.; electron-app/node_modules/ssh2/lib/protocol/kex.js:52-53 — Запрашиваемые границы GEX определены как 2048 и 8192 бит.; electron-app/node_modules/ssh2/lib/protocol/kex.js:1395-1398 — Эти границы отправляются серверу в GEX_REQUEST.; electron-app/node_modules/ssh2/lib/protocol/kex.js:1470-1485 — После извлечения p/g из пакета код вызывает setDHParams и generateKeys; оставлен TODO validate prime.; electron-app/node_modules/ssh2/lib/protocol/kex.js:1403-1415 — Параметры проверяются на Buffer, затем передаются в Node crypto без отдельной JS-проверки длины группы.; electron-app/node_modules/ssh2/lib/protocol/kex.js:698-714 — Подпись обмена обязательна; её провал вызывает fatal error и ограничивает возможность сетевой подмены группы. |
| renderer | not recorded | Reported | Полностью просмотрены все 14 назначенных файлов, включая UI-стенды. Подтверждён один дефект средней серьёзности: автоматические ответы xterm на команды SSH-сервера обновляют общий таймер активности и позволяют удалённому endpoint предотвращать автоблокировку всех открытых сейфов. Остальные проверенные границы и ограничения перечислены отдельно. Вставляются ли поля сейфа, SSH-вывод или URL как исполняемый HTML? Подтверждённого пути DOM-инъекции не найдено: имена/поля выводятся через Vue-интерполяции и form bindings; URL редактируется как текст. SSH-вывод передаётся xterm.write. Source index.html получает CSP через Vite transform и main response header, поэтому отсутствие CSP meta в исходном HTML само по себе не является дефектом. electron-app/src/renderer/src/App.vue:533-557 — Имена выводятся интерполяцией; пароль и URL привязаны к input, URL не используется как href/src.; electron-app/src/renderer/src/components/FolderTreeNode.vue:14-20 — Имена папок интерполируются в текст; рекурсивный компонент не создаёт HTML из имени.; electron-app/src/renderer/src/components/FluentIcon.vue:5-44 — Иконки выбираются из статически описанных SVG-шаблонов.; electron-app/src/renderer/src/components/TerminalSession.vue:95-96 — Удалённый вывод направляется в parser xterm, а не в HTML sink.; electron-app/src/shared/content-security-policy.ts:1-6 — Общая CSP запрещает сети/frames/objects и inline scripts, оставляя inline CSS для xterm.; electron-app/vite.config.ts:9-15 — Vite добавляет общую CSP в meta построенного HTML.; electron-app/src/main/main.ts:65-74 — Та же CSP добавляется в response headers.; electron-app/src/main/main.ts:91-100 — Продукт включает sandbox/contextIsolation/webSecurity и отключает nodeIntegration/webviewTag.; electron-app/src/main/main.ts:112-114 — Навигация, новые окна и webview запрещены. Можно ли обойти подтверждение SSH или заменить закреплённый ключ через renderer? Проверенный путь сохраняет доверенное решение в main: renderer передаёт только идентификаторы и геометрию. UI-подтверждение legacy является дополнительным; main повторно показывает native-предупреждение. Fingerprint из renderer при сохранении ограничивается main-owned состоянием для того же назначения. electron-app/src/renderer/src/components/TerminalSession.vue:140-149 — Запрос запуска содержит terminalId/vaultSessionId/recordId и cols/rows, без credentials или fingerprint.; electron-app/src/renderer/src/App.vue:324-337 — Включение legacy требует явного действия в UI, отключение доступно отдельно.; electron-app/src/main/main.ts:196-224 — Назначение берётся из store, повторно сравнивается после native dialogs; первое доверие сохраняется main.; electron-app/src/main/main.ts:232-258 — Main имеет отдельные native-подтверждения назначения и legacy с default/cancel на отказ.; electron-app/src/main/vault/storage.ts:85-90 — Renderer-документ проходит validation и constrainSshFingerprints до сохранения.; electron-app/src/main/vault/storage.ts:278-285 — Для неизменного host/port сохраняется старый main-owned fingerprint; для нового назначения он сбрасывается. Достаточны ли видимые OSC/clipboard контроли для их заявленного узкого назначения? OSC-52 и переименование заголовков явно поглощаются, стандартные UI-пути копирования терминала вызывают main-managed conditional clear. Это не устраняет renderer-001, использующий CSI. Windows clipboard history/roaming остаются документированным ограничением; проверка не утверждает безопасность всех нативных способов копирования. electron-app/src/renderer/src/components/TerminalSession.vue:86-90 — OSC 52/0/1/2 перехватываются обработчиками, возвращающими true.; electron-app/src/renderer/src/components/TerminalSession.vue:226-247 — Копирование выделения и контекстное меню направлены в узкие preload API с временем очистки.; electron-app/src/main/main.ts:169-177 — Native-меню копирует через writeClipboardWithConditionalClear и ограничивает размер selection.; electron-app/src/main/main.ts:309-328 — Буфер очищается по таймеру только при совпадении SHA-256 текущего содержимого с ранее записанным.; docs/threat-model.md:14-14 — Подавление Windows clipboard history/roaming явно не реализовано и указано как ограничение. Остаются ли активные компоненты и подписки терминала после обычной обработки блокировки? При полученном событии блокировки Vue убирает соответствующие terminalTabs, а TerminalSession при unmount отписывается, закрывает SSH и dispose-ит xterm. Clear-функции снимают ссылки и очищают основные secret fields; это не является гарантией физического стирания JS-строк. Отдельная гонка незавершённого open рассматривается ниже. electron-app/src/renderer/src/App.vue:91-99 — onLock вызывает clearRendererSecrets; onVaultLocked вызывает removeLockedVault.; electron-app/src/renderer/src/App.vue:437-466 — При блокировке удаляются вкладки, draft и основные secret fields; полная блокировка очищает dialogState.; electron-app/src/renderer/src/components/TerminalSession.vue:126-138 — Unmount отписывается от событий, прекращает observer, закрывает SSH и dispose-ит xterm.; electron-app/src/renderer/src/components/TerminalSession.vue:166-168 — Поздний успешный SSH result после unmount вызывает закрытие терминала.; electron-app/src/renderer/src/recordDraft.ts:17-23 — Переключение SSH-записи на другой тип удаляет ssh payload.; electron-app/src/renderer/src/recordDraft.test.ts:54-62 — Имеется статически просмотренный тест удаления hidden SSH secrets при смене типа.; docs/threat-model.md:9-9 — Модель отдельно оговаривает невозможность гарантировать неперемещаемую/невыгружаемую JS-память. Связан ли отображённый HIBP-результат с текущим значением поля пароля? Есть ограничение корректности UI: после await проверяется только идентичность draft, но не неизменность пароля; обычный v-model также не сбрасывает breach metadata при изменении значения. Поэтому результат для прежнего значения может остаться рядом с новым. Отдельная атакующая сторона и нарушение разрешённого сетевого назначения этим кодом не доказаны; в findings не включено. Согласие по-прежнему получает и сохраняет main, а сетевой сбой UI обозначает как «не проверено». electron-app/src/renderer/src/App.vue:269-289 — Пароль снимается до await; затем проверяется только draft identity и результат записывается в breach. Failed отображается как непроверенное состояние.; electron-app/src/renderer/src/App.vue:554-556 — Изменение password через v-model не содержит сброса breach status/message.; electron-app/src/renderer/src/App.vue:566-568 — SSH-password имеет ту же привязку без invalidation результата.; electron-app/src/main/main.ts:143-159 — HIBP запросу предшествует проверка сохранённого согласия или native-подтверждение.; electron-app/src/main/vault/storage.ts:85-90 — При сохранении renderer не может самостоятельно изменить main-owned hibpConsent. Может ли поздний open/create snapshot появиться после события блокировки? Статически подтверждён пробел отмены: submitVaultDialog без проверки актуальности операции вызывает addTab после await; onLock очищает состояние, но не отмечает незавершённый запрос отменённым. Main closeAll закрывает только уже зарегистрированные сеансы, а open может зарегистрировать новый позже. Передано интеграции для совместной оценки с vault-storage/electron-boundary. Здесь не заявляется отдельная подтверждённая эксплуатация: влияние гонки на поддерживаемой Windows-платформе не воспроизводилось, а одно предположение о доступе к доверенному разблокированному host недостаточно для finding. electron-app/src/renderer/src/App.vue:128-149 — submitVaultDialog удерживает локальный state, ожидает open/create и без generation/state guard вызывает addTab.; electron-app/src/renderer/src/App.vue:158-164 — addTab вставляет полученный snapshot и делает его активным.; electron-app/src/renderer/src/App.vue:466-466 — clearRendererSecrets сбрасывает UI-ссылки, но не вводит отмену pending open/create.; electron-app/src/main/main.ts:270-274 — Событие app:lock отправляется после store.closeAll.; electron-app/src/main/vault/storage.ts:32-41 — open асинхронно читает/декодирует файл и регистрирует сеанс после ожиданий.; electron-app/src/main/vault/storage.ts:162-175 — closeAll перечисляет текущие session keys; addSession не проверяет эпоху блокировки.; docs/threat-model.md:5-5 — Разблокированный Windows-account/process является доверенной зависимостью; это ограничивает самостоятельную квалификацию ущерба. Могут ли дерево папок, цвета или UI-стенды сами по себе расширить возможности атакующего? Подтверждённого самостоятельного пути не найдено. Рекурсивное дерево получает документ, чья ancestry проверяется main; terminal colors допускают только полную hex-форму перед передачей xterm. Стенды используют синтетический bridge и намеренные CSP-negative probes. Их executeJavaScript/capturePage выполняются trusted тестовым main над синтетическим содержимым; это не доказательство соответствующей production-возможности. electron-app/src/renderer/src/components/FolderTreeNode.vue:6-20 — Рекурсия строится из folder parentId и Vue-компонентов.; electron-app/src/main/vault/codec.ts:283-287 — Перед использованием документа проверяется root и ancestry всех папок.; electron-app/src/main/vault/codec.ts:326-337 — Циклы, отсутствующие родители и глубина более 64 отвергаются.; electron-app/src/renderer/src/terminalAppearance.ts:5-13 — Принимаются только полные #RRGGBB цвета, иначе фиксированный fallback.; electron-app/src/renderer/src/components/TerminalSession.vue:30-53 — xterm theme получает нормализованные foreground/background.; electron-app/tests/terminal-renderer/fixture.ts:5-31 — Fixture задаёт синтетический frozen bridge без production vault/credential IPC.; electron-app/tests/terminal-renderer/fixture.ts:134-148 — Inline script, remote style и OSC/HTML строки намеренно используются как отрицательные CSP/terminal проверки.; electron-app/tests/terminal-renderer/main.cjs:21-35 — Тестовый main использует sandboxed offscreen window и сохраняет результат/снимок синтетического стенда; он не обращается к vault.; electron-app/src/renderer/src/App.vue:44-44 — Диагностический badge зависит от build-defined значения.; electron-app/src/renderer/src/App.vue:473-477 — При diagnostic сборке badge видимо включается в header.; electron-app/vite.config.ts:17-19 — Значение PM_SCREENSHOT_DIAGNOSTICS определяется на этапе сборки renderer. |
| build-release | not recorded | No issue found | Все девять назначенных файлов проверены статически, включая все записи package-lock.json. Подтверждённых уязвимостей с пересечением заявленной границы доверия не обнаружено. Зафиксированы работающие ограничения сборки и проверки подписи, а также ограничения ручного процесса выпуска; управление средой сборки и подписи остаётся обязанностью доверенного оператора. Зафиксированы ли версии и источники npm-зависимостей? Да. Проверены корневая запись и все 426 записей пакетов lockfile. Все прямые зависимости совпадают между package.json, корнем lockfile и установленной в lockfile версией. У каждой записи пакета точная версия, URL https://registry.npmjs.org с путём соответствующего имени и версии и синтаксически корректный SHA-512 integrity длиной 64 байта после декодирования. Дублирующихся JSON-ключей нет. Проверка прочитала только текст JSON; скачивание и сверка фактических архивов не выполнялись. Диапазоны в зависимостях сторонних пакетов не отменяют точные разрешённые версии в lockfile. electron-app/package.json:22-42 — Все прямые production- и development-зависимости заданы точными версиями.; electron-app/package-lock.json:1-31 — Lockfile версии 3 содержит корневой манифест с теми же прямыми зависимостями.; electron-app/package-lock.json:32-5752 — Полный диапазон 426 записей пакетов, проверенный на точные версии, соответствующие npm HTTPS URL и корректный SHA-512 integrity; исключений не найдено. Позволяет ли lockfile заключить, что выполнены проверка лицензий и актуальный vulnerability review? Нет. Метаданные lockfile не заменяют актуальную проверку advisory и содержимого поставляемых зависимостей. У buildcheck, cpu-features и ssh2 отсутствует поле license; это вопрос проверки лицензий, а не доказательство отсутствия лицензии или уязвимости. glob и inflight содержат предупреждения deprecated и помечены dev; такие предупреждения сами по себе не устанавливают применимый CVE или путь эксплуатации в продукте. Никакие CVE по памяти не приписывались. Наличие install scripts означает, что установка зависимостей исполняет сторонний код в доверенной среде; проверка integrity фиксирует архив, но не доказывает безопасность его поведения. electron-app/package-lock.json:2119-2127 — Запись buildcheck не содержит license.; electron-app/package-lock.json:2383-2396 — cpu-features помечен optional, содержит hasInstallScript и не содержит license.; electron-app/package-lock.json:5026-5042 — ssh2 содержит hasInstallScript и optional-зависимости cpu-features/nan; поле license отсутствует.; electron-app/package-lock.json:3268-3289 — glob имеет предупреждение deprecated и dev=true.; electron-app/package-lock.json:3538-3549 — inflight имеет предупреждение deprecated и dev=true.; electron-app/package.json:20-20 — Для проверки полного и production-дерева предусмотрен отдельный скрипт audit:all; его результат в данном статическом аудите не получался. Может ли runtime-переменная включить режим скриншотов в обычной сборке? В проверенном пути сборки такой переход не обнаружен: esbuild заменяет обращение main-процесса строковой константой, Vite заменяет соответствующее выражение renderer булевой константой. Оба включают диагностику только при значении '1' в окружении процесса сборки. Потребитель main вызывает настройку защиты до показа окна; ошибка конфигурации уничтожает окно. Renderer показывает диагностическую метку по своей скомпилированной константе. Тесты проверяют обычный и диагностический режим и отказ платформенного вызова, но здесь не запускались. electron-app/scripts/build.mjs:11-20 — define подставляет литерал для PM_SCREENSHOT_DIAGNOSTICS при сборке main и preload.; electron-app/vite.config.ts:17-19 — Renderer получает булев литерал диагностики из окружения сборки.; electron-app/src/main/main.ts:103-121 — configureCaptureProtection вызывается до ready-to-show и загрузки UI.; electron-app/src/main/services/capture-protection.ts:7-17 — Функция устанавливает ожидаемое состояние, проверяет isContentProtected и уничтожает окно при ошибке.; electron-app/src/renderer/src/App.vue:44-44 — Флаг метки renderer берётся из заменяемого при сборке выражения.; electron-app/src/renderer/src/App.vue:471-476 — Диагностический режим обозначается видимой меткой в заголовке.; electron-app/src/main/services/capture-protection.test.ts:9-39 — Исходник тестов содержит положительные и отрицательные проверки настройки capture protection. Автоматически ли исключены диагностические, неподписанные и тестово подписанные кандидаты из выпуска? Полный автоматический release gate в назначенных скриптах отсутствует: dist выполняет сборку и упаковку, sign и sign:test являются отдельными командами и используют тот же путь PasswordManager.exe. Выбор диагностического окружения и разделение каталогов остаются ручными. Это ограничение процедуры выпуска, требующее соблюдения правил доверенным оператором. Путь от vault/SSH/renderer-ввода к изменению этой среды или публикации артефакта не установлен. При явно доверенной среде выпуска данный пробел не классифицирован как эксплуатация атакующим. Для будущего выпуска полезен единый gate с очисткой окружения, отдельными каталогами диагностики/тестов, обязательной production-проверкой подписи и проверкой итогового артефакта. electron-app/package.json:9-20 — Команды сборки, упаковки, тестового и production-подписания раздельны; dist сам не вызывает sign.; electron-app/package.json:49-65 — Настройки по умолчанию используют общий каталог release и имя PasswordManager.exe.; electron-app/scripts/build.mjs:11-13 — Режим main-процесса выбирается окружением доверенной сборки.; README.md:7-7 — Документация прямо обозначает development build и незавершённый полный release gate.; README.md:40-40 — Документация требует отдельного каталога диагностического кандидата и запрещает его выпуск.; docs/threat-model.md:5-5 — Trusted release worker является доверенной предпосылкой, а не границей изоляции от атакующего. Отказывает ли production-команда подписи при ошибке подписи или недоверенной цепочке? Да, по статическому пути sign.ps1: обязательны входы среды и существующие файлы, успешный SignTool sign с SHA256 и RFC 3161 /tr, наличие сертификата, его текущий срок действия, Code Signing EKU и сертификат отметки времени. В production-ветке требуются успешный SignTool verify /pa /all /v и Authenticode Status=Valid. TestBuild представляет отдельную явно выбранную ветку с требованием метки Test Build (Untrusted), которая пропускает production-проверку цепочки. Самоподписанный сертификат, которому Windows не доверяет, не удовлетворяет production-ветке. Корневое хранилище доверия, Windows SDK, выбранный PFX и отсутствие подмены файла во время подписи являются доверенными предпосылками; отдельного запрета уже доверенного самоподписанного сертификата или pinning личности подписанта здесь нет. Злоупотребление этими настройками доверенным оператором не выдано за внешнюю атаку. electron-app/scripts/sign.ps1:21-40 — Скрипт проверяет наличие входов и файлов, выбирает Windows SDK x64 SignTool, подписывает с /fd SHA256 /td SHA256 /tr и проверяет exit code.; electron-app/scripts/sign.ps1:46-58 — Проверяются сертификат подписанта, его срок действия, Code Signing EKU и наличие TimeStamperCertificate.; electron-app/scripts/sign.ps1:60-71 — TestBuild выделен явно; production-ветка требует успешные SignTool verify и Authenticode Valid.; SECURITY.md:24-24 — Среда подписи и Windows входят в заявленные зависимости доверия.; SECURITY.md:39-39 — Политика выпуска требует доверенную Code Signing подпись и RFC 3161 timestamp; самоподписанные сертификаты разрешены только для test builds. Остаётся ли пароль PFX исключительно в переменных окружения? Нет. Вход действительно читается только из SIGNING_PFX_PASSWORD в Process/User environment, но затем передаётся SignTool через аргумент /p. Обнуление переменной PowerShell в finally не удаляет исходное значение окружения и уже переданные аргументы дочернего процесса. Это отклонение от документированного требования об отсутствии секретов в командной строке. Подтверждённого чтения этих аргументов атакующим за пределами доверенной среды подписи нет; поэтому зарегистрировано ограничение обработки секрета, а не доказанная уязвимость между Windows-аккаунтами. Нужна отдельная проверка политики рабочей станции подписи, журналирования и предпочтительно механизма подписи без передачи пароля PFX в argv. Реальные переменные, процессы подписи и файлы PFX не читались. electron-app/scripts/sign.ps1:12-19 — Пароль и путь PFX читаются из одноимённых Process/User environment variables.; electron-app/scripts/sign.ps1:38-43 — Пароль передаётся дочернему SignTool аргументом /p; finally присваивает null только локальной переменной pfxPassword.; SECURITY.md:37-37 — Политика запрещает реальные секреты в командных строках.; docs/threat-model.md:15-15 — Модель описывает путь и пароль сертификата как существующие только в environment values.; docs/threat-model.md:31-31 — Компрометация среды подписи и привилегированного хоста исключена из гарантий. Полностью ли проверка пути PFX обеспечивает правило «вне репозитория»? Нет. projectRoot вычисляется как родитель electron-app/scripts, то есть electron-app. Проверка StartsWith запрещает PFX внутри electron-app, но не внутри других каталогов самого репозитория. Это неполная реализация политики размещения сертификата; путь выбирает доверенный оператор через окружение, и сам скрипт не копирует сертификат в репозиторий. Путь от недоверенных продуктовых входов к такому выбору не найден. Политику следует проверять относительно настоящего корня репозитория; текущую проверку нельзя описывать как гарантию для всего репозитория. electron-app/scripts/sign.ps1:10-19 — База projectRoot является родителем каталога scripts; вход PFX приходит из среды доверенного запуска.; electron-app/scripts/sign.ps1:25-30 — Запрет проверяет только префикс projectRoot с разделителем, затем существование файла.; README.md:53-53 — Документированное правило требует хранить PFX вне всего репозитория.; docs/threat-model.md:5-5 — Настройки и действия доверенного release worker не являются входами внешнего атакующего в данной модели. Попадают ли тестовый Electron harness и его снимки в заявленные входы production-упаковки? Прямого пути не обнаружено. Main и preload собираются из двух явно заданных production entry points, renderer собирается из src/renderer, а terminal harness получает отдельный root tests/terminal-renderer и outDir .runtime-probe/terminal-renderer. Его фиксированный дочерний запуск получает только путь тестового main.cjs и созданного config JSON; vault/SSH-данные не являются входами скрипта. Пользовательский files whitelist упаковщика перечисляет dist/\*\*/\* и package.json, а не tests или .runtime-probe. Сам harness использует executeJavaScript/capturePage только в тестовом процессе. Окончательный архив не исследовался: правило dist/\*\*/\* требует чистого доверенного каталога сборки; esbuild перезаписывает два файла и не очищает весь dist, поэтому наличие лишних ранее созданных файлов статически не исключено. electron-app/scripts/build.mjs:18-21 — Production entry points ограничены src/main/main.ts и src/preload/preload.ts.; electron-app/vite.config.ts:6-8 — Основной renderer собирается из src/renderer с относительным base.; electron-app/vite.config.ts:26-31 — Vite очищает собственный dist/renderer и отключает sourcemap.; electron-app/scripts/test-terminal.mjs:8-22 — Тестовая сборка использует отдельные root/outDir, фиксированные размеры и фиксированные пути spawn; ELECTRON_RUN_AS_NODE удаляется, exit code проверяется.; electron-app/package.json:43-65 — Настроены ASAR, files=\[dist/\*\*/\*, package.json\] и portable с requestExecutionLevel=user.; electron-app/tests/terminal-renderer/main.cjs:21-37 — executeJavaScript и capturePage находятся в отдельном offscreen тестовом harness, который пишет результаты в config.root. Сохраняет ли renderer-сборка заявленную CSP, и как разграничены проверки TypeScript и тесты? Vite добавляет CSP meta из общей константы, которую main использует в заголовке ответа. Политика запрещает renderer-сеть, внешние скрипты и frames; unsafe-inline разрешено только для CSS. В production BrowserWindow явно включены sandbox/contextIsolation/webSecurity и отключены nodeIntegration/webviewTag, DevTools зависят от app.isPackaged. Оба tsconfig включают strict и noUncheckedIndexedAccess, а npm build сначала запускает typecheck. Vitest работает с исходными \*.test.ts в node-среде отдельной командой; это не проверка готового portable-бинарника. Отсутствие запуска тестов внутри build само по себе не устанавливает обход границы доверия. electron-app/vite.config.ts:4-16 — HTML получает CSP meta из CONTENT_SECURITY_POLICY.; electron-app/src/shared/content-security-policy.ts:1-6 — Общая CSP допускает self scripts, inline CSS и запрещает connect, object и frame источники.; electron-app/src/main/main.ts:65-74 — Main устанавливает ту же CSP в response header и запрещает разрешения.; electron-app/src/main/main.ts:91-100 — Production-потребитель использует явные параметры sandbox, contextIsolation, webSecurity, nodeIntegration и packaged DevTools.; electron-app/tsconfig.json:2-17 — Renderer/shared TypeScript проверяется в strict-режиме с noUncheckedIndexedAccess.; electron-app/tsconfig.node.json:2-14 — Main/preload/shared имеют отдельный NodeNext strict tsconfig с noUncheckedIndexedAccess.; electron-app/package.json:9-14 — Build запускает typecheck до компиляции; unit- и terminal-тесты вынесены в отдельные команды.; electron-app/vitest.config.ts:3-11 — Vitest запускает src/\*\*/\*.test.ts в node-среде без fileParallelism. |
| vault-storage-005 duplicate reconciliation | not recorded | Rejected | Дубликат electron-boundary-001: тот же переход closeAll против pending open/create, та же регистрация addSession и необходимая отмена по поколению. Все исходные доказательства сохранены при объединении. Original evidence retained in electron-boundary-001 and security-check/runs/20260915-audit/results/vault-storage.json. |
| vault-storage | not recorded | Needs follow-up | Полностью статически проверены оба назначенных файла и необходимые вызывающие пути. Выявлены пять дефектов: разрыв между проверкой и заменой при сохранении; перезапись возникшего назначения при создании; отсутствие проверки актуального владения writer lock; сохранение скрытой сессии при ошибке очистки; завершение начатого открытия после общей блокировки. Критических и высоких находок нет. Эксплуатационные предпосылки, контрдоказательства и отсутствие динамического подтверждения указаны отдельно. |
| hibp | not recorded | Needs follow-up | Полностью проверен hibp.ts и прослежены его вызывающие пути. Найден один дефект низкой серьёзности: проверка NFC-нормализованного значения вместо фактического пароля записи. Передача полного пароля или полного хеша, обход согласия через сохранение документа и перенаправление запроса по коду не подтверждены. Некорректные успешные ответы и отсутствие абсолютного срока запроса отдельно отмечены с учётом доверия к HIBP/HTTPS PKI. |
| ssh-terminal | not recorded | No issue found | Оба назначенных файла полностью прочитаны; проверены вызывающий main-процесс, потребитель терминальных событий и соответствующие участки установленного ssh2/xterm. Подтверждённых уязвимостей в заявленной модели угроз не установлено. Обнаруженные пробелы отмены незавершённых подключений, управления потоком и очистки обработчиков сохранены отдельно от уязвимостей. Проверка границ параметров DH group exchange в криптографическом runtime остаётся открытым вопросом. |
| renderer | not recorded | Needs follow-up | Полностью просмотрены все 14 назначенных файлов, включая UI-стенды. Подтверждён один дефект средней серьёзности: автоматические ответы xterm на команды SSH-сервера обновляют общий таймер активности и позволяют удалённому endpoint предотвращать автоблокировку всех открытых сейфов. Остальные проверенные границы и ограничения перечислены отдельно. |
| build-release | not recorded | No issue found | Все девять назначенных файлов проверены статически, включая все записи package-lock.json. Подтверждённых уязвимостей с пересечением заявленной границы доверия не обнаружено. Зафиксированы работающие ограничения сборки и проверки подписи, а также ограничения ручного процесса выпуска; управление средой сборки и подписи остаётся обязанностью доверенного оператора. |

## Open Questions And Follow Up

- electron-boundary: Разрешён только offline static review: приложение, unit/integration tests, builds, Electron/Windows capture/clipboard/SMB поведение не запускались; сеть, внешние приложения и история git не использовались.
- electron-boundary: Источник main и четыре остальных назначенных файла прочитаны полностью. Supporting files использованы только для фактических consumers, lifecycle и counterevidence; полный аудит их модулей не заявляется.
- electron-boundary: Severity учитывает ограниченные предпосылки: правильный пароль/предварительное SSH approval уже есть, атака на шифрование не доказана, Windows account/kernel и привилегированный разблокированный host остаются доверенными согласно SECURITY.md:19-25 и docs/threat-model.md:5.
- electron-boundary: Для задержек filesystem нет измеренного верхнего времени; статически доказана зависимость UI cleanup от завершения await (main.ts:270-294, storage.ts:208-210), но реальные SMB сроки требуют платформенной проверки.
- electron-boundary: Нет доказанного источника исполнения произвольного кода renderer или чужого pmapp-frame. Неполная привязка sender к mainFrame и отсутствие отдельного download handler сохранены как вопросы усиления и интеграционной проверки, а не выданы за выполненный обход.
- electron-boundary: Реальные vault/key/credential/runtime/signing файлы и результаты других модулей не читались. Исходники не изменялись.
- vault-codec: Только offline static review исходного текста. Приложение, криптографические операции, тесты, сборки и PoC не запускались; network/apps, git history, реальные vault, environment secrets и результаты других модулей не читались.
- vault-codec: Фактические OOM-пороги, задержки, поведение structuredClone на целевом Electron и сохранение разделяемых ссылок через contextBridge/IPC не измерены; finding отделяет подтверждённые отсутствующие лимиты и порядок операций от этих эксплуатационных параметров.
- vault-codec: Полностью проверенными считаются только три назначенных файла. storage.ts, main.ts, preload.ts, SSH-service и локальный исходник hash-wasm использованы для проверки конкретных потребителей/контрмер; это не полная независимая проверка этих модулей или зависимости.
- vault-codec: Установленная зависимость hash-wasm прочитана локально для проверки Argon2 version/type. Доверенность supply chain, соответствие node_modules lock integrity, runtime/OpenSSL и наличие независимых известных ответов не проверялись.
- vault-codec: Остатки секретов в памяти после временных копий и ограничения стирания JavaScript strings отмечены отдельно; эксплуатация через administrator/debugger/unlocked-memory capture исключена supplied threat model и не добавлена как самостоятельная vulnerability.
- vault-storage: Аудит полностью статический. Приложение, тесты, сборки и команды с приложенческим кодом не запускались; сетевые службы и SMB не использовались. Динамические PoC и подтверждение конкретной конфигурации Windows отсутствуют.
- vault-storage: Полностью проверены только electron-app/src/main/vault/storage.ts и electron-app/src/main/vault/storage.test.ts. Codec, main, preload, renderer и supplied policy прочитаны в объёме, необходимом для проверки вызывающих путей и контрдоказательств; полнота их отдельного аудита не заявлена.
- vault-storage: Тяжесть учитывает доверенную локальную учётную запись и отсутствие доказанного пути удалённого извлечения plaintext. SECURITY.md:19-25 и docs/threat-model.md:5,31 исключают malware/admin/process-dump атаки и обычную потерю доступности.
- vault-storage: Сетевые файловые гонки требуют заявленных в каждой находке прав или влияния на SMB. Native sharing modes, lease/reconnect, гарантии rename и долговечность каталога при сбое питания не проверены на Windows 10 22H2/Windows 11 x64; docs/vault-format.md:62 описывает ожидаемые гарантии, а storage.ts:221-234 использует sync и rename.
- vault-storage: Материалы реальных сейфов, ключи, пароли, runtime-данные, история git и результаты других модулей не читались. Исходники не изменялись.
- hibp: Аудит выполнен только статическим чтением. Приложение, тесты, сборки, сетевые обращения и воспроизведение ответов не запускались; динамическая проверка Node/Electron событий timeout, aborted, close и error остаётся за последующим изолированным тестированием.
- hibp: Для hibp-001 подтверждено несовпадение проверяемого и используемого значения по исходному коду; наличие конкретных затронутых паролей в реальной HIBP-базе и частота таких случаев не проверялись.
- hibp: Строки hash/suffix и результат body.toString не имеют гарантированного стирания; body и normalized очищаются явно, а накопленные chunks на успешном пути отдельно не очищаются (electron-app/src/main/services/hibp.ts:8-14,18-28,40-47). Это не квалифицировано как уязвимость против разрешённой модели: атаки на память разблокированного процесса исключены SECURITY.md:19.
- ssh-terminal: Проверка выполнена только статическим чтением. Приложение, тесты, сборки, реальные SSH-подключения и инструментальные PoC не запускались; сеть, реальные секреты, git history и результаты других модулей не читались.
- ssh-terminal: Прочитаны целиком только два файла, перечисленные в fully_reviewed_files; supporting source и установленные зависимости использованы адресно для проверки потребителей и контрдоказательств. Полный аудит ssh2, xterm, Electron и OpenSSL не заявляется.
- ssh-terminal: Отсутствие findings означает отсутствие подтверждённой уязвимости в выбранной модели и методе проверки, а не доказательство полной безопасности. Пробелы отмены pending-соединений, потоковых лимитов и очистки listeners сохранены с доказательствами в resolved_questions.
- ssh-terminal: Набор тестов назначенного модуля содержит положительные TOFU/password/keyboard-interactive/legacy сценарии и отдельные проверки политики, но не отдельные случаи изменённого host key, блокировки во время pending shell, повторных terminalId и потока вывода. Это ограничение доказательств, а не самостоятельная уязвимость (electron-app/src/main/services/ssh-terminal.test.ts:11-199).
- ssh-terminal: Поведение pinned Electron/OpenSSL при неверных DH GEX параметрах требует отдельной разрешённой проверки; существование CVE или успешная эксплуатация не утверждаются.
- renderer: Аудит статический и offline: приложение, тесты, Electron и SSH-сервер не запускались; фактическая эксплуатация и поведение Windows не заявляются как воспроизведённые.
- renderer: После отдельного разрешения координатора прочитан supporting исходник установленного @xterm/xterm 6.0.0 для проверки автоматических DSR-ответов. Его пути и точные строки приведены в validation renderer-001; node_modules не входит в manifest/source_digest и не включён в fully_reviewed_files.
- renderer: Связанные main/preload/storage/CSP файлы читались только для установления потребителей, доверенных подтверждений и контрдоказательств; полнота их самостоятельного модульного аудита здесь не заявляется.
- renderer: Гонка позднего open/create после lock требует интеграционного решения; конкретное нарушение границы для внешнего атакующего в этом модуле отдельно не подтверждено.
- renderer: Результаты других модулей, реальные vault-файлы, ключи, credentials, signing material и runtime-данные не читались. Изменений исходников не делалось.
- build-release: Выполнен только разрешённый offline static review исходников, конфигурации и тестового текста. npm ci, тесты, сборки, packaging, SignTool и приложение не запускались; свойства реального PE/ASAR-артефакта и Windows API не подтверждались экспериментально.
- build-release: Актуальные advisory, лицензии содержимого архивов и безопасность стороннего кода не устанавливались сетевыми запросами. Проверка всего lockfile подтверждает структуру записей и согласованность закреплённых метаданных, а не фактические хеши скачанных пакетов.
- build-release: Реальные signing inputs, PFX, environment secrets, vault-файлы и runtime-данные не читались. Изоляция и журналирование рабочей станции подписи остаются непроверенными предпосылками; конкретные несоответствия политики отражены в resolved_questions с привязкой к строкам.
- build-release: Вывод ограничен девятью назначенными файлами. Поддерживающие исходники читались только для установления потребителей и контрдоказательств; результаты других модулей и история Git не использовались.
- Independent module result awaits source validation
  - Follow-up prompt: Review deferred unit vault-storage-005 and close its stated proof gap.
