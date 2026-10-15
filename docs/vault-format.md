# `.pmvault` format v1

All integers are unsigned little-endian unless stated otherwise. Parsers must reject trailing bytes, truncation, duplicate or unknown fields, invalid UTF-8/JSON, files larger than 256 MiB, and unsupported versions without changing the source file.

## Cryptographic suite 1

- Master-password normalization: Unicode NFC, then strict UTF-8.
- Root derivation: Argon2id v1.3, 64 MiB, 3 iterations, 4 lanes, 16-byte random salt, 32-byte output.
- KEK derivation: HKDF-SHA-256 with a fresh 32-byte wrap salt, info `PasswordManager/v1/data-key-wrap`, 32-byte output.
- Key wrap: AES-256-GCM, 12-byte random nonce, 16-byte tag.
- Payload: a fresh 32-byte random data key and AES-256-GCM with a fresh 12-byte random nonce and 16-byte tag.

Every complete save creates a new data key, wrap salt, wrap nonce, and payload nonce. The probability-based uniqueness of 96-bit random nonces is coupled with mandatory key rotation per save. The master password and derived root key are never stored.

## Binary layout

| Field | Size | Meaning |
|---|---:|---|
| Magic | 8 | ASCII `PMVAULT1` |
| Version | 2 | `1` |
| CipherSuite | 2 | `1` |
| HeaderLength | 4 | `220` for v1 |
| VaultId | 16 | Random UUID in RFC 4122/network byte order, stable for the vault |
| KdfMemoryKiB | 4 | `65536` in v1; accepted range 32768–262144 |
| KdfIterations | 4 | `3`; accepted range 2–10 |
| KdfParallelism | 4 | `4`; accepted range 1–16 |
| KdfSalt | 16 | Random, stable until master-password change |
| WrapSalt | 32 | Fresh per save |
| WrapNonce | 12 | Fresh per save |
| WrappedDataKey | 32 | Encrypted data key |
| WrapTag | 16 | GCM tag |
| PayloadNonce | 12 | Fresh per save |
| CiphertextLength | 8 | Encrypted padded payload length; 4096–268431360 |
| PayloadTag | 16 | GCM tag |
| HeaderDigest | 32 | SHA-256 of all preceding header bytes |
| Ciphertext | variable | Encrypted padded payload |

`HeaderLength` includes all fixed fields through `HeaderDigest`, but not ciphertext. The digest is an early corruption check only; cryptographic integrity comes from the two GCM tags.

## AAD

Wrap AAD is the exact byte sequence from `Magic` through `WrapNonce` inclusive. Payload AAD is the exact fixed header with `WrappedDataKey`, `WrapTag`, and `PayloadTag` zeroed, ending immediately before `HeaderDigest`. This binds the format, suite, VaultId, KDF configuration, salts/nonces, and ciphertext length. Any changed authenticated header byte causes opening to fail.

## Payload

The decrypted payload is:

| Field | Size | Meaning |
|---|---:|---|
| JsonLength | 4 | Number of JSON bytes, maximum 64 MiB |
| JSON | variable | Strict UTF-8 serialized `VaultDocument` |
| Padding | variable | CSPRNG bytes to the next 4096-byte boundary |

At least one 4096-byte block is emitted. Padding bytes have no structure and are ignored only after the authenticated `JsonLength` has been bounded. Folder depth is limited to 64 and all names and settings live inside JSON ciphertext.

`settings.autoLockMinutes` is an authenticated integer in the inclusive range 0-240. `0` disables inactivity auto-lock for that vault; it does not disable locking on Windows lock, suspend, shutdown, explicit close, or application exit. Older v1 payloads remain compatible because their existing positive value retains the same meaning.

`settings.notesWorkspace` is optional authenticated UI state: `{ openRecordIds: UUID[], activeRecordId: UUID | null, autoOpen: boolean }`. IDs are unique, limited to 128, and a non-null active ID must belong to the list. Unknown fields or wrong types are rejected. A missing field in an older v1 document means no remembered tabs and requires no rewrite to open it. The field is created only when the notes workspace is used. Names and note text remain in the existing record fields; neither tabs nor the manual-close preference are stored outside ciphertext. This additive JSON field does not change the v1 binary header, KDF, AAD or encryption. Current readers continue opening legacy payloads; older readers may ignore this field or fail closed and must not be used to maintain the new workspace state.

Manually closing the notes window sets `autoOpen` to false while retaining the remembered IDs. Explicitly opening notes sets it to true. Vault lock, app exit and system lock close all note views without suppressing restoration at the next unlock. Deleted/non-note records are not restored.

SSH profile payloads include `allowLegacyAlgorithms`, a boolean that defaults to `false`. Readers treat the missing field in an older authenticated v1 payload as `false`, so this additive payload migration preserves v1 binary/AAD compatibility. Non-boolean values are rejected. Enabling the flag is per record and still requires a native warning before every compatibility-mode connection.

## Saving and migration

The application serializes in memory, encrypts a same-directory uniquely named temp file, opens it with exclusive sharing, flushes with write-through, rereads and authenticates it, rechecks the SHA-256 hash of the source version, and uses an atomic filesystem replacement. No backup is created. Unsupported replacement leaves the original untouched and requires Save As.

Unknown versions are never opened or rewritten. A format change requires a new version, documented AAD, test vectors, tamper tests for each field, a one-way explicit migration, and preservation of the original until the migrated vault has been authenticated.
