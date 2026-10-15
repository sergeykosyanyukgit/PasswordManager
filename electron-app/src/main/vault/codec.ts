import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';
import { argon2id } from 'hash-wasm';
import type { VaultDocument, VaultFolder, VaultRecord } from '../../shared/contracts.js';

export const HEADER_SIZE = 220;
export const MAXIMUM_FILE_SIZE = 256 * 1024 * 1024;
const MAXIMUM_JSON_SIZE = 64 * 1024 * 1024;
const MAGIC = Buffer.from('PMVAULT1', 'ascii');
// Historical format constant: preserve it when changing the product name.
const WRAP_INFO = Buffer.from('PasswordManager/v1/data-key-wrap', 'ascii');
const OFFSETS = {
  version: 8,
  suite: 10,
  headerLength: 12,
  vaultId: 16,
  memory: 32,
  iterations: 36,
  parallelism: 40,
  kdfSalt: 44,
  wrapSalt: 60,
  wrapNonce: 92,
  wrappedKey: 104,
  wrapTag: 136,
  payloadNonce: 152,
  ciphertextLength: 164,
  payloadTag: 172,
  headerDigest: 188
} as const;

export interface KdfParameters {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export interface VaultMaterial {
  vaultId: Buffer;
  kdfSalt: Buffer;
  parameters: KdfParameters;
  rootKey: Buffer;
}

export interface DecodedVault {
  document: VaultDocument;
  material: VaultMaterial;
}

export class VaultFormatError extends Error {}
export class VaultAuthenticationError extends VaultFormatError {}

export function createEmptyDocument(): VaultDocument {
  const rootFolderId = randomUUID();
  return {
    rootFolderId,
    folders: [{ id: rootFolderId, parentId: null, name: 'Заметки', isDeleted: false, deletedUtc: null }],
    records: [],
    settings: { hibpConsent: false, clipboardClearSeconds: 30, autoLockMinutes: 15, sessionLanguage: '' },
    modifiedUtc: new Date().toISOString()
  };
}

export async function createMaterial(password: string, vaultId = randomUUID()): Promise<VaultMaterial> {
  validateNewMasterPassword(password);
  const kdfSalt = randomBytes(16);
  const parameters = { memoryKiB: 65_536, iterations: 3, parallelism: 4 };
  return {
    vaultId: uuidToBytes(vaultId),
    kdfSalt,
    parameters,
    rootKey: await deriveRootKey(password, kdfSalt, parameters)
  };
}

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
}

export function verifyAndDecode(fileBytes: Buffer, material: VaultMaterial): VaultDocument {
  const parsed = parseHeader(fileBytes);
  if (!timingSafeEqual(parsed.vaultId, material.vaultId) ||
      !timingSafeEqual(parsed.kdfSalt, material.kdfSalt) ||
      parsed.parameters.memoryKiB !== material.parameters.memoryKiB ||
      parsed.parameters.iterations !== material.parameters.iterations ||
      parsed.parameters.parallelism !== material.parameters.parallelism) {
    throw new VaultAuthenticationError('Vault identity or KDF metadata changed unexpectedly.');
  }
  return decryptDocument(fileBytes, material);
}

export function encodeVault(document: VaultDocument, material: VaultMaterial): Buffer {
  validateDocument(document);
  const json = Buffer.from(JSON.stringify(document), 'utf8');
  if (json.length > MAXIMUM_JSON_SIZE) throw new VaultFormatError('Vault JSON is too large.');
  const plaintextLength = Math.max(4096, Math.ceil((json.length + 4) / 4096) * 4096);
  if (HEADER_SIZE + plaintextLength > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Vault is too large.');

  const plaintext = Buffer.allocUnsafe(plaintextLength);
  const dataKey = randomBytes(32);
  const kek = Buffer.alloc(32);
  const header = Buffer.alloc(HEADER_SIZE);
  let payloadAad: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  try {
    plaintext.writeInt32LE(json.length, 0);
    json.copy(plaintext, 4);
    randomBytes(plaintext.length - json.length - 4).copy(plaintext, json.length + 4);
    initializeHeader(header, material, plaintextLength);
    Buffer.from(hkdfSync('sha256', material.rootKey, header.subarray(OFFSETS.wrapSalt, OFFSETS.wrapNonce), WRAP_INFO, 32)).copy(kek);

    const wrapCipher = createCipheriv('aes-256-gcm', kek, header.subarray(OFFSETS.wrapNonce, OFFSETS.wrappedKey), { authTagLength: 16 });
    wrapCipher.setAAD(header.subarray(0, OFFSETS.wrappedKey));
    const wrapped = Buffer.concat([wrapCipher.update(dataKey), wrapCipher.final()]);
    wrapped.copy(header, OFFSETS.wrappedKey);
    wrapCipher.getAuthTag().copy(header, OFFSETS.wrapTag);

    payloadAad = buildPayloadAad(header);
    const payloadCipher = createCipheriv('aes-256-gcm', dataKey, header.subarray(OFFSETS.payloadNonce, OFFSETS.ciphertextLength), { authTagLength: 16 });
    payloadCipher.setAAD(payloadAad);
    const ciphertext = Buffer.concat([payloadCipher.update(plaintext), payloadCipher.final()]);
    payloadCipher.getAuthTag().copy(header, OFFSETS.payloadTag);
    createHash('sha256').update(header.subarray(0, OFFSETS.headerDigest)).digest().copy(header, OFFSETS.headerDigest);
    return Buffer.concat([header, ciphertext]);
  } finally {
    json.fill(0);
    plaintext.fill(0);
    dataKey.fill(0);
    kek.fill(0);
    header.fill(0);
    payloadAad.fill(0);
  }
}

export function disposeMaterial(material: VaultMaterial): void {
  material.rootKey.fill(0);
  material.kdfSalt.fill(0);
  material.vaultId.fill(0);
}

function parseHeader(fileBytes: Buffer): { vaultId: Buffer; kdfSalt: Buffer; parameters: KdfParameters; ciphertextLength: number } {
  if (fileBytes.length < HEADER_SIZE || fileBytes.length > MAXIMUM_FILE_SIZE) throw new VaultFormatError('Invalid vault size.');
  const header = fileBytes.subarray(0, HEADER_SIZE);
  if (!header.subarray(0, 8).equals(MAGIC)) throw new VaultFormatError('Not a MyNotes vault.');
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
  const parameters = {
    memoryKiB: header.readInt32LE(OFFSETS.memory),
    iterations: header.readInt32LE(OFFSETS.iterations),
    parallelism: header.readInt32LE(OFFSETS.parallelism)
  };
  validateKdf(parameters);
  return {
    vaultId: Buffer.from(header.subarray(OFFSETS.vaultId, OFFSETS.memory)),
    kdfSalt: Buffer.from(header.subarray(OFFSETS.kdfSalt, OFFSETS.wrapSalt)),
    parameters,
    ciphertextLength
  };
}

function decryptDocument(fileBytes: Buffer, material: VaultMaterial): VaultDocument {
  const header = fileBytes.subarray(0, HEADER_SIZE);
  const kek = Buffer.from(hkdfSync('sha256', material.rootKey, header.subarray(OFFSETS.wrapSalt, OFFSETS.wrapNonce), WRAP_INFO, 32));
  const dataKey = Buffer.alloc(32);
  let plaintext = Buffer.alloc(0);
  const payloadAad = buildPayloadAad(header);
  try {
    const wrapCipher = createDecipheriv('aes-256-gcm', kek, header.subarray(OFFSETS.wrapNonce, OFFSETS.wrappedKey), { authTagLength: 16 });
    wrapCipher.setAAD(header.subarray(0, OFFSETS.wrappedKey));
    wrapCipher.setAuthTag(header.subarray(OFFSETS.wrapTag, OFFSETS.payloadNonce));
    Buffer.concat([wrapCipher.update(header.subarray(OFFSETS.wrappedKey, OFFSETS.wrapTag)), wrapCipher.final()]).copy(dataKey);

    const payloadCipher = createDecipheriv('aes-256-gcm', dataKey, header.subarray(OFFSETS.payloadNonce, OFFSETS.ciphertextLength), { authTagLength: 16 });
    payloadCipher.setAAD(payloadAad);
    payloadCipher.setAuthTag(header.subarray(OFFSETS.payloadTag, OFFSETS.headerDigest));
    plaintext = Buffer.concat([payloadCipher.update(fileBytes.subarray(HEADER_SIZE)), payloadCipher.final()]);
    const jsonLength = plaintext.readInt32LE(0);
    if (jsonLength < 2 || jsonLength > MAXIMUM_JSON_SIZE || jsonLength > plaintext.length - 4) throw new VaultFormatError('Invalid authenticated JSON length.');
    const json = new TextDecoder('utf-8', { fatal: true }).decode(plaintext.subarray(4, 4 + jsonLength));
    const document = JSON.parse(json) as VaultDocument;
    validateDocument(document);
    return document;
  } catch (error) {
    if (error instanceof VaultFormatError) throw error;
    throw new VaultAuthenticationError('Wrong password or vault authentication failed.');
  } finally {
    kek.fill(0);
    dataKey.fill(0);
    plaintext.fill(0);
    payloadAad.fill(0);
  }
}

function initializeHeader(header: Buffer, material: VaultMaterial, ciphertextLength: number): void {
  MAGIC.copy(header);
  header.writeUInt16LE(1, OFFSETS.version);
  header.writeUInt16LE(1, OFFSETS.suite);
  header.writeInt32LE(HEADER_SIZE, OFFSETS.headerLength);
  material.vaultId.copy(header, OFFSETS.vaultId);
  header.writeInt32LE(material.parameters.memoryKiB, OFFSETS.memory);
  header.writeInt32LE(material.parameters.iterations, OFFSETS.iterations);
  header.writeInt32LE(material.parameters.parallelism, OFFSETS.parallelism);
  material.kdfSalt.copy(header, OFFSETS.kdfSalt);
  randomBytes(32).copy(header, OFFSETS.wrapSalt);
  randomBytes(12).copy(header, OFFSETS.wrapNonce);
  randomBytes(12).copy(header, OFFSETS.payloadNonce);
  header.writeBigInt64LE(BigInt(ciphertextLength), OFFSETS.ciphertextLength);
}

function buildPayloadAad(header: Buffer): Buffer {
  const aad = Buffer.from(header.subarray(0, OFFSETS.headerDigest));
  aad.fill(0, OFFSETS.wrappedKey, OFFSETS.wrapTag);
  aad.fill(0, OFFSETS.wrapTag, OFFSETS.payloadNonce);
  aad.fill(0, OFFSETS.payloadTag, OFFSETS.headerDigest);
  return aad;
}

async function deriveRootKey(password: string, salt: Buffer, parameters: KdfParameters): Promise<Buffer> {
  validateKdf(parameters);
  const passwordBytes = Buffer.from(password.normalize('NFC'), 'utf8');
  let derived: Uint8Array | null = null;
  try {
    derived = await argon2id({
      password: passwordBytes,
      salt,
      parallelism: parameters.parallelism,
      hashLength: 32,
      memorySize: parameters.memoryKiB,
      iterations: parameters.iterations,
      outputType: 'binary'
    });
    return Buffer.from(derived);
  } finally {
    derived?.fill(0);
    passwordBytes.fill(0);
  }
}

function validateKdf(parameters: KdfParameters): void {
  if (parameters.memoryKiB < 32_768 || parameters.memoryKiB > 262_144 || parameters.iterations < 2 || parameters.iterations > 10 || parameters.parallelism < 1 || parameters.parallelism > 16) {
    throw new VaultFormatError('Unsafe Argon2id parameters.');
  }
}

function validateNewMasterPassword(password: string): void {
  if (password.normalize('NFC').length < 8) throw new VaultFormatError('Master password must contain at least 8 characters.');
}

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
  const workspace = document.settings.notesWorkspace;
  if (workspace !== undefined && (!workspace || typeof workspace !== 'object' ||
      Object.keys(workspace).some((key) => !['openRecordIds', 'activeRecordId', 'autoOpen'].includes(key)) ||
      !Array.isArray(workspace.openRecordIds) || workspace.openRecordIds.length > 128 ||
      workspace.openRecordIds.some((id) => !isUuid(id)) || new Set(workspace.openRecordIds).size !== workspace.openRecordIds.length ||
      (workspace.activeRecordId !== null && !workspace.openRecordIds.includes(workspace.activeRecordId)) || typeof workspace.autoOpen !== 'boolean')) {
    throw new VaultFormatError('Invalid notes workspace.');
  }
}

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
}

function validateName(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > 512 || hasUnpairedSurrogate(value)) throw new VaultFormatError('Invalid name.');
}

function validateField(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length > 16 * 1024 * 1024 || hasUnpairedSurrogate(value)) throw new VaultFormatError('Invalid field.');
}

function validateUtc(value: unknown, nullable: boolean): void {
  if (nullable && value === null) return;
  if (typeof value !== 'string' || value.length < 20 || value.length > 64 || !Number.isFinite(Date.parse(value))) throw new VaultFormatError('Invalid timestamp.');
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (next < 0xdc00 || next > 0xdfff) return true;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function uuidToBytes(uuid: string): Buffer {
  if (!isUuid(uuid)) throw new VaultFormatError('Invalid UUID.');
  return Buffer.from(uuid.replaceAll('-', ''), 'hex');
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
