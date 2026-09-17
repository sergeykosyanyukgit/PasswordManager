import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { SshProfile, VaultDocument } from '../../shared/contracts.js';
import {
  createEmptyDocument,
  createMaterial,
  decodeVault,
  disposeMaterial,
  encodeVault,
  HEADER_SIZE,
  VaultAuthenticationError,
  VaultFormatError,
  validateDocument,
  verifyAndDecode,
  type VaultMaterial
} from './codec.js';

const SYNTHETIC_PASSWORD = 'Synthetic-Test-Password-Only!42';
let material: VaultMaterial;
let document: VaultDocument;

beforeAll(async () => {
  material = await createMaterial(SYNTHETIC_PASSWORD);
  document = createEmptyDocument();
  document.records.push({
    id: crypto.randomUUID(),
    folderId: document.rootFolderId,
    type: 0,
    name: 'Synthetic record',
    userName: 'synthetic-user',
    email: 'synthetic@example.invalid',
    password: 'Synthetic-Record-Secret!84',
    url: 'https://example.invalid',
    notes: 'Synthetic test data only.',
    ssh: null,
    customFields: [{ name: 'Synthetic field', value: 'Synthetic value', isSecret: false }],
    breach: { status: 0, occurrenceCount: 0, checkedUtc: null, compromisedSaveConfirmed: false },
    isDeleted: false,
    deletedUtc: null,
    modifiedUtc: new Date().toISOString()
  });
});

afterAll(() => disposeMaterial(material));

describe('pmvault v1 codec', () => {
  it('round-trips an authenticated, padded document', () => {
    const encoded = encodeVault(document, material);
    try {
      expect(encoded.subarray(0, 8).toString('ascii')).toBe('PMVAULT1');
      expect((encoded.length - HEADER_SIZE) % 4096).toBe(0);
      expect(verifyAndDecode(encoded, material)).toEqual(document);
    } finally {
      encoded.fill(0);
    }
  });

  it('generates fresh ciphertext for every save', () => {
    const first = encodeVault(document, material);
    const second = encodeVault(document, material);
    try {
      expect(first.equals(second)).toBe(false);
      expect(verifyAndDecode(first, material)).toEqual(verifyAndDecode(second, material));
    } finally {
      first.fill(0);
      second.fill(0);
    }
  });

  it.each([0, 8, 10, 16, 32, 44, 60, 92, 104, 136, 152, 164, 172, 188, 219, 220])('rejects mutation at byte %i', (offset) => {
    const encoded = encodeVault(document, material);
    encoded[offset] = encoded[offset]! ^ 0x80;
    try {
      expect(() => verifyAndDecode(encoded, material)).toThrow(VaultFormatError);
    } finally {
      encoded.fill(0);
    }
  });

  it('rejects a wrong master password', async () => {
    const encoded = encodeVault(document, material);
    try {
      await expect(decodeVault(encoded, 'Synthetic-Wrong-Password!19')).rejects.toBeInstanceOf(VaultAuthenticationError);
    } finally {
      encoded.fill(0);
    }
  });

  it('rejects a short new master password', async () => {
    await expect(createMaterial('too-short')).rejects.toBeInstanceOf(VaultFormatError);
  });

  it('allows disabling inactivity auto-lock but rejects invalid timeouts', () => {
    const disabled = createEmptyDocument();
    disabled.settings.autoLockMinutes = 0;
    expect(() => validateDocument(disabled)).not.toThrow();

    disabled.settings.autoLockMinutes = -1;
    expect(() => validateDocument(disabled)).toThrow(VaultFormatError);
    disabled.settings.autoLockMinutes = 241;
    expect(() => validateDocument(disabled)).toThrow(VaultFormatError);
  });

  it('migrates an authenticated legacy SSH profile to modern-only mode', () => {
    const legacy = createEmptyDocument();
    const ssh: SshProfile = {
      host: 'synthetic.example.invalid', port: 22, userName: 'synthetic-user', authenticationKind: 0,
      password: 'Synthetic-SSH-Password-Only!42', privateKeyPem: '', privateKeyPassphrase: '', hostKeySha256: '', allowLegacyAlgorithms: false
    };
    delete (ssh as Partial<SshProfile>).allowLegacyAlgorithms;
    legacy.records.push({
      id: crypto.randomUUID(), folderId: legacy.rootFolderId, type: 4, name: 'Synthetic legacy SSH',
      userName: '', email: '', password: '', url: '', notes: '', ssh, customFields: [],
      breach: { status: 0, occurrenceCount: 0, checkedUtc: null, compromisedSaveConfirmed: false },
      isDeleted: false, deletedUtc: null, modifiedUtc: new Date().toISOString()
    });

    validateDocument(legacy);

    expect(ssh.allowLegacyAlgorithms).toBe(false);
  });

  it('rejects a non-boolean legacy SSH policy', () => {
    const invalid = createEmptyDocument();
    const ssh = {
      host: 'synthetic.example.invalid', port: 22, userName: 'synthetic-user', authenticationKind: 0,
      password: 'Synthetic-SSH-Password-Only!42', privateKeyPem: '', privateKeyPassphrase: '', hostKeySha256: '', allowLegacyAlgorithms: 'yes'
    };
    invalid.records.push({
      id: crypto.randomUUID(), folderId: invalid.rootFolderId, type: 4, name: 'Synthetic invalid SSH',
      userName: '', email: '', password: '', url: '', notes: '', ssh: ssh as unknown as SshProfile, customFields: [],
      breach: { status: 0, occurrenceCount: 0, checkedUtc: null, compromisedSaveConfirmed: false },
      isDeleted: false, deletedUtc: null, modifiedUtc: new Date().toISOString()
    });

    expect(() => validateDocument(invalid)).toThrow(VaultFormatError);
  });
});
