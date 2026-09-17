import { describe, expect, it } from 'vitest';
import type { VaultRecord } from '@shared/contracts';
import { applyRecordType, normalizeRecordTypePayload } from './recordDraft';

function syntheticRecord(): VaultRecord {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    folderId: '00000000-0000-4000-8000-000000000002',
    type: 0,
    name: 'Synthetic SSH test record',
    userName: '',
    email: '',
    password: '',
    url: '',
    notes: '',
    ssh: null,
    customFields: [],
    breach: { status: 0, occurrenceCount: 0, checkedUtc: null, compromisedSaveConfirmed: false },
    isDeleted: false,
    deletedUtc: null,
    modifiedUtc: '2026-01-01T00:00:00.000Z'
  };
}

describe('SSH record draft transitions', () => {
  it('creates the complete SSH payload when changing a regular record to SSH', () => {
    const record = syntheticRecord();

    applyRecordType(record, 4);

    expect(record.type).toBe(4);
    expect(record.ssh).toEqual({
      host: '',
      port: 22,
      userName: '',
      authenticationKind: 0,
      password: '',
      privateKeyPem: '',
      privateKeyPassphrase: '',
      hostKeySha256: '',
      allowLegacyAlgorithms: false
    });
  });

  it('repairs a legacy SSH record whose profile is missing', () => {
    const record = syntheticRecord();
    record.type = 4;

    normalizeRecordTypePayload(record);

    expect(record.ssh?.port).toBe(22);
  });

  it('removes hidden SSH secrets when changing to another record type', () => {
    const record = syntheticRecord();
    applyRecordType(record, 4);
    record.ssh!.password = 'Synthetic-SSH-Password-Only!42';

    applyRecordType(record, 0);

    expect(record.ssh).toBeNull();
  });
});
