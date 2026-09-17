import type { RecordType, SshProfile, VaultRecord } from '@shared/contracts';

export function createEmptySshProfile(): SshProfile {
  return {
    host: '',
    port: 22,
    userName: '',
    authenticationKind: 0,
    password: '',
    privateKeyPem: '',
    privateKeyPassphrase: '',
    hostKeySha256: '',
    allowLegacyAlgorithms: false
  };
}

export function applyRecordType(record: VaultRecord, type: RecordType): void {
  record.type = type;
  record.ssh = type === 4 ? (record.ssh ?? createEmptySshProfile()) : null;
}

export function normalizeRecordTypePayload(record: VaultRecord): void {
  applyRecordType(record, record.type);
}

export function isRecordType(value: number): value is RecordType {
  return Number.isInteger(value) && value >= 0 && value <= 4;
}
