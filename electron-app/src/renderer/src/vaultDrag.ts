export const VAULT_ITEM_MIME = 'application/x-mynotes-vault-item';
export function beginItemDrag(event: DragEvent, sessionId: string, kind: 'folder' | 'record', id: string): void {
  if (!event.dataTransfer) return;
  event.dataTransfer.effectAllowed = 'move';
  event.dataTransfer.setData(VAULT_ITEM_MIME, JSON.stringify({ sessionId, kind, id }));
}
export function acceptsVaultDrop(event: DragEvent): boolean { return !!event.dataTransfer && (event.dataTransfer.types.includes(VAULT_ITEM_MIME) || event.dataTransfer.types.includes('Files')); }
