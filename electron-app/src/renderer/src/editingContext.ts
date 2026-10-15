import type { EditingContext } from '@shared/contracts';

export function trackEditingContext(api: { setEditingContext(context: EditingContext): void }): () => void {
  const report = () => {
    const element = document.activeElement;
    const context: EditingContext = element?.closest('.xterm') ? 'terminal' :
      element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLElement && element.isContentEditable ? 'text' : 'none';
    api.setEditingContext?.(context);
  };
  document.addEventListener('focusin', report);
  document.addEventListener('focusout', report);
  report();
  return () => { document.removeEventListener('focusin', report); document.removeEventListener('focusout', report); };
}
