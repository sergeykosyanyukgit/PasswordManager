interface CaptureProtectedWindow {
  setContentProtection(enabled: boolean): void;
  isContentProtected(): boolean;
  destroy(): void;
}

export function configureCaptureProtection(window: CaptureProtectedWindow, diagnosticScreenshots = false): void {
  const expectedProtection = !diagnosticScreenshots;
  try {
    window.setContentProtection(expectedProtection);
    if (window.isContentProtected() !== expectedProtection) {
      throw new Error('Screen-capture protection could not be configured.');
    }
  } catch (error) {
    window.destroy();
    throw error;
  }
}
