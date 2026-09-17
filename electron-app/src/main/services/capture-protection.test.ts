import { describe, expect, it, vi } from 'vitest';
import { configureCaptureProtection } from './capture-protection.js';

describe('window capture protection', () => {
  function syntheticWindow(protectedState: boolean) {
    return { setContentProtection: vi.fn(), isContentProtected: vi.fn(() => protectedState), destroy: vi.fn() };
  }

  it('requires protection by default before showing the window', () => {
    const window = syntheticWindow(true);
    configureCaptureProtection(window);
    expect(window.setContentProtection).toHaveBeenCalledWith(true);
    expect(window.destroy).not.toHaveBeenCalled();
  });

  it('allows capture only when the diagnostic build explicitly opts in', () => {
    const window = syntheticWindow(false);
    configureCaptureProtection(window, true);
    expect(window.setContentProtection).toHaveBeenCalledWith(false);
    expect(window.destroy).not.toHaveBeenCalled();
  });

  it('destroys the window if the normal build cannot enable protection', () => {
    const window = syntheticWindow(false);
    expect(() => configureCaptureProtection(window)).toThrow('Screen-capture protection');
    expect(window.destroy).toHaveBeenCalledOnce();
  });

  it('does not claim that capture is allowed if protection remains enabled', () => {
    const window = syntheticWindow(true);
    expect(() => configureCaptureProtection(window, true)).toThrow('Screen-capture protection');
    expect(window.destroy).toHaveBeenCalledOnce();
  });

  it('destroys the window if the platform call throws', () => {
    const window = syntheticWindow(true);
    window.setContentProtection.mockImplementation(() => { throw new Error('Synthetic platform failure'); });
    expect(() => configureCaptureProtection(window)).toThrow('Synthetic platform failure');
    expect(window.destroy).toHaveBeenCalledOnce();
  });
});
