import { describe, expect, it, beforeEach } from 'bun:test';
import { NetworkChecker } from '../src/checks/network.js';

describe('NetworkChecker', () => {
  let checker: NetworkChecker;

  beforeEach(() => {
    checker = new NetworkChecker();
  });

  describe('when OpenClaw config is not present', () => {
    it('should skip checks gracefully', async () => {
      const result = await checker.run();
      // Either skipped or no findings - verify it's truthy (non-empty string) or empty array
      expect(result.skipped !== undefined || result.findings.length === 0).toBe(true);
    });
  });

  describe('NET-001: Gateway binding', () => {
    it('should not report finding when config is missing', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'NET-001');
      // No config means no finding
      expect(finding).toBeUndefined();
    });
  });

  describe('NET-002: Gateway auth', () => {
    it('should not report finding when config is missing', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'NET-002');
      // No config means no finding
      expect(finding).toBeUndefined();
    });
  });
});
