import { describe, expect, it, beforeEach } from 'bun:test';
import { ChannelsChecker } from '../src/checks/channels.js';

describe('ChannelsChecker', () => {
  let checker: ChannelsChecker;

  beforeEach(() => {
    checker = new ChannelsChecker();
  });

  describe('when OpenClaw config is not present', () => {
    it('should skip checks gracefully', async () => {
      const result = await checker.run();
      // Either skipped or no findings
      expect(result.skipped !== undefined || result.findings.length === 0).toBe(
        true,
      );
    });
  });

  describe('CHAN-001: DM Policy', () => {
    it('should not report finding when config is missing', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'CHAN-001');
      // No config means no finding
      expect(finding).toBeUndefined();
    });
  });

  describe('CHAN-002: Group Policy', () => {
    it('should not report finding when config is missing', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'CHAN-002');
      expect(finding).toBeUndefined();
    });
  });

  describe('CHAN-007: Open channel + tools combo', () => {
    it('should not report when no config', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'CHAN-007');
      expect(finding).toBeUndefined();
    });
  });

  describe('CHAN-008: Session isolation', () => {
    it('should not report when no config', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'CHAN-008');
      // No config means skipped, not finding
      expect(finding).toBeUndefined();
    });
  });
});
