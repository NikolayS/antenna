import { describe, expect, it, beforeEach } from 'bun:test';
import { ToolsChecker } from '../src/checks/tools.js';

describe('ToolsChecker', () => {
  let checker: ToolsChecker;

  beforeEach(() => {
    checker = new ToolsChecker();
  });

  describe('when OpenClaw config is not present', () => {
    it('should skip checks gracefully', async () => {
      const result = await checker.run();
      expect(result.skipped !== undefined || result.findings.length === 0).toBe(
        true,
      );
    });
  });

  describe('TOOL-001: Elevated tools allowFrom', () => {
    it('should not report finding when config is missing', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'TOOL-001');
      expect(finding).toBeUndefined();
    });
  });

  describe('TOOL-002: Sandbox disabled', () => {
    it('should not report finding when config is missing', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'TOOL-002');
      expect(finding).toBeUndefined();
    });
  });

  describe('TOOL-003: Browser control', () => {
    it('should not report finding when config is missing', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'TOOL-003');
      expect(finding).toBeUndefined();
    });
  });

  describe('TOOL-006: Sandbox network egress', () => {
    it('should not report finding when config is missing', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'TOOL-006');
      expect(finding).toBeUndefined();
    });
  });
});
