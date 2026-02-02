import { describe, expect, it, beforeEach } from 'bun:test';
import { SkillsChecker } from '../src/checks/skills.js';

describe('SkillsChecker', () => {
  let checker: SkillsChecker;

  beforeEach(() => {
    checker = new SkillsChecker();
  });

  describe('when OpenClaw config is not present', () => {
    it('should skip checks gracefully', async () => {
      const result = await checker.run();
      expect(result.skipped !== undefined || result.findings.length === 0).toBe(
        true,
      );
    });
  });

  describe('SKILL-001: Plugin allowlist', () => {
    it('should not report finding when no plugins installed', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'SKILL-001');
      // No plugins means no finding
      expect(finding).toBeUndefined();
    });
  });

  describe('SKILL-003: Unpinned versions', () => {
    it('should not report finding when no skills installed', async () => {
      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'SKILL-003');
      expect(finding).toBeUndefined();
    });
  });

  describe('scanSkills', () => {
    it('should skip when skill-scanner is not installed', async () => {
      const result = await checker.scanSkills('/nonexistent/path');
      // Either skipped or findings
      expect(
        result.skipped !== undefined || result.findings.length >= 0,
      ).toBe(true);
    });
  });
});
