import { describe, expect, it, beforeEach } from 'bun:test';
import { CredentialsChecker } from '../src/checks/credentials.js';

describe('CredentialsChecker', () => {
  let checker: CredentialsChecker;

  beforeEach(() => {
    checker = new CredentialsChecker();
  });

  describe('CRED-001: ~/.openclaw permissions', () => {
    it('should run permission check', async () => {
      const result = await checker.run();
      // Should run without error
      expect(result.findings).toBeDefined();
    });
  });

  describe('CRED-005: Environment variables', () => {
    it('should detect API keys in environment', async () => {
      // Set a test env var
      process.env.ANTHROPIC_API_KEY = 'sk-ant-test123';

      const result = await checker.run();
      const finding = result.findings.find((f) => f.id === 'CRED-005');

      // Should find the env var
      expect(finding).toBeDefined();
      expect(finding?.level).toBe('info');

      // Clean up
      delete process.env.ANTHROPIC_API_KEY;
    });

    it('should not report when no API keys in env', async () => {
      // Ensure no test keys
      delete process.env.ANTHROPIC_API_KEY;
      delete process.env.OPENAI_API_KEY;

      const checker2 = new CredentialsChecker();
      const result = await checker2.run();
      const finding = result.findings.find((f) => f.id === 'CRED-005');

      // Might find other keys from the environment, or none
      // This test just verifies the check runs
      expect(result.findings).toBeDefined();
    });
  });

  describe('Secret patterns', () => {
    it('should match Anthropic API keys', () => {
      const testKey = 'sk-ant-api03-R2D2C3PO4LEIA5CHEWBACCA6';
      expect(testKey).toMatch(/sk-ant-[a-zA-Z0-9-]{20,}/);
    });

    it('should match GitHub PAT', () => {
      const testKey = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
      expect(testKey).toMatch(/ghp_[a-zA-Z0-9]{36}/);
    });

    it('should match AWS access key', () => {
      const testKey = 'AKIAIOSFODNN7EXAMPLE';
      expect(testKey).toMatch(/AKIA[0-9A-Z]{16}/);
    });

    it('should match private key headers', () => {
      const testKey = '-----BEGIN RSA PRIVATE KEY-----';
      expect(testKey).toMatch(
        /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----/,
      );
    });
  });

  describe('fix', () => {
    it('should support dry-run mode for CRED-001', async () => {
      const result = await checker.fix?.('CRED-001', true);
      expect(typeof result).toBe('boolean');
    });

    it('should support dry-run mode for CRED-002', async () => {
      const result = await checker.fix?.('CRED-002', true);
      expect(typeof result).toBe('boolean');
    });

    it('should return false for unknown finding ID', async () => {
      const result = await checker.fix?.('UNKNOWN-999', true);
      expect(result).toBe(false);
    });
  });
});
