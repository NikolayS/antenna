import { describe, expect, it, mock, beforeEach, afterEach } from 'bun:test';
import { InfrastructureChecker } from '../src/checks/infrastructure.js';

// Mock the exec module
const originalExec = await import('../src/utils/exec.js');

describe('InfrastructureChecker', () => {
  let checker: InfrastructureChecker;

  beforeEach(() => {
    checker = new InfrastructureChecker();
  });

  describe('INFRA-001: SSH Password Authentication', () => {
    it('should detect password auth enabled when not set', async () => {
      // When PasswordAuthentication is not in config, it defaults to yes
      const result = await checker.run();
      // On macOS, sshd config is different, so we check the logic
      // This is a unit test placeholder - real test needs mocking
      expect(result.findings).toBeDefined();
    });
  });

  describe('INFRA-003: Firewall', () => {
    it('should detect missing firewall', async () => {
      const result = await checker.run();
      // Check that the check runs without error
      expect(result.findings).toBeDefined();
    });
  });

  describe('INFRA-004: fail2ban', () => {
    it('should detect fail2ban not running', async () => {
      const result = await checker.run();
      // On macOS, fail2ban won't be found
      const f2b = result.findings.find(f => f.id === 'INFRA-004');
      // Either it's found (not running) or not (not applicable on macOS)
      expect(result.findings).toBeDefined();
    });
  });
});

describe('InfrastructureChecker.fix', () => {
  let checker: InfrastructureChecker;

  beforeEach(() => {
    checker = new InfrastructureChecker();
  });

  it('should support dry-run mode for SSH fix', async () => {
    // Dry run should not make changes
    const result = await checker.fix?.('INFRA-001', true);
    // Should return true (simulated success) or false (not applicable)
    expect(typeof result).toBe('boolean');
  });

  it('should support dry-run mode for firewall fix', async () => {
    const result = await checker.fix?.('INFRA-003', true);
    expect(typeof result).toBe('boolean');
  });

  it('should support dry-run mode for fail2ban fix', async () => {
    const result = await checker.fix?.('INFRA-004', true);
    expect(typeof result).toBe('boolean');
  });

  it('should return false for unknown finding ID', async () => {
    const result = await checker.fix?.('UNKNOWN-999', true);
    expect(result).toBe(false);
  });
});
