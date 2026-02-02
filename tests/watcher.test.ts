import { describe, expect, it } from 'bun:test';
import {
  SecurityWatcher,
  generateAuditdRules,
  installAuditdRules,
} from '../src/runtime/index.js';

describe('SecurityWatcher', () => {
  it('should create watcher with default options', () => {
    const watcher = new SecurityWatcher();
    expect(watcher).toBeDefined();
  });

  it('should create watcher with custom options', () => {
    const watcher = new SecurityWatcher({
      killOn: 'critical',
      maxKillsPerHour: 5,
      startupCooldown: 120,
    });
    expect(watcher).toBeDefined();
  });
});

describe('generateAuditdRules', () => {
  it('should generate rules for default user', () => {
    const rules = generateAuditdRules();
    expect(rules).toContain('openclaw');
    expect(rules).toContain('antenna_ssh');
    expect(rules).toContain('antenna_aws');
    expect(rules).toContain('antenna_gpg');
    expect(rules).toContain('antenna_config');
  });

  it('should generate rules for custom user', () => {
    const rules = generateAuditdRules('myuser');
    expect(rules).toContain('/home/myuser/');
    // The default user 'openclaw' should not appear when custom user is specified
    expect(rules).not.toContain('/home/openclaw/');
  });

  it('should include all sensitive paths', () => {
    const rules = generateAuditdRules();
    expect(rules).toContain('.ssh');
    expect(rules).toContain('.aws');
    expect(rules).toContain('.gnupg');
    expect(rules).toContain('.openclaw');
    expect(rules).toContain('.config/gcloud');
  });
});

describe('installAuditdRules', () => {
  it('should support dry-run mode', () => {
    // Dry run should not fail
    const result = installAuditdRules('testuser', true);
    expect(result).toBe(true);
  });
});
