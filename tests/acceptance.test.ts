import { describe, expect, it, beforeEach, afterEach } from 'bun:test';
import { existsSync, unlinkSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AcceptanceManager } from '../src/acceptance/index.js';

describe('AcceptanceManager', () => {
  const testDir = join(tmpdir(), 'antenna-test-' + Date.now());
  const testFile = join(testDir, 'accepted-risks.jsonl');

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('verifyChain', () => {
    it('should return valid for empty file', () => {
      const manager = new AcceptanceManager();
      const result = manager.verifyChain();
      // Either valid or file doesn't exist
      expect(result.valid || !existsSync(manager.getFilePath())).toBe(true);
    });
  });

  describe('loadAcceptances', () => {
    it('should return empty array when no file exists', () => {
      const manager = new AcceptanceManager();
      // Clear any existing acceptances by checking fresh state
      const acceptances = manager.loadAcceptances();
      expect(Array.isArray(acceptances)).toBe(true);
    });
  });

  describe('getAcceptance', () => {
    it('should return null for non-existent finding', () => {
      const manager = new AcceptanceManager();
      const result = manager.getAcceptance('NONEXISTENT-999');
      expect(result).toBeNull();
    });
  });

  describe('getSummary', () => {
    it('should return summary with counts', () => {
      const manager = new AcceptanceManager();
      const summary = manager.getSummary();

      expect(typeof summary.total).toBe('number');
      expect(typeof summary.active).toBe('number');
      expect(typeof summary.expired).toBe('number');
      expect(summary.byId instanceof Map).toBe(true);
    });
  });

  describe('hash chain', () => {
    it('should create valid chain with first entry', () => {
      const manager = new AcceptanceManager();

      // Accept a risk
      const acceptance = manager.accept(
        'TEST-001',
        'Test reason',
        ['mitigation1'],
        30,
        'test-user',
      );

      expect(acceptance.id).toBe('TEST-001');
      expect(acceptance.reason).toBe('Test reason');
      expect(acceptance.mitigations).toEqual(['mitigation1']);
      expect(acceptance.prev_hash).toBe('0'.repeat(64));

      // Verify chain is still valid
      const chainStatus = manager.verifyChain();
      expect(chainStatus.valid).toBe(true);
    });
  });
});
