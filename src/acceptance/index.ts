import { createHash } from 'node:crypto';
import {
  existsSync,
  readFileSync,
  appendFileSync,
  mkdirSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import type { RiskAcceptance } from '../models.js';
import { exec, isRoot } from '../utils/exec.js';

/**
 * Default acceptance file locations
 */
const SYSTEM_ACCEPTANCE_FILE = '/var/lib/antenna/accepted-risks.jsonl';
const USER_ACCEPTANCE_FILE = join(
  homedir(),
  '.openclaw',
  'antenna-accepted-risks.jsonl',
);

/**
 * Risk Acceptance Manager
 * Implements Section 5 from SPEC.md with hash chain verification
 */
export class AcceptanceManager {
  private filePath: string;
  private useSystemFile: boolean;

  constructor() {
    // Use system file if running as root or if it exists and is writable
    this.useSystemFile = isRoot() || this.canWriteSystemFile();
    this.filePath = this.useSystemFile
      ? SYSTEM_ACCEPTANCE_FILE
      : USER_ACCEPTANCE_FILE;
  }

  /**
   * Check if we can write to the system acceptance file
   */
  private canWriteSystemFile(): boolean {
    if (existsSync(SYSTEM_ACCEPTANCE_FILE)) {
      const result = exec(`test -w "${SYSTEM_ACCEPTANCE_FILE}" && echo "yes"`);
      return result.success && result.stdout === 'yes';
    }
    return false;
  }

  /**
   * Initialize the acceptance file
   */
  initialize(): void {
    if (existsSync(this.filePath)) {
      return;
    }

    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    writeFileSync(this.filePath, '', { mode: 0o600 });
  }

  /**
   * Get the file path being used
   */
  getFilePath(): string {
    return this.filePath;
  }

  /**
   * Is using the system-wide file?
   */
  isUsingSystemFile(): boolean {
    return this.useSystemFile;
  }

  /**
   * Load all accepted risks
   */
  loadAcceptances(): RiskAcceptance[] {
    if (!existsSync(this.filePath)) {
      return [];
    }

    const content = readFileSync(this.filePath, 'utf8');
    const lines = content.trim().split('\n').filter(Boolean);

    return lines.map((line) => JSON.parse(line) as RiskAcceptance);
  }

  /**
   * Get acceptance for a specific finding
   */
  getAcceptance(findingId: string): RiskAcceptance | null {
    const acceptances = this.loadAcceptances();
    const acceptance = acceptances.find((a) => a.id === findingId);

    if (!acceptance) {
      return null;
    }

    // Check if expired
    if (new Date(acceptance.expires_at) < new Date()) {
      return null;
    }

    return acceptance;
  }

  /**
   * Accept a risk
   */
  accept(
    findingId: string,
    reason: string,
    mitigations: string[],
    expirationDays: number,
    acceptedBy?: string,
  ): RiskAcceptance {
    this.initialize();

    const lines = existsSync(this.filePath)
      ? readFileSync(this.filePath, 'utf8').trim().split('\n').filter(Boolean)
      : [];

    // Calculate previous hash
    const prevHash =
      lines.length > 0
        ? this.sha256(lines[lines.length - 1])
        : '0'.repeat(64);

    // Create acceptance record
    const now = new Date();
    const expiresAt = new Date(now);
    expiresAt.setDate(expiresAt.getDate() + expirationDays);

    const acceptance: RiskAcceptance = {
      id: findingId,
      accepted_at: now.toISOString(),
      accepted_by: acceptedBy ?? this.getCurrentUser(),
      reason,
      mitigations,
      expires_at: expiresAt.toISOString(),
      prev_hash: prevHash,
    };

    // Append to file
    appendFileSync(this.filePath, JSON.stringify(acceptance) + '\n');

    return acceptance;
  }

  /**
   * Verify the hash chain integrity
   */
  verifyChain(): { valid: boolean; error?: string } {
    if (!existsSync(this.filePath)) {
      return { valid: true };
    }

    const content = readFileSync(this.filePath, 'utf8');
    const lines = content.trim().split('\n').filter(Boolean);

    let expectedPrevHash = '0'.repeat(64);

    for (let i = 0; i < lines.length; i++) {
      try {
        const record = JSON.parse(lines[i]) as RiskAcceptance;

        if (record.prev_hash !== expectedPrevHash) {
          return {
            valid: false,
            error: `Chain broken at line ${i + 1}: expected ${expectedPrevHash.slice(0, 16)}..., got ${record.prev_hash.slice(0, 16)}...`,
          };
        }

        expectedPrevHash = this.sha256(lines[i]);
      } catch (e) {
        return {
          valid: false,
          error: `Invalid JSON at line ${i + 1}`,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Get summary of current acceptances
   */
  getSummary(): {
    total: number;
    active: number;
    expired: number;
    byId: Map<string, RiskAcceptance>;
  } {
    const acceptances = this.loadAcceptances();
    const now = new Date();
    const byId = new Map<string, RiskAcceptance>();

    let active = 0;
    let expired = 0;

    for (const acceptance of acceptances) {
      const isExpired = new Date(acceptance.expires_at) < now;
      if (isExpired) {
        expired++;
      } else {
        active++;
        byId.set(acceptance.id, acceptance);
      }
    }

    return {
      total: acceptances.length,
      active,
      expired,
      byId,
    };
  }

  /**
   * SHA256 hash of a string
   */
  private sha256(data: string): string {
    return createHash('sha256').update(data, 'utf8').digest('hex');
  }

  /**
   * Get current username
   */
  private getCurrentUser(): string {
    const result = exec('whoami');
    return result.success ? result.stdout : 'unknown';
  }
}
