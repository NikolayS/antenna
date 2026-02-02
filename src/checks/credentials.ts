import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join, basename } from 'node:path';
import { BaseChecker } from './base.js';
import type { CheckResult, Finding, SecretFinding } from '../models.js';
import { exec } from '../utils/exec.js';

/**
 * Secret patterns - from SPEC.md Section 4.5
 * Last updated: 2026-02
 */
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // Anthropic
  { name: 'Anthropic API key', pattern: /sk-ant-[a-zA-Z0-9-]{20,}/ },

  // OpenAI
  { name: 'OpenAI API key', pattern: /sk-[a-zA-Z0-9]{32,}/ },

  // AWS
  { name: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Temp Access Key', pattern: /ASIA[0-9A-Z]{16}/ },

  // GitHub
  { name: 'GitHub PAT (classic)', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  {
    name: 'GitHub PAT (fine-grained)',
    pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,
  },
  { name: 'GitHub OAuth', pattern: /gho_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub User-to-server', pattern: /ghu_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub Server-to-server', pattern: /ghs_[a-zA-Z0-9]{36}/ },

  // GitLab
  { name: 'GitLab PAT', pattern: /glpat-[a-zA-Z0-9\-_]{20,}/ },

  // HuggingFace
  { name: 'HuggingFace Access Token', pattern: /hf_[a-zA-Z]{34}/ },

  // Slack
  { name: 'Slack token', pattern: /xox[baprs]-[0-9]{10,}-[a-zA-Z0-9\-]+/ },

  // Private keys
  {
    name: 'Private key',
    pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----/,
  },

  // Connection strings
  {
    name: 'Database connection string',
    pattern: /(?:postgres|mysql|mongodb)(?:\+srv)?:\/\/[^:]+:[^@]+@/i,
  },
];

/**
 * Credential security checks
 * Implements CRED-001 through CRED-006 from SPEC.md
 */
export class CredentialsChecker extends BaseChecker {
  name = 'credentials';
  private secretLookbackDays: number;

  constructor(secretLookbackDays = 7) {
    super();
    this.secretLookbackDays = secretLookbackDays;
  }

  async run(): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Run all credential checks
    findings.push(...this.checkOpenClawDirPerms());
    findings.push(...this.checkConfigFilePerms());
    findings.push(...this.checkSecretsInTranscripts());
    findings.push(...this.checkAnthropicOAuthOnVM());
    findings.push(...this.checkEnvVars());
    findings.push(...this.checkLogRedaction());

    return { findings };
  }

  /**
   * CRED-001: Check ~/.openclaw directory permissions
   */
  private checkOpenClawDirPerms(): Finding[] {
    const openclawDir = join(homedir(), '.openclaw');

    if (!existsSync(openclawDir)) {
      return [];
    }

    try {
      const stats = statSync(openclawDir);
      const mode = stats.mode & 0o777;

      // Check if world-readable (others have read permission)
      if (mode & 0o004) {
        return [
          this.createFinding(
            'CRED-001',
            'block',
            '~/.openclaw world-readable',
            `~/.openclaw has mode ${mode.toString(8)}, allowing any user to read secrets.`,
            {
              autoFixable: true,
              ocsasControl: 'LS-01',
              details: 'Fix: chmod 700 ~/.openclaw',
            },
          ),
        ];
      }
    } catch {
      // Can't stat, skip
    }

    return [];
  }

  /**
   * CRED-002: Check config file permissions
   */
  private checkConfigFilePerms(): Finding[] {
    const configPaths = [
      join(homedir(), '.openclaw', 'openclaw.json'),
      join(homedir(), '.openclaw', 'credentials.json'),
      join(homedir(), '.openclaw', 'auth-profiles.json'),
    ];

    const findings: Finding[] = [];

    for (const configPath of configPaths) {
      if (!existsSync(configPath)) {
        continue;
      }

      try {
        const stats = statSync(configPath);
        const mode = stats.mode & 0o777;

        // Check if world-readable
        if (mode & 0o004) {
          findings.push(
            this.createFinding(
              'CRED-002',
              'critical',
              'Config file world-readable',
              `${basename(configPath)} has mode ${mode.toString(8)}, allowing any user to read it.`,
              {
                autoFixable: true,
                ocsasControl: 'LS-01',
                file: configPath,
                details: `Fix: chmod 600 ${configPath}`,
              },
            ),
          );
        }
      } catch {
        // Can't stat, skip
      }
    }

    return findings;
  }

  /**
   * CRED-003: Check for secrets in session transcripts
   */
  private checkSecretsInTranscripts(): Finding[] {
    const sessionsDir = join(homedir(), '.openclaw', 'agents');

    if (!existsSync(sessionsDir)) {
      return [];
    }

    const findings: Finding[] = [];
    const secretFindings: SecretFinding[] = [];
    const cutoffTime =
      this.secretLookbackDays > 0
        ? Date.now() - this.secretLookbackDays * 24 * 60 * 60 * 1000
        : 0;

    // Recursively find .jsonl files
    const jsonlFiles = this.findJsonlFiles(sessionsDir);

    for (const file of jsonlFiles) {
      try {
        const stats = statSync(file);

        // Skip old files if lookback is set
        if (cutoffTime > 0 && stats.mtimeMs < cutoffTime) {
          continue;
        }

        const content = readFileSync(file, 'utf8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (!line.trim()) continue;

          for (const { name, pattern } of SECRET_PATTERNS) {
            const match = line.match(pattern);
            if (match) {
              const valueHash = createHash('sha256')
                .update(match[0])
                .digest('hex');

              // Check if we already found this exact secret
              if (secretFindings.some((f) => f.valueHash === valueHash)) {
                continue;
              }

              secretFindings.push({
                file,
                line: i + 1,
                pattern: name,
                valueHash,
                context: {
                  before: lines[i - 1] || '',
                  match: line.replace(pattern, '[REDACTED]'),
                  after: lines[i + 1] || '',
                },
              });
            }
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    if (secretFindings.length > 0) {
      const fileCount = new Set(secretFindings.map((f) => f.file)).size;
      findings.push(
        this.createFinding(
          'CRED-003',
          'warning',
          'Secrets in session transcripts',
          `Found ${secretFindings.length} potential secrets in ${fileCount} transcript file(s).`,
          {
            ocsasControl: 'LS-02',
            details: `Use 'antenna audit --output json' for details. Consider rotating affected keys.`,
            evidence: secretFindings
              .slice(0, 5)
              .map((f) => `${basename(f.file)}:${f.line} - ${f.pattern}`),
          },
        ),
      );
    }

    return findings;
  }

  /**
   * CRED-004: Check for Anthropic Console OAuth on VM
   */
  private checkAnthropicOAuthOnVM(): Finding[] {
    // Check if running on a VM
    const isVM = this.isRunningOnVM();
    if (!isVM) {
      return [];
    }

    // Check for OAuth-style keys
    const authProfilesPath = join(homedir(), '.openclaw', 'auth-profiles.json');
    if (!existsSync(authProfilesPath)) {
      return [];
    }

    try {
      const content = readFileSync(authProfilesPath, 'utf8');

      // Look for OAuth indicators (console, oauth in metadata or sid-style keys)
      if (
        content.includes('sk-ant-sid') ||
        content.includes('"oauth"') ||
        content.includes('"console"')
      ) {
        return [
          this.createFinding(
            'CRED-004',
            'warning',
            'Anthropic Console OAuth key on VM',
            'Console OAuth keys are tied to personal accounts. Use org-managed API keys instead.',
          ),
        ];
      }
    } catch {
      // Can't read, skip
    }

    return [];
  }

  /**
   * CRED-005: Check for API keys in environment variables
   */
  private checkEnvVars(): Finding[] {
    const sensitiveEnvVars = [
      'ANTHROPIC_API_KEY',
      'OPENAI_API_KEY',
      'AWS_SECRET_ACCESS_KEY',
      'GITHUB_TOKEN',
      'GITLAB_TOKEN',
      'HF_TOKEN',
      'SLACK_TOKEN',
    ];

    const found = sensitiveEnvVars.filter((name) => process.env[name]);

    if (found.length > 0) {
      return [
        this.createFinding(
          'CRED-005',
          'info',
          'API keys in environment variables',
          `Found ${found.length} API key(s) in environment: ${found.join(', ')}.`,
          {
            ocsasControl: 'LS-01',
            details:
              'Consider using a secrets manager or config file with restricted permissions.',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * CRED-006: Check if log redaction is disabled
   */
  private checkLogRedaction(): Finding[] {
    const configPath = join(homedir(), '.openclaw', 'openclaw.json');

    if (!existsSync(configPath)) {
      return [];
    }

    try {
      const content = readFileSync(configPath, 'utf8');
      const config = JSON.parse(content);

      if (config.logging?.redactSensitive === false) {
        return [
          this.createFinding(
            'CRED-006',
            'warning',
            'Log redaction disabled',
            'logging.redactSensitive is false. Secrets may appear in logs.',
            {
              autoFixable: true,
              ocsasControl: 'LS-02',
            },
          ),
        ];
      }
    } catch {
      // Can't parse, skip
    }

    return [];
  }

  /**
   * Check if running on a VM (cloud or virtualized)
   */
  private isRunningOnVM(): boolean {
    // Check for cloud metadata endpoints
    const awsCheck = exec(
      'curl -s -m 1 http://169.254.169.254/latest/meta-data/ 2>/dev/null',
    );
    if (awsCheck.success) {
      return true;
    }

    // Check DMI for virtualization
    const dmiCheck = exec('cat /sys/class/dmi/id/product_name 2>/dev/null');
    if (dmiCheck.success) {
      const product = dmiCheck.stdout.toLowerCase();
      if (
        product.includes('virtual') ||
        product.includes('vmware') ||
        product.includes('kvm') ||
        product.includes('xen') ||
        product.includes('hetzner') ||
        product.includes('digitalocean')
      ) {
        return true;
      }
    }

    // Check systemd-detect-virt
    const virtCheck = exec('systemd-detect-virt 2>/dev/null');
    if (virtCheck.success && virtCheck.stdout !== 'none') {
      return true;
    }

    return false;
  }

  /**
   * Find all .jsonl files recursively
   */
  private findJsonlFiles(dir: string): string[] {
    const files: string[] = [];

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          files.push(...this.findJsonlFiles(fullPath));
        } else if (entry.isFile() && entry.name.endsWith('.jsonl')) {
          files.push(fullPath);
        }
      }
    } catch {
      // Can't read dir, skip
    }

    return files;
  }

  /**
   * Auto-fix implementation
   */
  async fix(findingId: string, dryRun = false): Promise<boolean> {
    switch (findingId) {
      case 'CRED-001':
        return this.fixOpenClawPerms(dryRun);
      case 'CRED-002':
        return this.fixConfigPerms(dryRun);
      default:
        return false;
    }
  }

  private fixOpenClawPerms(dryRun: boolean): boolean {
    const openclawDir = join(homedir(), '.openclaw');

    if (dryRun) {
      console.log(`[DRY RUN] Would run: chmod 700 ${openclawDir}`);
      return true;
    }

    const result = exec(`chmod 700 "${openclawDir}"`);
    return result.success;
  }

  private fixConfigPerms(dryRun: boolean): boolean {
    const configPaths = [
      join(homedir(), '.openclaw', 'openclaw.json'),
      join(homedir(), '.openclaw', 'credentials.json'),
      join(homedir(), '.openclaw', 'auth-profiles.json'),
    ];

    let success = true;

    for (const configPath of configPaths) {
      if (!existsSync(configPath)) {
        continue;
      }

      if (dryRun) {
        console.log(`[DRY RUN] Would run: chmod 600 ${configPath}`);
      } else {
        const result = exec(`chmod 600 "${configPath}"`);
        if (!result.success) {
          success = false;
        }
      }
    }

    return success;
  }
}
