import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { BaseChecker } from './base.js';
import type { CheckResult, Finding } from '../models.js';
import { exec, commandExists } from '../utils/exec.js';

interface OpenClawConfig {
  plugins?: {
    allow?: string[];
    installed?: string[];
  };
}

interface PluginManifest {
  name: string;
  version?: string;
  description?: string;
}

/**
 * Skills & Supply Chain checks
 * Implements SKILL-001 through SKILL-003 from SPEC.md
 */
export class SkillsChecker extends BaseChecker {
  name = 'skills';
  private config: OpenClawConfig | null = null;

  async run(): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Load OpenClaw config
    this.config = this.loadOpenClawConfig();

    if (!this.config) {
      return {
        findings: [],
        skipped: 'OpenClaw config not found',
      };
    }

    // Run all skill checks
    findings.push(...this.checkPluginAllowlist());
    findings.push(...this.checkUnpinnedVersions());

    return { findings };
  }

  /**
   * SKILL-001: Check if plugins are installed without explicit allowlist
   */
  private checkPluginAllowlist(): Finding[] {
    const skillsDir = join(homedir(), '.openclaw', 'skills');
    const pluginsDir = join(homedir(), '.openclaw', 'plugins');

    // Get installed plugins
    const installed: string[] = [];

    for (const dir of [skillsDir, pluginsDir]) {
      if (existsSync(dir)) {
        try {
          const entries = readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.isDirectory()) {
              installed.push(entry.name);
            }
          }
        } catch {
          // Can't read, skip
        }
      }
    }

    if (installed.length === 0) {
      return [];
    }

    // Get allowlist from config
    const allowed = this.config?.plugins?.allow ?? [];

    // Check for plugins not in allowlist
    const unallowed = installed.filter(
      (plugin) => !allowed.includes(plugin) && !allowed.includes('*'),
    );

    if (unallowed.length > 0) {
      return [
        this.createFinding(
          'SKILL-001',
          'critical',
          'Plugins without explicit allowlist',
          `${unallowed.length} plugin(s) installed but not in plugins.allow: ${unallowed.slice(0, 5).join(', ')}${unallowed.length > 5 ? '...' : ''}`,
          {
            ocsasControl: 'SC-01',
            evidence: unallowed.slice(0, 10),
          },
        ),
      ];
    }

    return [];
  }

  /**
   * SKILL-003: Check for unpinned plugin versions
   */
  private checkUnpinnedVersions(): Finding[] {
    const findings: Finding[] = [];
    const skillsDir = join(homedir(), '.openclaw', 'skills');

    if (!existsSync(skillsDir)) {
      return [];
    }

    try {
      const entries = readdirSync(skillsDir, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;

        const manifestPath = join(skillsDir, entry.name, 'manifest.json');
        const packagePath = join(skillsDir, entry.name, 'package.json');

        let version: string | undefined;

        // Try manifest.json first
        if (existsSync(manifestPath)) {
          try {
            const manifest = JSON.parse(
              readFileSync(manifestPath, 'utf8'),
            ) as PluginManifest;
            version = manifest.version;
          } catch {
            // Invalid manifest
          }
        }

        // Try package.json
        if (!version && existsSync(packagePath)) {
          try {
            const pkg = JSON.parse(
              readFileSync(packagePath, 'utf8'),
            ) as PluginManifest;
            version = pkg.version;
          } catch {
            // Invalid package.json
          }
        }

        // Check if version is unpinned
        if (!version || version === 'latest' || version.includes('*')) {
          findings.push(
            this.createFinding(
              'SKILL-003',
              'warning',
              `Unpinned version: ${entry.name}`,
              `Skill "${entry.name}" has unpinned or missing version. Pin to specific version.`,
              {
                ocsasControl: 'SC-02',
              },
            ),
          );
        }
      }
    } catch {
      // Can't read, skip
    }

    return findings;
  }

  /**
   * Scan skills using Cisco Skill Scanner (if available)
   */
  async scanSkills(path?: string): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Check if skill-scanner is available
    if (!commandExists('skill-scanner')) {
      return {
        findings: [],
        skipped: 'skill-scanner not installed (npm install -g @cisco-ai-defense/skill-scanner)',
      };
    }

    const targetPath = path ?? join(homedir(), '.openclaw', 'skills');

    if (!existsSync(targetPath)) {
      return {
        findings: [],
        skipped: `Path not found: ${targetPath}`,
      };
    }

    // Run skill-scanner
    const result = exec(`skill-scanner scan "${targetPath}" --output json 2>/dev/null`);

    if (!result.success) {
      return {
        findings: [
          this.createFinding(
            'SKILL-002',
            'warning',
            'Skill Scanner failed',
            'Failed to run skill-scanner. Check installation.',
          ),
        ],
      };
    }

    try {
      const scanResult = JSON.parse(result.stdout) as {
        findings?: Array<{
          severity: string;
          message: string;
          file?: string;
        }>;
      };

      if (scanResult.findings && scanResult.findings.length > 0) {
        // Group by severity
        const critical = scanResult.findings.filter(
          (f) => f.severity === 'critical' || f.severity === 'high',
        );

        if (critical.length > 0) {
          findings.push(
            this.createFinding(
              'SKILL-002',
              'critical',
              'Skills with security findings',
              `Skill Scanner found ${critical.length} high/critical issues.`,
              {
                evidence: critical.slice(0, 5).map((f) => f.message),
              },
            ),
          );
        }
      }
    } catch {
      // Invalid JSON from scanner
    }

    return { findings };
  }

  /**
   * Load OpenClaw configuration
   */
  private loadOpenClawConfig(): OpenClawConfig | null {
    const configPaths = [
      join(homedir(), '.openclaw', 'openclaw.json'),
      join(process.cwd(), 'openclaw.json'),
      '/etc/openclaw/openclaw.json',
    ];

    for (const configPath of configPaths) {
      if (existsSync(configPath)) {
        try {
          const content = readFileSync(configPath, 'utf8');
          return JSON.parse(content) as OpenClawConfig;
        } catch {
          // Try next path
        }
      }
    }

    return null;
  }
}
