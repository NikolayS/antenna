import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { BaseChecker } from './base.js';
import type { CheckResult, Finding } from '../models.js';

interface OpenClawConfig {
  tools?: {
    elevated?: {
      allowFrom?: string[] | '*';
    };
    exec?: {
      host?: boolean;
    };
  };
  agents?: Record<
    string,
    {
      sandbox?: {
        mode?: 'full' | 'partial' | 'off';
        docker?: {
          network?: 'none' | 'bridge' | 'host';
        };
        workspaceAccess?: 'read' | 'read-write';
      };
      model?: string;
    }
  >;
  gateway?: {
    nodes?: {
      browser?: {
        mode?: 'disabled' | 'local' | 'remote';
      };
    };
  };
}

// Models considered weaker for tool use
const WEAK_MODELS = [
  'gpt-3.5-turbo',
  'claude-instant',
  'claude-2.0',
  'mistral-7b',
  'llama-7b',
  'llama-13b',
];

/**
 * Tool & Execution security checks
 * Implements TOOL-001 through TOOL-007 from SPEC.md
 */
export class ToolsChecker extends BaseChecker {
  name = 'tools';
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

    // Run all tool checks
    findings.push(...this.checkElevatedAllowFrom());
    findings.push(...this.checkSandboxDisabled());
    findings.push(...this.checkBrowserControl());
    findings.push(...this.checkExecTool());
    findings.push(...this.checkWorkspaceAccess());
    findings.push(...this.checkSandboxNetworkEgress());
    findings.push(...this.checkWeakModelWithTools());

    return { findings };
  }

  /**
   * TOOL-001: Check if elevated tools allowFrom is "*"
   */
  private checkElevatedAllowFrom(): Finding[] {
    const elevatedAllowFrom = this.config?.tools?.elevated?.allowFrom;

    if (elevatedAllowFrom === '*') {
      return [
        this.createFinding(
          'TOOL-001',
          'block',
          'Elevated tools allow everyone',
          'tools.elevated.allowFrom is "*". This MUST be removed - no exception.',
          {
            ocsasControl: 'TB-02',
            details:
              'This is a BLOCK finding that cannot be accepted. Remove the wildcard.',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * TOOL-002: Check if sandbox is disabled with tools enabled
   */
  private checkSandboxDisabled(): Finding[] {
    const findings: Finding[] = [];
    const agents = this.config?.agents;

    if (!agents) return [];

    for (const [name, agent] of Object.entries(agents)) {
      if (agent.sandbox?.mode === 'off') {
        findings.push(
          this.createFinding(
            'TOOL-002',
            'critical',
            `Sandbox disabled for ${name}`,
            `Agent "${name}" has sandbox.mode: "off". Tools run directly on host.`,
            {
              ocsasControl: 'TB-03',
            },
          ),
        );
      }
    }

    return findings;
  }

  /**
   * TOOL-003: Check if browser control is enabled remotely
   */
  private checkBrowserControl(): Finding[] {
    const browserMode = this.config?.gateway?.nodes?.browser?.mode;

    if (browserMode === 'remote') {
      return [
        this.createFinding(
          'TOOL-003',
          'warning',
          'Browser control enabled remotely',
          'gateway.nodes.browser.mode is "remote". Remote users can control the browser.',
          {
            ocsasControl: 'TB-02',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * TOOL-004: Check if exec tool is enabled without sandbox
   */
  private checkExecTool(): Finding[] {
    const execHost = this.config?.tools?.exec?.host;
    const agents = this.config?.agents;

    if (execHost !== true) return [];

    // Check if any agent has sandbox off
    if (agents) {
      for (const agent of Object.values(agents)) {
        if (agent.sandbox?.mode === 'off') {
          return [
            this.createFinding(
              'TOOL-004',
              'warning',
              'Exec tool without sandbox',
              'tools.exec.host is true and sandbox is disabled. Commands run directly on host.',
              {
                ocsasControl: 'TB-03',
              },
            ),
          ];
        }
      }
    }

    return [];
  }

  /**
   * TOOL-005: Check if workspace access is read-write
   */
  private checkWorkspaceAccess(): Finding[] {
    const findings: Finding[] = [];
    const agents = this.config?.agents;

    if (!agents) return [];

    for (const [name, agent] of Object.entries(agents)) {
      if (agent.sandbox?.workspaceAccess === 'read-write') {
        findings.push(
          this.createFinding(
            'TOOL-005',
            'info',
            `${name} has read-write workspace`,
            `Agent "${name}" has sandbox.workspaceAccess: "read-write".`,
            {
              ocsasControl: 'TB-01',
            },
          ),
        );
      }
    }

    return findings;
  }

  /**
   * TOOL-006: Check if sandbox allows network egress
   */
  private checkSandboxNetworkEgress(): Finding[] {
    const findings: Finding[] = [];
    const agents = this.config?.agents;

    if (!agents) return [];

    for (const [name, agent] of Object.entries(agents)) {
      const network = agent.sandbox?.docker?.network;

      // 'bridge' or 'host' allows network access
      if (network === 'bridge' || network === 'host') {
        findings.push(
          this.createFinding(
            'TOOL-006',
            'critical',
            `${name} sandbox allows network`,
            `Agent "${name}" has sandbox.docker.network: "${network}". Agent can make network requests.`,
            {
              ocsasControl: 'TB-04',
            },
          ),
        );
      }
    }

    return findings;
  }

  /**
   * TOOL-007: Check for weak model with tools enabled
   */
  private checkWeakModelWithTools(): Finding[] {
    const findings: Finding[] = [];
    const agents = this.config?.agents;

    if (!agents) return [];

    for (const [name, agent] of Object.entries(agents)) {
      const model = agent.model?.toLowerCase();
      const sandboxOff = agent.sandbox?.mode === 'off';

      if (model && sandboxOff) {
        // Check if model is considered weak
        const isWeak = WEAK_MODELS.some((weak) => model.includes(weak));

        if (isWeak) {
          findings.push(
            this.createFinding(
              'TOOL-007',
              'warning',
              `Weak model with tools for ${name}`,
              `Agent "${name}" uses model "${model}" with sandbox disabled. Weaker models are more susceptible to prompt injection.`,
              {
                ocsasControl: 'LS-03',
              },
            ),
          );
        }
      }
    }

    return findings;
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
