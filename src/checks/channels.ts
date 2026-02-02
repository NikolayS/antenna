import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { BaseChecker } from './base.js';
import type { CheckResult, Finding } from '../models.js';

interface ChannelConfig {
  dmPolicy?: 'open' | 'pairing' | 'allowlist' | 'disabled';
  groupPolicy?: 'open' | 'allowlist' | 'disabled';
  allowFrom?: string[] | '*';
  requireMention?: boolean;
  guilds?: string[];
}

interface OpenClawConfig {
  channels?: {
    telegram?: ChannelConfig;
    whatsapp?: ChannelConfig;
    discord?: ChannelConfig;
    slack?: ChannelConfig;
    imessage?: ChannelConfig;
    signal?: ChannelConfig;
  };
  session?: {
    dmScope?: 'user' | 'channel' | 'global';
  };
  tools?: {
    elevated?: {
      allowFrom?: string[] | '*';
    };
  };
  agents?: Record<
    string,
    {
      sandbox?: {
        mode?: 'full' | 'partial' | 'off';
      };
    }
  >;
}

/**
 * Channel security checks
 * Implements CHAN-001 through CHAN-010 from SPEC.md
 */
export class ChannelsChecker extends BaseChecker {
  name = 'channels';
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

    // Run all channel checks
    findings.push(...this.checkDMPolicies());
    findings.push(...this.checkGroupPolicies());
    findings.push(...this.checkTelegramAllowlist());
    findings.push(...this.checkWhatsAppPairing());
    findings.push(...this.checkIMessage());
    findings.push(...this.checkDiscordGuilds());
    findings.push(...this.checkOpenChannelWithTools());
    findings.push(...this.checkSessionIsolation());
    findings.push(...this.checkGroupMentionGating());

    return { findings };
  }

  /**
   * CHAN-001: Check for any channel with dmPolicy: "open"
   */
  private checkDMPolicies(): Finding[] {
    const findings: Finding[] = [];
    const channels = this.config?.channels;

    if (!channels) return [];

    for (const [name, config] of Object.entries(channels)) {
      if (config?.dmPolicy === 'open') {
        findings.push(
          this.createFinding(
            'CHAN-001',
            'critical',
            `${name} DMs open to anyone`,
            `${name} channel has dmPolicy: "open". Anyone can message your agent.`,
            {
              ocsasControl: 'ID-01',
              details: `Accept: antenna accept CHAN-001 --reason "..."`,
            },
          ),
        );
      }
    }

    return findings;
  }

  /**
   * CHAN-002: Check for any channel with groupPolicy: "open"
   */
  private checkGroupPolicies(): Finding[] {
    const findings: Finding[] = [];
    const channels = this.config?.channels;

    if (!channels) return [];

    for (const [name, config] of Object.entries(channels)) {
      if (config?.groupPolicy === 'open') {
        findings.push(
          this.createFinding(
            'CHAN-002',
            'critical',
            `${name} groups open to anyone`,
            `${name} channel has groupPolicy: "open". Agent responds in any group.`,
            {
              ocsasControl: 'ID-03',
            },
          ),
        );
      }
    }

    return findings;
  }

  /**
   * CHAN-003: Check if Telegram is configured without allowlist
   */
  private checkTelegramAllowlist(): Finding[] {
    const telegram = this.config?.channels?.telegram;

    if (!telegram) return [];

    // Check if DMs are enabled but no allowlist
    if (
      telegram.dmPolicy !== 'disabled' &&
      telegram.dmPolicy !== 'allowlist' &&
      (!telegram.allowFrom || telegram.allowFrom === '*')
    ) {
      return [
        this.createFinding(
          'CHAN-003',
          'warning',
          'Telegram without allowlist',
          'Telegram DMs are enabled without an allowlist. Consider restricting access.',
          {
            ocsasControl: 'ID-01',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * CHAN-004: Check if WhatsApp is configured without pairing
   */
  private checkWhatsAppPairing(): Finding[] {
    const whatsapp = this.config?.channels?.whatsapp;

    if (!whatsapp) return [];

    if (whatsapp.dmPolicy === 'open') {
      return [
        this.createFinding(
          'CHAN-004',
          'warning',
          'WhatsApp without pairing',
          'WhatsApp DMs are open without pairing requirement.',
          {
            ocsasControl: 'ID-01',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * CHAN-005: Warn if iMessage is enabled (inherently open)
   */
  private checkIMessage(): Finding[] {
    const imessage = this.config?.channels?.imessage;

    if (!imessage) return [];

    // iMessage is inherently open - anyone with your number/email can message
    return [
      this.createFinding(
        'CHAN-005',
        'warning',
        'iMessage enabled',
        'iMessage is enabled. This channel is inherently open to anyone with your contact info.',
      ),
    ];
  }

  /**
   * CHAN-006: Check Discord guild restrictions
   */
  private checkDiscordGuilds(): Finding[] {
    const discord = this.config?.channels?.discord;

    if (!discord) return [];

    if (discord.groupPolicy !== 'disabled' && !discord.guilds?.length) {
      return [
        this.createFinding(
          'CHAN-006',
          'info',
          'Discord without guild restrictions',
          'Discord is enabled without specific guild restrictions.',
          {
            ocsasControl: 'ID-03',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * CHAN-007: Check for open channel + tools enabled combo (BLOCK)
   */
  private checkOpenChannelWithTools(): Finding[] {
    const findings: Finding[] = [];
    const channels = this.config?.channels;
    const elevatedTools = this.config?.tools?.elevated;
    const agents = this.config?.agents;

    if (!channels) return [];

    // Check if any agent has sandbox off
    let toolsFullyEnabled = false;
    if (agents) {
      for (const agent of Object.values(agents)) {
        if (agent.sandbox?.mode === 'off') {
          toolsFullyEnabled = true;
          break;
        }
      }
    }

    // Check if elevated tools allow everyone
    if (elevatedTools?.allowFrom === '*') {
      toolsFullyEnabled = true;
    }

    if (!toolsFullyEnabled) return [];

    // Check each channel
    for (const [name, config] of Object.entries(channels)) {
      if (config?.dmPolicy === 'open') {
        findings.push(
          this.createFinding(
            'CHAN-007',
            'block',
            `Open ${name} + tools enabled`,
            `CRITICAL: ${name} has open DMs AND tools are enabled. This is extremely dangerous.`,
            {
              details:
                'Either restrict the channel or disable tools. Cannot proceed without --force.',
            },
          ),
        );
      }
    }

    return findings;
  }

  /**
   * CHAN-008: Check if session isolation is configured
   */
  private checkSessionIsolation(): Finding[] {
    const dmScope = this.config?.session?.dmScope;

    // If not specified or set to 'global', warn
    if (!dmScope || dmScope === 'global') {
      return [
        this.createFinding(
          'CHAN-008',
          'critical',
          'Session isolation not configured',
          'session.dmScope is not set or set to "global". Users may see each other\'s context.',
          {
            ocsasControl: 'ID-02',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * CHAN-009: Check if group mention gating is disabled
   */
  private checkGroupMentionGating(): Finding[] {
    const findings: Finding[] = [];
    const channels = this.config?.channels;

    if (!channels) return [];

    for (const [name, config] of Object.entries(channels)) {
      if (
        config?.groupPolicy !== 'disabled' &&
        config?.requireMention === false
      ) {
        findings.push(
          this.createFinding(
            'CHAN-009',
            'warning',
            `${name} group mention gating disabled`,
            `${name} responds to all messages in groups without requiring a mention.`,
            {
              ocsasControl: 'ID-03',
            },
          ),
        );
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
