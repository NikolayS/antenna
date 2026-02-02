import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AcceptanceManager } from '../acceptance/index.js';
import type { RiskAcceptance, Finding } from '../models.js';
import type { WatchEvent } from '../runtime/index.js';

export interface IncidentReport {
  id: string;
  timestamp: string;
  summary: string;
  timeline: IncidentTimelineEntry[];
  configAtIncident: ConfigSnapshot;
  acceptedRisksContributed: AcceptedRiskContribution[];
  evidence: EvidenceItem[];
  recommendations: string[];
}

export interface IncidentTimelineEntry {
  timestamp: string;
  event: string;
  severity: string;
  source: string;
}

export interface ConfigSnapshot {
  findings: Finding[];
  acceptedRisks: RiskAcceptance[];
}

export interface AcceptedRiskContribution {
  acceptance: RiskAcceptance;
  howContributed: string;
}

export interface EvidenceItem {
  type: 'transcript' | 'log' | 'auditd';
  path: string;
  relevantLines?: string;
}

/**
 * Incident Report Generator
 * Implements Section 6.2 from SPEC.md
 */
export class IncidentReporter {
  private acceptanceManager: AcceptanceManager;

  constructor() {
    this.acceptanceManager = new AcceptanceManager();
  }

  /**
   * Generate incident report from watch events
   */
  generateFromEvents(
    events: WatchEvent[],
    findings: Finding[],
  ): IncidentReport {
    const now = new Date();
    const id = `INC-${now.toISOString().slice(0, 10)}-${Date.now().toString(36)}`;

    // Get accepted risks
    const acceptedRisks = this.acceptanceManager.loadAcceptances();
    const activeAcceptances = acceptedRisks.filter(
      (a) => new Date(a.expires_at) > now,
    );

    // Build timeline
    const timeline: IncidentTimelineEntry[] = events.map((e) => ({
      timestamp: e.timestamp,
      event: e.message,
      severity: e.severity,
      source: e.source,
    }));

    // Find accepted risks that may have contributed
    const contributions = this.findContributingRisks(events, activeAcceptances);

    // Collect evidence
    const evidence = this.collectEvidence(events);

    // Generate recommendations
    const recommendations = this.generateRecommendations(
      events,
      contributions,
      findings,
    );

    // Create summary
    const criticalEvents = events.filter(
      (e) => e.severity === 'critical' || e.severity === 'high',
    );
    const summary =
      criticalEvents.length > 0
        ? criticalEvents[0].message
        : events[0]?.message ?? 'Unknown incident';

    return {
      id,
      timestamp: now.toISOString(),
      summary,
      timeline,
      configAtIncident: {
        findings,
        acceptedRisks: activeAcceptances,
      },
      acceptedRisksContributed: contributions,
      evidence,
      recommendations,
    };
  }

  /**
   * Generate report for the last incident
   */
  async generateLastIncident(): Promise<IncidentReport | null> {
    // Read recent events from output file or logs
    const eventsFile = join(homedir(), '.openclaw', 'antenna-events.jsonl');

    if (!existsSync(eventsFile)) {
      return null;
    }

    const content = readFileSync(eventsFile, 'utf8');
    const lines = content.trim().split('\n').filter(Boolean);

    if (lines.length === 0) {
      return null;
    }

    // Get last hour of events
    const oneHourAgo = Date.now() - 3600000;
    const recentEvents: WatchEvent[] = [];

    for (const line of lines.reverse()) {
      try {
        const event = JSON.parse(line) as WatchEvent;
        if (new Date(event.timestamp).getTime() < oneHourAgo) {
          break;
        }
        recentEvents.unshift(event);
      } catch {
        // Invalid JSON, skip
      }
    }

    if (recentEvents.length === 0) {
      return null;
    }

    return this.generateFromEvents(recentEvents, []);
  }

  /**
   * Find accepted risks that may have contributed to the incident
   */
  private findContributingRisks(
    events: WatchEvent[],
    acceptances: RiskAcceptance[],
  ): AcceptedRiskContribution[] {
    const contributions: AcceptedRiskContribution[] = [];

    for (const acceptance of acceptances) {
      let howContributed: string | null = null;

      // Check if acceptance relates to the incident
      if (acceptance.id.startsWith('CHAN-')) {
        // Channel-related acceptances
        const hasChannelEvent = events.some(
          (e) =>
            e.message.toLowerCase().includes('telegram') ||
            e.message.toLowerCase().includes('discord') ||
            e.message.toLowerCase().includes('whatsapp'),
        );
        if (hasChannelEvent) {
          howContributed = `Channel policy acceptance may have allowed unauthorized access`;
        }
      }

      if (acceptance.id.startsWith('TOOL-')) {
        // Tool-related acceptances
        const hasFileAccess = events.some((e) => e.type === 'file_access');
        if (hasFileAccess) {
          howContributed = `Tool/sandbox acceptance may have allowed file system access`;
        }
      }

      if (acceptance.id.startsWith('NET-')) {
        // Network-related acceptances
        const hasNetworkEvent = events.some(
          (e) =>
            e.message.toLowerCase().includes('gateway') ||
            e.message.toLowerCase().includes('network'),
        );
        if (hasNetworkEvent) {
          howContributed = `Network exposure acceptance may have allowed remote access`;
        }
      }

      if (howContributed) {
        contributions.push({
          acceptance,
          howContributed,
        });
      }
    }

    return contributions;
  }

  /**
   * Collect evidence for the incident
   */
  private collectEvidence(events: WatchEvent[]): EvidenceItem[] {
    const evidence: EvidenceItem[] = [];

    // Find relevant transcript files
    const sessionsDir = join(homedir(), '.openclaw', 'agents');
    if (existsSync(sessionsDir)) {
      const today = new Date().toISOString().slice(0, 10);
      const transcripts = this.findTranscriptsForDate(sessionsDir, today);

      for (const transcript of transcripts.slice(0, 5)) {
        evidence.push({
          type: 'transcript',
          path: transcript,
        });
      }
    }

    // Add gateway log if exists
    const gatewayLog = '/var/log/openclaw/gateway.log';
    if (existsSync(gatewayLog)) {
      evidence.push({
        type: 'log',
        path: gatewayLog,
      });
    }

    // Add auditd evidence
    const hasAuditEvents = events.some((e) => e.source === 'auditd');
    if (hasAuditEvents) {
      evidence.push({
        type: 'auditd',
        path: 'ausearch -k antenna_* -ts recent',
      });
    }

    return evidence;
  }

  /**
   * Find transcript files for a given date
   */
  private findTranscriptsForDate(dir: string, date: string): string[] {
    const files: string[] = [];

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          files.push(...this.findTranscriptsForDate(fullPath, date));
        } else if (entry.name.includes(date) && entry.name.endsWith('.jsonl')) {
          files.push(fullPath);
        }
      }
    } catch {
      // Can't read directory
    }

    return files;
  }

  /**
   * Generate recommendations based on the incident
   */
  private generateRecommendations(
    events: WatchEvent[],
    contributions: AcceptedRiskContribution[],
    _findings: Finding[],
  ): string[] {
    const recommendations: string[] = [];

    // Based on event types
    const hasFileAccess = events.some((e) => e.type === 'file_access');
    const hasSecretDetected = events.some((e) => e.type === 'secret_detected');

    if (hasFileAccess) {
      recommendations.push('Enable sandbox mode for agents');
      recommendations.push('Add sensitive paths to exec blocked paths');
    }

    if (hasSecretDetected) {
      recommendations.push('Rotate any exposed credentials immediately');
      recommendations.push('Enable log redaction');
    }

    // Based on contributing acceptances
    for (const contrib of contributions) {
      if (contrib.acceptance.id.startsWith('CHAN-')) {
        recommendations.push('Restrict channel to allowlist');
      }
      if (contrib.acceptance.id.startsWith('TOOL-')) {
        recommendations.push('Re-evaluate sandbox settings');
      }
    }

    // Remove duplicates
    return [...new Set(recommendations)];
  }

  /**
   * Format report as markdown
   */
  formatAsMarkdown(report: IncidentReport): string {
    const lines: string[] = [];

    lines.push(`# Incident Report: ${report.timestamp}`);
    lines.push('');
    lines.push('## Summary');
    lines.push(report.summary);
    lines.push('');

    lines.push('## Timeline');
    lines.push('');
    for (const entry of report.timeline) {
      lines.push(
        `- ${entry.timestamp} - ${entry.event} (${entry.severity}, ${entry.source})`,
      );
    }
    lines.push('');

    lines.push('## Configuration at Time of Incident');
    lines.push('');
    for (const acceptance of report.configAtIncident.acceptedRisks) {
      lines.push(
        `- ${acceptance.id}: Accepted by ${acceptance.accepted_by} on ${acceptance.accepted_at}`,
      );
    }
    lines.push('');

    if (report.acceptedRisksContributed.length > 0) {
      lines.push('## Accepted Risks That May Have Contributed');
      lines.push('');
      for (const contrib of report.acceptedRisksContributed) {
        lines.push(`### ${contrib.acceptance.id}`);
        lines.push(`- Accepted: ${contrib.acceptance.accepted_at}`);
        lines.push(`- Reason: ${contrib.acceptance.reason}`);
        lines.push(`- How contributed: ${contrib.howContributed}`);
        lines.push('');
      }
    }

    lines.push('## Evidence');
    lines.push('');
    for (const item of report.evidence) {
      lines.push(`- ${item.type}: \`${item.path}\``);
    }
    lines.push('');

    lines.push('## Recommendations');
    lines.push('');
    for (let i = 0; i < report.recommendations.length; i++) {
      lines.push(`${i + 1}. ${report.recommendations[i]}`);
    }

    return lines.join('\n');
  }
}
