/**
 * Core types for Antenna security findings and risk management
 */

export type SeverityLevel = 'block' | 'critical' | 'warning' | 'info';

export interface Finding {
  id: string;
  level: SeverityLevel;
  title: string;
  message: string;
  details?: string;
  file?: string;
  line?: number;
  autoFixable: boolean;
  ocsasControl?: string;
  evidence?: string[];
  confidence?: 'high' | 'medium' | 'low';
}

export interface RiskAcceptance {
  id: string;
  accepted_at: string;
  accepted_by: string;
  reason: string;
  mitigations: string[];
  expires_at: string;
  prev_hash: string;
}

export interface CheckResult {
  findings: Finding[];
  skipped?: string;
}

export interface AuditReport {
  timestamp: string;
  version: string;
  hostname: string;
  findings: Finding[];
  acceptedRisks: RiskAcceptance[];
  score: number;
  summary: {
    blocked: number;
    critical: number;
    warnings: number;
    info: number;
  };
}

export interface BaseChecker {
  name: string;
  run(): Promise<CheckResult>;
  fix?(findingId: string, dryRun?: boolean): Promise<boolean>;
}

export interface SecretFinding {
  file: string;
  line: number;
  pattern: string;
  valueHash: string;
  jsonKeyPath?: string;
  context: {
    before: string;
    match: string;
    after: string;
  };
}
