import type { SeverityLevel } from './models.js';

/**
 * Security profiles for different deployment scenarios
 *
 * Each profile defines severity overrides for specific findings.
 * If a finding is not in the overrides, it uses its default severity.
 */
export interface SecurityProfile {
  name: string;
  description: string;
  /**
   * Map of finding ID patterns to severity overrides
   * Patterns can be exact (e.g., 'CHAN-001') or wildcards (e.g., 'CHAN-*')
   */
  severityOverrides: Record<string, SeverityLevel>;
  /**
   * Findings to completely skip in this profile
   */
  skip: string[];
}

/**
 * Public-facing bot profile - Most restrictive
 *
 * For bots exposed to untrusted users (public Telegram/Discord bots).
 * Assumes all incoming messages are potential attacks.
 */
export const publicBotProfile: SecurityProfile = {
  name: 'public-bot',
  description: 'Maximum security for public-facing bots',
  severityOverrides: {
    // Open channels are blocked for public bots
    'CHAN-001': 'block', // DM policy open → block
    'CHAN-002': 'block', // Group policy open → block
    // Sandbox is mandatory
    'TOOL-002': 'block', // Sandbox disabled → block
    'TOOL-004': 'block', // Exec without sandbox → block
    'TOOL-006': 'block', // Sandbox network egress → block
    // Log redaction mandatory
    'CRED-006': 'critical', // Log redaction disabled → critical
  },
  skip: [],
};

/**
 * Internal agent profile - Medium security
 *
 * For internal tools used by trusted employees only.
 * Some restrictions relaxed but still maintains good security.
 */
export const internalAgentProfile: SecurityProfile = {
  name: 'internal-agent',
  description: 'Balanced security for internal/trusted users',
  severityOverrides: {
    // DM policies can be more relaxed for internal users
    'CHAN-001': 'warning', // DM policy open → warning (not critical)
    // Session isolation still important
    'CHAN-008': 'critical', // Session isolation → critical
    // Sandbox recommended but not mandatory
    'TOOL-002': 'warning', // Sandbox disabled → warning
  },
  skip: [
    'INFRA-011', // SSH on port 22 is fine internally
    'NET-006', // mDNS is fine on internal networks
  ],
};

/**
 * Production enterprise profile - Full audit mode
 *
 * For production deployments in enterprise environments.
 * All checks enabled, strict mode, compliance-focused.
 */
export const prodEnterpriseProfile: SecurityProfile = {
  name: 'prod-enterprise',
  description: 'Strict compliance mode for production',
  severityOverrides: {
    // Everything that's normally warning becomes critical
    'INFRA-004': 'critical', // fail2ban → critical
    'INFRA-006': 'critical', // Security updates → critical
    'INFRA-008': 'critical', // Node.js outdated → critical
    'INFRA-009': 'critical', // OpenClaw outdated → critical
    'INFRA-010': 'critical', // Unattended upgrades → critical
    'CHAN-003': 'critical', // Telegram allowlist → critical
    'CHAN-005': 'critical', // iMessage → critical
    'CHAN-009': 'critical', // Group mention gating → critical
    'CRED-005': 'warning', // Env vars → warning (audit trail)
    // All network exposure is blocked
    'NET-001': 'block', // Gateway non-loopback → block
    'NET-003': 'block', // Gateway exposed → block
  },
  skip: [],
};

/**
 * Available profiles by name
 */
export const profiles: Record<string, SecurityProfile> = {
  'public-bot': publicBotProfile,
  'internal-agent': internalAgentProfile,
  'prod-enterprise': prodEnterpriseProfile,
};

/**
 * Get a profile by name
 */
export function getProfile(name: string): SecurityProfile | undefined {
  return profiles[name];
}

/**
 * List available profile names
 */
export function listProfiles(): string[] {
  return Object.keys(profiles);
}

/**
 * Apply profile overrides to a finding's severity
 */
export function applySeverityOverride(
  profile: SecurityProfile,
  findingId: string,
  defaultSeverity: SeverityLevel,
): SeverityLevel {
  // Check if finding should be skipped
  if (profile.skip.includes(findingId)) {
    return defaultSeverity; // Let caller handle skip
  }

  // Check exact match first
  if (profile.severityOverrides[findingId]) {
    return profile.severityOverrides[findingId];
  }

  // Check wildcard patterns (e.g., 'CHAN-*')
  for (const pattern of Object.keys(profile.severityOverrides)) {
    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1);
      if (findingId.startsWith(prefix)) {
        return profile.severityOverrides[pattern];
      }
    }
  }

  return defaultSeverity;
}

/**
 * Check if a finding should be skipped in this profile
 */
export function shouldSkipFinding(
  profile: SecurityProfile,
  findingId: string,
): boolean {
  return profile.skip.includes(findingId);
}
