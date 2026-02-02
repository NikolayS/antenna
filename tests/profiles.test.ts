import { describe, expect, it } from 'bun:test';
import {
  getProfile,
  listProfiles,
  applySeverityOverride,
  shouldSkipFinding,
  publicBotProfile,
  internalAgentProfile,
  prodEnterpriseProfile,
} from '../src/profiles.js';

describe('Security Profiles', () => {
  describe('listProfiles', () => {
    it('should return all profile names', () => {
      const profiles = listProfiles();

      expect(profiles).toContain('public-bot');
      expect(profiles).toContain('internal-agent');
      expect(profiles).toContain('prod-enterprise');
    });
  });

  describe('getProfile', () => {
    it('should return profile by name', () => {
      const profile = getProfile('public-bot');

      expect(profile).toBeDefined();
      expect(profile?.name).toBe('public-bot');
    });

    it('should return undefined for unknown profile', () => {
      const profile = getProfile('unknown-profile');

      expect(profile).toBeUndefined();
    });
  });

  describe('public-bot profile', () => {
    it('should block open DM policy', () => {
      const severity = applySeverityOverride(
        publicBotProfile,
        'CHAN-001',
        'critical',
      );

      expect(severity).toBe('block');
    });

    it('should block sandbox disabled', () => {
      const severity = applySeverityOverride(
        publicBotProfile,
        'TOOL-002',
        'critical',
      );

      expect(severity).toBe('block');
    });

    it('should not override findings without overrides', () => {
      const severity = applySeverityOverride(
        publicBotProfile,
        'INFRA-001',
        'block',
      );

      expect(severity).toBe('block');
    });
  });

  describe('internal-agent profile', () => {
    it('should downgrade open DM to warning', () => {
      const severity = applySeverityOverride(
        internalAgentProfile,
        'CHAN-001',
        'critical',
      );

      expect(severity).toBe('warning');
    });

    it('should skip SSH port check', () => {
      const skip = shouldSkipFinding(internalAgentProfile, 'INFRA-011');

      expect(skip).toBe(true);
    });

    it('should skip mDNS check', () => {
      const skip = shouldSkipFinding(internalAgentProfile, 'NET-006');

      expect(skip).toBe(true);
    });
  });

  describe('prod-enterprise profile', () => {
    it('should upgrade fail2ban to critical', () => {
      const severity = applySeverityOverride(
        prodEnterpriseProfile,
        'INFRA-004',
        'warning',
      );

      expect(severity).toBe('critical');
    });

    it('should block gateway non-loopback', () => {
      const severity = applySeverityOverride(
        prodEnterpriseProfile,
        'NET-001',
        'critical',
      );

      expect(severity).toBe('block');
    });

    it('should not skip any findings', () => {
      const skip1 = shouldSkipFinding(prodEnterpriseProfile, 'INFRA-011');
      const skip2 = shouldSkipFinding(prodEnterpriseProfile, 'NET-006');

      expect(skip1).toBe(false);
      expect(skip2).toBe(false);
    });
  });

  describe('applySeverityOverride', () => {
    it('should return default severity when no override', () => {
      const severity = applySeverityOverride(
        publicBotProfile,
        'UNKNOWN-001',
        'info',
      );

      expect(severity).toBe('info');
    });
  });
});
