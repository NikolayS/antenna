import { describe, expect, it } from 'bun:test';
import { generateHtml } from '../src/output/html.js';
import { generateJson } from '../src/output/json.js';
import { generateMarkdown } from '../src/output/markdown.js';
import type { AuditReport } from '../src/models.js';

const sampleReport: AuditReport = {
  timestamp: '2026-02-01T10:00:00Z',
  version: '0.1.0',
  hostname: 'test-host',
  findings: [
    {
      id: 'INFRA-001',
      title: 'SSH password auth enabled',
      message: 'Password authentication is enabled for SSH',
      level: 'block',
      autoFixable: true,
    },
    {
      id: 'CHAN-001',
      title: 'Telegram DMs open',
      message: 'Telegram allows DMs from anyone',
      level: 'critical',
      ocsasControl: 'ID-01',
    },
    {
      id: 'INFRA-004',
      title: 'fail2ban not running',
      message: 'fail2ban is not active',
      level: 'warning',
      autoFixable: true,
    },
  ],
  acceptedRisks: [],
  score: 55,
  summary: {
    blocked: 1,
    critical: 1,
    warnings: 1,
    info: 0,
  },
};

describe('Output Formats', () => {
  describe('HTML', () => {
    it('should generate valid HTML', () => {
      const html = generateHtml(sampleReport);

      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('<html lang="en">');
      expect(html).toContain('</html>');
    });

    it('should include report metadata', () => {
      const html = generateHtml(sampleReport);

      expect(html).toContain('test-host');
      expect(html).toContain('2026-02-01');
      expect(html).toContain('0.1.0');
    });

    it('should include score', () => {
      const html = generateHtml(sampleReport);

      expect(html).toContain('>55<');
    });

    it('should include findings', () => {
      const html = generateHtml(sampleReport);

      expect(html).toContain('INFRA-001');
      expect(html).toContain('SSH password auth enabled');
      expect(html).toContain('CHAN-001');
      expect(html).toContain('INFRA-004');
    });

    it('should include severity sections', () => {
      const html = generateHtml(sampleReport);

      expect(html).toContain('BLOCKED');
      expect(html).toContain('CRITICAL');
      expect(html).toContain('WARNING');
    });

    it('should escape HTML entities', () => {
      const reportWithSpecialChars: AuditReport = {
        ...sampleReport,
        findings: [
          {
            id: 'TEST-001',
            title: 'Test <script>alert("xss")</script>',
            message: 'Message with & and < and >',
            level: 'warning',
          },
        ],
      };

      const html = generateHtml(reportWithSpecialChars);

      expect(html).not.toContain('<script>');
      expect(html).toContain('&lt;script&gt;');
      expect(html).toContain('&amp;');
    });
  });

  describe('Markdown', () => {
    it('should generate markdown report', () => {
      const md = generateMarkdown(sampleReport);

      expect(md).toContain('# Antenna Security Audit Report');
      expect(md).toContain('**Host:** test-host');
      expect(md).toContain('**Score:** 55/100');
    });

    it('should include findings by level', () => {
      const md = generateMarkdown(sampleReport);

      expect(md).toContain('## 🔴 BLOCKED');
      expect(md).toContain('## 🟠 CRITICAL');
      expect(md).toContain('## 🟡 WARNING');
    });

    it('should include finding details', () => {
      const md = generateMarkdown(sampleReport);

      expect(md).toContain('### INFRA-001: SSH password auth enabled');
      expect(md).toContain('### CHAN-001: Telegram DMs open');
    });
  });

  describe('JSON', () => {
    it('should generate valid JSON', () => {
      const json = generateJson(sampleReport);
      const parsed = JSON.parse(json);

      expect(parsed.hostname).toBe('test-host');
      expect(parsed.score).toBe(55);
      expect(parsed.findings.length).toBe(3);
    });

    it('should include all report fields', () => {
      const json = generateJson(sampleReport);
      const parsed = JSON.parse(json);

      expect(parsed.timestamp).toBe('2026-02-01T10:00:00Z');
      expect(parsed.version).toBe('0.1.0');
      expect(parsed.summary.blocked).toBe(1);
      expect(parsed.summary.critical).toBe(1);
    });
  });
});
