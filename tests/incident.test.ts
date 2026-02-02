import { describe, expect, it } from 'bun:test';
import { IncidentReporter } from '../src/incident/index.js';
import type { WatchEvent } from '../src/runtime/index.js';

describe('IncidentReporter', () => {
  it('should create reporter', () => {
    const reporter = new IncidentReporter();
    expect(reporter).toBeDefined();
  });

  it('should generate report from events', () => {
    const reporter = new IncidentReporter();

    const events: WatchEvent[] = [
      {
        timestamp: new Date().toISOString(),
        type: 'file_access',
        severity: 'high',
        source: 'auditd',
        message: 'Sensitive file access: ~/.aws/credentials',
        details: { file: '~/.aws/credentials' },
      },
    ];

    const report = reporter.generateFromEvents(events, []);

    expect(report.id).toMatch(/^INC-/);
    expect(report.summary).toContain('aws');
    expect(report.timeline.length).toBe(1);
    expect(report.recommendations.length).toBeGreaterThan(0);
  });

  it('should format report as markdown', () => {
    const reporter = new IncidentReporter();

    const events: WatchEvent[] = [
      {
        timestamp: new Date().toISOString(),
        type: 'file_access',
        severity: 'critical',
        source: 'auditd',
        message: 'Credential file accessed',
      },
    ];

    const report = reporter.generateFromEvents(events, []);
    const markdown = reporter.formatAsMarkdown(report);

    expect(markdown).toContain('# Incident Report');
    expect(markdown).toContain('## Summary');
    expect(markdown).toContain('## Timeline');
    expect(markdown).toContain('## Recommendations');
  });

  it('should identify contributing risks', () => {
    const reporter = new IncidentReporter();

    const events: WatchEvent[] = [
      {
        timestamp: new Date().toISOString(),
        type: 'file_access',
        severity: 'high',
        source: 'auditd',
        message: 'File access via telegram session',
      },
    ];

    const report = reporter.generateFromEvents(events, []);

    // Should generate recommendations
    expect(report.recommendations.length).toBeGreaterThan(0);
  });
});
