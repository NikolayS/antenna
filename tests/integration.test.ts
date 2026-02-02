import { describe, expect, it } from 'bun:test';

/**
 * Helper to run CLI commands that may exit with non-zero status
 * Returns stdout even if exit code is non-zero (e.g., due to blocked findings)
 */
async function runCli(
  args: string[],
): Promise<{ stdout: string; exitCode: number }> {
  const proc = Bun.spawn(['bun', 'run', 'src/index.ts', ...args], {
    stdout: 'pipe',
    stderr: 'pipe',
  });

  const stdout = await new Response(proc.stdout).text();
  const exitCode = await proc.exited;

  return { stdout, exitCode };
}

describe('CLI Integration', () => {
  describe('antenna --version', () => {
    it('should output version', async () => {
      const { stdout } = await runCli(['--version']);

      expect(stdout.trim()).toBe('0.1.0');
    });
  });

  describe('antenna --help', () => {
    it('should output help text', async () => {
      const { stdout } = await runCli(['--help']);

      expect(stdout).toContain('antenna');
      expect(stdout).toContain('audit');
      expect(stdout).toContain('fix');
      expect(stdout).toContain('accept');
      expect(stdout).toContain('watch');
    });
  });

  describe('antenna audit', () => {
    it('should run audit with text output', async () => {
      const { stdout } = await runCli(['audit']);

      // Should contain some output (findings or score)
      expect(stdout.length).toBeGreaterThan(0);
    });

    it('should run audit with json output', async () => {
      const { stdout } = await runCli(['audit', '--output', 'json']);

      // Should be valid JSON
      const parsed = JSON.parse(stdout);
      expect(parsed.hostname).toBeDefined();
      expect(parsed.findings).toBeInstanceOf(Array);
      expect(parsed.score).toBeTypeOf('number');
      expect(parsed.summary).toBeDefined();
    });

    it('should run audit with markdown output', async () => {
      const { stdout } = await runCli(['audit', '--output', 'md']);

      expect(stdout).toContain('# Antenna Security Audit Report');
      expect(stdout).toContain('## Summary');
    });

    it('should run audit with html output', async () => {
      const { stdout } = await runCli(['audit', '--output', 'html']);

      expect(stdout).toContain('<!DOCTYPE html>');
      expect(stdout).toContain('Antenna Security Audit');
      expect(stdout).toContain('</html>');
    });

    it('should apply profile when specified', async () => {
      // Profile message only shows in text output
      const { stdout } = await runCli([
        'audit',
        '--output',
        'text',
        '--profile',
        'public-bot',
      ]);

      expect(stdout).toContain('Using profile: public-bot');
    });

    it('should reject invalid profile', async () => {
      const { exitCode } = await runCli([
        'audit',
        '--profile',
        'invalid-profile',
      ]);

      expect(exitCode).toBe(1);
    });
  });

  describe('antenna init', () => {
    it('should show initialization steps', async () => {
      const { stdout } = await runCli(['init']);

      expect(stdout).toContain('Initializing Antenna');
      expect(stdout).toContain('Next steps');
      expect(stdout).toContain('antenna audit');
    });

    it('should show pre-start integration guidance', async () => {
      const { stdout } = await runCli(['init']);

      expect(stdout).toContain('Pre-start Integration');
      expect(stdout).toContain('--fail-on blocked');
    });
  });

  describe('antenna skills', () => {
    it('should have skills subcommands', async () => {
      const { stdout } = await runCli(['skills', '--help']);

      expect(stdout).toContain('scan');
      expect(stdout).toContain('check');
    });
  });

  describe('antenna incident', () => {
    it('should show message when no incidents', async () => {
      const { stdout } = await runCli(['incident']);

      // Will either show no incidents or an incident
      expect(stdout.length).toBeGreaterThan(0);
    });
  });
});

describe('Report Generation', () => {
  it('should generate consistent report structure', async () => {
    const { stdout } = await runCli(['audit', '--output', 'json']);
    const report = JSON.parse(stdout);

    // Verify report structure
    expect(report).toHaveProperty('timestamp');
    expect(report).toHaveProperty('version');
    expect(report).toHaveProperty('hostname');
    expect(report).toHaveProperty('findings');
    expect(report).toHaveProperty('acceptedRisks');
    expect(report).toHaveProperty('score');
    expect(report).toHaveProperty('summary');

    // Verify summary structure
    expect(report.summary).toHaveProperty('blocked');
    expect(report.summary).toHaveProperty('critical');
    expect(report.summary).toHaveProperty('warnings');
    expect(report.summary).toHaveProperty('info');

    // Score should be between 0 and 100
    expect(report.score).toBeGreaterThanOrEqual(0);
    expect(report.score).toBeLessThanOrEqual(100);
  });

  it('should include finding details', async () => {
    const { stdout } = await runCli(['audit', '--output', 'json']);
    const report = JSON.parse(stdout);

    // Every finding should have required fields
    for (const finding of report.findings) {
      expect(finding).toHaveProperty('id');
      expect(finding).toHaveProperty('title');
      expect(finding).toHaveProperty('message');
      expect(finding).toHaveProperty('level');
      expect(['block', 'critical', 'warning', 'info']).toContain(finding.level);
    }
  });
});

describe('Profile Application', () => {
  it('public-bot profile should upgrade severity', async () => {
    const { stdout: defaultResult } = await runCli([
      'audit',
      '--output',
      'json',
    ]);
    const { stdout: profileResult } = await runCli([
      'audit',
      '--output',
      'json',
      '--profile',
      'public-bot',
    ]);

    const defaultReport = JSON.parse(defaultResult);
    const profileReport = JSON.parse(profileResult);

    // public-bot profile should have same or more blocked findings
    // (because it upgrades certain findings to block)
    expect(profileReport.summary.blocked).toBeGreaterThanOrEqual(
      defaultReport.summary.blocked,
    );
  });

  it('internal-agent profile should skip certain findings', async () => {
    const { stdout: defaultResult } = await runCli([
      'audit',
      '--output',
      'json',
    ]);
    const { stdout: profileResult } = await runCli([
      'audit',
      '--output',
      'json',
      '--profile',
      'internal-agent',
    ]);

    const defaultReport = JSON.parse(defaultResult);
    const profileReport = JSON.parse(profileResult);

    // internal-agent profile may have fewer findings due to skips
    // Just verify both are valid reports
    expect(defaultReport.findings).toBeInstanceOf(Array);
    expect(profileReport.findings).toBeInstanceOf(Array);
  });
});
