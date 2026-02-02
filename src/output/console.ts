import pc from 'picocolors';
import type { AuditReport, Finding, SeverityLevel } from '../models.js';

const BANNER = `
░██                                                                    ░██
░██                                                                    ░██
░██████   ░████████  ░████████  ░███████  ░████████  ░████████   ░██████
     ░██  ░██    ░██    ░██    ░██    ░██ ░██    ░██ ░██    ░██       ░██
░███████  ░██    ░██    ░██    ░█████████ ░██    ░██ ░██    ░██  ░███████
░██   ░██ ░██    ░██    ░██    ░██        ░██    ░██ ░██    ░██ ░██   ░██
░█████░██ ░██    ░██    ░████  ░███████   ░██    ░██ ░██    ░██ ░█████░██
`;

const LEVEL_ICONS: Record<SeverityLevel, string> = {
  block: '🔴',
  critical: '🟠',
  warning: '🟡',
  info: '🔵',
};

const LEVEL_NAMES: Record<SeverityLevel, string> = {
  block: 'BLOCKED',
  critical: 'CRITICAL',
  warning: 'WARNING',
  info: 'INFO',
};

function colorForLevel(level: SeverityLevel): (text: string) => string {
  switch (level) {
    case 'block':
      return pc.red;
    case 'critical':
      return pc.magenta;
    case 'warning':
      return pc.yellow;
    case 'info':
      return pc.blue;
  }
}

export function printBanner(version: string): void {
  console.log(pc.cyan(BANNER));
  console.log(
    pc.dim(
      `                                                            v${version} 🦞📡🚨\n`,
    ),
  );
}

export function printFinding(finding: Finding): void {
  const color = colorForLevel(finding.level);
  const icon = LEVEL_ICONS[finding.level];

  console.log(`  ${icon} ${pc.bold(finding.id)}  ${finding.title}`);
  console.log(`     ${pc.dim(finding.message)}`);

  if (finding.file) {
    console.log(`     ${pc.dim(`File: ${finding.file}`)}`);
  }

  if (finding.details) {
    console.log(`     ${color(finding.details)}`);
  }

  console.log();
}

export function printReport(report: AuditReport): void {
  printBanner(report.version);

  console.log(
    pc.dim(
      'Note: Network checks use local inference. Cloud firewalls and external',
    ),
  );
  console.log(
    pc.dim('proxies may affect accuracy. See NET-003 confidence levels.\n'),
  );

  console.log('Scanning...');
  console.log(pc.green('  Infrastructure ✓\n'));

  // Group findings by level
  const byLevel = new Map<SeverityLevel, Finding[]>();
  for (const finding of report.findings) {
    const existing = byLevel.get(finding.level) ?? [];
    existing.push(finding);
    byLevel.set(finding.level, existing);
  }

  // Print in order: block, critical, warning, info
  const levels: SeverityLevel[] = ['block', 'critical', 'warning', 'info'];

  for (const level of levels) {
    const findings = byLevel.get(level);
    if (!findings || findings.length === 0) continue;

    const color = colorForLevel(level);
    console.log(
      color(
        `${LEVEL_ICONS[level]} ${LEVEL_NAMES[level]} (${findings.length})\n`,
      ),
    );

    for (const finding of findings) {
      printFinding(finding);
    }
  }

  // Print summary
  console.log(pc.dim('──────────────────────────────────────────────'));
  console.log(
    `  ${pc.red(`🔴 ${report.summary.blocked} blocked`)}   ` +
      `${pc.magenta(`🟠 ${report.summary.critical} critical`)}   ` +
      `${pc.yellow(`🟡 ${report.summary.warnings} warnings`)}`,
  );
  console.log(`  Score: ${report.score}/100`);
  console.log(pc.dim('──────────────────────────────────────────────\n'));

  if (report.summary.blocked > 0 || report.summary.critical > 0) {
    console.log(`Fix all safe issues:  ${pc.cyan('antenna fix --all')}`);
  }
}

export function printSuccess(message: string): void {
  console.log(pc.green(`✓ ${message}`));
}

export function printError(message: string): void {
  console.log(pc.red(`✗ ${message}`));
}

export function printWarning(message: string): void {
  console.log(pc.yellow(`⚠ ${message}`));
}
