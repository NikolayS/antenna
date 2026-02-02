import { Command } from 'commander';
import { AcceptanceManager } from './acceptance/index.js';
import {
  ChannelsChecker,
  CredentialsChecker,
  InfrastructureChecker,
  NetworkChecker,
  ToolsChecker,
} from './checks/index.js';
import type { AuditReport, Finding } from './models.js';
import {
  printError,
  printReport,
  printSuccess,
  printWarning,
} from './output/index.js';
import { exec } from './utils/exec.js';

const VERSION = '0.1.0';

function createProgram(): Command {
  const program = new Command();

  program
    .name('antenna')
    .description(
      'Security audit and monitoring for OpenClaw deployments on Ubuntu VMs',
    )
    .version(VERSION);

  // audit command
  program
    .command('audit')
    .description('Run security audit')
    .option('--deep', 'Run deep audit including Lynis')
    .option('--fix', 'Automatically fix safe issues')
    .option('-o, --output <format>', 'Output format: text, json, md', 'text')
    .option('--no-auditd', 'Skip auditd-related checks')
    .option(
      '--fail-on <level>',
      'Exit with code 1 if findings at level',
      'blocked',
    )
    .action(async (options) => {
      await runAudit(options);
    });

  // fix command
  program
    .command('fix [findingId]')
    .description('Auto-fix a finding or all fixable findings')
    .option('--all', 'Fix all auto-fixable findings')
    .option('--dry-run', 'Show what would be done without making changes')
    .option('--ssh-port <port>', 'SSH port for firewall rules')
    .action(async (findingId, options) => {
      await runFix(findingId, options);
    });

  // accept command
  program
    .command('accept <findingId>')
    .description('Accept a risk with documentation')
    .requiredOption('--reason <reason>', 'Why this risk is acceptable')
    .option(
      '--mitigations <mitigations>',
      'Compensating controls (comma-separated)',
    )
    .option('--expires <days>', 'Days until re-evaluation', '30')
    .action(async (findingId, options) => {
      await runAccept(findingId, options);
    });

  // watch command
  program
    .command('watch')
    .description('Start runtime monitoring daemon')
    .option(
      '--kill-on <level>',
      'Stop gateway on findings at level',
      'critical',
    )
    .option('--max-kills-per-hour <n>', 'Rate limit kills to prevent DoS', '3')
    .option('--restart-after <secs>', 'Auto-restart gateway after kill')
    .option(
      '--startup-cooldown <secs>',
      'Dont kill within first N seconds',
      '60',
    )
    .option('-o, --output <file>', 'Write events to file')
    .action(async (_options) => {
      console.log('Watch mode not yet implemented');
      // TODO: Implement watch daemon
    });

  // init command
  program
    .command('init')
    .description('Initialize Antenna configuration')
    .option('--hardened', 'Use hardened defaults')
    .action(async (_options) => {
      console.log('Init not yet implemented');
      // TODO: Implement init
    });

  // incident command
  program
    .command('incident')
    .description('Generate incident report')
    .option('--last', 'Show last incident')
    .option('--date <date>', 'Show incident from specific date')
    .option('--encrypt-to <email>', 'Encrypt report to email')
    .action(async (_options) => {
      console.log('Incident reporting not yet implemented');
      // TODO: Implement incident reporting
    });

  // status command
  program
    .command('status')
    .description('Show current security status')
    .action(async () => {
      console.log('Status not yet implemented');
      // TODO: Implement status
    });

  // skills command group
  const skills = program
    .command('skills')
    .description('Skill security scanning');

  skills
    .command('scan [path]')
    .description('Scan skills for vulnerabilities')
    .option('--all', 'Scan all installed skills')
    .action(async (_path, _options) => {
      console.log('Skills scanning not yet implemented');
      // TODO: Implement skill scanning
    });

  skills
    .command('check <url>')
    .description('Check a skill before installing')
    .action(async (_url) => {
      console.log('Skill checking not yet implemented');
      // TODO: Implement skill checking
    });

  // report command
  program
    .command('report')
    .description('Generate security report')
    .option('-o, --output <file>', 'Output file')
    .option('-f, --format <format>', 'Format: md, json, html', 'md')
    .action(async (_options) => {
      console.log('Report generation not yet implemented');
      // TODO: Implement report generation
    });

  return program;
}

async function runAudit(options: {
  deep?: boolean;
  fix?: boolean;
  output: string;
  auditd?: boolean;
  failOn: string;
}): Promise<void> {
  const findings: Finding[] = [];
  const skipped: string[] = [];

  // Run infrastructure checks
  const infraChecker = new InfrastructureChecker();
  const infraResult = await infraChecker.run();
  findings.push(...infraResult.findings);
  if (infraResult.skipped) skipped.push(`Infrastructure: ${infraResult.skipped}`);

  // Run network checks
  const networkChecker = new NetworkChecker();
  const networkResult = await networkChecker.run();
  findings.push(...networkResult.findings);
  if (networkResult.skipped) skipped.push(`Network: ${networkResult.skipped}`);

  // Run credentials checks
  const credentialsChecker = new CredentialsChecker();
  const credentialsResult = await credentialsChecker.run();
  findings.push(...credentialsResult.findings);
  if (credentialsResult.skipped) skipped.push(`Credentials: ${credentialsResult.skipped}`);

  // Run channels checks
  const channelsChecker = new ChannelsChecker();
  const channelsResult = await channelsChecker.run();
  findings.push(...channelsResult.findings);
  if (channelsResult.skipped) skipped.push(`Channels: ${channelsResult.skipped}`);

  // Run tools checks
  const toolsChecker = new ToolsChecker();
  const toolsResult = await toolsChecker.run();
  findings.push(...toolsResult.findings);
  if (toolsResult.skipped) skipped.push(`Tools: ${toolsResult.skipped}`);

  // Create report
  const hostname = exec('hostname').stdout || 'unknown';
  const report: AuditReport = {
    timestamp: new Date().toISOString(),
    version: VERSION,
    hostname,
    findings,
    acceptedRisks: [],
    score: calculateScore(findings),
    summary: {
      blocked: findings.filter((f) => f.level === 'block').length,
      critical: findings.filter((f) => f.level === 'critical').length,
      warnings: findings.filter((f) => f.level === 'warning').length,
      info: findings.filter((f) => f.level === 'info').length,
    },
  };

  // Output
  if (options.output === 'json') {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printReport(report);
  }

  // Auto-fix if requested
  if (options.fix) {
    const fixable = findings.filter((f) => f.autoFixable);
    for (const finding of fixable) {
      const fixed = await infraChecker.fix?.(finding.id);
      if (fixed) {
        printSuccess(`Fixed ${finding.id}`);
      } else {
        printError(`Failed to fix ${finding.id}`);
      }
    }
  }

  // Exit with error if findings at specified level
  const failLevel = options.failOn;
  if (failLevel === 'blocked' && report.summary.blocked > 0) {
    process.exit(1);
  }
  if (
    failLevel === 'critical' &&
    (report.summary.blocked > 0 || report.summary.critical > 0)
  ) {
    process.exit(1);
  }
}

async function runFix(
  findingId: string | undefined,
  options: { all?: boolean; dryRun?: boolean; sshPort?: string },
): Promise<void> {
  if (!findingId && !options.all) {
    printError('Specify a finding ID or use --all');
    process.exit(1);
  }

  const infraChecker = new InfrastructureChecker();

  if (options.all) {
    // First run audit to get findings
    const result = await infraChecker.run();
    const fixable = result.findings.filter((f) => f.autoFixable);

    if (fixable.length === 0) {
      printSuccess('No auto-fixable findings');
      return;
    }

    for (const finding of fixable) {
      console.log(`\nFixing ${finding.id}: ${finding.title}`);
      const fixed = await infraChecker.fix?.(finding.id, options.dryRun);
      if (fixed) {
        printSuccess(`Fixed ${finding.id}`);
      } else {
        printError(`Failed to fix ${finding.id}`);
      }
    }
  } else if (findingId) {
    const fixed = await infraChecker.fix?.(findingId, options.dryRun);
    if (fixed) {
      printSuccess(`Fixed ${findingId}`);
    } else {
      printError(`Failed to fix ${findingId}`);
    }
  }
}

function calculateScore(findings: Finding[]): number {
  let score = 100;

  for (const finding of findings) {
    switch (finding.level) {
      case 'block':
        score -= 25;
        break;
      case 'critical':
        score -= 15;
        break;
      case 'warning':
        score -= 5;
        break;
      case 'info':
        score -= 1;
        break;
    }
  }

  return Math.max(0, score);
}

async function runAccept(
  findingId: string,
  options: { reason: string; mitigations?: string; expires: string },
): Promise<void> {
  const manager = new AcceptanceManager();

  // Parse mitigations
  const mitigations = options.mitigations
    ? options.mitigations.split(',').map((m) => m.trim())
    : [];

  // Parse expiration days
  const expirationDays = Number.parseInt(options.expires, 10);
  if (Number.isNaN(expirationDays) || expirationDays <= 0) {
    printError('Invalid expiration days');
    process.exit(1);
  }

  // Warn if not using system file
  if (!manager.isUsingSystemFile()) {
    printWarning(
      'Using user-level acceptance file. For production, run with sudo to use system file.',
    );
  }

  // Verify chain integrity before adding
  const chainStatus = manager.verifyChain();
  if (!chainStatus.valid) {
    printError(`Acceptance file integrity check failed: ${chainStatus.error}`);
    printError('Cannot add new acceptance until file is fixed.');
    process.exit(1);
  }

  // Accept the risk
  const acceptance = manager.accept(
    findingId,
    options.reason,
    mitigations,
    expirationDays,
  );

  printSuccess(`Accepted ${findingId}`);
  console.log(`  Reason: ${acceptance.reason}`);
  console.log(`  Expires: ${acceptance.expires_at}`);
  console.log(`  File: ${manager.getFilePath()}`);
}

export function run(): void {
  const program = createProgram();
  program.parse();
}
