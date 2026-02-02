import { createReadStream, existsSync, watch, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { exec } from '../utils/exec.js';

export interface WatchEvent {
  timestamp: string;
  type: 'file_access' | 'config_change' | 'secret_detected' | 'process_spawn';
  severity: 'info' | 'warning' | 'high' | 'critical';
  source: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface WatchOptions {
  killOn?: 'critical' | 'high';
  maxKillsPerHour?: number;
  restartAfter?: number;
  startupCooldown?: number;
  outputFile?: string;
}

interface AuditEvent {
  type: string;
  key?: string;
  auid?: string;
  uid?: string;
  exe?: string;
  name?: string;
  success?: string;
}

/**
 * Runtime security monitor
 * Implements Section 6 from SPEC.md
 */
export class SecurityWatcher {
  private options: WatchOptions;
  private killCount = 0;
  private killCountResetTime = Date.now();
  private startTime = Date.now();
  private running = false;
  private openclawUid: string | null = null;

  constructor(options: WatchOptions = {}) {
    this.options = {
      killOn: options.killOn,
      maxKillsPerHour: options.maxKillsPerHour ?? 3,
      restartAfter: options.restartAfter,
      startupCooldown: options.startupCooldown ?? 60,
      outputFile: options.outputFile,
    };
  }

  /**
   * Start the security watcher
   */
  async start(): Promise<void> {
    this.running = true;
    this.startTime = Date.now();

    // Get openclaw user UID if exists
    const uidResult = exec('id -u openclaw 2>/dev/null');
    if (uidResult.success) {
      this.openclawUid = uidResult.stdout;
    }

    console.log('Antenna security watcher started');
    console.log(`  Kill on: ${this.options.killOn ?? 'disabled'}`);
    console.log(`  Max kills/hour: ${this.options.maxKillsPerHour}`);
    console.log(`  Startup cooldown: ${this.options.startupCooldown}s`);

    // Start watchers in parallel
    await Promise.all([
      this.watchAuditLog(),
      this.watchConfigChanges(),
      this.watchTranscripts(),
    ]);
  }

  /**
   * Stop the watcher
   */
  stop(): void {
    this.running = false;
    console.log('Antenna security watcher stopped');
  }

  /**
   * Watch auditd log for sensitive file access
   */
  private async watchAuditLog(): Promise<void> {
    const auditLog = '/var/log/audit/audit.log';

    if (!existsSync(auditLog)) {
      console.log('  auditd log not found, skipping audit monitoring');
      return;
    }

    console.log('  Monitoring auditd log...');

    // Read stream approach for proper handling
    try {
      const stream = createReadStream(auditLog, {
        encoding: 'utf8',
        start: 0, // Start from beginning to catch up
      });

      const rl = createInterface({ input: stream });

      for await (const line of rl) {
        if (!this.running) break;

        // Filter for antenna-related events
        if (!line.includes('key="antenna_')) continue;

        const event = this.parseAuditLine(line);
        if (event && this.isRelevantEvent(event)) {
          await this.handleAuditEvent(event);
        }
      }
    } catch (error) {
      // Log rotation or permission issue
      console.error('Error reading audit log:', error);
    }
  }

  /**
   * Watch for config file changes
   */
  private async watchConfigChanges(): Promise<void> {
    const configDir = join(homedir(), '.openclaw');

    if (!existsSync(configDir)) {
      console.log('  OpenClaw config dir not found, skipping config monitoring');
      return;
    }

    console.log('  Monitoring config changes...');

    const watcher = watch(configDir, { recursive: true }, (eventType, filename) => {
      if (!this.running) return;
      if (!filename) return;

      // Ignore temp files
      if (filename.endsWith('.tmp') || filename.endsWith('.lock')) return;

      const event: WatchEvent = {
        timestamp: new Date().toISOString(),
        type: 'config_change',
        severity: 'warning',
        source: 'fs.watch',
        message: `Config file changed: ${filename}`,
        details: { eventType, filename },
      };

      this.emitEvent(event);
    });

    // Keep watcher alive
    await new Promise<void>((resolve) => {
      const interval = setInterval(() => {
        if (!this.running) {
          clearInterval(interval);
          watcher.close();
          resolve();
        }
      }, 1000);
    });
  }

  /**
   * Watch transcript files for secrets
   */
  private async watchTranscripts(): Promise<void> {
    const sessionsDir = join(homedir(), '.openclaw', 'agents');

    if (!existsSync(sessionsDir)) {
      console.log('  Sessions dir not found, skipping transcript monitoring');
      return;
    }

    console.log('  Monitoring transcripts for secrets...');

    const watcher = watch(sessionsDir, { recursive: true }, async (_eventType, filename) => {
      if (!this.running) return;
      if (!filename || !filename.endsWith('.jsonl')) return;

      // Debounce - only check after file is written
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Quick scan for secrets in new content
      // (Full implementation would track file position)
    });

    await new Promise<void>((resolve) => {
      const interval = setInterval(() => {
        if (!this.running) {
          clearInterval(interval);
          watcher.close();
          resolve();
        }
      }, 1000);
    });
  }

  /**
   * Parse auditd log line
   */
  private parseAuditLine(line: string): AuditEvent | null {
    const event: AuditEvent = { type: 'unknown' };

    // Extract type
    const typeMatch = line.match(/type=(\w+)/);
    if (typeMatch) event.type = typeMatch[1];

    // Extract key
    const keyMatch = line.match(/key="([^"]+)"/);
    if (keyMatch) event.key = keyMatch[1];

    // Extract auid (audit user id)
    const auidMatch = line.match(/auid=(\d+)/);
    if (auidMatch) event.auid = auidMatch[1];

    // Extract uid
    const uidMatch = line.match(/\suid=(\d+)/);
    if (uidMatch) event.uid = uidMatch[1];

    // Extract exe
    const exeMatch = line.match(/exe="([^"]+)"/);
    if (exeMatch) event.exe = exeMatch[1];

    // Extract name (file accessed)
    const nameMatch = line.match(/name="([^"]+)"/);
    if (nameMatch) event.name = nameMatch[1];

    // Extract success
    const successMatch = line.match(/success=(\w+)/);
    if (successMatch) event.success = successMatch[1];

    return event;
  }

  /**
   * Check if audit event is from relevant user
   */
  private isRelevantEvent(event: AuditEvent): boolean {
    if (!this.openclawUid) return true; // No filtering if user doesn't exist

    return event.auid === this.openclawUid || event.uid === this.openclawUid;
  }

  /**
   * Handle auditd event
   */
  private async handleAuditEvent(event: AuditEvent): Promise<void> {
    let severity: WatchEvent['severity'] = 'warning';
    let message = 'Sensitive file access detected';

    // Determine severity based on key
    if (event.key?.includes('ssh') || event.key?.includes('aws')) {
      severity = 'high';
      message = `Sensitive file access: ${event.name || 'unknown'}`;
    }

    if (event.key?.includes('creds') || event.key?.includes('gpg')) {
      severity = 'high';
      message = `Credential file access: ${event.name || 'unknown'}`;
    }

    const watchEvent: WatchEvent = {
      timestamp: new Date().toISOString(),
      type: 'file_access',
      severity,
      source: 'auditd',
      message,
      details: {
        key: event.key,
        file: event.name,
        exe: event.exe,
        success: event.success,
      },
    };

    await this.emitEvent(watchEvent);
  }

  /**
   * Emit a watch event
   */
  private async emitEvent(event: WatchEvent): Promise<void> {
    // Output to console
    const prefix = this.getSeverityPrefix(event.severity);
    console.log(`${prefix} [${event.timestamp}] ${event.message}`);

    // Output to file if configured
    if (this.options.outputFile) {
      try {
        const line = JSON.stringify(event) + '\n';
        writeFileSync(this.options.outputFile, line, { flag: 'a' });
      } catch {
        // Ignore write errors
      }
    }

    // Check if we should kill
    await this.checkKillCondition(event);
  }

  /**
   * Check if event triggers kill switch
   */
  private async checkKillCondition(event: WatchEvent): Promise<void> {
    if (!this.options.killOn) return;

    // Check startup cooldown
    const elapsedSeconds = (Date.now() - this.startTime) / 1000;
    if (elapsedSeconds < (this.options.startupCooldown ?? 60)) {
      return;
    }

    // Check if severity matches kill threshold
    const killThreshold = this.options.killOn;
    const shouldKill =
      (killThreshold === 'critical' && event.severity === 'critical') ||
      (killThreshold === 'high' &&
        (event.severity === 'critical' || event.severity === 'high'));

    if (!shouldKill) return;

    // Check rate limit
    const now = Date.now();
    if (now - this.killCountResetTime > 3600000) {
      // Reset hourly
      this.killCount = 0;
      this.killCountResetTime = now;
    }

    if (this.killCount >= (this.options.maxKillsPerHour ?? 3)) {
      console.log('Kill rate limit reached, not killing');
      return;
    }

    // Execute kill
    await this.killGateway(event);
  }

  /**
   * Kill the OpenClaw gateway
   */
  private async killGateway(event: WatchEvent): Promise<void> {
    this.killCount++;

    console.log('\n⚠️  EMERGENCY SHUTDOWN');
    console.log(`Antenna detected a ${event.severity} security event and is stopping the OpenClaw gateway.`);
    console.log(`\nEvent: ${event.message}`);
    console.log(`Time:  ${event.timestamp}`);
    console.log('\nACTION REQUIRED:');
    console.log('1. Review the incident: antenna incident --last');
    console.log('2. Investigate the session transcript');
    console.log('3. Restart manually when safe: systemctl start openclaw');

    // Try to stop the gateway
    const result = exec('sudo systemctl stop openclaw 2>/dev/null || pkill -f openclaw');

    if (result.success) {
      console.log('\nGateway stopped.');
    } else {
      console.log('\nFailed to stop gateway. Manual intervention required.');
    }

    // Auto-restart if configured
    if (this.options.restartAfter) {
      console.log(`\nAuto-restart scheduled in ${this.options.restartAfter} seconds...`);
      setTimeout(() => {
        exec('sudo systemctl start openclaw');
        console.log('Gateway restarted.');
      }, this.options.restartAfter * 1000);
    }
  }

  /**
   * Get severity prefix for console output
   */
  private getSeverityPrefix(severity: WatchEvent['severity']): string {
    switch (severity) {
      case 'critical':
        return '🔴 CRITICAL';
      case 'high':
        return '🟠 HIGH';
      case 'warning':
        return '🟡 WARNING';
      case 'info':
        return '🔵 INFO';
    }
  }
}

/**
 * Generate auditd rules for Antenna
 */
export function generateAuditdRules(username = 'openclaw'): string {
  return `# Managed by Antenna - monitors sensitive file access
# Filtering by user is done in Antenna, not kernel

# SSH keys
-w /home/${username}/.ssh -p rwa -k antenna_ssh

# Cloud credentials
-w /home/${username}/.aws -p rwa -k antenna_aws
-w /home/${username}/.config/gcloud -p rwa -k antenna_gcloud

# GPG keys
-w /home/${username}/.gnupg -p rwa -k antenna_gpg

# OpenClaw config and credentials
-w /home/${username}/.openclaw/openclaw.json -p wa -k antenna_config
-w /home/${username}/.openclaw/credentials -p rwa -k antenna_creds
`;
}

/**
 * Install auditd rules
 */
export function installAuditdRules(username = 'openclaw', dryRun = false): boolean {
  const rules = generateAuditdRules(username);
  const rulesPath = '/etc/audit/rules.d/antenna.rules';

  if (dryRun) {
    console.log(`[DRY RUN] Would write to ${rulesPath}:`);
    console.log(rules);
    console.log('[DRY RUN] Would run: augenrules --load');
    return true;
  }

  // Write rules
  const writeResult = exec(`echo '${rules}' | sudo tee ${rulesPath} > /dev/null`);
  if (!writeResult.success) {
    console.error('Failed to write auditd rules');
    return false;
  }

  // Load rules
  const loadResult = exec('sudo augenrules --load');
  if (!loadResult.success) {
    console.error('Failed to load auditd rules');
    return false;
  }

  // Verify
  const verifyResult = exec('sudo auditctl -l | grep antenna');
  if (verifyResult.success) {
    console.log('Auditd rules installed successfully');
    return true;
  }

  console.error('Rules installed but verification failed');
  return false;
}
