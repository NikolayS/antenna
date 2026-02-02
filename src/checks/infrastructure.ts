import { existsSync, readFileSync } from 'node:fs';
import type { CheckResult, Finding } from '../models.js';
import { commandExists, exec } from '../utils/exec.js';
import { BaseChecker } from './base.js';

/**
 * Infrastructure security checks for Ubuntu VMs
 * Implements INFRA-001 through INFRA-017 from SPEC.md
 */
export class InfrastructureChecker extends BaseChecker {
  name = 'infrastructure';

  async run(): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Run all infrastructure checks
    findings.push(...this.checkSSHPasswordAuth());
    findings.push(...this.checkSSHRootLogin());
    findings.push(...this.checkFirewall());
    findings.push(...this.checkFail2ban());
    findings.push(...this.checkUnattendedUpgrades());

    return { findings };
  }

  /**
   * INFRA-001: Check if SSH password authentication is enabled
   */
  private checkSSHPasswordAuth(): Finding[] {
    const config = this.getSSHConfig();
    if (config === null) {
      return [
        this.createFinding(
          'INFRA-001',
          'warning',
          'SSH config not readable',
          'Could not read SSH configuration. Run as root or check permissions.',
        ),
      ];
    }

    // Check for PasswordAuthentication setting
    // Default is 'yes' if not specified
    const match = config.match(/^\s*PasswordAuthentication\s+(yes|no)/im);
    const passwordAuthEnabled = !match || match[1].toLowerCase() === 'yes';

    if (passwordAuthEnabled) {
      return [
        this.createFinding(
          'INFRA-001',
          'block',
          'SSH password auth enabled',
          'Password authentication is enabled for SSH, allowing brute-force attacks.',
          {
            autoFixable: true,
            details: 'Fix: antenna fix INFRA-001',
            file: '/etc/ssh/sshd_config',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * INFRA-002: Check if SSH root login is allowed
   */
  private checkSSHRootLogin(): Finding[] {
    const config = this.getSSHConfig();
    if (config === null) {
      return [];
    }

    // Check for PermitRootLogin setting
    // Default varies by distro, but we want it explicitly disabled
    const match = config.match(
      /^\s*PermitRootLogin\s+(yes|no|prohibit-password|without-password)/im,
    );
    const rootLoginAllowed = !match || match[1].toLowerCase() === 'yes';

    if (rootLoginAllowed) {
      return [
        this.createFinding(
          'INFRA-002',
          'block',
          'SSH root login allowed',
          'Root login via SSH is allowed, creating a high-value target for attackers.',
          {
            autoFixable: true,
            details: 'Fix: antenna fix INFRA-002',
            file: '/etc/ssh/sshd_config',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * INFRA-003: Check if firewall is active
   */
  private checkFirewall(): Finding[] {
    // Check UFW first (most common on Ubuntu)
    if (commandExists('ufw')) {
      const result = exec(
        'sudo ufw status 2>/dev/null || ufw status 2>/dev/null',
      );
      if (result.success && result.stdout.includes('Status: active')) {
        return [];
      }
    }

    // Check iptables
    const iptables = exec('sudo iptables -L -n 2>/dev/null | grep -c "^Chain"');
    if (iptables.success && Number.parseInt(iptables.stdout, 10) > 3) {
      // More than default 3 chains suggests custom rules
      return [];
    }

    // Check nftables
    const nft = exec('sudo nft list ruleset 2>/dev/null | grep -c "chain"');
    if (nft.success && Number.parseInt(nft.stdout, 10) > 0) {
      return [];
    }

    return [
      this.createFinding(
        'INFRA-003',
        'block',
        'No firewall active',
        'No active firewall detected. All ports may be exposed to the internet.',
        {
          autoFixable: true,
          details: 'Fix: antenna fix INFRA-003',
        },
      ),
    ];
  }

  /**
   * INFRA-004: Check if fail2ban is running
   */
  private checkFail2ban(): Finding[] {
    const result = exec('systemctl is-active fail2ban 2>/dev/null');

    if (!result.success || result.stdout !== 'active') {
      return [
        this.createFinding(
          'INFRA-004',
          'warning',
          'fail2ban not running',
          'fail2ban is not running. Brute-force attacks will not be automatically blocked.',
          {
            autoFixable: true,
            details: 'Fix: antenna fix INFRA-004',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * INFRA-010: Check if unattended-upgrades is enabled
   */
  private checkUnattendedUpgrades(): Finding[] {
    // Check if package is installed
    const installed = exec(
      'dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"',
    );
    if (!installed.success) {
      return [
        this.createFinding(
          'INFRA-010',
          'warning',
          'Unattended upgrades disabled',
          'Automatic security updates are not configured. System may become vulnerable to known exploits.',
          {
            autoFixable: true,
            details: 'Fix: antenna fix INFRA-010',
          },
        ),
      ];
    }

    // Check if enabled
    const enabled = exec(
      'systemctl is-enabled unattended-upgrades 2>/dev/null',
    );
    if (!enabled.success || enabled.stdout !== 'enabled') {
      return [
        this.createFinding(
          'INFRA-010',
          'warning',
          'Unattended upgrades not enabled',
          'unattended-upgrades is installed but not enabled.',
          {
            autoFixable: true,
          },
        ),
      ];
    }

    return [];
  }

  /**
   * Get effective SSH configuration (main config + drop-in files)
   */
  private getSSHConfig(): string | null {
    // Try to get effective config via sshd -T (requires root)
    const effective = exec('sudo sshd -T 2>/dev/null');
    if (effective.success) {
      return effective.stdout;
    }

    // Fall back to reading config files directly
    const mainConfig = '/etc/ssh/sshd_config';
    const dropInDir = '/etc/ssh/sshd_config.d';

    let config = '';

    if (existsSync(mainConfig)) {
      try {
        config = readFileSync(mainConfig, 'utf8');
      } catch {
        return null;
      }
    }

    // Read drop-in configs
    if (existsSync(dropInDir)) {
      try {
        const files = exec(`ls ${dropInDir}/*.conf 2>/dev/null`);
        if (files.success) {
          for (const file of files.stdout.split('\n')) {
            if (file && existsSync(file)) {
              config += '\n' + readFileSync(file, 'utf8');
            }
          }
        }
      } catch {
        // Ignore errors reading drop-in files
      }
    }

    return config || null;
  }

  /**
   * Auto-fix implementation for infrastructure findings
   */
  async fix(findingId: string, dryRun = false): Promise<boolean> {
    switch (findingId) {
      case 'INFRA-001':
      case 'INFRA-002':
        return this.fixSSH(findingId, dryRun);
      case 'INFRA-003':
        return this.fixFirewall(dryRun);
      case 'INFRA-004':
        return this.fixFail2ban(dryRun);
      case 'INFRA-010':
        return this.fixUnattendedUpgrades(dryRun);
      default:
        return false;
    }
  }

  /**
   * Fix SSH configuration using drop-in config (safe approach)
   */
  private fixSSH(_findingId: string, dryRun: boolean): boolean {
    const dropInFile = '/etc/ssh/sshd_config.d/99-antenna-hardening.conf';
    const content = `# Managed by Antenna - do not edit manually
PasswordAuthentication no
PermitRootLogin no
`;

    if (dryRun) {
      console.log(`[DRY RUN] Would write to ${dropInFile}:`);
      console.log(content);
      console.log('[DRY RUN] Would run: sshd -t && systemctl reload ssh');
      return true;
    }

    // Write drop-in config
    const write = exec(
      `echo '${content}' | sudo tee ${dropInFile} > /dev/null`,
    );
    if (!write.success) {
      console.error('Failed to write SSH drop-in config');
      return false;
    }

    // Validate config before reload
    const validate = exec('sudo sshd -t');
    if (!validate.success) {
      console.error('SSH config validation failed, reverting...');
      exec(`sudo rm -f ${dropInFile}`);
      return false;
    }

    // Reload SSH
    const reload = exec(
      'sudo systemctl reload ssh || sudo systemctl reload sshd',
    );
    return reload.success;
  }

  /**
   * Fix firewall by installing and enabling UFW
   */
  private fixFirewall(dryRun: boolean): boolean {
    // Detect SSH port from current connection or config
    let sshPort = '22';
    const sshConnection = process.env.SSH_CONNECTION;
    if (sshConnection) {
      const parts = sshConnection.split(' ');
      if (parts.length >= 4) {
        sshPort = parts[3];
      }
    } else {
      // Try to get from sshd config
      const config = exec('sudo sshd -T 2>/dev/null | grep "^port "');
      if (config.success) {
        const match = config.stdout.match(/^port\s+(\d+)/i);
        if (match) {
          sshPort = match[1];
        }
      }
    }

    const commands = [
      'apt install -y ufw',
      'ufw default deny incoming',
      'ufw default allow outgoing',
      `ufw allow ${sshPort}/tcp comment 'SSH'`,
      'ufw --force enable',
    ];

    if (dryRun) {
      console.log('[DRY RUN] Would run:');
      for (const cmd of commands) {
        console.log(`  sudo ${cmd}`);
      }
      console.log(`\nDetected SSH port: ${sshPort}`);
      return true;
    }

    for (const cmd of commands) {
      const result = exec(`sudo ${cmd}`);
      if (!result.success) {
        console.error(`Failed to run: ${cmd}`);
        return false;
      }
    }

    console.log(
      `\n⚠️  DO NOT close this SSH session until you verify a new session works!`,
    );
    console.log(`    SSH port: ${sshPort}`);
    return true;
  }

  /**
   * Fix fail2ban by installing and enabling
   */
  private fixFail2ban(dryRun: boolean): boolean {
    if (dryRun) {
      console.log('[DRY RUN] Would run:');
      console.log('  sudo apt install -y fail2ban');
      console.log('  sudo systemctl enable --now fail2ban');
      return true;
    }

    const install = exec('sudo apt install -y fail2ban');
    if (!install.success) {
      console.error('Failed to install fail2ban');
      return false;
    }

    const enable = exec('sudo systemctl enable --now fail2ban');
    return enable.success;
  }

  /**
   * Fix unattended-upgrades
   */
  private fixUnattendedUpgrades(dryRun: boolean): boolean {
    if (dryRun) {
      console.log('[DRY RUN] Would run:');
      console.log('  sudo apt install -y unattended-upgrades apt-listchanges');
      console.log('  sudo dpkg-reconfigure -plow unattended-upgrades');
      return true;
    }

    const install = exec(
      'sudo apt install -y unattended-upgrades apt-listchanges',
    );
    if (!install.success) {
      console.error('Failed to install unattended-upgrades');
      return false;
    }

    // Non-interactive reconfigure
    const configure = exec(
      'echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections && sudo dpkg-reconfigure -plow unattended-upgrades',
    );
    return configure.success;
  }
}
