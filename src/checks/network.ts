import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { BaseChecker } from './base.js';
import type { CheckResult, Finding } from '../models.js';
import { exec } from '../utils/exec.js';

interface OpenClawConfig {
  gateway?: {
    bind?: string;
    port?: number;
    auth?: {
      mode?: string;
    };
    trustedProxies?: string[];
  };
  controlUi?: {
    allowInsecureAuth?: boolean;
  };
}

/**
 * Network exposure checks
 * Implements NET-001 through NET-008 from SPEC.md
 */
export class NetworkChecker extends BaseChecker {
  name = 'network';
  private config: OpenClawConfig | null = null;

  async run(): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Load OpenClaw config
    this.config = this.loadOpenClawConfig();

    if (!this.config) {
      return {
        findings: [],
        skipped: 'OpenClaw config not found',
      };
    }

    // Run all network checks
    findings.push(...this.checkGatewayBinding());
    findings.push(...this.checkGatewayAuth());
    findings.push(...this.checkGatewayExposure());
    findings.push(...this.checkTLS());
    findings.push(...this.checkTrustedProxies());
    findings.push(...this.checkControlUIAuth());

    return { findings };
  }

  /**
   * NET-001: Check if gateway is bound to non-loopback
   */
  private checkGatewayBinding(): Finding[] {
    const bind = this.config?.gateway?.bind;

    // If not specified or loopback, it's safe
    if (!bind || bind === 'loopback' || bind === 'localhost' || bind === '127.0.0.1') {
      return [];
    }

    return [
      this.createFinding(
        'NET-001',
        'critical',
        'Gateway bound to non-loopback',
        `Gateway is bound to "${bind}", making it accessible beyond localhost.`,
        {
          ocsasControl: 'CP-01',
          details: 'Consider using a reverse proxy (nginx/caddy) in front of the gateway.',
        },
      ),
    ];
  }

  /**
   * NET-002: Check if gateway auth is configured
   */
  private checkGatewayAuth(): Finding[] {
    const authMode = this.config?.gateway?.auth?.mode;

    // If no auth configured, it's a problem
    if (!authMode || authMode === 'none') {
      return [
        this.createFinding(
          'NET-002',
          'block',
          'Gateway auth not configured',
          'Gateway authentication is not configured. Anyone can access the agent.',
          {
            autoFixable: true,
            ocsasControl: 'CP-02',
            details: 'Fix: Configure gateway.auth.mode in openclaw.json',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * NET-003: Check if gateway port is exposed to internet (local inference)
   */
  private checkGatewayExposure(): Finding[] {
    const evidence: string[] = [];
    const gatewayPort = this.config?.gateway?.port ?? 18789;
    const bind = this.config?.gateway?.bind;

    // If bound to loopback, skip this check
    if (!bind || bind === 'loopback' || bind === 'localhost' || bind === '127.0.0.1') {
      return [];
    }

    // Check if listening on 0.0.0.0
    const listening = exec(`ss -tlnp 2>/dev/null | grep ":${gatewayPort}"`);
    if (listening.success && listening.stdout.includes('0.0.0.0')) {
      evidence.push('listening on 0.0.0.0');
    }

    // Check UFW rules
    const ufwStatus = exec('sudo ufw status 2>/dev/null || ufw status 2>/dev/null');
    if (ufwStatus.success && ufwStatus.stdout.includes(String(gatewayPort))) {
      evidence.push(`ufw allows port ${gatewayPort}`);
    }

    // Check for reverse proxy
    const hasNginx = exec('systemctl is-active nginx 2>/dev/null');
    const hasCaddy = exec('systemctl is-active caddy 2>/dev/null');
    if (!hasNginx.success && !hasCaddy.success) {
      evidence.push('no reverse proxy detected');
    }

    if (evidence.length === 0) {
      return [];
    }

    // Determine confidence
    let confidence: 'high' | 'medium' | 'low';
    if (evidence.length >= 3) {
      confidence = 'high';
    } else if (evidence.length >= 2) {
      confidence = 'medium';
    } else {
      confidence = 'low';
    }

    return [
      this.createFinding(
        'NET-003',
        confidence === 'high' ? 'critical' : 'warning',
        'Gateway may be exposed to internet',
        `Gateway port ${gatewayPort} may be exposed (${confidence} confidence).`,
        {
          ocsasControl: 'CP-01',
          confidence,
          evidence,
        },
      ),
    ];
  }

  /**
   * NET-004: Check for HTTP without TLS on non-localhost
   */
  private checkTLS(): Finding[] {
    const bind = this.config?.gateway?.bind;
    const gatewayPort = this.config?.gateway?.port ?? 18789;

    // If bound to loopback, TLS not required
    if (!bind || bind === 'loopback' || bind === 'localhost' || bind === '127.0.0.1') {
      return [];
    }

    // Check if a reverse proxy with TLS is in front
    // Look for nginx/caddy with SSL config
    const nginxSsl = exec('grep -r "ssl_certificate" /etc/nginx 2>/dev/null');
    const caddySsl = exec('grep -r "tls" /etc/caddy 2>/dev/null');

    if (nginxSsl.success || caddySsl.success) {
      // TLS is likely configured via reverse proxy
      return [];
    }

    return [
      this.createFinding(
        'NET-004',
        'critical',
        'HTTP without TLS on non-localhost',
        `Gateway on port ${gatewayPort} is accessible without TLS encryption.`,
        {
          ocsasControl: 'NS-01',
          details: 'Configure TLS via reverse proxy (nginx/caddy) or use Tailscale.',
        },
      ),
    ];
  }

  /**
   * NET-007: Check if trusted proxies are configured
   */
  private checkTrustedProxies(): Finding[] {
    const bind = this.config?.gateway?.bind;

    // Only relevant if not on loopback
    if (!bind || bind === 'loopback' || bind === 'localhost' || bind === '127.0.0.1') {
      return [];
    }

    const trustedProxies = this.config?.gateway?.trustedProxies;

    if (!trustedProxies || trustedProxies.length === 0) {
      return [
        this.createFinding(
          'NET-007',
          'warning',
          'Trusted proxies not configured',
          'gateway.trustedProxies is not configured. X-Forwarded-For headers may be spoofed.',
          {
            ocsasControl: 'CP-03',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * NET-008: Check if Control UI has insecure auth enabled
   */
  private checkControlUIAuth(): Finding[] {
    if (this.config?.controlUi?.allowInsecureAuth === true) {
      return [
        this.createFinding(
          'NET-008',
          'critical',
          'Control UI insecure auth enabled',
          'controlUi.allowInsecureAuth is true. This may allow bypassing authentication.',
          {
            ocsasControl: 'CP-02',
          },
        ),
      ];
    }

    return [];
  }

  /**
   * Load OpenClaw configuration
   */
  private loadOpenClawConfig(): OpenClawConfig | null {
    const configPaths = [
      join(homedir(), '.openclaw', 'openclaw.json'),
      join(process.cwd(), 'openclaw.json'),
      '/etc/openclaw/openclaw.json',
    ];

    for (const configPath of configPaths) {
      if (existsSync(configPath)) {
        try {
          const content = readFileSync(configPath, 'utf8');
          return JSON.parse(content) as OpenClawConfig;
        } catch {
          // Try next path
        }
      }
    }

    return null;
  }
}
