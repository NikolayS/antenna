# Antenna 🦞📡🚨

**Version 1.0.0** | Last updated: 2026-02-02

## Security Audit & Monitoring for OpenClaw Deployments on Ubuntu VMs

> *A lobster's antenna detects threats in the water before they get close.*

---

## 1. Overview

**Antenna** is a security tool designed specifically for OpenClaw deployments running on Ubuntu VMs (22.04, 24.04). It audits configuration, monitors runtime behavior, and ensures administrators explicitly acknowledge dangerous settings.

### Why Another Tool?

Several tools exist in this space, but none combine infrastructure + OpenClaw + risk tracking:

| Tool | What It Does | Gap |
|------|--------------|-----|
| **Lynis** | General Linux hardening audit (since 2007, 13K+ stars) | No OpenClaw awareness |
| **`openclaw security audit`** | Built-in config checker | No infrastructure, no risk acceptance |
| **OCSAS** | Security checklist/docs for OpenClaw | Documentation only, no tooling |
| **Nono** | Kernel-enforced sandbox (Landlock/Seatbelt) | Runtime isolation, not audit |
| **Skulto** | Scans skills for prompt injection | Skills only |
| **Cisco Skill Scanner** | Scans skills for vulnerabilities | Skills only |

**Antenna fills the gap:** One command that checks infrastructure + OpenClaw config + skills, with risk acceptance tracking and incident correlation. FOSS, runs via `npx`, no account needed.

```bash
# One command to audit everything
npx antenna@latest audit

# For production, pin the version
npm install -g antenna@0.1.0
```

> ⚠️ **Production note:** Don't use `@latest` in prod scripts. Pin versions.

### OCSAS Compatibility

Antenna implements checks for [OCSAS](https://github.com/gensecaihq/ocsas) (OpenClaw Security Assurance Standard) controls. OCSAS is documentation; Antenna is the tool that verifies it.

| OCSAS Control Category | Controls | Antenna Coverage |
|------------------------|----------|------------------|
| Control Plane (CP-01 to CP-04) | 4 | ✅ 4/4 |
| Inbound Identity (ID-01 to ID-03) | 3 | ✅ 3/3 |
| Tool Governance (TB-01 to TB-04) | 4 | ✅ 4/4 |
| Local State (LS-01 to LS-04) | 4 | ✅ 4/4 |
| Supply Chain (SC-01 to SC-02) | 2 | ✅ 2/2 |
| Network Security (NS-01 to NS-04) | 4 | ✅ 4/4 |
| **Infrastructure (Antenna-only)** | — | ✅ 11 checks |

Antenna adds infrastructure checks OCSAS doesn't cover: SSH hardening, firewall, fail2ban, OS/software updates.

### Target Environment

- **OS**: Ubuntu 22.04 LTS, 24.04 LTS (VMs on DigitalOcean, Hetzner, AWS, GCP, etc.)
- **Runtime**: OpenClaw with Node.js 22+
- **Not for**: macOS local installs, Docker-only deployments (different threat model)

### Installation & Usage

```bash
# Quick audit (dev/testing)
npx antenna@latest audit

# Production: pin version + verify
npm install -g antenna@0.1.0
# Verify checksum (published with each release)
npm pack antenna@0.1.0
sha256sum antenna-0.1.0.tgz  # compare to published checksum

# Then use
antenna audit
antenna watch
```

> ⚠️ **Security note:** Don't use `@latest` in production scripts. Pin to a specific version. Watch for typosquatting packages (`antena`, `antenna-security`, etc.) — only use `antenna` from npm.

### Tech Stack

- **TypeScript** — Type-safe, matches OpenClaw's codebase
- **Bun** — Fast runtime, but Node.js compatible
- **Zero config** — Works out of the box with OpenClaw defaults

### Core Principles

1. **Default Deny** — Everything risky requires explicit admin acknowledgment
2. **No Silent Failures** — Dangerous configs must be accepted in writing with documented reason
3. **Defense in Depth** — Check infrastructure, OpenClaw config, runtime, and skills
4. **Audit Trail** — Every admin decision is logged and timestamped
5. **Reveal on Incident** — When something bad happens, show what led to it

### Non-Goals (v1)

- Not a replacement for proper security practices
- Not a WAF or runtime blocker (monitoring + alerting only)
- Not responsible for fixing OpenClaw bugs

---

## 2. Threat Model

### Attack Surfaces

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ATTACK SURFACES                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  EXTERNAL                        INTERNAL                            │
│  ─────────                       ─────────                           │
│  • SSH brute force               • Prompt injection via messages     │
│  • Gateway port exposure         • Malicious skills (supply chain)   │
│  • HTTP without TLS              • Credential leakage in transcripts │
│  • Open messaging channels       • Agent accessing sensitive files   │
│                                  • Unintended tool execution         │
│                                                                      │
│  CONFIGURATION                   RUNTIME                             │
│  ─────────────                   ───────                             │
│  • No firewall                   • Unexpected network egress         │
│  • Weak/no gateway auth          • Shell spawning                    │
│  • Open DM policies              • Secrets in logs                   │
│  • Elevated tools for all        • API key abuse                     │
│  • Sandbox disabled              • Session hijacking                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Risk Framework: RAK (Root, Agency, Keys)

From Composio's analysis, adapted for our use:

| Risk Type | Description | Example |
|-----------|-------------|---------|
| **Root** | Host/VM compromise | Prompt injection → shell command → reverse shell |
| **Agency** | Agent does unintended actions | "Clean inbox" interpreted as "delete all" |
| **Keys** | Credential theft/abuse | API keys leaked in transcripts, OAuth tokens stolen |

---

## 3. Severity Classification

```
┌──────────┬───────────────────────────────────────────────────────────┐
│ LEVEL    │ DESCRIPTION                                               │
├──────────┼───────────────────────────────────────────────────────────┤
│ 🔴 BLOCK │ Cannot proceed without --force. Auto-remediation offered. │
│          │ Examples: elevated tools allowFrom="*", no firewall       │
├──────────┼───────────────────────────────────────────────────────────┤
│ 🟠 CRIT  │ Requires explicit acceptance with documented reason.      │
│          │ Examples: open DMs, gateway exposed, sandbox disabled     │
├──────────┼───────────────────────────────────────────────────────────┤
│ 🟡 WARN  │ Strong recommendation to fix. Logged if not addressed.    │
│          │ Examples: fail2ban missing, iMessage enabled              │
├──────────┼───────────────────────────────────────────────────────────┤
│ 🔵 INFO  │ Best practice recommendation. No action required.         │
│          │ Examples: SSH on port 22, mDNS in full mode               │
├──────────┼───────────────────────────────────────────────────────────┤
│ ⚪ ACCEPT│ Previously acknowledged risk (with expiration)            │
└──────────┴───────────────────────────────────────────────────────────┘
```

---

## 4. Check Categories

### 4.1 Infrastructure Security (VM/OS Level)

| ID | Check | Level | Auto-Fix | Detection Method |
|----|-------|-------|----------|------------------|
| `INFRA-001` | SSH password auth enabled | 🔴 BLOCK | ✅ | Parse `/etc/ssh/sshd_config` + `sshd_config.d/*.conf` |
| `INFRA-002` | SSH root login allowed | 🔴 BLOCK | ✅ | Parse sshd config for `PermitRootLogin` |
| `INFRA-003` | No firewall active | 🔴 BLOCK | ✅ | Check `ufw status`, `iptables -L`, `nft list` |
| `INFRA-004` | fail2ban not running | 🟡 WARN | ✅ | `systemctl is-active fail2ban` |
| `INFRA-005` | Ubuntu version outdated/EOL | 🟠 CRIT | ❌ | Check `/etc/os-release`, compare to EOL dates |
| `INFRA-006` | Security updates pending | 🟡 WARN | ✅ | `apt list --upgradable` with security filter |
| `INFRA-007` | OpenSSL version has known CVEs | 🟠 CRIT | ✅ | USN-based check (not naive version matching) |
| `INFRA-008` | Node.js version outdated | 🟡 WARN | ❌ | `node --version` vs LTS schedule |
| `INFRA-009` | OpenClaw version outdated | 🟡 WARN | ❌ | Compare installed vs latest npm release |
| `INFRA-010` | Unattended upgrades disabled | 🟡 WARN | ✅ | Check apt config |
| `INFRA-011` | SSH on default port 22 | 🔵 INFO | ❌ | Informational only |
| `INFRA-012` | No swap configured | 🟡 WARN | ❌ | `swapon --show` empty |
| `INFRA-013` | OpenClaw service runs as root | 🔴 BLOCK | ❌ | Check systemd unit `User=` |
| `INFRA-014` | Systemd unit missing hardening | 🟡 WARN | ❌ | Check for NoNewPrivileges, etc. |
| `INFRA-015` | Cloud IMDS v1 accessible (AWS) | 🟠 CRIT | ❌ | See below |
| `INFRA-015G` | GCP metadata accessible without header | 🟠 CRIT | ❌ | See below |
| `INFRA-016` | AppArmor disabled | 🟡 WARN | ❌ | `aa-status` check |
| `INFRA-017` | auditd backlog too small | 🟡 WARN | ❌ | `auditctl -s` backlog check |

**INFRA-007: OpenSSL Security (distro-aware)**
```
Don't do naive "openssl version → CVE database" — Ubuntu backports patches.
Instead:
1. Primary: `pro security-status --format json` (if available)
2. Secondary: `apt-cache policy openssl` — is installed version from security pocket?
3. If uncertain: downgrade to WARN with "run apt update && apt upgrade"
```

**INFRA-012: Why check for swap?**
```
AI agents load models into RAM. If VM runs out of memory:
- Linux OOM Killer may kill Antenna before the agent
- No swap = hard OOM, with swap = graceful degradation
Recommend: at least 1GB swap for safety
```

**INFRA-010: Unattended Upgrades**
```
For internet-exposed AI agents, unpatched systems are high risk.
Strongly recommended for unattended agents.
```

**INFRA-013: Systemd Root Check (BLOCK)**
```
Running an AI agent gateway as root is catastrophic. This is not a recommendation.
Detection: Parse systemd unit file, check if User= is missing or set to root.
If root: 🔴 BLOCK — must be fixed before proceeding
```

**INFRA-014: Systemd Hardening Checks (WARN)**
```
Check OpenClaw's systemd unit for recommended flags:
- NoNewPrivileges=true
- PrivateTmp=true  
- ProtectSystem=strict                 (careful: may break writes to /home)
- ProtectKernelTunables=true
- ProtectControlGroups=true
- LockPersonality=true
- RestrictSUIDSGID=true

If none present: WARN with suggested unit snippet
Note: ProtectHome= can break if OpenClaw writes under /home/openclaw
```

**INFRA-015 / INFRA-015G: Cloud Metadata Service Checks**
```bash
# Check current backlog status
auditctl -s | grep -E 'backlog|lost'

# If lost > 0: WARN — events are being dropped
# If backlog_limit < 8192: INFO — suggest increasing
# Recommend 16384 for agent-heavy workloads

# Fix: edit /etc/audit/audit.rules
# -b 16384
```

**INFRA-015 / INFRA-015G: Cloud Metadata Service Checks**
```typescript
// CRITICAL: Always use short timeouts to avoid blocking audit!
const TIMEOUT_MS = 500;

// Check all cloud providers in parallel to minimize total timeout
async function checkCloudIMDS(): Promise<Finding[]> {
  const [awsResult, gcpResult] = await Promise.all([
    checkAWSIMDS(),
    checkGCPMetadata(),
  ]);
  
  const findings = [awsResult, gcpResult].filter(Boolean) as Finding[];
  
  // If no cloud detected, emit INFO (not silent skip)
  if (findings.length === 0) {
    findings.push({
      id: 'INFRA-015-SKIP',
      level: 'info',
      message: 'Cloud metadata service not detected (bare metal or unknown cloud)',
    });
  }
  
  return findings;
}

// AWS IMDS check
async function checkAWSIMDS(): Promise<Finding | null> {
  try {
    // Try IMDSv2 first (token required)
    const tokenRes = await fetch('http://169.254.169.254/latest/api/token', {
      method: 'PUT',
      headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '21600' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    
    if (tokenRes.ok) {
      // IMDSv2 works, now check if IMDSv1 also works (BAD)
      const v1Res = await fetch('http://169.254.169.254/latest/meta-data/', {
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (v1Res.ok) {
        return { id: 'INFRA-015', level: 'critical', 
          message: 'AWS IMDSv1 accessible - agent can steal instance role credentials' };
      }
    }
  } catch (e) {
    // Timeout or not on AWS - that's fine
  }
  return null;
}

// GCP metadata check
async function checkGCPMetadata(): Promise<Finding | null> {
  try {
    // GCP requires Metadata-Flavor header
    const withHeader = await fetch('http://metadata.google.internal/computeMetadata/v1/', {
      headers: { 'Metadata-Flavor': 'Google' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    
    // Check if it works WITHOUT the required header (BAD configuration)
    const withoutHeader = await fetch('http://metadata.google.internal/computeMetadata/v1/', {
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    
    if (withoutHeader.ok) {
      return { id: 'INFRA-015G', level: 'critical',
        message: 'GCP metadata accessible without required header' };
    }
  } catch (e) {
    // Timeout or not on GCP
  }
  return null;
}
```

> ⚠️ **Timeouts are critical:** Without timeouts, IMDS checks hang the entire audit on non-cloud VMs. 500ms is aggressive but safe.

**INFRA-017: auditd Backlog Check**

**Ubuntu EOL Dates (for INFRA-005):**
```
# Source: https://ubuntu.com/about/release-cycle
Ubuntu 20.04 LTS → May 2025 (standard), April 2030 (ESM)
Ubuntu 22.04 LTS → June 2027 (standard), April 2032 (ESM)
Ubuntu 24.04 LTS → May 2029 (standard), April 2034 (ESM)

# Node.js 22 EOL: April 2027 (source: nodejs.org)
```

**Auto-fix approach (safe, uses drop-in configs):**
```bash
# INFRA-001 & INFRA-002: SSH hardening via drop-in (doesn't touch main config)
sudo tee /etc/ssh/sshd_config.d/99-antenna-hardening.conf << 'EOF'
# Managed by Antenna - do not edit manually
PasswordAuthentication no
PermitRootLogin no
EOF
sudo sshd -t && sudo systemctl reload ssh  # validate before reload

# INFRA-003: Install and enable ufw (DETECTS SSH PORT SAFELY)
# Priority: 1) current SSH session, 2) sshd -T, 3) require --ssh-port flag

# Try to detect from current SSH session (safest)
if [ -n "$SSH_CONNECTION" ]; then
  SSH_PORT=$(echo "$SSH_CONNECTION" | awk '{print $4}')
fi

# Fallback to sshd effective config (may have multiple ports)
if [ -z "$SSH_PORT" ]; then
  SSH_PORT=$(sshd -T 2>/dev/null | grep "^port " | head -1 | awk '{print $2}')
fi

# Final fallback
SSH_PORT=${SSH_PORT:-22}

sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ${SSH_PORT}/tcp comment 'SSH'
sudo ufw --force enable
echo "⚠️  DO NOT close this SSH session until you verify a new session works!"
echo "    Detected SSH port: ${SSH_PORT}"

# INFRA-004: Install and enable fail2ban
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban
```

> ⚠️ **Why drop-in configs?** Editing `/etc/ssh/sshd_config` directly with `sed` can brick SSH access if the file has custom `Match` blocks or includes. Drop-in files in `sshd_config.d/` are safer and reversible.

> ⚠️ **SSH port detection:** We parse `sshd -T` (effective config) to find the actual SSH port. If detection fails, we require `--ssh-port` flag.

---

### 4.2 Network Exposure

| ID | Check | Level | Auto-Fix | Detection Method | OCSAS |
|----|-------|-------|----------|------------------|-------|
| `NET-001` | Gateway bound to non-loopback | 🟠 CRIT | ❌ | Parse `gateway.bind` in config | CP-01 |
| `NET-002` | Gateway auth not configured | 🔴 BLOCK | ✅ | Check `gateway.auth.mode` | CP-02 |
| `NET-003` | Gateway port exposed to internet | 🟠 CRIT | ❌ | Local inference (see below) | CP-01 |
| `NET-004` | HTTP without TLS on non-localhost | 🟠 CRIT | ❌ | Check reverse proxy config + exposed ports | NS-01 |
| `NET-005` | Tailscale Funnel enabled | 🟡 WARN | ❌ | `tailscale status --json` | NS-02 |
| `NET-006` | mDNS broadcasting sensitive info | 🔵 INFO | ✅ | Check `discovery.mdns.mode` | NS-04 |
| `NET-007` | Trusted proxies not configured | 🟡 WARN | ❌ | Check `gateway.trustedProxies` | CP-03 |
| `NET-008` | Control UI insecure auth enabled | 🟠 CRIT | ❌ | Check `controlUi.allowInsecureAuth` | CP-02 |

**NET-003 Detection (local inference with confidence levels):**
```typescript
interface ExposureFinding {
  id: 'NET-003';
  level: 'critical' | 'warning';
  confidence: 'high' | 'medium' | 'low';
  evidence: string[];
  message: string;
}

function checkGatewayExposure(): ExposureFinding | null {
  const evidence: string[] = [];
  
  // Check gateway.bind
  const bind = config.gateway?.bind;
  if (bind === 'loopback') return null; // Safe
  
  // Check listening ports
  const listening = execSync('ss -tlnp').toString();
  const gatewayPort = config.gateway?.port || 18789;
  const onAllInterfaces = listening.includes(`0.0.0.0:${gatewayPort}`);
  
  if (onAllInterfaces) evidence.push('listening on 0.0.0.0');
  
  // Check firewall
  const ufwStatus = execSync('ufw status').toString();
  const portAllowed = ufwStatus.includes(String(gatewayPort));
  
  if (portAllowed) evidence.push(`ufw allows port ${gatewayPort}`);
  
  // Check for reverse proxy
  const hasProxy = checkForReverseProxy(gatewayPort);
  if (!hasProxy) evidence.push('no reverse proxy detected');
  
  // Determine confidence
  let confidence: 'high' | 'medium' | 'low';
  if (evidence.length >= 3) {
    confidence = 'high';
  } else if (evidence.length >= 2) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }
  
  if (evidence.length === 0) return null;
  
  return {
    id: 'NET-003',
    level: confidence === 'high' ? 'critical' : 'warning',
    confidence,
    evidence,
    message: `Gateway may be exposed to internet (${confidence} confidence)`,
  };
}
```

> **Why confidence matters:** Local inference can be very right or very wrong depending on cloud firewalls and reverse proxies. Exposing confidence helps operators decide whether to investigate further.

**HTTP/HTTPS Detection Logic (NET-004):**
```
1. Get gateway port from config (default: 18789)
2. Check gateway.bind:
   - "loopback" → Safe (localhost only)
   - "lan"/"tailnet"/"custom" → Check further
3. If non-loopback:
   a. Check if reverse proxy is in front (nginx/caddy/traefik)
   b. Check if TLS is terminated at proxy
   c. BUT: gateway might still be reachable directly on backend port (common misconfig)
4. If exposed without TLS → CRITICAL
```

---

### 4.3 OpenClaw Channel Security

| ID | Check | Level | Auto-Fix | Detection Method | OCSAS |
|----|-------|-------|----------|------------------|-------|
| `CHAN-001` | Any channel `dmPolicy: "open"` | 🟠 CRIT | ❌ | Parse channel configs | ID-01 |
| `CHAN-002` | Any channel `groupPolicy: "open"` | 🟠 CRIT | ❌ | Parse channel configs | ID-03 |
| `CHAN-003` | Telegram without allowlist | 🟡 WARN | ❌ | Check `channels.telegram.allowFrom` | ID-01 |
| `CHAN-004` | WhatsApp without pairing | 🟡 WARN | ❌ | Check `channels.whatsapp.dmPolicy` | ID-01 |
| `CHAN-005` | iMessage enabled | 🟡 WARN | ❌ | Always warn if enabled (inherently open) | — |
| `CHAN-006` | Discord without guild restrictions | 🔵 INFO | ❌ | Check `channels.discord.guilds` | ID-03 |
| `CHAN-007` | Open channel + tools enabled combo | 🔴 BLOCK | ❌ | Cross-check channel policy + tool config | — |
| `CHAN-008` | Session isolation not configured | 🟠 CRIT | ❌ | Check `session.dmScope` | ID-02 |
| `CHAN-009` | Group mention gating disabled | 🟡 WARN | ❌ | Check `requireMention` in groups | ID-03 |
| `CHAN-010` | Verbose/reasoning in public channels | 🟡 WARN | ❌ | Check `/verbose`, `/reasoning` settings | LS-03 |

**Channel Risk Matrix:**

```
                    Tools Enabled
                    ─────────────────────────────
                    │  Full    │ Sandbox │ None  │
────────────────────┼──────────┼─────────┼───────┤
DM Policy: open     │ 🔴 BLOCK │ 🟠 CRIT │ 🟡 WARN│
DM Policy: pairing  │ 🟡 WARN  │ 🔵 INFO │ ✅ OK  │
DM Policy: allowlist│ 🔵 INFO  │ ✅ OK   │ ✅ OK  │
DM Policy: disabled │ ✅ OK    │ ✅ OK   │ ✅ OK  │
────────────────────┴──────────┴─────────┴───────┘
```

---

### 4.4 Tool & Execution Security

| ID | Check | Level | Auto-Fix | Detection Method | OCSAS |
|----|-------|-------|----------|------------------|-------|
| `TOOL-001` | `tools.elevated.allowFrom: "*"` | 🔴 BLOCK | ❌ | NEVER allow - must be removed | TB-02 |
| `TOOL-002` | Sandbox disabled + tools enabled | 🟠 CRIT | ❌ | Check `agents.*.sandbox.mode` | TB-03 |
| `TOOL-003` | Browser control enabled remotely | 🟡 WARN | ❌ | Check `gateway.nodes.browser.mode` | TB-02 |
| `TOOL-004` | Exec tool without sandbox | 🟡 WARN | ❌ | Check `tools.exec.host` | TB-03 |
| `TOOL-005` | Workspace access is read-write | 🔵 INFO | ❌ | Check `sandbox.workspaceAccess` | TB-01 |
| `TOOL-006` | Sandbox network egress allowed | 🟠 CRIT | ❌ | Check `sandbox.docker.network` | TB-04 |
| `TOOL-007` | Weak model with tools enabled | 🟡 WARN | ❌ | Check model tier vs tool config | LS-03 |

---

### 4.5 Credential Security

| ID | Check | Level | Auto-Fix | Detection Method | OCSAS |
|----|-------|-------|----------|------------------|-------|
| `CRED-001` | `~/.openclaw` world-readable | 🔴 BLOCK | ✅ | `stat` permissions check | LS-01 |
| `CRED-002` | Config file world-readable | 🟠 CRIT | ✅ | Check `openclaw.json` perms | LS-01 |
| `CRED-003` | Secrets in session transcripts | 🟡 WARN | ❌ | Pattern + entropy scan | LS-02 |
| `CRED-004` | Anthropic Console OAuth on VM | 🟡 WARN | ❌ | Check for `sk-ant-sid*` patterns | — |
| `CRED-005` | API keys in environment variables | 🔵 INFO | ❌ | Check common env var names | LS-01 |
| `CRED-006` | Log redaction disabled | 🟡 WARN | ✅ | Check `logging.redactSensitive` | LS-02 |

**CRED-003: Secret Scanning Patterns**

```typescript
// SECRET_PATTERNS - Last updated: 2026-02
// 
// Maintenance schedule:
// - Review quarterly (add to release checklist)
// - Update when major providers announce format changes
// - Add patterns after security incidents involving credential leakage
//
// Sources: Provider documentation (Anthropic, OpenAI, AWS, GitHub, HuggingFace)

const SECRET_PATTERNS = [
  // Anthropic
  /sk-ant-[a-zA-Z0-9-]{20,}/,              // Anthropic API keys
  
  // OpenAI (formats vary, be conservative)
  /sk-[a-zA-Z0-9]{32,}/,                    // OpenAI API keys (legacy + new)
  
  // AWS
  /AKIA[0-9A-Z]{16}/,                       // AWS Access Key ID
  /ASIA[0-9A-Z]{16}/,                       // AWS Temp Access Key ID
  
  // GitHub
  /ghp_[a-zA-Z0-9]{36}/,                    // GitHub PAT (classic)
  /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/, // GitHub PAT (fine-grained)
  /gho_[a-zA-Z0-9]{36}/,                    // GitHub OAuth
  /ghu_[a-zA-Z0-9]{36}/,                    // GitHub User-to-server
  /ghs_[a-zA-Z0-9]{36}/,                    // GitHub Server-to-server
  
  // GitLab
  /glpat-[a-zA-Z0-9\-_]{20,}/,             // GitLab PAT
  
  // HuggingFace (critical for AI agents!)
  /hf_[a-zA-Z]{34}/,                        // HuggingFace Access Tokens
  
  // Slack
  /xox[baprs]-[0-9]{10,}-[a-zA-Z0-9\-]+/,  // Slack tokens
  
  // Private keys (match header line literally)
  /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----/,
  
  // Connection strings with passwords
  /(?:postgres|mysql|mongodb)(?:\+srv)?:\/\/[^:]+:[^@]+@/i,
];
```

**Context windows for operator usability:**
```typescript
interface SecretFinding {
  file: string;
  line: number;
  pattern: string;
  valueHash: string;           // SHA256 of the matched value (for dedup)
  jsonKeyPath?: string;        // e.g., "config.anthropic.apiKey"
  context: {
    before: string;            // Line N-1 (redacted if contains secrets)
    match: string;             // Line N with value replaced: "apiKey": "[REDACTED]"
    after: string;             // Line N+1 (redacted if contains secrets)
  };
}

// Example output:
// {
//   file: "~/.openclaw/agents/main/sessions/2026-02-01.jsonl",
//   line: 847,
//   pattern: "sk-ant-*",
//   valueHash: "a1b2c3...",
//   jsonKeyPath: "message.content",
//   context: {
//     before: '  "role": "assistant",',
//     match:  '  "content": "Here is your key: [REDACTED]"',
//     after:  '  "timestamp": "2026-02-01T10:30:00Z"'
//   }
// }
```

> **Important:** We report the *presence* of secrets, not the actual values. Context helps operators understand *why* something was flagged without leaking the secret.

**CRED-004: Anthropic OAuth Warning**

Anthropic's Console OAuth keys (prefix `sk-ant-sid*` or used via OAuth flow) are tied to personal accounts. Using these on a VM/server:
- Creates compliance risk (keys tied to individual, not org)
- Risk of revocation if detected as automated/shared usage
- Should use org-managed API keys from console.anthropic.com instead

Detection:
```bash
# Check auth-profiles.json for OAuth-style keys
# Check for keys with "console" or "oauth" in metadata
# Check if running on VM (cloud metadata endpoints, /sys/class/dmi)
# Warn if OAuth key + VM detected
```

---

### 4.6 Skills & Supply Chain

| ID | Check | Level | Auto-Fix | Detection Method | OCSAS |
|----|-------|-------|----------|------------------|-------|
| `SKILL-001` | Plugins without explicit allowlist | 🟠 CRIT | ❌ | Check `plugins.allow` vs installed | SC-01 |
| `SKILL-002` | Skills with security findings | 🟠 CRIT | ❌ | Run Cisco Skill Scanner | — |
| `SKILL-003` | Unpinned plugin versions | 🟡 WARN | ❌ | Check for `@latest` or missing versions | SC-02 |

**Integration with external scanners:**
```bash
# Antenna wraps Cisco Skill Scanner for SKILL-002
antenna skills scan ~/.openclaw/skills/

# Or scan a specific skill before installing
antenna skills check https://github.com/user/skill
```

---

## 5. Admin Acknowledgment System

### 5.1 Risk Acceptance Requirements

For `🟠 CRIT` findings, admin must provide:
1. **Reason** — Why this risk is acceptable
2. **Mitigations** — What compensating controls are in place
3. **Expiration** — When to re-evaluate (default: 30 days)

For `🔴 BLOCK` findings:
- Most cannot be accepted (e.g., `TOOL-001`)
- Some can be forced with `--i-understand-this-is-dangerous`
- All forced acceptances are prominently logged

### 5.2 Acceptance Storage

File: `/var/lib/antenna/accepted-risks.jsonl` (root-owned, append-only)

> **Why root-owned?** If attacker compromises the `openclaw` user, they shouldn't be able to silence alerts by editing the acceptance file. `antenna accept` requires `sudo`.

```jsonl
{"id":"CHAN-001","accepted_at":"2026-02-01T10:30:00Z","accepted_by":"nik","reason":"Public support bot","mitigations":["tools disabled","sandbox enabled"],"expires_at":"2026-03-01T10:30:00Z","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}
{"id":"NET-001","accepted_at":"2026-02-01T11:00:00Z","accepted_by":"nik","reason":"Behind Tailscale","mitigations":["tailnet only"],"expires_at":"2026-03-01T11:00:00Z","prev_hash":"a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"}
```

**Hash chain implementation (full SHA256, canonicalized):**
```typescript
import { createHash } from 'crypto';

interface RiskAcceptance {
  id: string;
  accepted_at: string;
  accepted_by: string;
  reason: string;
  mitigations: string[];
  expires_at: string;
  prev_hash: string;
}

// Canonical JSON: sorted keys, no extra whitespace
function canonicalize(obj: Omit<RiskAcceptance, 'prev_hash'>): string {
  const sorted = Object.keys(obj).sort().reduce((acc, key) => {
    acc[key] = obj[key];
    return acc;
  }, {} as Record<string, unknown>);
  return JSON.stringify(sorted);
}

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

// When writing a new acceptance:
function appendAcceptance(file: string, record: Omit<RiskAcceptance, 'prev_hash'>): void {
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
  const prevHash = lines.length > 0 
    ? sha256(lines[lines.length - 1])  // Hash the full previous line
    : '0'.repeat(64);                   // Genesis block
  
  const fullRecord: RiskAcceptance = { ...record, prev_hash: prevHash };
  fs.appendFileSync(file, JSON.stringify(fullRecord) + '\n');
}

// Verification (on every antenna audit):
function verifyChain(lines: string[]): { valid: boolean; error?: string } {
  let expectedPrevHash = '0'.repeat(64);
  
  for (let i = 0; i < lines.length; i++) {
    const record = JSON.parse(lines[i]) as RiskAcceptance;
    
    if (record.prev_hash !== expectedPrevHash) {
      return { 
        valid: false, 
        error: `Chain broken at line ${i + 1}: expected ${expectedPrevHash.slice(0, 16)}..., got ${record.prev_hash.slice(0, 16)}...`
      };
    }
    
    expectedPrevHash = sha256(lines[i]);
  }
  
  return { valid: true };
}
```

> ⚠️ **Full SHA256 (64 hex chars):** Previous versions used truncated hashes. Full 256-bit hashes provide proper collision resistance.

**Additional hardening (optional):**
```bash
# Make file append-only at filesystem level (ext4/xfs)
# NOTE: Some virtualized filesystems or containers may not support chattr
if sudo chattr +a /var/lib/antenna/accepted-risks.jsonl 2>/dev/null; then
  echo "Append-only attribute set"
else
  echo "Warning: chattr not supported on this filesystem, skipping"
fi

# Ship acceptances to central logging (for audit trail)
antenna accept CHAN-001 --reason "..." | logger -t antenna
```

**Known limitations:**
- If root is compromised, attacker can truncate and rebuild the chain
- Hash chain is tamper-*evident*, not tamper-*proof*
- For stronger guarantees: v2 will add optional external sync (`--sync-to s3://...`)

**For single-user setups** (most OpenClaw users), can fall back to `~/.openclaw/antenna-accepted-risks.jsonl` with a warning about reduced integrity.

### 5.3 Acceptance CLI Flow

```bash
# View what needs acceptance
$ antenna audit

# Accept with full documentation
$ sudo antenna accept CHAN-001 \
    --reason "Public customer support bot" \
    --mitigations "tools disabled,sandbox enabled" \
    --expires 30

# For CRITICAL findings, double confirmation required:
# 1. Confirm understanding of risk
# 2. Type "I accept CHAN-001" to confirm
```

---

## 6. Incident Detection & Revelation

### 6.1 What We Monitor (Runtime)

> **Philosophy:** Keep it simple. Falco/eBPF is powerful but needs kernel headers and often breaks. For v1, use `auditd` (standard on Ubuntu) and `fs.watch` on critical paths.

| Event | Detection Method | Alert Level |
|-------|------------------|-------------|
| Agent accessing `~/.ssh`, `~/.aws`, `~/.gnupg` | `auditd` watch rules | 🟠 HIGH |
| Agent spawning shell processes | System audit rules (if configured) | 🟡 MEDIUM |
| Secrets appearing in transcripts | `fs.watch` + regex scan | 🟠 HIGH |
| Config files modified | `fs.watch` on `~/.openclaw/` | 🟡 MEDIUM |
| Gateway accessed from new IP | Parse gateway logs | 🔵 INFO |

> **Note on execve monitoring:** Shell/process spawning detection relies on existing system audit rules for execve syscalls. Antenna doesn't install these by default (too noisy). If you need process monitoring, configure your own `-a always,exit -F arch=b64 -S execve` rules with appropriate filters.

**Persistent auditd rules (survives reboot):**
```bash
# Install rules to /etc/audit/rules.d/ (NOT ephemeral auditctl)
# NOTE: Watch rules (-w) do NOT support -F auid= filters!
# We filter by UID in Antenna's parser instead.

sudo tee /etc/audit/rules.d/antenna.rules << 'EOF'
# Managed by Antenna - monitors sensitive file access
# Filtering by user is done in Antenna, not kernel

-w /home/openclaw/.ssh     -p rwa -k antenna_ssh
-w /home/openclaw/.aws     -p rwa -k antenna_aws
-w /home/openclaw/.gnupg   -p rwa -k antenna_gpg
-w /home/openclaw/.openclaw/openclaw.json -p wa -k antenna_config
EOF

# Load rules (persistent across reboot)
sudo augenrules --load

# Verify
sudo auditctl -l | grep antenna
```

> ⚠️ **Why no UID filter in kernel?** Watch rules (`-w`) don't support syscall-style filters like `-F auid=`. We filter noise in Antenna's log parser: only events where `auid` or `uid` matches the openclaw user are treated as relevant.

```typescript
// In watcher.ts - filter auditd events by user
const OPENCLAW_UID = execSync('id -u openclaw').toString().trim();

function isRelevantEvent(event: AuditEvent): boolean {
  return event.auid === OPENCLAW_UID || event.uid === OPENCLAW_UID;
}
```

**Privilege separation for `antenna watch`:**
```bash
# DON'T run antenna watch as root. Instead:
# 1. Add openclaw user to adm group (can read /var/log/audit/audit.log)
sudo usermod -aG adm openclaw

# 2. Run watch as openclaw user
sudo -u openclaw antenna watch

# 3. For kill switch, grant specific sudo permission:
echo "openclaw ALL=(ALL) NOPASSWD: /bin/systemctl stop openclaw" | sudo tee /etc/sudoers.d/antenna
```

**What we explicitly don't do in v1:**
- Falco (kernel module dependency hell)
- eBPF (requires recent kernels, CAP_BPF)
- Network egress monitoring (complex, use firewall rules instead)
- Running as root (security risk if antenna has vulnerabilities)

### 6.2 Incident Report Generation

When something bad happens, `antenna incident` generates:

```markdown
# Incident Report: 2026-02-01T15:30:00Z

## Summary
Agent executed unexpected shell command that accessed ~/.aws/credentials

## Timeline
- 15:28:00 - Message received from Telegram user @attacker
- 15:28:05 - Message contained prompt injection attempt
- 15:28:10 - Agent invoked exec tool with: cat ~/.aws/credentials
- 15:28:11 - Antenna detected sensitive file access
- 15:28:12 - Alert sent, gateway stopped (kill switch active)

## Configuration at Time of Incident
- Telegram dmPolicy: "open" ⚠️ ACCEPTED RISK (CHAN-001)
- Sandbox mode: off ⚠️ ACCEPTED RISK (TOOL-002)
- Elevated tools: allowFrom: ["nik"] ✓

## Accepted Risks That May Have Contributed
1. CHAN-001 - Telegram open DMs
   - Accepted: 2026-01-15 by nik
   - Reason: "Public support bot"
   - This allowed the attacker to message the bot

2. TOOL-002 - Sandbox disabled
   - Accepted: 2026-01-20 by nik  
   - Reason: "Need full filesystem access for backups"
   - This allowed the exec to run on host

## Evidence
- Session transcript: ~/.openclaw/agents/main/sessions/2026-02-01-telegram-xxxxx.jsonl
  (line 847: matched SECRET_PATTERN sk-ant-***)
- Gateway log: /var/log/openclaw/gateway.log (lines 5420-5450)
- auditd events: `ausearch -k antenna_aws -ts 15:28:00` attached

## Recommendations
1. Enable sandbox mode
2. Restrict Telegram to allowlist
3. Add ~/.aws to exec blocked paths
```

---

## 7. CLI Interface

```bash
# Main commands (can use npx/bunx or installed globally)
antenna audit [--deep] [--fix] [--output json|md|text] [--no-auditd]
antenna fix [FINDING_ID | --all] [--dry-run] [--ssh-port PORT]
antenna accept FINDING_ID --reason "..." [--mitigations "..."] [--expires DAYS]
antenna watch [--kill-on critical|high] [--max-kills-per-hour N] [--restart-after SECS]
antenna init [--hardened]
antenna incident [--last | --date DATE] [--encrypt-to EMAIL]
antenna status

# Skill scanning
antenna skills scan [PATH | --all]
antenna skills check SKILL_URL

# Reports
antenna report [--output FILE] [--format md|json|html]

# Secret scanning options
antenna audit --secret-lookback-days 7    # default: 7 days
antenna audit --secret-lookback-days 0    # scan all transcripts (slow)

# Quick one-liner audit (no install)
npx antenna@latest audit
bunx antenna@latest audit
```

> **Secret lookback:** By default, only transcripts from the last 7 days are scanned. Old leaked secrets (likely already rotated) are downgraded to INFO to reduce alert fatigue. Set to 0 to scan all transcripts.

**Watch daemon options:**
```bash
# Basic watch
antenna watch

# Kill gateway on critical findings, max 3 kills/hour to prevent DoS
antenna watch --kill-on critical --max-kills-per-hour 3

# Auto-restart gateway after kill (requires sudo permission)
antenna watch --kill-on critical --restart-after 60

# Startup cooldown: don't kill within first 60s (prevents boot loops)
antenna watch --kill-on critical --startup-cooldown 60

# Output to file for external alerting
antenna watch --output /var/log/antenna/events.jsonl
```

**Implementation notes for `watcher.ts`:**
```typescript
// CRITICAL: Use streaming parser, not load-all approach!
// auditd logs can grow to 1GB+, loading all will OOM the process.

import { createReadStream } from 'fs';
import { createInterface } from 'readline';

async function tailAuditLog(path: string, onLine: (line: string) => void) {
  const stream = createReadStream(path, { encoding: 'utf8' });
  const rl = createInterface({ input: stream });
  
  for await (const line of rl) {
    // Filter by user in userspace (kernel watch rules don't support UID filter)
    const event = parseAuditLine(line);
    if (event && isRelevantUser(event)) {
      onLine(line);
    }
  }
}

// Handle log rotation (inode changes)
// Use chokidar or similar with { usePolling: false, followSymlinks: true }
```

**Kill switch warning:**
```
⚠️  EMERGENCY SHUTDOWN
Antenna detected a critical security event and stopped the OpenClaw gateway.

Event: Sensitive file access (~/.aws/credentials)
Time:  2026-02-01T15:30:00Z
User:  telegram/@attacker

ACTION REQUIRED:
1. Review the incident: antenna incident --last
2. Check database integrity if using vector DB (pgvector/Chroma/Qdrant)
3. Investigate the session transcript
4. Restart manually when safe: systemctl start openclaw
```

**Systemd unit for `antenna watch`:**
```ini
# /etc/systemd/system/antenna-watch.service
[Unit]
Description=Antenna Security Monitor
After=network.target openclaw.service

[Service]
Type=simple
User=openclaw
ExecStart=/usr/local/bin/antenna watch --kill-on critical --max-kills-per-hour 3 --startup-cooldown 60
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> ⚠️ **Monitor the monitor:** If `antenna watch` crashes, there's no security monitoring. Use `Restart=always` in systemd. Consider external health checks.

### Example Session

```
$ antenna audit

░██                                                                    ░██
░██                                                                    ░██
░██████   ░████████  ░████████  ░███████  ░████████  ░████████   ░██████
     ░██  ░██    ░██    ░██    ░██    ░██ ░██    ░██ ░██    ░██       ░██
░███████  ░██    ░██    ░██    ░█████████ ░██    ░██ ░██    ░██  ░███████
░██   ░██ ░██    ░██    ░██    ░██        ░██    ░██ ░██    ░██ ░██   ░██
░█████░██ ░██    ░██    ░████  ░███████   ░██    ░██ ░██    ░██ ░█████░██
                                                            v1.0.0 🦞📡🚨

Note: Network checks use local inference. Cloud firewalls and external
proxies may affect accuracy. See NET-003 confidence levels for details.

Scanning...
  Infrastructure ✓  Network ✓  OpenClaw ✓  Credentials ✓

🔴 BLOCKED (2)

  INFRA-001  SSH password auth enabled
             /etc/ssh/sshd_config → PasswordAuthentication yes
             Fix: antenna fix INFRA-001

  NET-002    Gateway auth not configured
             Fix: antenna fix NET-002

🟠 CRITICAL (2)

  CHAN-001   Telegram DMs open to anyone
             Anyone on Telegram can message your agent
             Accept: antenna accept CHAN-001 --reason "..."

  CRED-004   Anthropic Console OAuth key on VM
             Use org-managed API keys instead

🟡 WARNING (2)

  INFRA-004  fail2ban not running
  INFRA-009  OpenClaw outdated (0.4.2 → 0.5.1)

🔵 INFO (1)

  INFRA-015-SKIP  Cloud metadata service not detected (bare metal)

──────────────────────────────────────────────
  🔴 2 blocked   🟠 2 critical   🟡 2 warnings
  Score: 25/100
──────────────────────────────────────────────

Fix all safe issues:  antenna fix --all
```

---

## 8. Integration Points

### 8.1 OpenClaw Integration

```bash
# Pre-start hook (add to openclaw config or wrapper script)
npx antenna@latest audit --fail-on blocked || exit 1
openclaw gateway

# Or as systemd ExecStartPre
[Service]
ExecStartPre=/usr/bin/env npx antenna@latest audit --fail-on blocked
ExecStart=/usr/local/bin/openclaw gateway

# Or add to package.json scripts
{
  "scripts": {
    "start": "antenna audit --fail-on blocked && openclaw gateway",
    "audit": "antenna audit"
  }
}
```

### 8.2 External Tool Integration

| Tool | Integration | Purpose |
|------|-------------|---------|
| `openclaw security audit` | Run and parse output | OpenClaw's built-in checks |
| `auditd` | Install rules, parse `/var/log/audit/audit.log` | Runtime file access monitoring |
| Cisco Skill Scanner | `antenna skills scan` shells out | Skills supply chain |
| Lynis | Optional `--deep` mode | Comprehensive system audit |

**What we shell out to (standard Linux):**
- `ss -tlnp` — listening ports
- `ufw status` / `iptables -L` — firewall rules
- `systemctl is-active` — service status
- `stat` — file permissions
- `apt list --upgradable` — pending updates
- `sshd -T` — effective SSH config

**What we DON'T depend on (too heavy for average user):**
- Falco (kernel modules)
- eBPF/osquery (complex setup)
- Trivy (adds container scanning scope creep)

**`openclaw security audit` integration:**
```bash
# Antenna runs this internally and incorporates findings
openclaw security audit --json

# We parse the output and merge with our own checks
# This avoids duplicating OpenClaw's config validation logic
```

---

## 9. File Structure

```
antenna/
├── README.md
├── package.json
├── tsconfig.json
├── biome.json              # Linting/formatting
├── src/
│   ├── index.ts            # Entry point
│   ├── cli.ts              # Commander CLI
│   ├── models.ts           # Finding, RiskAcceptance, Report types
│   ├── config.ts           # Load antenna + openclaw configs
│   │
│   ├── checks/
│   │   ├── index.ts
│   │   ├── base.ts         # BaseChecker class
│   │   ├── infrastructure.ts  # SSH, firewall, fail2ban
│   │   ├── network.ts      # Gateway exposure, TLS
│   │   ├── channels.ts     # DM/group policies
│   │   ├── tools.ts        # Elevated, sandbox, exec
│   │   ├── credentials.ts  # Permissions, secrets, OAuth keys
│   │   └── skills.ts       # Skill Scanner wrapper
│   │
│   ├── runtime/
│   │   ├── index.ts
│   │   ├── watcher.ts      # Continuous monitoring daemon
│   │   ├── falco.ts        # Falco integration
│   │   └── transcript.ts   # Real-time transcript scanning
│   │
│   ├── incident/
│   │   ├── index.ts
│   │   ├── detector.ts     # Incident detection logic
│   │   └── report.ts       # Incident report generation
│   │
│   └── output/
│       ├── index.ts
│       ├── console.ts      # Colorful terminal output (chalk/picocolors)
│       ├── json.ts
│       ├── markdown.ts
│       └── html.ts
│
├── rules/
│   └── auditd/
│       └── antenna.rules     # auditd rules for sensitive paths
│
├── templates/
│   ├── hardened-config.json
│   └── incident-report.md
│
└── tests/
    ├── infrastructure.test.ts
    ├── channels.test.ts
    └── fixtures/
        └── sample-configs/
```

---

## 10. Implementation Phases

### Phase 1: Core Audit — MVP (Week 1-2)
- [x] Project setup (TypeScript, Bun, tsconfig, biome)
- [x] CLI scaffold with Commander.js
- [x] Infrastructure checks (SSH, firewall, fail2ban) with **drop-in config fixes**
- [x] Network checks (gateway exposure, auth)
- [x] Channel policy checks
- [x] Credential permission checks
- [x] Risk acceptance system (JSONL, root-owned)
- [x] Console output with picocolors
- [ ] Publish to npm as `antenna-security` (antenna is taken)
- [x] **Pin dependencies, run `npm audit` in CI**

### Phase 2: Full OCSAS Coverage (Week 2-3)
- [x] Session isolation checks (dmScope) — in channels.ts CHAN-008
- [x] Group mention gating — in channels.ts CHAN-009
- [x] Sandbox network egress — in tools.ts TOOL-006
- [x] Log redaction checks — in credentials.ts CRED-006
- [x] Plugin allowlist checks
- [x] Skill Scanner integration
- [x] JSON/Markdown output formats

### Phase 3: Lite Runtime (Week 3-4)
- [x] `auditd` rules for sensitive file access
- [x] `fs.watch` on config/transcript directories
- [x] Watch daemon (outputs to stdout/file)
- [x] Incident correlation with accepted risks
- [ ] OpenClaw pre-start integration

### Phase 4: Polish (Week 4+)
- [ ] HTML report output
- [ ] `antenna probe --from <host>` for external validation
- [ ] Profile presets (public-bot, internal-agent, prod-enterprise)
- [ ] Documentation
- [ ] Integration tests with Vitest

---

## 11. Design Decisions

### Resolved Questions

1. **Should antenna block OpenClaw startup by default?**
   
   **No.** Antenna is an auditing/warning tool, not a gatekeeper. It reports findings and lets the admin decide. If they want to block startup, they can add `antenna audit --fail-on blocked` to their own scripts.

2. **How to handle OpenClaw updates that change config schema?**
   
   **Out of scope.** Config schema changes are OpenClaw's responsibility. Antenna focuses on:
   - Warning about outdated software (Ubuntu, OpenSSL, OpenClaw itself)
   - Checking security-relevant config values that exist
   - Graceful handling of unknown config keys (ignore, don't crash)

3. **Should we fork/extend `openclaw security audit` or build separately?**
   
   **Build separately, but integrate.** `openclaw security audit` is one of the available tools we can call. Antenna wraps it and adds:
   - Infrastructure checks (SSH, firewall, fail2ban)
   - Risk acceptance system with audit trail
   - Runtime monitoring
   - Incident reporting

4. **Runtime monitoring: in-process or separate daemon?**
   
   **Separate daemon.** "In-process" would mean running inside the OpenClaw gateway process, which is fragile (crashes with gateway, can't monitor gateway itself). Separate daemon (`antenna watch`) runs independently and can:
   - Survive gateway crashes
   - Monitor gateway behavior from outside
   - Output events to stdout/file (pipe to your own alerting)
   - Be started/stopped independently

### Key Architectural Decisions (from reviews)

| Decision | Why |
|----------|-----|
| **Drop-in configs, not `sed`** | Editing `/etc/ssh/sshd_config` directly can brick SSH access. Drop-in files in `sshd_config.d/` are safer and reversible. |
| **SSH port from current session first** | `$SSH_CONNECTION` gives the actual port you're connected on. `sshd -T` can return multiple ports or depend on `Match` conditions. |
| **Root-owned acceptance file** | If attacker compromises `openclaw` user, they shouldn't be able to silence alerts. JSONL with hash chain for tamper evidence. |
| **Full SHA256 hashes** | Previous designs used truncated hashes (10 chars = 40 bits). Full 256-bit hashes provide proper collision resistance. |
| **`auditd` over Falco** | Falco needs kernel headers and breaks often. `auditd` is standard on Ubuntu, requires no extra setup. |
| **Watch rules without UID filter** | auditd watch rules (`-w`) don't support `-F auid=`. Filter by UID in Antenna's log parser instead. |
| **Persistent auditd rules** | `auditctl -w ...` is ephemeral (gone after reboot). Use `/etc/audit/rules.d/` + `augenrules --load`. |
| **Privilege separation** | Don't run `antenna watch` as root. Use `adm` group for log reading, specific `sudoers` entry for kill switch. |
| **Local inference, not external scan** | We can't truly scan from inside the VM. Be honest: check firewall rules + `ss -tlnp`, label as "local inference". |
| **Cloud-aware IMDS checks** | Different clouds (AWS/GCP/Azure) have different metadata APIs. Check each with short timeouts to avoid hanging. |
| **USN-based OpenSSL checks** | Naive version matching causes false positives. Ubuntu backports patches without bumping version. Check USNs instead. |
| **Pin versions in prod** | `npx antenna@latest` is convenient for dev, but prod should pin `antenna@x.y.z` + verify checksum. |
| **Watch daemon rate limits** | `--max-kills-per-hour` prevents DoS via false positives. |
| **Minimal dependencies** | npm supply chain is a risk. Keep deps small, pin with integrity hashes, run `npm audit` in CI. |

### Edge Cases for v1.1 Backlog

| Issue | Risk | Fix |
|-------|------|-----|
| **Log rotation race** | auditd rotates to `audit.log.1`, watcher loses events | Use inode tracking (like `tail -F`), not filename |
| **auditd buffer overflow** | High-traffic agents drop events | Check `-b` backlog setting in `antenna init`, suggest 16384 |
| **fs.watch feedback loops** | Watcher triggers on `.tmp`/`.lock` files it creates | Debounce (100ms) + ignore list for temp files |
| **Config reload after audit** | User modifies config + SIGHUP after audit passed | Document limitation; add `--monitor-config` in v1.1 |
| **Incident report permissions** | Reports contain secrets, default perms too open | `chmod 600` on reports; add `--encrypt-to` option |
| **Transcript scan performance** | Scanning all `.jsonl` on large deployments is slow | Add `--transcript-lookback 24h` limit |

### Out of Scope for v1

- Cloud control plane checks (AWS SG, GCP firewall) — too cloud-specific
- Network egress monitoring — use firewall rules instead
- Kernel-level monitoring (eBPF, Falco) — too fragile
- Windows/macOS — Ubuntu VMs only

---

## 12. Success Metrics

1. **Adoption**: Number of OpenClaw deployments using antenna
2. **Prevention**: Incidents prevented by blocked findings
3. **Detection**: Time to detect runtime anomalies
4. **Coverage**: % of OCSAS controls verified

---

## Appendix A: Full Check Reference

See `checks/` module documentation for complete list with detection logic.

## Appendix B: auditd Rules

```bash
# /etc/audit/rules.d/antenna.rules
# Managed by Antenna - monitors sensitive file access
#
# NOTE: Watch rules (-w) do NOT support UID filters!
# Filtering by user is done in Antenna's log parser, not here.
# See watcher.ts for the isRelevantEvent() function.

# SSH keys
-w /home/openclaw/.ssh -p rwa -k antenna_ssh

# Cloud credentials
-w /home/openclaw/.aws -p rwa -k antenna_aws
-w /home/openclaw/.config/gcloud -p rwa -k antenna_gcloud

# GPG keys
-w /home/openclaw/.gnupg -p rwa -k antenna_gpg

# OpenClaw config and credentials
-w /home/openclaw/.openclaw/openclaw.json -p wa -k antenna_config
-w /home/openclaw/.openclaw/credentials -p rwa -k antenna_creds
```

**Installation:**
```bash
sudo cp antenna.rules /etc/audit/rules.d/
sudo augenrules --load
sudo auditctl -l | grep antenna  # verify
```

**Log rotation note:** Ensure your watcher handles inode changes (like `tail -F`), not just filename tracking. auditd rotates logs to `audit.log.1`, etc.

**Buffer tuning:** For high-traffic agents, check `/etc/audit/audit.rules` for the `-b` (backlog) setting. Default is often 320 or 8192. Consider bumping to 16384 if events are being dropped.

## Appendix C: Sample Hardened Config

See `templates/hardened-config.json` for maximum security configuration.
