# Antenna 🦞📡🚨

> *A lobster's antenna detects threats in the water before they get close.*

Security audit and monitoring for OpenClaw deployments on Ubuntu VMs.

## Quick Start

```bash
# One command audit (dev/testing)
npx antenna-security audit

# Production: pin version
npm install -g antenna-security@0.1.0
antenna audit
```

## What It Does

Antenna checks your OpenClaw deployment for security issues across multiple layers:

- **Infrastructure**: SSH hardening, firewall, fail2ban, unattended-upgrades
- **Network**: Gateway exposure, TLS, authentication
- **Channels**: DM/group policies, session isolation
- **Credentials**: File permissions, secret scanning, API key detection
- **Tools**: Sandbox configuration, elevated permissions
- **Skills**: Plugin allowlist, version pinning

## Commands

### Audit

```bash
# Basic audit (text output)
antenna audit

# JSON output for automation
antenna audit --output json

# Markdown report
antenna audit --output md > report.md

# HTML report
antenna audit --output html > report.html

# Use security profile
antenna audit --profile public-bot
antenna audit --profile internal-agent
antenna audit --profile prod-enterprise

# Exit with error on blocked/critical findings
antenna audit --fail-on blocked   # default
antenna audit --fail-on critical
antenna audit --fail-on warning
```

### Fix

```bash
# Fix a specific finding
antenna fix INFRA-001

# Fix all auto-fixable findings
antenna fix --all

# Preview what would be fixed
antenna fix --all --dry-run
```

### Accept Risk

```bash
# Accept a risk with documentation
antenna accept CHAN-001 \
  --reason "Public support bot" \
  --mitigations "tools disabled,sandbox enabled" \
  --expires 30
```

Acceptances are stored with SHA256 hash chain verification for tamper evidence.

### Watch (Runtime Monitoring)

```bash
# Start monitoring daemon
antenna watch

# Kill gateway on critical findings (with rate limiting)
antenna watch --kill-on critical --max-kills-per-hour 3

# Auto-restart gateway after kill
antenna watch --kill-on critical --restart-after 60

# Startup cooldown (prevent boot loops)
antenna watch --kill-on critical --startup-cooldown 60

# Output events to file
antenna watch --output /var/log/antenna/events.jsonl
```

### Incident Reports

```bash
# Generate report for last incident
antenna incident --last

# View incident by date
antenna incident --date 2026-02-01
```

### Initialize

```bash
# Setup Antenna
antenna init

# Install auditd rules
antenna init --install-auditd
```

### Skills Scanning

```bash
# Scan installed skills
antenna skills scan ~/.openclaw/skills/

# Check a skill before installing
antenna skills check https://github.com/user/skill
```

## Security Profiles

Profiles adjust severity levels for different deployment scenarios:

| Profile | Description | Use Case |
|---------|-------------|----------|
| `public-bot` | Maximum security | Public-facing bots on Telegram/Discord |
| `internal-agent` | Balanced security | Internal tools for trusted employees |
| `prod-enterprise` | Strict compliance | Production enterprise deployments |

```bash
antenna audit --profile public-bot
```

## Pre-start Integration

Block OpenClaw startup on security findings:

```bash
# Simple pre-start check
antenna audit --fail-on blocked && openclaw gateway

# Systemd unit (ExecStartPre)
[Service]
ExecStartPre=/usr/local/bin/antenna audit --fail-on blocked
ExecStart=/usr/local/bin/openclaw gateway

# package.json scripts
{
  "scripts": {
    "start": "antenna audit --fail-on blocked && openclaw gateway",
    "audit": "antenna audit"
  }
}
```

## Example Output

```
🔴 BLOCKED (2)

  INFRA-001  SSH password auth enabled
             Fix: antenna fix INFRA-001

  NET-002    Gateway auth not configured

🟠 CRITICAL (1)

  CHAN-001   Telegram DMs open to anyone
             Accept: antenna accept CHAN-001 --reason "..."

🟡 WARNING (2)

  INFRA-004  fail2ban not running
  CRED-003   Secrets in session transcripts

──────────────────────────────────────────────
  🔴 2 blocked   🟠 1 critical   🟡 2 warnings
  Score: 35/100
```

## Severity Levels

| Level | Description |
|-------|-------------|
| 🔴 BLOCK | Must be fixed before proceeding |
| 🟠 CRIT | Requires explicit risk acceptance |
| 🟡 WARN | Strong recommendation to fix |
| 🔵 INFO | Best practice recommendation |

## Target Environment

- **OS**: Ubuntu 22.04 LTS, 24.04 LTS
- **Runtime**: OpenClaw with Node.js 22+
- **Not for**: macOS local installs, Docker-only deployments

## OCSAS Compatibility

Antenna implements checks for [OCSAS](https://github.com/gensecaihq/ocsas) (OpenClaw Security Assurance Standard) controls plus additional infrastructure checks.

## Development

```bash
bun install
bun test
bun run src/index.ts audit
```

## License

Apache-2.0

---

See [SPEC.md](./SPEC.md) for full specification.
