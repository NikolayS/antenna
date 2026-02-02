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

## Commands

```bash
antenna audit              # Run security audit
antenna fix [FINDING_ID]   # Auto-fix a finding
antenna accept <ID>        # Accept a risk with documentation
antenna watch              # Start runtime monitoring (TODO)
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

## Risk Acceptance

For findings you've reviewed and accept:

```bash
antenna accept CHAN-001 \
  --reason "Public support bot" \
  --mitigations "tools disabled,sandbox enabled" \
  --expires 30
```

Acceptances are stored with hash chain verification for tamper evidence.

## Target Environment

- **OS**: Ubuntu 22.04 LTS, 24.04 LTS
- **Runtime**: OpenClaw with Node.js 22+
- **Not for**: macOS local installs, Docker-only deployments

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
