import type { AuditReport, Finding, SeverityLevel } from '../models.js';

const LEVEL_COLORS: Record<SeverityLevel, string> = {
  block: '#dc2626',
  critical: '#ea580c',
  warning: '#ca8a04',
  info: '#2563eb',
};

const LEVEL_BG: Record<SeverityLevel, string> = {
  block: '#fef2f2',
  critical: '#fff7ed',
  warning: '#fefce8',
  info: '#eff6ff',
};

const LEVEL_EMOJI: Record<SeverityLevel, string> = {
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

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getScoreColor(score: number): string {
  if (score >= 80) return '#16a34a';
  if (score >= 60) return '#ca8a04';
  if (score >= 40) return '#ea580c';
  return '#dc2626';
}

function renderFinding(finding: Finding): string {
  const color = LEVEL_COLORS[finding.level];
  const bg = LEVEL_BG[finding.level];

  let html = `
    <div class="finding" style="border-left: 4px solid ${color}; background: ${bg};">
      <div class="finding-header">
        <span class="finding-id">${escapeHtml(finding.id)}</span>
        <span class="finding-title">${escapeHtml(finding.title)}</span>
      </div>
      <p class="finding-message">${escapeHtml(finding.message)}</p>`;

  if (finding.file) {
    html += `<p class="finding-file"><strong>File:</strong> <code>${escapeHtml(finding.file)}</code></p>`;
  }

  if (finding.details) {
    html += `<p class="finding-action"><strong>Action:</strong> ${escapeHtml(finding.details)}</p>`;
  }

  if (finding.ocsasControl) {
    html += `<p class="finding-ocsas"><strong>OCSAS Control:</strong> ${escapeHtml(finding.ocsasControl)}</p>`;
  }

  if (finding.evidence && finding.evidence.length > 0) {
    html += '<div class="finding-evidence"><strong>Evidence:</strong><ul>';
    for (const e of finding.evidence) {
      html += `<li>${escapeHtml(e)}</li>`;
    }
    html += '</ul></div>';
  }

  html += '</div>';
  return html;
}

/**
 * Generate HTML report from audit results
 */
export function generateHtml(report: AuditReport): string {
  const scoreColor = getScoreColor(report.score);

  // Group findings by level
  const byLevel = new Map<SeverityLevel, Finding[]>();
  for (const finding of report.findings) {
    const existing = byLevel.get(finding.level) ?? [];
    existing.push(finding);
    byLevel.set(finding.level, existing);
  }

  const levels: SeverityLevel[] = ['block', 'critical', 'warning', 'info'];

  let findingsHtml = '';
  for (const level of levels) {
    const findings = byLevel.get(level);
    if (!findings || findings.length === 0) continue;

    findingsHtml += `
      <section class="findings-section">
        <h2>${LEVEL_EMOJI[level]} ${LEVEL_NAMES[level]} (${findings.length})</h2>
        ${findings.map(renderFinding).join('\n')}
      </section>`;
  }

  // Accepted risks
  let acceptedHtml = '';
  if (report.acceptedRisks.length > 0) {
    acceptedHtml = `
      <section class="findings-section">
        <h2>⚪ Accepted Risks (${report.acceptedRisks.length})</h2>
        ${report.acceptedRisks
          .map(
            (a) => `
          <div class="finding accepted">
            <div class="finding-header">
              <span class="finding-id">${escapeHtml(a.id)}</span>
            </div>
            <p><strong>Accepted by:</strong> ${escapeHtml(a.accepted_by)}</p>
            <p><strong>Reason:</strong> ${escapeHtml(a.reason)}</p>
            <p><strong>Expires:</strong> ${escapeHtml(a.expires_at)}</p>
            ${a.mitigations.length > 0 ? `<p><strong>Mitigations:</strong> ${escapeHtml(a.mitigations.join(', '))}</p>` : ''}
          </div>`,
          )
          .join('\n')}
      </section>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Antenna Security Audit Report</title>
  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #1f2937;
      background: #f9fafb;
      padding: 2rem;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background: white;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      padding: 2rem;
    }
    header {
      border-bottom: 1px solid #e5e7eb;
      padding-bottom: 1.5rem;
      margin-bottom: 1.5rem;
    }
    h1 {
      font-size: 1.75rem;
      margin-bottom: 0.5rem;
    }
    .header-logo {
      font-size: 2rem;
      margin-right: 0.5rem;
    }
    .meta {
      color: #6b7280;
      font-size: 0.875rem;
    }
    .meta span {
      margin-right: 1.5rem;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .summary-card {
      background: #f9fafb;
      border-radius: 8px;
      padding: 1rem;
      text-align: center;
    }
    .summary-card.score {
      background: ${scoreColor}10;
      border: 2px solid ${scoreColor};
    }
    .summary-value {
      font-size: 1.5rem;
      font-weight: bold;
    }
    .summary-label {
      font-size: 0.75rem;
      color: #6b7280;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .findings-section {
      margin-bottom: 2rem;
    }
    .findings-section h2 {
      font-size: 1.25rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid #e5e7eb;
    }
    .finding {
      border-radius: 6px;
      padding: 1rem;
      margin-bottom: 1rem;
    }
    .finding.accepted {
      background: #f9fafb;
      border-left: 4px solid #9ca3af;
    }
    .finding-header {
      display: flex;
      align-items: baseline;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
    }
    .finding-id {
      font-family: 'SF Mono', Monaco, Consolas, monospace;
      font-size: 0.875rem;
      font-weight: 600;
      color: #374151;
    }
    .finding-title {
      font-weight: 600;
    }
    .finding-message {
      margin-bottom: 0.5rem;
    }
    .finding p {
      margin: 0.25rem 0;
      font-size: 0.875rem;
    }
    .finding code {
      background: rgba(0,0,0,0.05);
      padding: 0.125rem 0.375rem;
      border-radius: 4px;
      font-family: 'SF Mono', Monaco, Consolas, monospace;
      font-size: 0.8125rem;
    }
    .finding-evidence ul {
      margin-left: 1.5rem;
      margin-top: 0.25rem;
    }
    footer {
      margin-top: 2rem;
      padding-top: 1rem;
      border-top: 1px solid #e5e7eb;
      color: #6b7280;
      font-size: 0.875rem;
      text-align: center;
    }
    footer a {
      color: #2563eb;
      text-decoration: none;
    }
    footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1><span class="header-logo">🦞📡🚨</span> Antenna Security Audit</h1>
      <div class="meta">
        <span><strong>Host:</strong> ${escapeHtml(report.hostname)}</span>
        <span><strong>Date:</strong> ${escapeHtml(report.timestamp)}</span>
        <span><strong>Version:</strong> ${escapeHtml(report.version)}</span>
      </div>
    </header>

    <div class="summary">
      <div class="summary-card score">
        <div class="summary-value" style="color: ${scoreColor}">${report.score}</div>
        <div class="summary-label">Score</div>
      </div>
      <div class="summary-card">
        <div class="summary-value" style="color: ${LEVEL_COLORS.block}">${report.summary.blocked}</div>
        <div class="summary-label">Blocked</div>
      </div>
      <div class="summary-card">
        <div class="summary-value" style="color: ${LEVEL_COLORS.critical}">${report.summary.critical}</div>
        <div class="summary-label">Critical</div>
      </div>
      <div class="summary-card">
        <div class="summary-value" style="color: ${LEVEL_COLORS.warning}">${report.summary.warnings}</div>
        <div class="summary-label">Warnings</div>
      </div>
      <div class="summary-card">
        <div class="summary-value" style="color: ${LEVEL_COLORS.info}">${report.summary.info}</div>
        <div class="summary-label">Info</div>
      </div>
    </div>

    ${findingsHtml}
    ${acceptedHtml}

    <footer>
      Generated by <a href="https://github.com/NikolayS/antenna">Antenna</a>
    </footer>
  </div>
</body>
</html>`;
}
