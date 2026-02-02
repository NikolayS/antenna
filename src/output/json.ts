import type { AuditReport } from '../models.js';

/**
 * Generate JSON report from audit results
 */
export function generateJson(report: AuditReport, pretty = true): string {
  if (pretty) {
    return JSON.stringify(report, null, 2);
  }
  return JSON.stringify(report);
}
