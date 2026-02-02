import type { CheckResult, Finding, SeverityLevel } from '../models.js';

/**
 * Base class for all security checks
 */
export abstract class BaseChecker {
  abstract name: string;

  abstract run(): Promise<CheckResult>;

  /**
   * Optional auto-fix implementation
   */
  fix?(findingId: string, dryRun?: boolean): Promise<boolean>;

  /**
   * Helper to create a finding
   */
  protected createFinding(
    id: string,
    level: SeverityLevel,
    title: string,
    message: string,
    options: Partial<Finding> = {},
  ): Finding {
    return {
      id,
      level,
      title,
      message,
      autoFixable: false,
      ...options,
    };
  }

  /**
   * Helper to create a result with no findings (all checks passed)
   */
  protected pass(): CheckResult {
    return { findings: [] };
  }

  /**
   * Helper to create a skipped result
   */
  protected skip(reason: string): CheckResult {
    return { findings: [], skipped: reason };
  }
}
