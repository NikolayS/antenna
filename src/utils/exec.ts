import { type ExecSyncOptions, execSync } from 'node:child_process';

export interface ExecResult {
  stdout: string;
  success: boolean;
  exitCode: number;
}

/**
 * Execute a shell command and return the result
 */
export function exec(
  command: string,
  options: ExecSyncOptions = {},
): ExecResult {
  try {
    const stdout = execSync(command, {
      encoding: 'utf8',
      timeout: 30000,
      ...options,
    }) as string;
    return {
      stdout: stdout.trim(),
      success: true,
      exitCode: 0,
    };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer | string };
    return {
      stdout: err.stdout?.toString().trim() ?? '',
      success: false,
      exitCode: err.status ?? 1,
    };
  }
}

/**
 * Check if a command exists
 */
export function commandExists(command: string): boolean {
  const result = exec(`which ${command} 2>/dev/null`);
  return result.success && result.stdout.length > 0;
}

/**
 * Check if running as root
 */
export function isRoot(): boolean {
  const result = exec('id -u');
  return result.success && result.stdout === '0';
}

/**
 * Get the current username
 */
export function getCurrentUser(): string {
  const result = exec('whoami');
  return result.success ? result.stdout : 'unknown';
}
