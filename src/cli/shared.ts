import { Command } from 'commander';

export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'] as const;
export type Severity = typeof SEVERITY_ORDER[number];

export function shouldFailBySeverity(findings: Array<{ severity: Severity }>, level?: string): boolean {
  if (!level) return false;
  const idx = SEVERITY_ORDER.indexOf(level as Severity);
  if (idx < 0) return false;
  const threshold = new Set(SEVERITY_ORDER.slice(idx));
  return findings.some((f) => threshold.has(f.severity));
}

// Convenience type for command registrar functions
export type RegisterCommands = (program: Command) => void;
