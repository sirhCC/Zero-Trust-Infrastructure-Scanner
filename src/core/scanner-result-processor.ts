/**
 * Scanner Result Processor
 * Utility class for processing scanner results and updating metrics
 */

import { SecurityFinding, ScanMetrics, ScanTarget } from './scanner';
import { ScannerConfig, DEFAULT_SCAN_CONFIG } from './scanner-config';

export class ScannerResultProcessor {
  /**
   * Process findings from any scanner and convert to standardized format
   */
  static processFindings(findings: Array<SecurityFinding | (Partial<SecurityFinding> & Record<string, unknown>)>): SecurityFinding[] {
    const ensureSeverity = (s: unknown): SecurityFinding['severity'] => {
      return s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'info' ? s : 'medium';
    };
    return findings.map((finding) => ({
      id: String(
        finding.id ?? `auto_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
      ),
      severity: ensureSeverity(finding.severity),
      category: String(finding.category ?? 'general'),
      title: String(finding.title ?? 'Untitled finding'),
      description: String(finding.description ?? ''),
      evidence: finding.evidence ?? {},
      recommendation: String(finding.recommendation ?? ''),
  compliance_impact: (Array.isArray(finding.compliance_impact) ? finding.compliance_impact : []) as any
    }));
  }

  /**
   * Calculate metrics based on findings and scanner configuration
   */
  static calculateMetrics(findings: SecurityFinding[], config: ScannerConfig): ScanMetrics {
    const failedChecks = findings.filter(f => 
      f.severity === 'critical' || f.severity === 'high'
    ).length;
    
    const warnings = findings.filter(f => 
      f.severity === 'medium' || f.severity === 'low'
    ).length;
    
    const passedChecks = Math.max(0, config.totalChecks - findings.length);

    return {
      total_checks: findings.length,
      failed_checks: failedChecks,
      warnings: warnings,
      passed_checks: passedChecks,
      resources_scanned: DEFAULT_SCAN_CONFIG.resourcesScanned,
      scan_coverage: DEFAULT_SCAN_CONFIG.scanCoverage
    };
  }

  /**
   * Load and instantiate a scanner module
   */
  static async loadScanner(config: ScannerConfig): Promise<{ scan(target: ScanTarget): Promise<SecurityFinding[]>; initialize?: () => Promise<void> }>
  {
    // Use literal imports for known built-in scanners so packagers (e.g., pkg) can include them.
    // Fall back to dynamic import for custom modules in dev environments.
    let module: any;
    switch (config.moduleImport) {
      case '../scanners/network-scanner':
        module = await import('../scanners/network-scanner');
        break;
      case '../scanners/identity-scanner':
        module = await import('../scanners/identity-scanner');
        break;
      case '../scanners/supply-chain-scanner':
        module = await import('../scanners/supply-chain-scanner');
        break;
      case '../scanners/compliance-scanner':
        module = await import('../scanners/compliance-scanner');
        break;
      default:
        throw new Error(
          `Unsupported scanner module '${config.moduleImport}' in packaged binary. ` +
          `Use the source build to load custom scanners.`
        );
    }
    const ScannerClass = module[config.className];
  const scanner: { scan(target: ScanTarget): Promise<SecurityFinding[]>; initialize?: () => Promise<void> } = new ScannerClass();
    
    if (config.requiresInitialization && scanner.initialize) {
      await scanner.initialize();
    }
    
  return scanner;
  }
}
