/**
 * Scanner Result Processor
 * Utility class for processing scanner results and updating metrics
 */

import { SecurityFinding, ScanMetrics } from './scanner';
import { ScannerConfig, DEFAULT_SCAN_CONFIG } from './scanner-config';

export class ScannerResultProcessor {
  /**
   * Process findings from any scanner and convert to standardized format
   */
  static processFindings(findings: any[]): SecurityFinding[] {
    return findings.map(finding => ({
      id: finding.id,
      severity: finding.severity,
      category: finding.category,
      title: finding.title,
      description: finding.description,
      evidence: finding.evidence,
      recommendation: finding.recommendation,
      compliance_impact: finding.compliance_impact || []
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
  static async loadScanner(config: ScannerConfig): Promise<any> {
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
    const scanner = new ScannerClass();
    
    if (config.requiresInitialization && scanner.initialize) {
      await scanner.initialize();
    }
    
    return scanner;
  }
}
