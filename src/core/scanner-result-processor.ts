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
    const module = await import(config.moduleImport);
    const ScannerClass = module[config.className];
    const scanner = new ScannerClass();
    
    if (config.requiresInitialization && scanner.initialize) {
      await scanner.initialize();
    }
    
    return scanner;
  }
}
