/**
 * Zero-Trust Scanner Core Engine
 * Main orchestrator for all security scanning operations
 */

import { SCANNER_CONFIGS } from './scanner-config';
import { ScannerResultProcessor } from './scanner-result-processor';

export interface ScanTarget {
  type: 'network' | 'identity' | 'supply-chain' | 'compliance' | 'comprehensive';
  target: string;
  options: Record<string, any>;
}

export interface ScanResult {
  id: string;
  timestamp: Date;
  target: ScanTarget;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  findings: SecurityFinding[];
  metrics: ScanMetrics;
  duration: number;
}

export interface SecurityFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  evidence: any;
  recommendation: string;
  compliance_impact?: ComplianceImpact[];
}

export interface ComplianceImpact {
  standard: 'SOC2' | 'PCI' | 'HIPAA' | 'GDPR' | 'ISO27001';
  control: string;
  impact: 'critical' | 'high' | 'medium' | 'low';
}

export interface ScanMetrics {
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  warnings: number;
  resources_scanned: number;
  scan_coverage: number;
}

export class ZeroTrustScanner {
  private scanners: Map<string, any> = new Map();
  private activeScans: Map<string, ScanResult> = new Map();
  private scanHistory: ScanResult[] = [];
  private isTestMode: boolean = false;

  constructor(testMode: boolean = false) {
    // Initialize with basic configuration
    this.isTestMode = testMode;
    this.initializeScanners();
  }

  /**
   * Initialize the scanner modules
   */
  private initializeScanners(): void {
    // Initialize scanner registry from configuration
    Object.keys(SCANNER_CONFIGS).forEach(scannerType => {
      const config = SCANNER_CONFIGS[scannerType];
      this.scanners.set(scannerType, config.className);
    });
  }

  /**
   * Initialize the scanner with all modules
   */
  async initialize(): Promise<void> {
    console.log('🔧 Initializing Zero-Trust Scanner...');
    
    // Scanner modules are loaded dynamically as needed
    console.log(`📊 Registered ${this.scanners.size} scanner types`);
    
    console.log('✅ Scanner initialization complete');
  }

  /**
   * Start the scanner service
   */
  async start(): Promise<void> {
    console.log('🚀 Zero-Trust Scanner service started');
    
    // Keep the process alive
    process.stdin.resume();
  }

  /**
   * Execute a security scan
   */
  async scan(target: ScanTarget, opts?: { signal?: AbortSignal; timeoutMs?: number }): Promise<ScanResult> {
    const scanId = this.generateScanId();
    const startTime = Date.now();
    let aborted = false;
    let timeoutHandle: NodeJS.Timeout | null = null;
    const onAbort = () => { aborted = true; };
    if (opts?.signal) {
      if (opts.signal.aborted) aborted = true;
      else opts.signal.addEventListener('abort', onAbort, { once: true });
    }
    if (opts?.timeoutMs && opts.timeoutMs > 0) {
      timeoutHandle = setTimeout(() => { aborted = true; }, opts.timeoutMs);
    }
    
    const scanResult: ScanResult = {
      id: scanId,
      timestamp: new Date(),
      target,
      status: 'running',
      findings: [],
      metrics: {
        total_checks: 0,
        passed_checks: 0,
        failed_checks: 0,
        warnings: 0,
        resources_scanned: 0,
        scan_coverage: 0
      },
      duration: 0
    };

    this.activeScans.set(scanId, scanResult);

    try {
  if (!this.isTestMode) {
        console.log(`🔍 Starting ${target.type} scan for: ${target.target}`);
      }
      
      // Route to appropriate scanner using configuration
      const config = SCANNER_CONFIGS[target.type];
      if (!config) {
        throw new Error(`Unsupported scan type: ${target.type}`);
      }

      const isAborted = () => aborted;
      if (target.type === 'comprehensive') {
        // Run comprehensive scan across all scanner types
        await this.runComprehensiveScan(target, scanResult, scanId, isAborted);
      } else {
        // Load scanner and execute scan
        const scanner = await ScannerResultProcessor.loadScanner(config);
        const findings = await scanner.scan(target);
        
        // Process findings and metrics using unified approach
        scanResult.findings = ScannerResultProcessor.processFindings(findings);
        scanResult.metrics = ScannerResultProcessor.calculateMetrics(scanResult.findings, config);
        
        // Additional processing time
  await this.simulateScan(config.processingTime, scanId, isAborted);
      }

      scanResult.status = 'completed';
      scanResult.duration = Date.now() - startTime;
      
      if (!this.isTestMode) {
        console.log(`✅ Scan ${scanId} completed in ${scanResult.duration}ms`);
      }
      
    } catch (error) {
      // Check if this was a cancellation
      if (error instanceof Error && error.message === 'Scan cancelled') {
        scanResult.status = 'cancelled';
        // Only log cancellation messages in non-test mode to avoid confusing test output
        if (!this.isTestMode) {
          console.log(`🚫 Scan ${scanId} was cancelled`);
        }
      } else {
        if (!this.isTestMode) {
          console.error(`❌ Scan ${scanId} failed:`, error);
        }
        scanResult.status = 'failed';
      }
      
      scanResult.duration = Date.now() - startTime;
    } finally {
      this.activeScans.delete(scanId);
      this.scanHistory.push(scanResult);
      if (opts?.signal) opts.signal.removeEventListener('abort', onAbort as any);
      if (timeoutHandle) clearTimeout(timeoutHandle);
    }

    return scanResult;
  }

  /**
   * Get all active scans
   */
  getActiveScans(): ScanResult[] {
    return Array.from(this.activeScans.values());
  }

  /**
   * Get scan history
   */
  getScanHistory(limit: number = 50): ScanResult[] {
    return this.scanHistory.slice(-limit);
  }

  /**
   * Get scan by ID
   */
  getScan(scanId: string): ScanResult | undefined {
    return this.activeScans.get(scanId) || 
           this.scanHistory.find(scan => scan.id === scanId);
  }

  /**
   * Simulate scan work with delay (for testing and demo purposes)
   */
  private async simulateScan(duration: number, scanId?: string, isAborted?: () => boolean): Promise<void> {
    const startTime = Date.now();
    const endTime = startTime + duration;
    
    while (Date.now() < endTime) {
      // Check if scan was cancelled
      if (scanId) {
        const scan = this.activeScans.get(scanId);
        if (!scan || scan.status === 'cancelled') {
          // This is expected behavior when tests cancel scans
          throw new Error('Scan cancelled');
        }
      }
      if (isAborted && isAborted()) {
        throw new Error('Scan cancelled');
      }
      
      // Wait 100ms before checking again
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  /**
   * Run comprehensive scan across all scanner types
   */
  private async runComprehensiveScan(target: ScanTarget, scanResult: ScanResult, scanId: string, isAborted?: () => boolean): Promise<void> {
    const allFindings: SecurityFinding[] = [];
    let totalChecks = 0;
  let _totalProcessingTime = 0;

    // Run all scanner types except comprehensive
    const scannerTypes = Object.keys(SCANNER_CONFIGS).filter(type => type !== 'comprehensive');
    
    if (!this.isTestMode) {
      console.log(`🔍 Running comprehensive scan across ${scannerTypes.length} scanner types...`);
    }
    
    for (const scannerType of scannerTypes) {
      const config = SCANNER_CONFIGS[scannerType];
      
      try {
        if (!this.isTestMode) {
          console.log(`  📊 Running ${scannerType} scan...`);
        }
        
        // Create sub-target for this scanner type
        const subTarget = { ...target, type: scannerType as any };
        
        // Load and run scanner
        const scanner = await ScannerResultProcessor.loadScanner(config);
        const findings = await scanner.scan(subTarget);
        
        // Process findings
        const processedFindings = ScannerResultProcessor.processFindings(findings);
        allFindings.push(...processedFindings);
        
        totalChecks += config.totalChecks;
  _totalProcessingTime += config.processingTime;
        
        // Simulate processing time for this scanner
  await this.simulateScan(Math.floor(config.processingTime * 0.3), scanId, isAborted);
        
      } catch (error) {
        if (!this.isTestMode) {
          console.warn(`  ⚠️ Warning: ${scannerType} scan failed:`, error);
        }
        // Continue with other scanners even if one fails
      }
    }

    // Aggregate results
    scanResult.findings = allFindings;
    
    // Calculate comprehensive metrics
    const failedChecks = allFindings.filter(f => 
      f.severity === 'critical' || f.severity === 'high'
    ).length;
    
    const warnings = allFindings.filter(f => 
      f.severity === 'medium' || f.severity === 'low'
    ).length;
    
    scanResult.metrics = {
      total_checks: allFindings.length,
      failed_checks: failedChecks,
      warnings: warnings,
      passed_checks: Math.max(0, totalChecks - allFindings.length),
      resources_scanned: scannerTypes.length,
      scan_coverage: Math.round((scannerTypes.length / Object.keys(SCANNER_CONFIGS).length) * 100)
    };
    
    if (!this.isTestMode) {
      console.log(`✅ Comprehensive scan completed: ${allFindings.length} findings across ${scannerTypes.length} scanners`);
    }
  }

  /**
   * Cancel an active scan
   */
  async cancelScan(scanId: string): Promise<boolean> {
    const scan = this.activeScans.get(scanId);
    if (scan) {
      scan.status = 'cancelled';
      this.activeScans.delete(scanId);
      this.scanHistory.push(scan);
      return true;
    }
    return false;
  }

  /**
   * Generate unique scan ID
   */
  private generateScanId(): string {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    if (!this.isTestMode) {
      console.log('🛑 Shutting down Zero-Trust Scanner...');
    }
    
    // Cancel all active scans
    for (const scanId of this.activeScans.keys()) {
      await this.cancelScan(scanId);
    }
    
    if (!this.isTestMode) {
      console.log('✅ Zero-Trust Scanner shutdown complete');
    }
  }
}
