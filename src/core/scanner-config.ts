/**
 * Scanner Configuration
 * Centralized configuration for all scanner types
 */

export interface ScannerConfig {
  moduleImport: string;
  className: string;
  totalChecks: number;
  processingTime: number;
  requiresInitialization?: boolean;
}

export const SCANNER_CONFIGS: Record<string, ScannerConfig> = {
  network: {
    moduleImport: '../scanners/network-scanner',
    className: 'NetworkScanner',
    totalChecks: 20,
    processingTime: 1500,
    requiresInitialization: false
  },
  identity: {
    moduleImport: '../scanners/identity-scanner',
    className: 'IdentityScanner',
    totalChecks: 25,
    processingTime: 1200,
    requiresInitialization: false
  },
  'supply-chain': {
    moduleImport: '../scanners/supply-chain-scanner',
    className: 'SupplyChainScanner',
    totalChecks: 30,
    processingTime: 1000,
    requiresInitialization: false
  },
  compliance: {
    moduleImport: '../scanners/compliance-scanner',
    className: 'ComplianceScanner',
    totalChecks: 25,
    processingTime: 2000,
    requiresInitialization: true
  },
  comprehensive: {
    moduleImport: '',
    className: '',
    totalChecks: 100,
    processingTime: 3000,
    requiresInitialization: false
  }
};

export const DEFAULT_SCAN_CONFIG = {
  scanCoverage: 100,
  resourcesScanned: 1
};
