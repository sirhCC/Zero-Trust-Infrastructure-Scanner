#!/usr/bin/env node

/**
 * Zero-Trust Infrastructure Scanner
 * Enterprise-grade security scanning platform
 * 
 * Core Features:
 * - Network Micro-Segmentation Analysis
 * - Identity Permission Mining
 * - Supply Chain Security Scanning
 * - Compliance Automation (SOC2, PCI, HIPAA)
 */

import { ZeroTrustScanner } from './core/scanner';
import { Logger } from './utils/logger';
import { ConfigManager } from './config/config-manager';
import { HealthChecker } from './monitoring/health-checker';

const logger = Logger.getInstance();

/**
 * Initialize and start the Zero-Trust Infrastructure Scanner
 */
async function main(): Promise<void> {
  try {
    logger.info('🚀 Zero-Trust Infrastructure Scanner Starting...');
    
    // Load configuration
    const configManager = ConfigManager.getInstance();
    await configManager.initialize();
    
    // Initialize health monitoring
    const healthChecker = new HealthChecker();
    await healthChecker.start();
    
    // Initialize the scanner
    const scanner = new ZeroTrustScanner();
    await scanner.initialize();
    
    logger.info('✅ Zero-Trust Infrastructure Scanner Ready');
    logger.info('📊 Access dashboard at: http://localhost:3000');
    logger.info('🔍 Use CLI commands to start scanning');
    
    // Start the scanner service
    await scanner.start();
    
  } catch (error) {
    logger.error('❌ Failed to start Zero-Trust Infrastructure Scanner:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  logger.info('🛑 Graceful shutdown initiated...');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('🛑 Graceful shutdown initiated...');
  process.exit(0);
});

// Start the application
if (require.main === module) {
  main().catch((error) => {
    console.error('💥 Unhandled error:', error);
    process.exit(1);
  });
}

export { main };
