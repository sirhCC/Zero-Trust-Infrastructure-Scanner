/**
 * Core Scanner Tests
 */

import { ZeroTrustScanner, ScanTarget } from '../../src/core/scanner';

describe('ZeroTrustScanner', () => {
  let scanner: ZeroTrustScanner;

  beforeEach(() => {
    scanner = new ZeroTrustScanner();
  });

  describe('initialization', () => {
    it('should create scanner instance', () => {
      expect(scanner).toBeInstanceOf(ZeroTrustScanner);
    });

    it('should initialize successfully', async () => {
      await expect(scanner.initialize()).resolves.not.toThrow();
    });
  });

  describe('scan operations', () => {
    beforeEach(async () => {
      await scanner.initialize();
    });

    it('should generate unique scan IDs', () => {
      // Call the private method through type assertion for testing
      const id1 = (scanner as any).generateScanId();
      const id2 = (scanner as any).generateScanId();
      
      expect(id1).not.toEqual(id2);
      expect(id1).toMatch(/^scan_\d+_[a-z0-9]+$/);
    });

    it('should track active scans', async () => {
      const target: ScanTarget = {
        type: 'network',
        target: '10.0.0.0/16',
        options: {}
      };

      const scanPromise = scanner.scan(target);
      
      // Wait a moment for scan to start
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Check active scans while scan is running
      const activeScans = scanner.getActiveScans();
      expect(activeScans.length).toBeGreaterThan(0);
      
      // Wait for scan to complete
      await scanPromise;
      
      // Check that scan is no longer active
      const activeScansFinal = scanner.getActiveScans();
      expect(activeScansFinal.length).toBe(0);
    });

    it('should store scan history', async () => {
      const target: ScanTarget = {
        type: 'network',
        target: '10.0.0.0/16',
        options: {}
      };

      await scanner.scan(target);
      
      const history = scanner.getScanHistory();
      expect(history.length).toBe(1);
      expect(history[0].target).toEqual(target);
      expect(history[0].status).toBe('completed');
    });

    it('should retrieve scan by ID', async () => {
      const target: ScanTarget = {
        type: 'identity',
        target: 'aws-iam',
        options: {}
      };

      const result = await scanner.scan(target);
      const retrievedScan = scanner.getScan(result.id);
      
      expect(retrievedScan).toBeDefined();
      expect(retrievedScan?.id).toBe(result.id);
    });
  });

  describe('scan cancellation', () => {
    beforeEach(async () => {
      await scanner.initialize();
    });

    it('should cancel active scan', async () => {
      const target: ScanTarget = {
        type: 'supply-chain',
        target: 'package.json',
        options: {}
      };

      // Start a scan but don't wait for it
      const scanPromise = scanner.scan(target);
      
      // Wait a moment for scan to start
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Get the scan ID from active scans
      const activeScans = scanner.getActiveScans();
      expect(activeScans.length).toBe(1);
      
      const scanId = activeScans[0].id;
      
      // Cancel the scan
      const cancelled = await scanner.cancelScan(scanId);
      expect(cancelled).toBe(true);
      
      // Verify scan is no longer active
      const finalActiveScans = scanner.getActiveScans();
      expect(finalActiveScans.length).toBe(0);
      
      // Wait for original scan promise to resolve
      await scanPromise;
      
      // Check that cancelled scan is in history
      const history = scanner.getScanHistory();
      const cancelledScan = history.find(s => s.id === scanId);
      expect(cancelledScan?.status).toBe('cancelled');
    });

    it('should return false when cancelling non-existent scan', async () => {
      const cancelled = await scanner.cancelScan('non-existent-scan-id');
      expect(cancelled).toBe(false);
    });
  });

  describe('graceful shutdown', () => {
    beforeEach(async () => {
      await scanner.initialize();
    });

    it('should shutdown gracefully', async () => {
      await expect(scanner.shutdown()).resolves.not.toThrow();
    });

    it('should cancel all active scans during shutdown', async () => {
      const target: ScanTarget = {
        type: 'compliance',
        target: 'soc2',
        options: {}
      };

      // Start multiple scans
      scanner.scan(target);
      scanner.scan({ ...target, target: 'pci' });
      
      // Wait a moment for scans to start
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(scanner.getActiveScans().length).toBe(2);
      
      // Shutdown should cancel all active scans
      await scanner.shutdown();
      
      expect(scanner.getActiveScans().length).toBe(0);
    });
  });
});
