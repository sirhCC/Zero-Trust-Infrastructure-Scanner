/**
 * Test comprehensive scan functionality
 */

import { ZeroTrustScanner } from '../core/scanner';

async function testComprehensiveScan() {
  const scanner = new ZeroTrustScanner();
  await scanner.initialize();
  
  console.log('🧪 Testing comprehensive scan...');
  
  const result = await scanner.scan({
    type: 'comprehensive',
    target: 'test-infrastructure',
    options: {}
  });
  
  console.log('\n📊 Comprehensive Scan Results:');
  console.log('Status:', result.status);
  console.log('Duration:', result.duration + 'ms');
  console.log('Findings:', result.findings.length);
  console.log('Total Checks:', result.metrics.total_checks);
  console.log('Failed Checks:', result.metrics.failed_checks);
  console.log('Warnings:', result.metrics.warnings);
  console.log('Resources Scanned:', result.metrics.resources_scanned);
  console.log('Scan Coverage:', result.metrics.scan_coverage + '%');
  
  await scanner.shutdown();
}

testComprehensiveScan().catch(console.error);
