/**
 * Test normal mode logging
 */

import { ZeroTrustScanner } from '../core/scanner';

async function testNormalMode() {
  console.log('🧪 Testing normal mode logging...\n');
  
  const scanner = new ZeroTrustScanner(); // Normal mode (not test mode)
  await scanner.initialize();
  
  const result = await scanner.scan({
    type: 'network',
    target: 'test-target',
    options: {}
  });
  
  console.log('\n📊 Final result status:', result.status);
  console.log('Duration:', result.duration + 'ms');
  
  await scanner.shutdown();
}

testNormalMode().catch(console.error);
