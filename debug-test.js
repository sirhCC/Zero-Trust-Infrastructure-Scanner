const { ZeroTrustScanner } = require('./dist/core/scanner.js');

async function debugTest() {
  console.log('Creating scanner...');
  const scanner = new ZeroTrustScanner();
  
  console.log('Initializing scanner...');
  await scanner.initialize();
  
  const target = {
    type: 'network',
    target: '10.0.0.0/16',
    options: {}
  };
  
  console.log('Starting scan...');
  const scanPromise = scanner.scan(target);
  
  console.log('Waiting 100ms...');
  await new Promise(resolve => setTimeout(resolve, 100));
  
  console.log('Checking active scans...');
  const activeScans = scanner.getActiveScans();
  console.log('Active scans count:', activeScans.length);
  
  console.log('Waiting for scan to complete...');
  try {
    const result = await scanPromise;
    console.log('Scan result:', result.status, 'findings:', result.findings.length);
  } catch (error) {
    console.log('Scan error:', error.message);
  }
  
  console.log('Final active scans:', scanner.getActiveScans().length);
  console.log('Scan history:', scanner.getScanHistory().length);
  if (scanner.getScanHistory().length > 0) {
    console.log('First history item status:', scanner.getScanHistory()[0].status);
  }
}

debugTest().catch(console.error);
