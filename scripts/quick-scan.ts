import { ZeroTrustScanner } from '../src/core/scanner';

(async () => {
  const s = new ZeroTrustScanner(true, true);
  await s.initialize();
  const r = await s.scan({ type: 'network', target: '10.0.0.0/16', options: {} });
  console.log('scan status:', r.status, 'duration:', r.duration);
  process.exit(0);
})();
