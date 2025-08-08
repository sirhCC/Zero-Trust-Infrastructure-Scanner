import * as fs from 'fs';
import * as path from 'path';
import { ZeroTrustScanner, ScanResult } from '../../src/core/scanner';

describe('Baseline and drift', () => {
  const tmpDir = path.join(__dirname, '..', '..', 'dist', 'tmp-tests');
  const baselinePath = path.join(tmpDir, 'baseline.json');

  beforeAll(() => {
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
  });

  afterAll(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* noop */ }
  });

  it('saves, loads baseline and computes drift', () => {
    const scanner = new ZeroTrustScanner(true);
    const baseline: ScanResult = {
      id: 'b1', timestamp: new Date(), status: 'completed', duration: 1,
      target: { type: 'network', target: 't', options: {} },
      findings: [ { id: 'f1', severity: 'high', category: 'network', title: 'x', description: '', evidence: {}, recommendation: '' } ],
      metrics: { total_checks: 1, failed_checks: 1, passed_checks: 0, warnings: 0, resources_scanned: 1, scan_coverage: 100 }
    };
    scanner.saveBaseline(baselinePath, baseline);
    const loaded = scanner.loadBaseline(baselinePath)!;
    expect(loaded.id).toBe('b1');

    const current: ScanResult = { ...baseline, id: 'c1', findings: [...baseline.findings, { id:'f2', severity:'critical', category:'network', title:'y', description:'', evidence:{}, recommendation:'' }] };
    const drift = scanner.computeDrift(current, loaded);
    expect(drift.critical).toBe(1);
    expect(drift.total).toBe(1);
  });
});
