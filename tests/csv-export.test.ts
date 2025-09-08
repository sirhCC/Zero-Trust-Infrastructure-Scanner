import { ZeroTrustScanner, ScanResult } from '../src/core/scanner';
import * as fs from 'fs';
import * as path from 'path';

describe('CSV export sanitizer', () => {
  const outDir = path.join(__dirname, 'dist', 'csv-tests');
  const outFile = path.join(outDir, 'report.csv');

  beforeAll(() => {
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  });

  afterAll(() => {
    try {
      fs.rmSync(outDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it('escapes leading = + - @ and tabs/control chars to prevent formula injection', () => {
    const z = new ZeroTrustScanner(true);
    const result: ScanResult = {
      id: 'x',
      timestamp: new Date(),
      status: 'completed',
      duration: 1,
      target: { type: 'network', target: 't', options: {} as any },
      findings: [
        {
          id: 'f1',
          severity: 'low',
          category: '=SUM(A1:A2)',
          title: '+HAX',
          description: '-MAL',
          evidence: {},
          recommendation: '@DO',
        },
        {
          id: 'f2',
          severity: 'medium',
          category: '\tTabbed',
          title: '\u0009TabCtrl',
          description: '\u001DGroupSep',
          evidence: {},
          recommendation: 'ok',
        },
        {
          id: 'f3',
          severity: 'low',
          category: ' \t=CMD()',
          title: ' space-prefix',
          description: 'safe',
          evidence: {},
          recommendation: 'safe',
        },
      ],
      metrics: {
        total_checks: 1,
        failed_checks: 1,
        passed_checks: 0,
        warnings: 0,
        resources_scanned: 1,
        scan_coverage: 100,
      },
    };
    z.exportReport(result, outFile, 'csv');
    const text = fs.readFileSync(outFile, 'utf8');
    // Expect prefixed single quotes for dangerous leading characters inside quoted CSV fields ("'...)
    // category and title are exported; description/recommendation are not part of CSV
    expect(text).toMatch(/"'=SUM/);
    expect(text).toMatch(/"'\+HAX/);
    // Whitespace-before-formula should also be prefixed (note: tabs are escaped by JSON.stringify as \t)
    expect(text).toMatch(/"' \\t=CMD/);
    // Tabs/control chars should be present (escaped as \t inside quoted JSON strings in CSV)
    expect(text).toContain('\\tTabbed');
  });
});
