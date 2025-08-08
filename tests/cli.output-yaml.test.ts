import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import * as YAML from 'yaml';

describe('CLI YAML output', () => {
  const distCli = path.join(__dirname, '..', 'dist', 'cli.js');
  const outFile = path.join(__dirname, '..', 'examples', 'test-data', 'cli-output.yaml');

  beforeAll(() => {
    if (!fs.existsSync(path.dirname(outFile))) fs.mkdirSync(path.dirname(outFile), { recursive: true });
  });

  afterAll(() => {
    if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
  });

  it('writes valid YAML when --output yaml --out-file is used', () => {
    if (!fs.existsSync(distCli)) return; // skip if not built
    const res = spawnSync(process.execPath, [distCli, 'network', '--output', 'yaml', '--out-file', outFile, '--scan-depth', '1'], { encoding: 'utf8' });
    expect(res.status).toBe(0);
    expect(fs.existsSync(outFile)).toBe(true);
    const text = fs.readFileSync(outFile, 'utf8');
    const parsed = YAML.parse(text);
    expect(parsed).toBeTruthy();
    expect(parsed).toHaveProperty('findings');
  });
});
