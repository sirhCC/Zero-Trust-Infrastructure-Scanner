import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';

describe('CLI output and fail-on behavior (supply-chain)', () => {
  const distCli = path.join(__dirname, '..', 'dist', 'cli.js');
  const outFile = path.join(__dirname, '..', 'examples', 'test-data', 'cli-supply-output.json');

  beforeAll(() => {
    if (!fs.existsSync(path.dirname(outFile))) fs.mkdirSync(path.dirname(outFile), { recursive: true });
  });

  afterAll(() => {
    if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
  });

  it('emits JSON to a file when --output json --out-file is used', () => {
    if (!fs.existsSync(distCli)) return; // skip if not built
    const res = spawnSync(process.execPath, [distCli, 'supply-chain', '--output', 'json', '--out-file', outFile], { encoding: 'utf8' });
    expect(res.status).toBe(0);
    expect(fs.existsSync(outFile)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    expect(parsed).toHaveProperty('findings');
  });

  it('fails with exit code 1 when --fail-on low (since there are always some findings)', () => {
    if (!fs.existsSync(distCli)) return; // skip if not built
    const res = spawnSync(process.execPath, [distCli, 'supply-chain', '--fail-on', 'low'], { encoding: 'utf8' });
    expect(res.status).toBe(1);
  });
});
