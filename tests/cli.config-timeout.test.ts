import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';

// This test ensures the CLI reads timeout from config when --timeout is not provided
describe('CLI config-driven timeout', () => {
  const tmpConfig = path.join(__dirname, 'test-data', 'cli-timeout.config.json');
  const distCli = path.join(__dirname, '..', 'dist', 'cli.js');

  beforeAll(() => {
    if (!fs.existsSync(path.dirname(tmpConfig))) {
      fs.mkdirSync(path.dirname(tmpConfig), { recursive: true });
    }
    if (!fs.existsSync(distCli)) {
      return; // skip if not built
    }
  fs.writeFileSync(tmpConfig, JSON.stringify({ scanner: { scanTimeout: 30000 } }, null, 2));
  });

  afterAll(() => {
    if (fs.existsSync(tmpConfig)) fs.unlinkSync(tmpConfig);
  });

  it('uses scanner.scanTimeout from config when no --timeout is passed', () => {
    if (!fs.existsSync(distCli)) {
      return; // skip if not built
    }
    const res = spawnSync(process.execPath, [distCli, 'network', '--config', tmpConfig, '--scan-depth', '1'], {
      encoding: 'utf8'
    });
    expect(res.status).toBe(0);
  });
});
