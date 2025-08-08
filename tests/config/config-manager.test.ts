import * as fs from 'fs';
import * as path from 'path';
import { ConfigManager } from '../../src/config/config-manager';

describe('ConfigManager', () => {
  const tmpDir = path.join(__dirname, '..', '..', 'test-data');
  const tmpJson = path.join(tmpDir, 'tmp.config.json');

  afterEach(() => {
    delete process.env.ZTIS_SERVER_PORT;
    delete process.env.ZTIS_SCANNER_TIMEOUT;
  delete process.env.ZTIS_LOGGING_LEVEL;
  delete process.env.ZTIS_SCANNER_RETRIES;
  delete process.env.ZTIS_SCANNER_PARALLEL;
    if (fs.existsSync(tmpJson)) fs.unlinkSync(tmpJson);
  });

  it('loads defaults when file missing', async () => {
    const mgr = ConfigManager.getInstance();
    await mgr.initialize('non-existent.config.json');
    const cfg = mgr.getConfig();
    expect(cfg.scanner.parallelScans).toBeGreaterThan(0);
    expect(cfg.server.port).toBeGreaterThan(0);
  });

  it('applies environment overrides', async () => {
    fs.writeFileSync(tmpJson, JSON.stringify({ server: { port: 3000 }, scanner: { scanTimeout: 50000 } }, null, 2));
    process.env.ZTIS_SERVER_PORT = '4500';
    process.env.ZTIS_SCANNER_TIMEOUT = '60000';
    const mgr = ConfigManager.getInstance();
    await mgr.initialize(tmpJson);
    const cfg = mgr.getConfig();
    expect(cfg.server.port).toBe(4500);
  expect(cfg.scanner.scanTimeout).toBe(60000);
  });

  it('fails validation for invalid config (schema)', async () => {
    // server.port invalid type
    fs.writeFileSync(tmpJson, JSON.stringify({ server: { port: -1 } }, null, 2));
    const mgr = ConfigManager.getInstance();
    await expect(mgr.initialize(tmpJson)).rejects.toThrowErrorMatchingSnapshot();
  });

  it('fails validation for invalid logging level (snapshot)', async () => {
    fs.writeFileSync(tmpJson, JSON.stringify({ logging: { level: 'verbose' } }, null, 2));
    const mgr = ConfigManager.getInstance();
    await expect(mgr.initialize(tmpJson)).rejects.toThrowErrorMatchingSnapshot();
  });

  it('applies logging level and scanner retries/parallel via env overrides', async () => {
    fs.writeFileSync(tmpJson, JSON.stringify({}, null, 2));
    process.env.ZTIS_LOGGING_LEVEL = 'debug';
    process.env.ZTIS_SCANNER_RETRIES = '4';
    process.env.ZTIS_SCANNER_PARALLEL = '5';
    const mgr = ConfigManager.getInstance();
    await mgr.initialize(tmpJson);
    const cfg = mgr.getConfig();
    expect(cfg.logging.level).toBe('debug');
    expect(cfg.scanner.retryAttempts).toBe(4);
    expect(cfg.scanner.parallelScans).toBe(5);
  });
});
