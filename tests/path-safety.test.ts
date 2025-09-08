import * as fs from 'fs';
import * as path from 'path';
import { sanitizeOutputPath } from '../src/utils/path-safe';

describe('Path safety utility', () => {
  const base = path.join(__dirname, 'tmp-paths');
  const allowed = path.join(base, 'out', 'file.json');
  const traversal = path.join('..', '..', 'etc', 'passwd');

  beforeAll(() => {
    if (!fs.existsSync(base)) fs.mkdirSync(base, { recursive: true });
  });

  afterAll(() => {
    try {
      fs.rmSync(base, { recursive: true, force: true });
    } catch (_e) {
      // ignore cleanup errors
      return;
    }
  });

  it('resolves a relative path under baseDir', () => {
    const p = sanitizeOutputPath('out/file.json', { baseDir: base });
    expect(p.startsWith(path.join(base, 'out'))).toBe(true);
  });

  it('blocks traversal escaping baseDir', () => {
    expect(() => sanitizeOutputPath(traversal, { baseDir: base })).toThrow();
  });

  it('allows absolute path under baseDir', () => {
    const p = sanitizeOutputPath(allowed, { baseDir: base });
    expect(p).toBe(allowed);
  });
});
