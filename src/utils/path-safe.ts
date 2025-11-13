import * as fs from 'fs';
import * as path from 'path';

/**
 * Resolve and validate an output file path against allowed roots.
 * - Relative paths resolve against baseDir (or CWD if not provided)
 * - Absolute paths must be inside one of the allowed roots (baseDir or CWD by default)
 * - Prevents directory traversal escapes and null byte injection
 */
export function sanitizeOutputPath(
  userPath: string,
  opts?: { baseDir?: string; allowRoots?: string[] }
): string {
  if (!userPath || typeof userPath !== 'string') {
    throw new Error('Invalid output path');
  }
  if (userPath.includes('\0')) {
    throw new Error('Invalid output path');
  }

  const cwd = path.resolve(process.cwd());
  const roots = new Set<string>([cwd]); // Always allow CWD
  if (opts?.baseDir) roots.add(path.resolve(opts.baseDir));
  if (opts?.allowRoots) opts.allowRoots.forEach((r) => roots.add(path.resolve(r)));

  const base = opts?.baseDir ? path.resolve(opts.baseDir) : cwd;
  const candidate = path.isAbsolute(userPath)
    ? path.resolve(userPath)
    : path.resolve(base, userPath);

  let allowed = false;
  for (const root of roots) {
    const rel = path.relative(root, candidate);
    if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) {
      allowed = true;
      break;
    }
  }

  if (!allowed) {
    throw new Error(`Refusing to write outside allowed directories`);
  }

  // Ensure directory exists
  const dir = path.dirname(candidate);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  return candidate;
}

export default sanitizeOutputPath;
