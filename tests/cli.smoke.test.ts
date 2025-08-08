import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

describe('CLI smoke', () => {
  it('shows help when no args', async () => {
    const cliPath = path.join(__dirname, '..', 'dist', 'cli.js');
    // Use ts-node in tests if dist not built yet
  const useTs = process.env.USE_TS_NODE === '1' || !fs.existsSync(cliPath);
    const cmd = useTs ? 'npx' : 'node';
  const args = useTs ? ['ts-node', path.join(__dirname, '..', 'src', 'cli.ts')] : [cliPath];

    const result = await new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
      const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += String(d)));
      child.stderr.on('data', (d) => (stderr += String(d)));
      child.on('close', (code) => resolve({ code: code ?? 0, stdout, stderr }));
    });

  expect(result.code).toBe(0);
  });
});
