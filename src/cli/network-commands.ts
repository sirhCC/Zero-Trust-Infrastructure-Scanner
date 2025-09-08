import { Command } from 'commander';
import chalk from 'chalk';
import * as YAML from 'yaml';
import * as fs from 'fs';
import * as path from 'path';
import { shouldFailBySeverity, RegisterCommands } from './shared';
import { sanitizeOutputPath } from '../utils/path-safe';

export const registerNetworkCommands: RegisterCommands = (program: Command) => {
  program
    .command('network')
    .description('Analyze network micro-segmentation and security policies')
    .option('-t, --target <target>', 'Target network or CIDR (e.g., 10.0.0.0/16)')
    .option('-p, --policy-file <file>', 'Network policy file to analyze')
    .option('--k8s-namespace <namespace>', 'Kubernetes namespace to scan')
    .option('--cloud-provider <provider>', 'Cloud provider (aws|azure|gcp)')
    .option('--scan-depth <level>', 'Scan depth level (1-5)', '3')
    .option('--out-file <file>', 'Write command output to file (respects --output)')
    .option(
      '--fail-on <severity>',
      'Exit non-zero if findings at/above severity exist (low|medium|high|critical)'
    )
    .option(
      '--export-report <file>',
      'Export compliance report to file (json or csv based on extension)'
    )
    .option('--save-baseline <file>', 'Save current scan as baseline to file')
    .option('--baseline <file>', 'Compare against baseline file and print drift')
    .option(
      '--fail-on-drift <severity>',
      'Fail (exit 1) if drift >= 1 at or above severity (low|medium|high|critical)'
    )
    .action(async (options, cmd) => {
      try {
        const { ConfigManager } = await import('../config/config-manager');
        const cfgMgr = ConfigManager.getInstance();
        const rootOpts = (cmd as any)?.optsWithGlobals?.() || program.opts();
        if (rootOpts.output === 'table') {
          console.log(chalk.blue('🔍 Network Micro-Segmentation Analysis'));
          console.log(chalk.gray('Target:'), options.target || 'Auto-detect');
        }
        await cfgMgr.initialize(rootOpts.config || './ztis.config.json');
        const cfg = cfgMgr.getConfig();

        const { ZeroTrustScanner } = await import('../core/scanner');
        const quietMode = !!rootOpts.quiet || (rootOpts.output && rootOpts.output !== 'table');
        const scanner = new ZeroTrustScanner(false, quietMode);
        await scanner.initialize();

        const target = {
          type: 'network' as const,
          target: options.target || 'auto-detect',
          options: {
            cloud_provider: options.cloudProvider,
            scan_depth: parseInt(options.scanDepth) || 3,
            k8s_namespace: options.k8sNamespace,
            policy_file: options.policyFile,
          },
        };

        const timeoutMsArg = rootOpts.timeout ? parseInt(rootOpts.timeout) : undefined;
        const scanOpts: { signal?: AbortSignal; timeoutMs?: number } = {};
        if (typeof timeoutMsArg === 'number' && !Number.isNaN(timeoutMsArg)) {
          scanOpts.timeoutMs = timeoutMsArg;
        } else if (cfg?.scanner?.scanTimeout) {
          scanOpts.timeoutMs = cfg.scanner.scanTimeout;
        }
        const result = await scanner.scan(target, scanOpts);

        if (options.exportReport) {
          const out = options.exportReport as string;
          const fmt = out.toLowerCase().endsWith('.csv') ? 'csv' : 'json';
          scanner.exportReport(result, out, fmt);
          console.log(chalk.gray(`Report saved to ${out}`));
        }

        if (options.saveBaseline) {
          scanner.saveBaseline(options.saveBaseline, result);
          console.log(chalk.gray(`Baseline saved to ${options.saveBaseline}`));
        }
        if (options.baseline) {
          const baseline = scanner.loadBaseline(options.baseline);
          if (baseline) {
            const drift = scanner.computeDrift(result, baseline);
            console.log(chalk.bold('\nDrift vs baseline:'));
            console.log(`  critical: ${drift.critical}`);
            console.log(`  high:     ${drift.high}`);
            console.log(`  medium:   ${drift.medium}`);
            console.log(`  low:      ${drift.low}`);
            console.log(`  total:    ${drift.total}`);
            const sevOrder = ['low', 'medium', 'high', 'critical'];
            if (options.failOnDrift) {
              const idx = sevOrder.indexOf(String(options.failOnDrift));
              const threshold = sevOrder.slice(idx);
              const shouldFail = threshold.some((s) => (drift as any)[s] >= 1);
              if (shouldFail) {
                console.error(chalk.red('Drift threshold met; failing.'));
                process.exit(1);
              }
            }
          } else {
            console.log(chalk.yellow('Baseline file not found; skipping drift comparison.'));
          }
        }

        if (rootOpts.output && rootOpts.output !== 'table') {
          const payload =
            rootOpts.output === 'yaml' ? YAML.stringify(result) : JSON.stringify(result, null, 2);
          if (options.outFile) {
            const outPath = sanitizeOutputPath(options.outFile);
            const dir = path.dirname(outPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(outPath, payload, 'utf8');
            if (rootOpts.output !== 'table') {
              console.error(chalk.gray(`Output written to ${outPath}`));
            }
          } else {
            console.log(payload);
          }
        } else {
          console.log(chalk.green(`✅ Scan completed in ${result.duration}ms`));
          console.log(chalk.gray(`Scan ID: ${result.id}`));
          console.log(chalk.gray(`Findings: ${result.findings.length}`));
        }

        if (rootOpts.output === 'table' && result.findings.length > 0) {
          console.log('\n' + chalk.bold('Security Findings:'));
          result.findings.forEach((finding, index) => {
            const severityColor = {
              critical: chalk.red,
              high: chalk.redBright,
              medium: chalk.yellow,
              low: chalk.blue,
              info: chalk.gray,
            }[finding.severity];
            console.log(
              `${index + 1}. ${severityColor(finding.severity.toUpperCase())} - ${finding.title}`
            );
            console.log(`   ${finding.description}`);
            if (finding.recommendation) {
              console.log(`   💡 ${chalk.cyan('Recommendation:')} ${finding.recommendation}`);
            }
            console.log('');
          });
        } else if (rootOpts.output === 'table') {
          console.log(chalk.green('\n✅ No security issues found!'));
        }

        if (shouldFailBySeverity(result.findings as any, options.failOn)) {
          console.error(chalk.red('Failing due to severity threshold.'));
          process.exit(1);
        }
      } catch (error) {
        console.error(
          chalk.red('❌ Network scan failed:'),
          error instanceof Error ? error.message : error
        );
        process.exit(1);
      }
    });
};

export default registerNetworkCommands;
