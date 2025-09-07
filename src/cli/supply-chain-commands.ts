import { Command } from 'commander';
import chalk from 'chalk';
import * as YAML from 'yaml';
import * as fs from 'fs';
import * as path from 'path';
import { shouldFailBySeverity, RegisterCommands } from './shared';

export const registerSupplyChainCommands: RegisterCommands = (program: Command) => {
  program
    .command('supply-chain')
    .alias('sc')
    .description('Scan container images and dependencies for vulnerabilities')
    .option('-i, --image <image>', 'Container image to scan')
    .option('-f, --file <file>', 'Dockerfile or package file to analyze')
    .option('-r, --registry <registry>', 'Container registry to scan')
    .option('--severity <level>', 'Minimum vulnerability severity (low|medium|high|critical)', 'medium')
    .option('--include-dev-deps', 'Include development dependencies')
    .option('--out-file <file>', 'Write command output to file (respects --output)')
    .option('--fail-on <severity>', 'Exit non-zero if findings at/above severity exist (low|medium|high|critical)')
    .action(async (options, cmd) => {
      try {
        const { ConfigManager } = await import('../config/config-manager');
        const cfgMgr = ConfigManager.getInstance();
        const rootOpts = (cmd as any)?.optsWithGlobals?.() || program.opts();
        if (rootOpts.output === 'table') {
          console.log(chalk.blue('🔍 Supply Chain Security Analysis'));
          console.log(chalk.gray('Target:'), options.image || options.file || 'Current directory');
        }
        await cfgMgr.initialize(rootOpts.config || './ztis.config.json');
        const cfg = cfgMgr.getConfig();

        const { ZeroTrustScanner } = await import('../core/scanner');
        const quietMode = !!rootOpts.quiet || (rootOpts.output && rootOpts.output !== 'table');
        const scanner = new ZeroTrustScanner(false, quietMode);
        await scanner.initialize();

        const target = {
          type: 'supply-chain' as const,
          target: options.image || options.file || 'current-directory',
          options: {
            image: options.image,
            file: options.file,
            registry: options.registry,
            severity: options.severity || 'medium',
            include_dev_deps: options.includeDevDeps,
            check_licenses: true,
            generate_sbom: false,
            ignore_unfixed: false,
            scan_depth: 3
          }
        };

        const timeoutMsArg = rootOpts.timeout ? parseInt(rootOpts.timeout) : undefined;
        const scanOpts: { signal?: AbortSignal; timeoutMs?: number } = {};
        if (typeof timeoutMsArg === 'number' && !Number.isNaN(timeoutMsArg)) {
          scanOpts.timeoutMs = timeoutMsArg;
        } else if (cfg?.scanner?.scanTimeout) {
          scanOpts.timeoutMs = cfg.scanner.scanTimeout;
        }
        const result = await scanner.scan(target, scanOpts);

        if (rootOpts.output && rootOpts.output !== 'table') {
          const payload = rootOpts.output === 'yaml' ? YAML.stringify(result) : JSON.stringify(result, null, 2);
          if (options.outFile) {
            const dir = path.dirname(options.outFile);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(options.outFile, payload, 'utf8');
            console.error(chalk.gray(`Output written to ${options.outFile}`));
          } else {
            console.log(payload);
          }
        } else {
          console.log(chalk.green(`✅ Scan completed in ${result.duration}ms`));
          console.log(chalk.gray(`Scan ID: ${result.id}`));
          console.log(chalk.gray(`Findings: ${result.findings.length}`));
        }

        if (rootOpts.output === 'table' && result.findings.length > 0) {
          console.log('\n' + chalk.bold('Supply Chain Security Findings:'));
          const findingsBySeverity = {
            critical: result.findings.filter(f => f.severity === 'critical'),
            high: result.findings.filter(f => f.severity === 'high'),
            medium: result.findings.filter(f => f.severity === 'medium'),
            low: result.findings.filter(f => f.severity === 'low'),
            info: result.findings.filter(f => f.severity === 'info')
          };
          Object.entries(findingsBySeverity).forEach(([severity, findings]) => {
            if (findings.length > 0) {
              const severityColor = {
                critical: chalk.red,
                high: chalk.redBright,
                medium: chalk.yellow,
                low: chalk.blue,
                info: chalk.gray
              }[severity as keyof typeof findingsBySeverity];
              console.log(`\n${severityColor(`${severity.toUpperCase()} (${findings.length})`)}`);
              findings.forEach((finding, index) => {
                console.log(`${index + 1}. ${finding.title}`);
                console.log(`   ${finding.description}`);
                if (finding.recommendation) {
                  console.log(`   💡 ${chalk.cyan('Recommendation:')} ${finding.recommendation}`);
                }
                if (finding.category.includes('cve') || finding.description.includes('CVE-')) {
                  console.log(`   🔗 ${chalk.magenta('Security Advisory')} - Check CVE database for details`);
                }
                console.log('');
              });
            }
          });
          const criticalCount = findingsBySeverity.critical.length;
          const highCount = findingsBySeverity.high.length;
          const totalVulns = criticalCount + highCount + findingsBySeverity.medium.length;
          if (totalVulns > 0) {
            console.log(chalk.bold('\n📊 Vulnerability Summary:'));
            console.log(`   ${chalk.red('Critical:')} ${criticalCount}`);
            console.log(`   ${chalk.redBright('High:')} ${highCount}`);
            console.log(`   ${chalk.yellow('Medium:')} ${findingsBySeverity.medium.length}`);
            console.log(`   ${chalk.blue('Low:')} ${findingsBySeverity.low.length}`);
            if (criticalCount > 0) {
              console.log(chalk.red('\n⚠️  CRITICAL vulnerabilities found - immediate action required!'));
            }
          }
        } else if (rootOpts.output === 'table') {
          console.log(chalk.green('\n✅ No supply chain security issues found!'));
        }

        if (shouldFailBySeverity(result.findings as any, options.failOn)) {
          console.error(chalk.red('Failing due to severity threshold.'));
          process.exit(1);
        }

      } catch (error) {
        console.error(chalk.red('❌ Supply chain scan failed:'), error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });
};

export default registerSupplyChainCommands;
