import { Command } from 'commander';
import chalk from 'chalk';
import * as YAML from 'yaml';
import * as fs from 'fs';
import * as path from 'path';
import { shouldFailBySeverity, RegisterCommands } from './shared';

export const registerIdentityCommands: RegisterCommands = (program: Command) => {
  program
    .command('identity')
    .description('Detect over-privileged accounts and analyze permissions')
    .option('-p, --provider <provider>', 'Identity provider (aws-iam|azure-ad|k8s-rbac|local)')
    .option('-u, --user <user>', 'Specific user to analyze')
    .option('-r, --role <role>', 'Specific role to analyze')
    .option('--include-service-accounts', 'Include service accounts in analysis')
    .option('--privilege-threshold <level>', 'Privilege risk threshold (low|medium|high)', 'medium')
    .option('--out-file <file>', 'Write command output to file (respects --output)')
    .option('--fail-on <severity>', 'Exit non-zero if findings at/above severity exist (low|medium|high|critical)')
    .action(async (options, cmd) => {
      try {
        const { ConfigManager } = await import('../config/config-manager');
        const cfgMgr = ConfigManager.getInstance();
        const rootOpts = (cmd as any)?.optsWithGlobals?.() || program.opts();
        if (rootOpts.output === 'table') {
          console.log(chalk.blue('🔍 Identity Permission Mining'));
          console.log(chalk.gray('Provider:'), options.provider || 'Auto-detect');
        }
        await cfgMgr.initialize(rootOpts.config || './ztis.config.json');
        const cfg = cfgMgr.getConfig();

        const { ZeroTrustScanner } = await import('../core/scanner');
        const quietMode = !!rootOpts.quiet || (rootOpts.output && rootOpts.output !== 'table');
        const scanner = new ZeroTrustScanner(false, quietMode);
        await scanner.initialize();

        const target = {
          type: 'identity' as const,
          target: options.provider || 'auto-detect',
          options: {
            provider: options.provider,
            user: options.user,
            role: options.role,
            include_service_accounts: options.includeServiceAccounts,
            privilege_threshold: options.privilegeThreshold || 'medium',
            check_unused_accounts: true,
            analyze_policies: true,
            days_inactive_threshold: 90
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
          console.log('\n' + chalk.bold('Identity Security Findings:'));
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
                console.log('');
              });
            }
          });
        } else if (rootOpts.output === 'table') {
          console.log(chalk.green('\n✅ No identity security issues found!'));
        }

        if (shouldFailBySeverity(result.findings as any, options.failOn)) {
          console.error(chalk.red('Failing due to severity threshold.'));
          process.exit(1);
        }

      } catch (error) {
        console.error(chalk.red('❌ Identity scan failed:'), error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });
};

export default registerIdentityCommands;
