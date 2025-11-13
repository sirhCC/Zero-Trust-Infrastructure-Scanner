import { Command } from 'commander';
import chalk from 'chalk';
import * as YAML from 'yaml';
import * as fs from 'fs';
import * as path from 'path';
import { shouldFailBySeverity, RegisterCommands } from './shared';

export const registerComplianceCommands: RegisterCommands = (program: Command) => {
  program
    .command('compliance')
    .description('Automated compliance checking (SOC2, PCI, HIPAA)')
    .option('-s, --standard <standard>', 'Compliance standard (soc2|pci|hipaa|all)', 'all')
    .option('-e, --environment <env>', 'Target environment (dev|staging|prod)')
    .option('--exclude-controls <controls>', 'Comma-separated list of controls to exclude')
    .option('--report-format <format>', 'Report format (pdf|html|json)', 'html')
    .option('--out-file <file>', 'Write command output to file (respects --output)')
    .option(
      '--fail-on <severity>',
      'Exit non-zero if findings at/above severity exist (low|medium|high|critical)'
    )
    .action(async (options, cmd) => {
      try {
        const { ConfigManager } = await import('../config/config-manager');
        const cfgMgr = ConfigManager.getInstance();
        const rootOpts = (cmd as any)?.optsWithGlobals?.() || program.opts();
        if (rootOpts.output === 'table') {
          console.log(chalk.blue('🔍 Compliance Automation'));
          console.log(chalk.gray('Standards:'), options.standard);
        }
        await cfgMgr.initialize(rootOpts.config || './ztis.config.json');
        const cfg = cfgMgr.getConfig();

        const { ZeroTrustScanner } = await import('../core/scanner');
        const scanner = new ZeroTrustScanner();
        await scanner.initialize();

        const target = {
          type: 'compliance' as const,
          target: options.environment || 'current-environment',
          options: {
            ...(options.standard && options.standard !== 'all'
              ? { frameworks: [{ name: String(options.standard).toUpperCase() }] }
              : {}),
            // scope parsing could be added here when exclude-controls is supported as explicit list
            evidence_collection: true,
            auto_remediation: false,
            report_format: (options.reportFormat as 'json' | 'html' | 'pdf' | 'csv') || 'json',
            include_recommendations: true,
            severity_threshold: 'medium' as const,
            custom_rules: [],
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

        if (rootOpts.output && rootOpts.output !== 'table') {
          const payload =
            rootOpts.output === 'yaml' ? YAML.stringify(result) : JSON.stringify(result, null, 2);
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
          console.log('\n' + chalk.bold('Compliance Findings:'));
          const findingsBySeverity = {
            critical: result.findings.filter((f) => f.severity === 'critical'),
            high: result.findings.filter((f) => f.severity === 'high'),
            medium: result.findings.filter((f) => f.severity === 'medium'),
            low: result.findings.filter((f) => f.severity === 'low'),
            info: result.findings.filter((f) => f.severity === 'info'),
          };
          Object.entries(findingsBySeverity).forEach(([severity, findings]) => {
            if (findings.length > 0) {
              const severityColor = {
                critical: chalk.red,
                high: chalk.redBright,
                medium: chalk.yellow,
                low: chalk.blue,
                info: chalk.gray,
              }[severity as keyof typeof findingsBySeverity];
              console.log(`\n${severityColor(`${severity.toUpperCase()} (${findings.length})`)}`);
              findings.forEach((finding, index) => {
                console.log(`${index + 1}. ${finding.title}`);
                console.log(`   ${finding.description}`);
                if (finding.recommendation) {
                  console.log(`   💡 ${chalk.cyan('Recommendation:')} ${finding.recommendation}`);
                }
                if (finding.compliance_impact && finding.compliance_impact.length > 0) {
                  finding.compliance_impact.forEach((impact) => {
                    console.log(
                      `   📋 ${chalk.magenta(impact.standard)} Control: ${impact.control} (${impact.impact} impact)`
                    );
                  });
                }
                console.log('');
              });
            }
          });
          const criticalCount = findingsBySeverity.critical.length;
          const highCount = findingsBySeverity.high.length;
          const totalIssues = criticalCount + highCount + findingsBySeverity.medium.length;
          console.log(chalk.bold('\n📊 Compliance Summary:'));
          console.log(`   ${chalk.red('Critical:')} ${criticalCount}`);
          console.log(`   ${chalk.redBright('High:')} ${highCount}`);
          console.log(`   ${chalk.yellow('Medium:')} ${findingsBySeverity.medium.length}`);
          console.log(`   ${chalk.blue('Low:')} ${findingsBySeverity.low.length}`);
          const totalChecks = result.metrics.total_checks || 25;
          const failedChecks = totalIssues;
          const complianceScore = Math.max(
            0,
            Math.round(((totalChecks - failedChecks) / totalChecks) * 100)
          );
          console.log(`\n📈 ${chalk.bold('Compliance Score:')} ${complianceScore}%`);
          if (criticalCount > 0) {
            console.log(
              chalk.red('\n🚨 CRITICAL compliance issues found - immediate remediation required!')
            );
          } else if (highCount > 0) {
            console.log(
              chalk.yellow('\n⚠️  HIGH severity compliance issues found - prioritize remediation')
            );
          } else {
            console.log(chalk.green('\n✅ No critical compliance issues found'));
          }
        } else if (rootOpts.output === 'table') {
          console.log(chalk.green('\n✅ No compliance issues found! 🎉'));
        }

        if (shouldFailBySeverity(result.findings as any, options.failOn)) {
          console.error(chalk.red('Failing due to severity threshold.'));
          process.exit(1);
        }

        // Explicit success exit
        process.exit(0);
      } catch (error) {
        console.error(
          chalk.red('❌ Compliance scan failed:'),
          error instanceof Error ? error.message : error
        );
        process.exit(1);
      }
    });
};

export default registerComplianceCommands;
