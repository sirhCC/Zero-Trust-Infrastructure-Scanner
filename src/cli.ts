#!/usr/bin/env node

/**
 * Zero-Trust Infrastructure Scanner CLI
 * Command-line interface for security scanning operations
 */

import { Command } from 'commander';
import chalk from 'chalk';
import * as YAML from 'yaml';
import * as fs from 'fs';
import * as path from 'path';
// Importing version directly from package.json can be problematic when bundling; guard and fallback to env
let version: string = '0.0.0';
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const pkg = require('../package.json');
  version = pkg?.version || process.env.npm_package_version || version;
} catch {
  version = process.env.npm_package_version || version;
}
import { createBehavioralCommands } from './cli/behavioral-commands';
import { addRiskScoringCommands } from './cli/risk-commands';
import mlRiskCommands from './cli/ml-risk-commands';

const program = new Command();

// Configure CLI
program
  .name('zero-trust-scanner')
  .description('Enterprise Zero-Trust Infrastructure Scanner')
  // Use default Commander flags for version: -V, --version
  .version(version);

// Global options
program
  .option('-c, --config <file>', 'Configuration file path', './ztis.config.json')
  .option('-o, --output <format>', 'Output format (json|yaml|table)', 'table')
  .option('--log-file <file>', 'Write logs to a specific file (in addition to defaults)')
  .option('--quiet', 'Suppress non-essential output')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--timeout <ms>', 'Global scan timeout in milliseconds')
  .option('--no-color', 'Disable colored output');

// Ensure verbose flag affects logging before any command action runs
program.hook('preAction', (_thisCmd, actionCmd) => {
  // Prefer merged options so globals work before or after subcommand
  const rootOpts = (actionCmd as any)?.optsWithGlobals?.() || program.opts();
  if (rootOpts?.verbose) {
    process.env.ZTIS_LOGGING_LEVEL = 'debug';
  }
  if (rootOpts?.quiet) {
    process.env.ZTIS_QUIET = '1';
  }
  if (rootOpts?.logFile) {
    process.env.ZTIS_LOG_FILE = rootOpts.logFile;
  }
});

// Helpers
const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'] as const;
type Severity = typeof SEVERITY_ORDER[number];
function shouldFailBySeverity(findings: Array<{ severity: Severity }>, level?: string): boolean {
  if (!level) return false;
  const idx = SEVERITY_ORDER.indexOf(level as Severity);
  if (idx < 0) return false;
  const threshold = new Set(SEVERITY_ORDER.slice(idx));
  return findings.some((f) => threshold.has(f.severity));
}

/**
 * Network Micro-Segmentation Command
 */
program
  .command('network')
  .description('Analyze network micro-segmentation and security policies')
  .option('-t, --target <target>', 'Target network or CIDR (e.g., 10.0.0.0/16)')
  .option('-p, --policy-file <file>', 'Network policy file to analyze')
  .option('--k8s-namespace <namespace>', 'Kubernetes namespace to scan')
  .option('--cloud-provider <provider>', 'Cloud provider (aws|azure|gcp)')
  .option('--scan-depth <level>', 'Scan depth level (1-5)', '3')
  .option('--out-file <file>', 'Write command output to file (respects --output)')
  .option('--fail-on <severity>', 'Exit non-zero if findings at/above severity exist (low|medium|high|critical)')
  .option('--export-report <file>', 'Export compliance report to file (json or csv based on extension)')
  .option('--save-baseline <file>', 'Save current scan as baseline to file')
  .option('--baseline <file>', 'Compare against baseline file and print drift')
  .option('--fail-on-drift <severity>', 'Fail (exit 1) if drift >= 1 at or above severity (low|medium|high|critical)')
  .action(async (options, cmd) => {
    try {
  // Load configuration
  const { ConfigManager } = await import('./config/config-manager');
  const cfgMgr = ConfigManager.getInstance();
  const rootOpts = (cmd as any)?.optsWithGlobals?.() || program.opts();
  if (rootOpts.output === 'table') {
    console.log(chalk.blue('🔍 Network Micro-Segmentation Analysis'));
    console.log(chalk.gray('Target:'), options.target || 'Auto-detect');
  }
  await cfgMgr.initialize(rootOpts.config || './ztis.config.json');
  const cfg = cfgMgr.getConfig();

      // Import and initialize scanner
    const { ZeroTrustScanner } = await import('./core/scanner');
  const quietMode = !!rootOpts.quiet || (rootOpts.output && rootOpts.output !== 'table');
  const scanner = new ZeroTrustScanner(false, quietMode);
  await scanner.initialize();
      
      // Prepare scan target
      const target = {
        type: 'network' as const,
        target: options.target || 'auto-detect',
        options: {
          cloud_provider: options.cloudProvider,
          scan_depth: parseInt(options.scanDepth) || 3,
          k8s_namespace: options.k8sNamespace,
          policy_file: options.policyFile
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

      // Export report if requested
      if (options.exportReport) {
        const out = options.exportReport as string;
        const fmt = out.toLowerCase().endsWith('.csv') ? 'csv' : 'json';
        scanner.exportReport(result, out, fmt);
        console.log(chalk.gray(`Report saved to ${out}`));
      }

      // Baseline save/compare
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
          const sevOrder = ['low','medium','high','critical'];
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
      
      // Output formatting (json|yaml|table)
      if (rootOpts.output && rootOpts.output !== 'table') {
        const payload = rootOpts.output === 'yaml' ? YAML.stringify(result) : JSON.stringify(result, null, 2);
        if (options.outFile) {
          const dir = path.dirname(options.outFile);
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(options.outFile, payload, 'utf8');
          // Provide a tiny confirmation to aid CI/debugging
          if (rootOpts.output !== 'table') {
            console.error(chalk.gray(`Output written to ${options.outFile}`));
          }
        } else {
          console.log(payload);
        }
      } else {
        // Display human-readable summary
        console.log(chalk.green(`✅ Scan completed in ${result.duration}ms`));
        console.log(chalk.gray(`Scan ID: ${result.id}`));
        console.log(chalk.gray(`Findings: ${result.findings.length}`));
      }
      
  // Display findings summary (table mode only)
  if (rootOpts.output === 'table' && result.findings.length > 0) {
        console.log('\n' + chalk.bold('Security Findings:'));
        result.findings.forEach((finding, index) => {
          const severityColor = {
            critical: chalk.red,
            high: chalk.redBright,
            medium: chalk.yellow,
            low: chalk.blue,
            info: chalk.gray
          }[finding.severity];
          
          console.log(`${index + 1}. ${severityColor(finding.severity.toUpperCase())} - ${finding.title}`);
          console.log(`   ${finding.description}`);
          if (finding.recommendation) {
            console.log(`   💡 ${chalk.cyan('Recommendation:')} ${finding.recommendation}`);
          }
          console.log('');
        });
      } else if (rootOpts.output === 'table') {
        console.log(chalk.green('\n✅ No security issues found!'));
      }

      // Fail on severity threshold if requested
      if (shouldFailBySeverity(result.findings as any, options.failOn)) {
        console.error(chalk.red('Failing due to severity threshold.'));
        process.exit(1);
      }
      
    } catch (error) {
      console.error(chalk.red('❌ Network scan failed:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

/**
 * Identity Permission Mining Command
 */
program
  .command('identity')
  .description('Detect over-privileged accounts and analyze permissions')
  .option('-p, --provider <provider>', 'Identity provider (aws-iam|azure-ad|k8s-rbac|local)')
  .option('-u, --user <user>', 'Specific user to analyze')
  .option('-r, --role <role>', 'Specific role to analyze')
  .option('--include-service-accounts', 'Include service accounts in analysis')
  .option('--privilege-threshold <level>', 'Privilege risk threshold (low|medium|high)', 'medium')
  .action(async (options) => {
    console.log(chalk.blue('🔍 Identity Permission Mining'));
    console.log(chalk.gray('Provider:'), options.provider || 'Auto-detect');
    
    try {
  // Load configuration
  const { ConfigManager } = await import('./config/config-manager');
  const cfgMgr = ConfigManager.getInstance();
  const rootOpts = program.opts();
  await cfgMgr.initialize(rootOpts.config || './ztis.config.json');
  const cfg = cfgMgr.getConfig();

      // Import and initialize scanner
    const { ZeroTrustScanner } = await import('./core/scanner');
  const quietMode = !!rootOpts.quiet || (rootOpts.output && rootOpts.output !== 'table');
  const scanner = new ZeroTrustScanner(false, quietMode);
  await scanner.initialize();
      
      // Prepare scan target
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
      
      // Display results
      console.log(chalk.green(`✅ Scan completed in ${result.duration}ms`));
      console.log(chalk.gray(`Scan ID: ${result.id}`));
      console.log(chalk.gray(`Findings: ${result.findings.length}`));
      
      // Display findings summary
      if (result.findings.length > 0) {
        console.log('\n' + chalk.bold('Identity Security Findings:'));
        
        // Group findings by severity
        const findingsBySeverity = {
          critical: result.findings.filter(f => f.severity === 'critical'),
          high: result.findings.filter(f => f.severity === 'high'),
          medium: result.findings.filter(f => f.severity === 'medium'),
          low: result.findings.filter(f => f.severity === 'low'),
          info: result.findings.filter(f => f.severity === 'info')
        };
        
        // Display critical findings first
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
      } else {
        console.log(chalk.green('\n✅ No identity security issues found!'));
      }
      
    } catch (error) {
      console.error(chalk.red('❌ Identity scan failed:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

/**
 * Supply Chain Security Command
 */
program
  .command('supply-chain')
  .alias('sc')
  .description('Scan container images and dependencies for vulnerabilities')
  .option('-i, --image <image>', 'Container image to scan')
  .option('-f, --file <file>', 'Dockerfile or package file to analyze')
  .option('-r, --registry <registry>', 'Container registry to scan')
  .option('--severity <level>', 'Minimum vulnerability severity (low|medium|high|critical)', 'medium')
  .option('--include-dev-deps', 'Include development dependencies')
  .action(async (options) => {
    console.log(chalk.blue('🔍 Supply Chain Security Analysis'));
    console.log(chalk.gray('Target:'), options.image || options.file || 'Current directory');
    
    try {
  // Load configuration
  const { ConfigManager } = await import('./config/config-manager');
  const cfgMgr = ConfigManager.getInstance();
  const rootOpts = program.opts();
  await cfgMgr.initialize(rootOpts.config || './ztis.config.json');
  const cfg = cfgMgr.getConfig();

      // Import and initialize scanner
    const { ZeroTrustScanner } = await import('./core/scanner');
  const quietMode = !!rootOpts.quiet || (rootOpts.output && rootOpts.output !== 'table');
  const scanner = new ZeroTrustScanner(false, quietMode);
  await scanner.initialize();
      
      // Prepare scan target
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
      
      // Display results
      console.log(chalk.green(`✅ Scan completed in ${result.duration}ms`));
      console.log(chalk.gray(`Scan ID: ${result.id}`));
      console.log(chalk.gray(`Findings: ${result.findings.length}`));
      
      // Display findings summary
      if (result.findings.length > 0) {
        console.log('\n' + chalk.bold('Supply Chain Security Findings:'));
        
        // Group findings by severity
        const findingsBySeverity = {
          critical: result.findings.filter(f => f.severity === 'critical'),
          high: result.findings.filter(f => f.severity === 'high'),
          medium: result.findings.filter(f => f.severity === 'medium'),
          low: result.findings.filter(f => f.severity === 'low'),
          info: result.findings.filter(f => f.severity === 'info')
        };
        
        // Display critical findings first
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
              
              // Show CVE information for vulnerabilities
              if (finding.category.includes('cve') || finding.description.includes('CVE-')) {
                console.log(`   🔗 ${chalk.magenta('Security Advisory')} - Check CVE database for details`);
              }
              console.log('');
            });
          }
        });
        
        // Display summary statistics
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
        
      } else {
        console.log(chalk.green('\n✅ No supply chain security issues found!'));
      }
      
    } catch (error) {
      console.error(chalk.red('❌ Supply chain scan failed:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

/**
 * Compliance Automation Command
 */
program
  .command('compliance')
  .description('Automated compliance checking (SOC2, PCI, HIPAA)')
  .option('-s, --standard <standard>', 'Compliance standard (soc2|pci|hipaa|all)', 'all')
  .option('-e, --environment <env>', 'Target environment (dev|staging|prod)')
  .option('--exclude-controls <controls>', 'Comma-separated list of controls to exclude')
  .option('--report-format <format>', 'Report format (pdf|html|json)', 'html')
  .action(async (options) => {
    console.log(chalk.blue('🔍 Compliance Automation'));
    console.log(chalk.gray('Standards:'), options.standard);
    
    try {
  // Load configuration
  const { ConfigManager } = await import('./config/config-manager');
  const cfgMgr = ConfigManager.getInstance();
  const rootOpts = program.opts();
  await cfgMgr.initialize(rootOpts.config || './ztis.config.json');
  const cfg = cfgMgr.getConfig();

      // Import and initialize scanner
      const { ZeroTrustScanner } = await import('./core/scanner');
  const scanner = new ZeroTrustScanner();
  await scanner.initialize();
      
      // Prepare scan target
      const target = {
        type: 'compliance' as const,
        target: options.environment || 'current-environment',
        options: {
          frameworks: options.standard === 'all' ? undefined : [{ name: options.standard.toUpperCase() }],
          scope: options.excludeControls ? 
            undefined : // If exclusions specified, we'd need to process them
            undefined,
          evidence_collection: true,
          auto_remediation: false,
          report_format: options.reportFormat || 'json',
          include_recommendations: true,
          severity_threshold: 'medium',
          custom_rules: []
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
      
      // Display results
      console.log(chalk.green(`✅ Scan completed in ${result.duration}ms`));
      console.log(chalk.gray(`Scan ID: ${result.id}`));
      console.log(chalk.gray(`Findings: ${result.findings.length}`));
      
      // Display findings summary
      if (result.findings.length > 0) {
        console.log('\n' + chalk.bold('Compliance Findings:'));
        
        // Group findings by severity
        const findingsBySeverity = {
          critical: result.findings.filter(f => f.severity === 'critical'),
          high: result.findings.filter(f => f.severity === 'high'),
          medium: result.findings.filter(f => f.severity === 'medium'),
          low: result.findings.filter(f => f.severity === 'low'),
          info: result.findings.filter(f => f.severity === 'info')
        };
        
        // Display critical findings first
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
              
              // Show compliance framework information
              if (finding.compliance_impact && finding.compliance_impact.length > 0) {
                finding.compliance_impact.forEach(impact => {
                  console.log(`   📋 ${chalk.magenta(impact.standard)} Control: ${impact.control} (${impact.impact} impact)`);
                });
              }
              console.log('');
            });
          }
        });
        
        // Display compliance summary
        const criticalCount = findingsBySeverity.critical.length;
        const highCount = findingsBySeverity.high.length;
        const totalIssues = criticalCount + highCount + findingsBySeverity.medium.length;
        
        console.log(chalk.bold('\n📊 Compliance Summary:'));
        console.log(`   ${chalk.red('Critical:')} ${criticalCount}`);
        console.log(`   ${chalk.redBright('High:')} ${highCount}`);
        console.log(`   ${chalk.yellow('Medium:')} ${findingsBySeverity.medium.length}`);
        console.log(`   ${chalk.blue('Low:')} ${findingsBySeverity.low.length}`);
        
        // Calculate compliance score (rough estimate)
        const totalChecks = result.metrics.total_checks || 25;
        const failedChecks = totalIssues;
        const complianceScore = Math.max(0, Math.round(((totalChecks - failedChecks) / totalChecks) * 100));
        
        console.log(`\n📈 ${chalk.bold('Compliance Score:')} ${complianceScore}%`);
        
        if (criticalCount > 0) {
          console.log(chalk.red('\n🚨 CRITICAL compliance issues found - immediate remediation required!'));
        } else if (highCount > 0) {
          console.log(chalk.yellow('\n⚠️  HIGH severity compliance issues found - prioritize remediation'));
        } else {
          console.log(chalk.green('\n✅ No critical compliance issues found'));
        }
        
      } else {
        console.log(chalk.green('\n✅ No compliance issues found! 🎉'));
      }
      
    } catch (error) {
      console.error(chalk.red('❌ Compliance scan failed:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

/**
 * Comprehensive Scan Command
 */
program
  .command('scan-all')
  .description('Run comprehensive zero-trust security scan')
  .option('-q, --quick', 'Quick scan mode (reduced depth)')
  .option('--parallel', 'Run scans in parallel for faster execution')
  .option('--exclude <modules>', 'Exclude specific modules (network,identity,supply-chain,compliance)')
  .action(async (options) => {
    console.log(chalk.blue('🔍 Comprehensive Zero-Trust Security Scan'));
    console.log(chalk.gray('Mode:'), options.quick ? 'Quick' : 'Deep');
    
    const modules = ['network', 'identity', 'supply-chain', 'compliance'];
    const excluded = options.exclude ? options.exclude.split(',') : [];
    const activeModules = modules.filter(m => !excluded.includes(m));
    
    console.log(chalk.gray('Active modules:'), activeModules.join(', '));
    
    // TODO: Implement comprehensive scanning
    console.log(chalk.yellow('⚠️  Comprehensive scanning coming soon...'));
  });

/**
 * Real-Time Monitoring Commands
 */
program
  .command('monitor')
  .description('Real-time continuous security monitoring')
  .option('-p, --port <port>', 'WebSocket server port', '3001')
  .option('-i, --interval <seconds>', 'Monitoring interval in seconds', '30')
  .option('-t, --targets <targets>', 'Comma-separated list of targets to monitor')
  .option('--webhooks <urls>', 'Comma-separated webhook URLs for alerts')
  .option('--slack-webhook <url>', 'Slack webhook URL for notifications')
  .option('--teams-webhook <url>', 'Microsoft Teams webhook URL')
  .option('--email-alerts <emails>', 'Comma-separated email addresses for alerts')
  .action(async (options) => {
    console.log(chalk.blue('📡 Starting Real-Time Security Monitoring'));
    console.log(chalk.gray('WebSocket Port:'), options.port);
    console.log(chalk.gray('Scan Interval:'), `${options.interval}s`);
    
    try {
      // Import and initialize real-time monitor
      const { RealTimeMonitor } = await import('./monitoring/real-time-monitor');
      
      // Parse targets
      const targets = options.targets 
        ? options.targets.split(',').map((t: string) => t.trim())
        : ['localhost'];
      
      // Parse webhook URLs
      const webhooks = options.webhooks 
        ? options.webhooks.split(',').map((w: string) => w.trim())
        : [];
      
      // Parse email addresses
      const emailAlerts = options.emailAlerts 
        ? options.emailAlerts.split(',').map((e: string) => e.trim())
        : [];
      
      // Configure monitoring
      const monitorConfig = {
        scan_interval: parseInt(options.interval) * 1000, // Convert to milliseconds
        targets: targets.map((target: string) => ({
          id: `target-${target}`,
          name: target,
          scan_target: {
            type: 'network' as const,
            target: target,
            options: {
              cloud_provider: null,
              k8s_namespace: null,
              policy_file: null,
              scan_depth: 3
            }
          },
          priority: 'medium' as const,
          enabled: true
        })),
        alerting: {
          enabled: true,
          channels: [
            ...webhooks.map((url: string) => ({
              type: 'webhook' as const,
              config: { url },
              enabled: true
            })),
            ...(options.slackWebhook ? [{
              type: 'slack' as const,
              config: { webhook_url: options.slackWebhook },
              enabled: true
            }] : []),
            ...(options.teamsWebhook ? [{
              type: 'teams' as const,
              config: { webhook_url: options.teamsWebhook },
              enabled: true
            }] : []),
            ...(emailAlerts.length > 0 ? [{
              type: 'email' as const,
              config: {
                recipients: emailAlerts,
                smtp: {
                  host: 'localhost',
                  port: 587,
                  secure: false,
                  auth: { user: '', pass: '' }
                }
              },
              enabled: true
            }] : [])
          ],
          severity_threshold: 'medium' as const,
          rate_limiting: {
            max_alerts_per_minute: 5,
            cooldown_period: 300 // 5 minutes
          }
        },
        websocket: {
          port: parseInt(options.port),
          path: '/ws',
          authentication: false,
          max_connections: 100
        },
        change_detection: {
          enabled: true,
          delta_threshold: 10, // 10% change threshold
          baseline_update_frequency: 24, // 24 hours
          ignore_transient_changes: true
        }
      };
      
      // Initialize and start monitor
      const monitor = new RealTimeMonitor(monitorConfig);
      
      console.log(chalk.green('✅ Real-time monitor initialized'));
      console.log(chalk.yellow('🔄 Starting continuous monitoring...'));
      
      await monitor.start();
      
      console.log(chalk.green('🚀 Monitoring active!'));
      console.log(chalk.blue(`📡 WebSocket server listening on port ${options.port}`));
      console.log(chalk.gray('📊 Connect to the dashboard at:'), chalk.cyan(`ws://localhost:${options.port}`));
      console.log(chalk.gray('⚡ Monitoring targets:'), targets.join(', '));
      console.log(chalk.yellow('🛑 Press Ctrl+C to stop monitoring'));
      
      // Handle graceful shutdown
      const shutdown = async () => {
        console.log(chalk.yellow('\n🛑 Shutting down monitor...'));
        await monitor.stop();
        console.log(chalk.green('✅ Monitor stopped gracefully'));
        process.exit(0);
      };
      
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
      
      // Keep process alive
      setInterval(() => {
        // Heartbeat to keep process running
      }, 1000);
      
    } catch (error: any) {
      console.error(chalk.red('❌ Monitor startup failed:'), error.message);
      process.exit(1);
    }
  });

program
  .command('dashboard')
  .description('Launch web dashboard for real-time monitoring')
  .option('-p, --port <port>', 'Dashboard port', '3000')
  .option('--monitor-port <port>', 'WebSocket monitor port to connect to', '3001')
  .action(async (options) => {
    console.log(chalk.blue('🌐 Starting Web Dashboard'));
    console.log(chalk.gray('Dashboard Port:'), options.port);
    console.log(chalk.gray('Monitor Port:'), options.monitorPort);
    
    try {
      // Simple HTTP server for dashboard
      const http = await import('http');
      
      const dashboardHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero-Trust Scanner - Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; }
        .header { background: #1e293b; padding: 1rem; border-bottom: 2px solid #334155; }
        .header h1 { color: #3b82f6; font-size: 1.5rem; }
        .header .status { color: #10b981; font-size: 0.9rem; margin-top: 0.5rem; }
        .main { padding: 2rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; }
        .card h3 { color: #60a5fa; margin-bottom: 1rem; }
        .metric { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
        .metric-value { font-weight: bold; color: #10b981; }
        .events { max-height: 400px; overflow-y: auto; }
        .event { background: #374151; padding: 0.75rem; margin-bottom: 0.5rem; border-radius: 4px; font-size: 0.85rem; }
        .event.critical { border-left: 4px solid #ef4444; }
        .event.warning { border-left: 4px solid #f59e0b; }
        .event.info { border-left: 4px solid #3b82f6; }
        .timestamp { color: #9ca3af; font-size: 0.75rem; }
        .connection-status { padding: 0.5rem 1rem; border-radius: 4px; font-size: 0.9rem; margin-bottom: 1rem; }
        .connected { background: #065f46; color: #d1fae5; }
        .disconnected { background: #7f1d1d; color: #fed7d7; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Zero-Trust Infrastructure Scanner - Live Dashboard</h1>
        <div class="status" id="status">Connecting to monitor...</div>
    </div>
    
    <div class="main">
        <div id="connection-status" class="connection-status disconnected">
            📡 Connecting to WebSocket monitor...
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>📊 Monitoring Overview</h3>
                <div class="metric">
                    <span>Targets Monitored:</span>
                    <span class="metric-value" id="target-count">0</span>
                </div>
                <div class="metric">
                    <span>Active Scans:</span>
                    <span class="metric-value" id="active-scans">0</span>
                </div>
                <div class="metric">
                    <span>Total Events:</span>
                    <span class="metric-value" id="total-events">0</span>
                </div>
                <div class="metric">
                    <span>Critical Alerts:</span>
                    <span class="metric-value" id="critical-alerts" style="color: #ef4444;">0</span>
                </div>
            </div>
            
            <div class="card">
                <h3>🚨 Recent Events</h3>
                <div class="events" id="events">
                    <div class="event info">
                        <div>System initialized</div>
                        <div class="timestamp">Waiting for events...</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let ws;
        let eventCount = 0;
        let criticalCount = 0;
        
        function connect() {
            ws = new WebSocket('ws://localhost:${options.monitorPort}/ws');
            
            ws.onopen = function() {
                document.getElementById('connection-status').className = 'connection-status connected';
                document.getElementById('connection-status').innerHTML = '✅ Connected to monitor';
                document.getElementById('status').textContent = 'Connected - Receiving live updates';
            };
            
            ws.onclose = function() {
                document.getElementById('connection-status').className = 'connection-status disconnected';
                document.getElementById('connection-status').innerHTML = '❌ Disconnected from monitor';
                document.getElementById('status').textContent = 'Disconnected - Attempting to reconnect...';
                
                // Reconnect after 3 seconds
                setTimeout(connect, 3000);
            };
            
            ws.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    handleEvent(data);
                } catch (e) {
                    console.error('Failed to parse WebSocket message:', e);
                }
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        function handleEvent(data) {
            eventCount++;
            document.getElementById('total-events').textContent = eventCount;
            
            if (data.type === 'status') {
                document.getElementById('target-count').textContent = data.data.targets || 0;
                return;
            }
            
            // Add event to list
            const eventsContainer = document.getElementById('events');
            const eventDiv = document.createElement('div');
            
            let eventClass = 'info';
            if (data.severity === 'critical' || data.severity === 'high') {
                eventClass = 'critical';
                criticalCount++;
                document.getElementById('critical-alerts').textContent = criticalCount;
            } else if (data.severity === 'medium') {
                eventClass = 'warning';
            }
            
            eventDiv.className = 'event ' + eventClass;
            eventDiv.innerHTML = \`
                <div>\${data.type}: \${data.message || JSON.stringify(data.data)}</div>
                <div class="timestamp">\${new Date(data.timestamp).toLocaleString()}</div>
            \`;
            
            eventsContainer.insertBefore(eventDiv, eventsContainer.firstChild);
            
            // Keep only last 50 events
            while (eventsContainer.children.length > 50) {
                eventsContainer.removeChild(eventsContainer.lastChild);
            }
        }
        
        // Start connection
        connect();
    </script>
</body>
</html>`;
      
  const server = http.createServer((_req: any, res: any) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(dashboardHtml);
      });
      
      server.listen(parseInt(options.port), () => {
        console.log(chalk.green('✅ Dashboard server started'));
        console.log(chalk.blue(`🌐 Open your browser to: http://localhost:${options.port}`));
        console.log(chalk.gray('📡 Connecting to monitor on port:'), options.monitorPort);
        console.log(chalk.yellow('🛑 Press Ctrl+C to stop dashboard'));
      });
      
      // Handle graceful shutdown
      const shutdown = () => {
        console.log(chalk.yellow('\n🛑 Shutting down dashboard...'));
        server.close(() => {
          console.log(chalk.green('✅ Dashboard stopped gracefully'));
          process.exit(0);
        });
      };
      
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
      
    } catch (error: any) {
      console.error(chalk.red('❌ Dashboard startup failed:'), error.message);
      process.exit(1);
    }
  });

/**
 * Configuration Command
 */
program
  .command('config')
  .description('Manage scanner configuration')
  .option('--init', 'Initialize configuration file')
  .option('--validate', 'Validate current configuration')
  .option('--show', 'Show current configuration')
  .action(async (options) => {
    const { ConfigManager } = await import('./config/config-manager');
    const configPath = (program.opts() as any).config as string;
    const mgr = ConfigManager.getInstance();
    if (options.init) {
      console.log(chalk.blue('📝 Initializing configuration...'));
      await mgr.initialize(configPath);
      await mgr.createDefaultConfig(configPath);
      console.log(chalk.green(`✅ Configuration file created: ${configPath}`));
    } else if (options.validate) {
      console.log(chalk.blue('🔍 Validating configuration...'));
      await mgr.initialize(configPath);
      const validation = mgr.validateConfig();
      if (!validation.valid) {
        console.error(chalk.red('❌ Configuration validation failed:'));
        (validation.errors || []).forEach(e => console.error('  -', e));
        process.exit(1);
      }
      console.log(chalk.green('✅ Configuration is valid'));
    } else if (options.show) {
      console.log(chalk.blue('📋 Current configuration:'));
      await mgr.initialize(configPath);
      const cfg = mgr.getConfig();
      const outFmt = (program.opts() as any).output as string;
      if (outFmt === 'yaml' || outFmt === 'yml') {
        const { stringify } = await import('yaml');
        console.log(stringify(cfg));
      } else {
        console.log(JSON.stringify(cfg, null, 2));
      }
    } else {
      console.log(chalk.red('❌ Please specify an action (--init, --validate, or --show)'));
    }
  });

/**
 * Server Command
 */
program
  .command('server')
  .description('Start the Zero-Trust Scanner web dashboard')
  .option('-p, --port <port>', 'Server port', '3000')
  .option('-h, --host <host>', 'Server host', 'localhost')
  .option('--api-only', 'Start API server without web interface')
  .action(async (options) => {
    console.log(chalk.blue('🚀 Starting Zero-Trust Scanner Server'));
    console.log(chalk.gray('URL:'), `http://${options.host}:${options.port}`);
    
    // TODO: Start server
    console.log(chalk.yellow('⚠️  Web server coming soon...'));
  });

// Add behavioral analysis commands
createBehavioralCommands(program);

// Add ML risk scoring commands
addRiskScoringCommands(program);

// Add enhanced ML risk scoring commands
program.addCommand(mlRiskCommands);

// Error handling
program.exitOverride((err) => {
  // Handle help/version exits gracefully
  if (
    err.code === 'commander.version' ||
    err.code === 'commander.help' ||
    err.code === 'commander.helpDisplayed'
  ) {
    process.exit(0);
  }
  console.error(chalk.red('❌ Command failed:'), err.message);
  process.exit(1);
});

// Parse arguments
program.parse();

// Show help if no command provided
if (!process.argv.slice(2).length) {
  console.log(chalk.bold.blue('🛡️  Zero-Trust Infrastructure Scanner'));
  console.log(chalk.gray('Enterprise-grade security scanning platform\n'));
  program.outputHelp();
}
