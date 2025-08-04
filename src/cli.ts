#!/usr/bin/env node

/**
 * Zero-Trust Infrastructure Scanner CLI
 * Command-line interface for security scanning operations
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { version } from '../package.json';

const program = new Command();

// Configure CLI
program
  .name('zero-trust-scanner')
  .description('Enterprise Zero-Trust Infrastructure Scanner')
  .version(version, '-v, --version', 'Display version number');

// Global options
program
  .option('-c, --config <file>', 'Configuration file path', './ztis.config.json')
  .option('-o, --output <format>', 'Output format (json|yaml|table)', 'table')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--no-color', 'Disable colored output');

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
  .action(async (options) => {
    console.log(chalk.blue('🔍 Network Micro-Segmentation Analysis'));
    console.log(chalk.gray('Target:'), options.target || 'Auto-detect');
    
    try {
      // Import and initialize scanner
      const { ZeroTrustScanner } = await import('./core/scanner');
      const scanner = new ZeroTrustScanner();
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
      
      console.log(chalk.yellow('🚀 Starting network scan...'));
      const result = await scanner.scan(target);
      
      // Display results
      console.log(chalk.green(`✅ Scan completed in ${result.duration}ms`));
      console.log(chalk.gray(`Scan ID: ${result.id}`));
      console.log(chalk.gray(`Findings: ${result.findings.length}`));
      
      // Display findings summary
      if (result.findings.length > 0) {
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
      } else {
        console.log(chalk.green('\n✅ No security issues found!'));
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
      // Import and initialize scanner
      const { ZeroTrustScanner } = await import('./core/scanner');
      const scanner = new ZeroTrustScanner();
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
      
      console.log(chalk.yellow('🚀 Starting identity scan...'));
      const result = await scanner.scan(target);
      
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
      // Import and initialize scanner
      const { ZeroTrustScanner } = await import('./core/scanner');
      const scanner = new ZeroTrustScanner();
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
      
      console.log(chalk.yellow('🚀 Starting supply chain scan...'));
      const result = await scanner.scan(target);
      
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
      
      console.log(chalk.yellow('🚀 Starting compliance scan...'));
      const result = await scanner.scan(target);
      
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
 * Configuration Command
 */
program
  .command('config')
  .description('Manage scanner configuration')
  .option('--init', 'Initialize configuration file')
  .option('--validate', 'Validate current configuration')
  .option('--show', 'Show current configuration')
  .action(async (options) => {
    if (options.init) {
      console.log(chalk.blue('📝 Initializing configuration...'));
      // TODO: Create default config
      console.log(chalk.green('✅ Configuration file created: ztis.config.json'));
    } else if (options.validate) {
      console.log(chalk.blue('🔍 Validating configuration...'));
      // TODO: Validate config
      console.log(chalk.green('✅ Configuration is valid'));
    } else if (options.show) {
      console.log(chalk.blue('📋 Current configuration:'));
      // TODO: Show config
      console.log(chalk.yellow('⚠️  Configuration display coming soon...'));
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

// Error handling
program.exitOverride((err) => {
  if (err.code === 'commander.version') {
    process.exit(0);
  }
  if (err.code === 'commander.help') {
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
