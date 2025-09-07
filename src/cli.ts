#!/usr/bin/env node

/**
 * Zero-Trust Infrastructure Scanner CLI
 * Command-line interface for security scanning operations
 */

import { Command } from 'commander';
import chalk from 'chalk';
// Removed unused imports moved into modular command files
// Prefer a typed JSON import; fallback to env if somehow missing at runtime
// TypeScript resolveJsonModule is enabled, so this is supported.
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import pkg from '../package.json';
const version: string =
  (pkg as { version?: string })?.version || process.env.npm_package_version || '0.0.0';
import { createBehavioralCommands } from './cli/behavioral-commands';
import { addRiskScoringCommands } from './cli/risk-commands';
import mlRiskCommands from './cli/ml-risk-commands';
import registerNetworkCommands from './cli/network-commands';
import registerIdentityCommands from './cli/identity-commands';
import registerSupplyChainCommands from './cli/supply-chain-commands';
import registerComplianceCommands from './cli/compliance-commands';
import registerMonitorCommands from './cli/monitor-commands';

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

// Helpers moved into per-command modules

registerNetworkCommands(program);

/**
 * Identity Permission Mining Command
 */
registerIdentityCommands(program);

/**
 * Supply Chain Security Command
 */
registerSupplyChainCommands(program);

registerComplianceCommands(program);

/**
 * Comprehensive Scan Command
 */
program
  .command('scan-all')
  .description('Run comprehensive zero-trust security scan')
  .option('-q, --quick', 'Quick scan mode (reduced depth)')
  .option('--parallel', 'Run scans in parallel for faster execution')
  .option(
    '--exclude <modules>',
    'Exclude specific modules (network,identity,supply-chain,compliance)'
  )
  .action(async (options) => {
    console.log(chalk.blue('🔍 Comprehensive Zero-Trust Security Scan'));
    console.log(chalk.gray('Mode:'), options.quick ? 'Quick' : 'Deep');

    const modules = ['network', 'identity', 'supply-chain', 'compliance'];
    const excluded = options.exclude ? options.exclude.split(',') : [];
    const activeModules = modules.filter((m) => !excluded.includes(m));

    console.log(chalk.gray('Active modules:'), activeModules.join(', '));

    // TODO: Implement comprehensive scanning
    console.log(chalk.yellow('⚠️  Comprehensive scanning coming soon...'));
  });

registerMonitorCommands(program);

/**
 * Configuration Command
 */
// config and server are registered in monitor-commands module

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
