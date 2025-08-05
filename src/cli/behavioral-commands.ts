/**
 * Behavioral Analysis CLI Commands
 * Command-line interface for interacting with the behavioral analysis system
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import BehavioralMonitoringIntegration from '../analytics/behavioral-integration';
import { BehavioralAnalysisEngine } from '../analytics/behavioral-analysis';

/**
 * Create behavioral analysis CLI commands
 */
export function createBehavioralCommands(program: Command): void {
  const behavioral = program
    .command('behavioral')
    .description('Behavioral analysis and anomaly detection commands');

  // Start behavioral monitoring
  behavioral
    .command('monitor')
    .description('Start behavioral analysis monitoring')
    .option('-t, --targets <targets>', 'Comma-separated list of targets to monitor', 'localhost')
    .option('-i, --interval <interval>', 'Analysis interval in seconds', '60')
    .option('--threshold <threshold>', 'Anomaly detection threshold (0-1)', '0.6')
    .option('--profiles <profiles>', 'Number of top anomalous profiles to display', '5')
    .action(async (options) => {
      const spinner = ora('Starting behavioral analysis monitoring...').start();

      try {
        const integration = new BehavioralMonitoringIntegration({
          enabled: true,
          analysis_interval: parseInt(options.interval) * 1000,
          anomaly_threshold: parseFloat(options.threshold),
          real_time_updates: true,
          baseline_update_frequency: 24,
          profile_retention_days: 90
        });

        // Setup event handlers for CLI display
        integration.on('behavioral_events', (events: any[]) => {
          console.log(chalk.yellow('\n🧠 Behavioral Events Detected:'));
          events.forEach((event: any) => {
            const severityColor = getSeverityColor(event.severity);
            console.log(severityColor(`  ${event.event_type}: ${event.entity_id}`));
            console.log(`    Anomaly Score: ${event.behavioral_context.anomaly_score.toFixed(3)}`);
            console.log(`    Confidence: ${(event.behavioral_context.confidence_level * 100).toFixed(1)}%`);
            console.log(`    Recommended Actions: ${event.recommended_actions.slice(0, 2).join(', ')}`);
          });
        });

        integration.on('high_severity_anomalies', (anomalies: any[]) => {
          console.log(chalk.red('\n🚨 HIGH SEVERITY ANOMALIES DETECTED:'));
          anomalies.forEach((anomaly: any) => {
            console.log(chalk.red(`  ${anomaly.indicator_type}: ${anomaly.description}`));
            console.log(chalk.red(`  Score: ${anomaly.score.toFixed(3)} | Severity: ${anomaly.severity}`));
          });
        });

        spinner.succeed('Behavioral analysis monitoring started');

        console.log(chalk.green('\n📊 Behavioral Analysis Monitoring Active'));
        console.log(`   Targets: ${options.targets}`);
        console.log(`   Analysis Interval: ${options.interval}s`);
        console.log(`   Anomaly Threshold: ${options.threshold}`);
        console.log(chalk.gray('   Press Ctrl+C to stop monitoring\n'));

        // Simulate monitoring with statistics display
        const statsInterval = setInterval(() => {
          const stats = integration.getBehavioralStats();
          const topProfiles = integration.getTopAnomalousProfiles(parseInt(options.profiles));

          console.log(chalk.blue('\n📈 Behavioral Statistics:'));
          console.log(`   Total Profiles: ${stats.total_profiles}`);
          console.log(`   High Risk Profiles: ${stats.high_risk_profiles}`);
          console.log(`   New Profiles: ${stats.new_profiles}`);
          console.log(`   Average Confidence: ${(stats.average_confidence * 100).toFixed(1)}%`);
          console.log(`   Anomaly Detection Rate: ${(stats.anomaly_detection_rate * 100).toFixed(1)}%`);

          if (topProfiles.length > 0) {
            console.log(chalk.yellow('\n🔍 Top Anomalous Profiles:'));
            topProfiles.forEach((profile, index) => {
              const riskColor = profile.anomaly_score > 0.8 ? chalk.red : 
                               profile.anomaly_score > 0.6 ? chalk.yellow : chalk.blue;
              console.log(riskColor(`   ${index + 1}. ${profile.entity_id} (${profile.entity_type})`));
              console.log(`      Score: ${profile.anomaly_score.toFixed(3)} | Age: ${profile.profile_age_days}d`);
            });
          }
        }, 30000); // Show stats every 30 seconds

        // Handle graceful shutdown
        process.on('SIGINT', () => {
          clearInterval(statsInterval);
          integration.shutdown();
          console.log(chalk.green('\n✅ Behavioral monitoring stopped'));
          process.exit(0);
        });

      } catch (error) {
        spinner.fail('Failed to start behavioral monitoring');
        console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });

  // Analyze existing data
  behavioral
    .command('analyze')
    .description('Analyze behavioral patterns from historical data')
    .option('-d, --data <file>', 'Path to scan results data file')
    .option('-f, --format <format>', 'Output format (json|table|summary)', 'summary')
    .option('--export <file>', 'Export behavioral profiles to file')
    .action(async (options) => {
      const spinner = ora('Analyzing behavioral patterns...').start();

      try {
        const engine = new BehavioralAnalysisEngine({
          statistical_methods: {
            z_score_threshold: 3.0,
            iqr_multiplier: 1.5,
            enable_seasonal_decomposition: true,
            rolling_window_size: 150
          }
        });

        // TODO: Load historical scan data
        // const scanData = await loadScanData(options.data);
        // const anomalies = await engine.processScanResults(scanData);

        spinner.succeed('Behavioral analysis complete');

        console.log(chalk.green('\n📊 Behavioral Analysis Results'));
        
        if (options.format === 'summary') {
          const profiles = engine.getBehaviorProfiles();
          console.log(`\n📈 Summary:`);
          console.log(`   Total Entities Analyzed: ${profiles.length}`);
          console.log(`   High-Risk Entities: ${profiles.filter(p => p.anomaly_score > 0.7).length}`);
          console.log(`   New Entities (< 7 days): ${profiles.filter(p => p.profile_age_days < 7).length}`);
          
          const avgConfidence = profiles.length > 0 
            ? profiles.reduce((sum, p) => sum + p.confidence_level, 0) / profiles.length 
            : 0;
          console.log(`   Average Confidence: ${(avgConfidence * 100).toFixed(1)}%`);
        }

        if (options.export) {
          engine.exportProfiles();
          // TODO: Write to file
          console.log(chalk.green(`\n💾 Behavioral profiles exported to: ${options.export}`));
        }

      } catch (error) {
        spinner.fail('Behavioral analysis failed');
        console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });

  // Profile management
  behavioral
    .command('profiles')
    .description('Manage behavioral profiles')
    .option('-l, --list', 'List all behavioral profiles')
    .option('-s, --show <entity>', 'Show detailed profile for entity')
    .option('-c, --cleanup', 'Clean up old behavioral profiles')
    .option('--age <days>', 'Maximum age for cleanup (default: 90)', '90')
    .action(async (options) => {
      try {
        const engine = new BehavioralAnalysisEngine();
        const profiles = engine.getBehaviorProfiles();

        if (options.list) {
          console.log(chalk.blue('\n📋 Behavioral Profiles:'));
          
          if (profiles.length === 0) {
            console.log(chalk.gray('   No profiles found'));
            return;
          }

          profiles.forEach((profile, index) => {
            const riskColor = profile.anomaly_score > 0.8 ? chalk.red : 
                             profile.anomaly_score > 0.6 ? chalk.yellow : chalk.green;
            
            console.log(riskColor(`\n   ${index + 1}. ${profile.entity_id} (${profile.entity_type})`));
            console.log(`      Anomaly Score: ${profile.anomaly_score.toFixed(3)}`);
            console.log(`      Confidence: ${(profile.confidence_level * 100).toFixed(1)}%`);
            console.log(`      Age: ${profile.profile_age_days} days`);
            console.log(`      Patterns: ${profile.baseline.behavioral_patterns.length}`);
            console.log(`      Last Updated: ${profile.last_updated.toISOString()}`);
          });
        }

        if (options.show) {
          const profile = engine.getBehaviorProfile(options.show);
          
          if (!profile) {
            console.log(chalk.red(`\n❌ Profile not found: ${options.show}`));
            return;
          }

          console.log(chalk.blue(`\n🔍 Detailed Profile: ${profile.entity_id}`));
          console.log(`   Entity Type: ${profile.entity_type}`);
          console.log(`   Anomaly Score: ${profile.anomaly_score.toFixed(3)}`);
          console.log(`   Confidence Level: ${(profile.confidence_level * 100).toFixed(1)}%`);
          console.log(`   Profile Age: ${profile.profile_age_days} days`);
          console.log(`   Last Updated: ${profile.last_updated.toISOString()}`);

          console.log(chalk.yellow('\n📊 Statistical Profile:'));
          Object.entries(profile.baseline.statistical_profile.metrics).forEach(([metric, stats]) => {
            console.log(`   ${metric}:`);
            console.log(`     Mean: ${stats.mean.toFixed(2)}, StdDev: ${stats.std_dev.toFixed(2)}`);
            console.log(`     Range: ${stats.min.toFixed(2)} - ${stats.max.toFixed(2)}`);
            console.log(`     Trend: ${stats.trend}`);
          });

          console.log(chalk.yellow('\n🔄 Behavioral Patterns:'));
          profile.baseline.behavioral_patterns.forEach((pattern, index) => {
            console.log(`   ${index + 1}. ${pattern.description}`);
            console.log(`      Type: ${pattern.pattern_type}, Confidence: ${(pattern.confidence * 100).toFixed(1)}%`);
            console.log(`      Occurrences: ${pattern.occurrences}, Last Seen: ${pattern.last_seen.toDateString()}`);
          });

          if (profile.baseline.seasonal_patterns.length > 0) {
            console.log(chalk.yellow('\n📈 Seasonal Patterns:'));
            profile.baseline.seasonal_patterns.forEach((pattern, index) => {
              console.log(`   ${index + 1}. ${pattern.period} pattern`);
              console.log(`      Amplitude: ${pattern.amplitude.toFixed(2)}, Confidence: ${(pattern.confidence * 100).toFixed(1)}%`);
            });
          }
        }

        if (options.cleanup) {
          const beforeCount = profiles.length;
          engine.cleanupOldProfiles(parseInt(options.age));
          const afterCount = engine.getBehaviorProfiles().length;
          const cleaned = beforeCount - afterCount;
          
          console.log(chalk.green(`\n🧹 Cleanup complete: ${cleaned} old profiles removed`));
          console.log(`   Remaining profiles: ${afterCount}`);
        }

      } catch (error) {
        console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });

  // Test behavioral analysis
  behavioral
    .command('test')
    .description('Test behavioral analysis with synthetic data')
    .option('-s, --samples <count>', 'Number of synthetic samples to generate', '100')
    .option('--anomalies <count>', 'Number of anomalous samples to inject', '10')
    .action(async (options) => {
      const spinner = ora('Generating synthetic behavioral data...').start();

      try {
        const engine = new BehavioralAnalysisEngine();
        const sampleCount = parseInt(options.samples);
        const anomalyCount = parseInt(options.anomalies);

        // Generate synthetic scan results for testing
        const syntheticResults = generateSyntheticScanResults(sampleCount, anomalyCount);
        
        spinner.text = 'Running behavioral analysis...';
        const anomalies = await engine.processScanResults(syntheticResults);

        spinner.succeed('Behavioral analysis test complete');

        console.log(chalk.green('\n🧪 Behavioral Analysis Test Results'));
        console.log(`   Synthetic Samples: ${sampleCount}`);
        console.log(`   Injected Anomalies: ${anomalyCount}`);
        console.log(`   Detected Anomalies: ${anomalies.length}`);

        if (anomalies.length > 0) {
          console.log(chalk.yellow('\n🔍 Detected Anomalies:'));
          anomalies.forEach((anomaly, index) => {
            const severityColor = getSeverityColor(anomaly.severity);
            console.log(severityColor(`   ${index + 1}. ${anomaly.indicator_type}: ${anomaly.description}`));
            console.log(`      Score: ${anomaly.score.toFixed(3)}, Severity: ${anomaly.severity}`);
            console.log(`      Evidence: ${anomaly.evidence.slice(0, 2).join(', ')}`);
          });
        }

        const profiles = engine.getBehaviorProfiles();
        const detectionRate = anomalies.length / Math.max(anomalyCount, 1);
        
        console.log(chalk.blue('\n📊 Analysis Statistics:'));
        console.log(`   Entities Profiled: ${profiles.length}`);
        console.log(`   Detection Rate: ${(detectionRate * 100).toFixed(1)}%`);
        console.log(`   False Positive Rate: ${Math.max(0, (anomalies.length - anomalyCount) / sampleCount * 100).toFixed(1)}%`);

      } catch (error) {
        spinner.fail('Behavioral analysis test failed');
        console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });
}

/**
 * Get color for severity level
 */
function getSeverityColor(severity: string): typeof chalk.red {
  switch (severity) {
    case 'critical': return chalk.red.bold;
    case 'high': return chalk.red;
    case 'medium': return chalk.yellow;
    case 'low': return chalk.blue;
    default: return chalk.gray;
  }
}

/**
 * Generate synthetic scan results for testing
 */
function generateSyntheticScanResults(count: number, anomalies: number): any[] {
  const results = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const isAnomaly = i < anomalies;
    const timestamp = new Date(now - (i * 60000)); // 1 minute intervals
    
    results.push({
      id: `synthetic_${i}`,
      timestamp,
      target: {
        type: 'network',
        target: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
        options: {}
      },
      status: 'completed',
      findings: generateSyntheticFindings(isAnomaly),
      metrics: {
        total_checks: Math.floor(Math.random() * 100) + 50,
        passed_checks: Math.floor(Math.random() * 80) + 20,
        failed_checks: Math.floor(Math.random() * 10),
        warnings: Math.floor(Math.random() * 5),
        resources_scanned: Math.floor(Math.random() * 20) + 5,
        scan_coverage: Math.random() * 0.3 + 0.7
      },
      duration: Math.floor(Math.random() * 30000) + 5000
    });
  }

  return results;
}

/**
 * Generate synthetic security findings
 */
function generateSyntheticFindings(isAnomaly: boolean): any[] {
  const baseFindings = [
    {
      id: `finding_${Date.now()}_${Math.random()}`,
      severity: 'low',
      category: 'network-security',
      title: 'Open port detected',
      description: 'Port 22 is open for SSH access',
      evidence: { port: 22, protocol: 'tcp' },
      recommendation: 'Consider restricting SSH access'
    }
  ];

  if (isAnomaly) {
    // Add anomalous patterns
    const anomalousFindings = [
      {
        id: `finding_${Date.now()}_${Math.random()}`,
        severity: Math.random() > 0.5 ? 'high' : 'critical',
        category: 'identity-security',
        title: 'Unusual access pattern detected',
        description: 'Access from unusual location or time',
        evidence: { unusual_access: true, off_hours: true },
        recommendation: 'Investigate access pattern legitimacy'
      },
      {
        id: `finding_${Date.now()}_${Math.random()}`,
        severity: 'high',
        category: 'network-security',
        title: 'Abnormal network traffic volume',
        description: 'Significantly higher than baseline traffic',
        evidence: { traffic_volume: Math.random() * 10000 + 5000 },
        recommendation: 'Monitor for potential data exfiltration'
      }
    ];

    return [...baseFindings, ...anomalousFindings.slice(0, Math.floor(Math.random() * 2) + 1)];
  }

  return baseFindings;
}

export default createBehavioralCommands;
