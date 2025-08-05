/**
 * Behavioral Analysis Demo
 * Demonstrates the capabilities of the behavioral analysis engine
 */

import chalk from 'chalk';
import { BehavioralAnalysisEngine } from '../analytics/behavioral-analysis';
import BehavioralMonitoringIntegration from '../analytics/behavioral-integration';

async function runBehavioralDemo(): Promise<void> {
  console.log(chalk.bold.blue('\n🧠 Zero-Trust Behavioral Analysis Demo'));
  console.log(chalk.gray('Demonstrating advanced anomaly detection and behavioral profiling\n'));

  try {
    // Initialize behavioral analysis engine
    console.log(chalk.yellow('📊 Initializing Behavioral Analysis Engine...'));
    const engine = new BehavioralAnalysisEngine({
      statistical_methods: {
        z_score_threshold: 2.5,
        iqr_multiplier: 1.5,
        enable_seasonal_decomposition: true,
        rolling_window_size: 100
      },
      machine_learning: {
        isolation_forest_contamination: 0.1,
        enable_clustering: true,
        feature_importance_threshold: 0.15
      },
      behavioral_thresholds: {
        frequency_deviation_threshold: 0.4,
        temporal_shift_threshold: 2.0,
        resource_access_anomaly_threshold: 0.6
      },
      context_awareness: {
        enable_contextual_scoring: true,
        business_hours: { start: 9, end: 17 },
        weekend_weight: 0.4,
        holiday_weight: 0.2
      }
    });

    // Generate synthetic behavioral data
    console.log(chalk.yellow('🔄 Generating synthetic behavioral data...'));
    const normalData = generateNormalBehaviorData(50);
    const anomalousData = generateAnomalousBehaviorData(10);
    const allData = [...normalData, ...anomalousData];

    // Process the data through behavioral analysis
    console.log(chalk.yellow('🔍 Processing behavioral patterns...'));
    const anomalies = await engine.processScanResults(allData);

    // Display results
    console.log(chalk.green('\n✅ Behavioral Analysis Complete!'));
    console.log(chalk.blue('\n📈 Analysis Results:'));
    console.log(`   Total Samples Processed: ${allData.length}`);
    console.log(`   Normal Behavior Samples: ${normalData.length}`);
    console.log(`   Anomalous Samples Injected: ${anomalousData.length}`);
    console.log(`   Anomalies Detected: ${anomalies.length}`);

    if (anomalies.length > 0) {
      console.log(chalk.red('\n🚨 Detected Anomalies:'));
      anomalies.forEach((anomaly, index) => {
        const severityColor = getSeverityColor(anomaly.severity);
        console.log(severityColor(`\n   ${index + 1}. ${anomaly.indicator_type.toUpperCase()} ANOMALY`));
        console.log(severityColor(`      Description: ${anomaly.description}`));
        console.log(severityColor(`      Severity: ${anomaly.severity}`));
        console.log(severityColor(`      Score: ${anomaly.score.toFixed(3)}`));
        console.log(`      Evidence: ${anomaly.evidence.slice(0, 2).join(', ')}`);
        console.log(`      Detected: ${anomaly.detected_at.toISOString()}`);
      });
    }

    // Show behavioral profiles
    const profiles = engine.getBehaviorProfiles();
    console.log(chalk.blue('\n👥 Behavioral Profiles Created:'));
    profiles.forEach((profile, index) => {
      const riskColor = profile.anomaly_score > 0.7 ? chalk.red : 
                       profile.anomaly_score > 0.4 ? chalk.yellow : chalk.green;
      
      console.log(riskColor(`\n   ${index + 1}. ${profile.entity_id} (${profile.entity_type})`));
      console.log(`      Anomaly Score: ${profile.anomaly_score.toFixed(3)}`);
      console.log(`      Confidence Level: ${(profile.confidence_level * 100).toFixed(1)}%`);
      console.log(`      Profile Age: ${profile.profile_age_days} days`);
      console.log(`      Behavioral Patterns: ${profile.baseline.behavioral_patterns.length}`);
      console.log(`      Seasonal Patterns: ${profile.baseline.seasonal_patterns.length}`);
    });

    // Demonstrate integration with monitoring
    console.log(chalk.yellow('\n🔧 Testing Monitoring Integration...'));
    const integration = new BehavioralMonitoringIntegration({
      enabled: true,
      analysis_interval: 5000,
      anomaly_threshold: 0.5,
      real_time_updates: true
    });

    // Setup event handlers
    integration.on('behavioral_events', (events: any[]) => {
      console.log(chalk.cyan(`\n📡 Real-time behavioral events: ${events.length} detected`));
      events.forEach((event: any, index: number) => {
        console.log(chalk.cyan(`   ${index + 1}. ${event.event_type}: ${event.entity_id}`));
        console.log(`      Anomaly Score: ${event.behavioral_context.anomaly_score.toFixed(3)}`);
      });
    });

    integration.on('high_severity_anomalies', (anomalies: any[]) => {
      console.log(chalk.red(`\n⚠️  HIGH SEVERITY: ${anomalies.length} critical anomalies detected!`));
    });

    // Process some data through integration
    const testData = generateAnomalousBehaviorData(3);
    const events = await integration.processScanResults(testData);
    
    console.log(chalk.green('\n✅ Integration test completed!'));
    console.log(`   Enhanced Security Events: ${events.length}`);

    // Show behavioral statistics
    const stats = integration.getBehavioralStats();
    console.log(chalk.blue('\n📊 Behavioral Statistics:'));
    console.log(`   Total Profiles: ${stats.total_profiles}`);
    console.log(`   High Risk Profiles: ${stats.high_risk_profiles}`);
    console.log(`   New Profiles: ${stats.new_profiles}`);
    console.log(`   Average Confidence: ${(stats.average_confidence * 100).toFixed(1)}%`);
    console.log(`   Anomaly Detection Rate: ${(stats.anomaly_detection_rate * 100).toFixed(1)}%`);

    // Show top anomalous profiles
    const topProfiles = integration.getTopAnomalousProfiles(3);
    if (topProfiles.length > 0) {
      console.log(chalk.yellow('\n🔍 Top Anomalous Profiles:'));
      topProfiles.forEach((profile, index) => {
        const riskColor = profile.anomaly_score > 0.8 ? chalk.red : chalk.yellow;
        console.log(riskColor(`   ${index + 1}. ${profile.entity_id} - Score: ${profile.anomaly_score.toFixed(3)}`));
      });
    }

    // Cleanup
    integration.shutdown();

    console.log(chalk.green('\n🎉 Behavioral Analysis Demo Complete!'));
    console.log(chalk.gray('\nKey Features Demonstrated:'));
    console.log(chalk.gray('  ✓ Statistical anomaly detection (Z-score, IQR)'));
    console.log(chalk.gray('  ✓ Behavioral pattern learning'));
    console.log(chalk.gray('  ✓ Temporal anomaly detection'));
    console.log(chalk.gray('  ✓ Real-time monitoring integration'));
    console.log(chalk.gray('  ✓ Enhanced security event generation'));
    console.log(chalk.gray('  ✓ Risk scoring and profiling'));

  } catch (error) {
    console.error(chalk.red('\n❌ Demo failed:'), error);
    process.exit(1);
  }
}

/**
 * Generate normal behavior data for testing
 */
function generateNormalBehaviorData(count: number): any[] {
  const results = [];
  const baseTime = Date.now();

  for (let i = 0; i < count; i++) {
    const timestamp = new Date(baseTime - (i * 60000)); // 1 minute intervals
    
    results.push({
      id: `normal_scan_${i}`,
      timestamp,
      target: {
        type: 'network',
        target: `192.168.1.${(i % 10) + 1}`,
        options: {}
      },
      status: 'completed',
      findings: [
        {
          id: `finding_${i}`,
          severity: 'low',
          category: 'network-security',
          title: 'Standard network check',
          description: 'Routine network security validation',
          evidence: { port: 22, protocol: 'tcp' },
          recommendation: 'Monitor regularly'
        }
      ],
      metrics: {
        total_checks: 50 + Math.floor(Math.random() * 20),
        passed_checks: 45 + Math.floor(Math.random() * 10),
        failed_checks: Math.floor(Math.random() * 3),
        warnings: Math.floor(Math.random() * 2),
        resources_scanned: 5 + Math.floor(Math.random() * 5),
        scan_coverage: 0.85 + Math.random() * 0.1
      },
      duration: 5000 + Math.floor(Math.random() * 10000)
    });
  }

  return results;
}

/**
 * Generate anomalous behavior data for testing
 */
function generateAnomalousBehaviorData(count: number): any[] {
  const results = [];
  const baseTime = Date.now();

  for (let i = 0; i < count; i++) {
    const timestamp = new Date(baseTime - (i * 120000)); // 2 minute intervals
    const isOffHours = Math.random() > 0.5;
    const isHighSeverity = Math.random() > 0.7;
    
    // Create anomalous timestamp (off-hours)
    if (isOffHours) {
      const hour = Math.random() > 0.5 ? 2 : 23; // 2 AM or 11 PM
      timestamp.setHours(hour);
    }

    results.push({
      id: `anomaly_scan_${i}`,
      timestamp,
      target: {
        type: 'network',
        target: `10.0.0.${Math.floor(Math.random() * 254) + 1}`,
        options: {}
      },
      status: 'completed',
      findings: [
        {
          id: `anomaly_finding_${i}`,
          severity: isHighSeverity ? 'high' : 'medium',
          category: 'identity-security',
          title: 'Unusual access pattern detected',
          description: `Anomalous activity: ${isOffHours ? 'off-hours access' : 'unusual frequency'}`,
          evidence: { 
            unusual_access: true, 
            off_hours: isOffHours,
            frequency_multiplier: 2 + Math.random() * 3
          },
          recommendation: 'Investigate immediately'
        },
        {
          id: `network_anomaly_${i}`,
          severity: 'medium',
          category: 'network-security',
          title: 'Abnormal network traffic',
          description: 'Traffic volume significantly above baseline',
          evidence: { 
            traffic_volume: 50000 + Math.random() * 100000,
            baseline_volume: 10000
          },
          recommendation: 'Monitor for data exfiltration'
        }
      ],
      metrics: {
        total_checks: 80 + Math.floor(Math.random() * 40), // Higher than normal
        passed_checks: 20 + Math.floor(Math.random() * 20), // Lower pass rate
        failed_checks: 10 + Math.floor(Math.random() * 15), // Higher failure rate
        warnings: 5 + Math.floor(Math.random() * 10), // More warnings
        resources_scanned: 15 + Math.floor(Math.random() * 10), // More resources
        scan_coverage: 0.95 + Math.random() * 0.05 // High coverage
      },
      duration: 15000 + Math.floor(Math.random() * 20000) // Longer duration
    });
  }

  return results;
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

// Run the demo if this file is executed directly
if (require.main === module) {
  runBehavioralDemo().catch(console.error);
}

export default runBehavioralDemo;
