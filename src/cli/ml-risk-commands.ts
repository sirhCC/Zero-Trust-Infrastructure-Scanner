/**
 * ML Risk Scoring CLI Commands
 * Command-line interface for testing and evaluating ML risk scoring
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { runMLRiskScoringEvaluation } from '../demos/ml-risk-scoring-eval';
import { runEnhancedMLEvaluation } from '../demos/enhanced-ml-comparison';
import { MLRiskScoringEngine } from '../analytics/ml-risk-scoring';
import { EnhancedMLRiskScoringEngine } from '../analytics/enhanced-ml-risk-scoring';
import { SecurityFinding } from '../core/scanner';

const mlRiskCommands = new Command('ml-risk')
  .description('🎯 ML-powered risk scoring and vulnerability prioritization');

/**
 * Test ML Risk Scoring Engine
 */
mlRiskCommands
  .command('test')
  .description('Run comprehensive ML risk scoring tests')
  .option('--original', 'Test only the original ML engine')
  .option('--enhanced', 'Test only the enhanced ML engine')
  .option('--comparison', 'Run comparison between engines')
  .action(async (options) => {
    console.log(chalk.blue('🎯 ML Risk Scoring Test Suite'));
    
    try {
      if (options.comparison) {
        await runEnhancedMLEvaluation();
      } else if (options.enhanced) {
        console.log(chalk.yellow('Running Enhanced ML Engine Tests...'));
        await runEnhancedMLEvaluation();
      } else if (options.original) {
        console.log(chalk.yellow('Running Original ML Engine Tests...'));
        await runMLRiskScoringEvaluation();
      } else {
        // Run both by default
        await runMLRiskScoringEvaluation();
        await runEnhancedMLEvaluation();
      }
    } catch (error) {
      console.error(chalk.red('❌ ML risk scoring test failed:'), error);
      process.exit(1);
    }
  });

/**
 * Score a custom finding
 */
mlRiskCommands
  .command('score')
  .description('Calculate risk score for a custom security finding')
  .requiredOption('-s, --severity <level>', 'Severity level (critical|high|medium|low|info)')
  .requiredOption('-c, --category <category>', 'Vulnerability category (injection|authentication|etc)')
  .requiredOption('-t, --title <title>', 'Finding title')
  .option('-d, --description <desc>', 'Finding description')
  .option('--asset-criticality <level>', 'Asset criticality (critical|high|medium|low)', 'medium')
  .option('--data-sensitivity <level>', 'Data sensitivity (restricted|confidential|internal|public)', 'internal')
  .option('--internet-facing', 'Asset is internet-facing', false)
  .option('--user-count <count>', 'Number of users affected', '1000')
  .option('--industry <type>', 'Industry type for enhanced scoring', 'technology')
  .option('--enhanced', 'Use enhanced ML engine')
  .action(async (options) => {
    console.log(chalk.blue('🎯 Custom Risk Scoring'));
    console.log(chalk.gray(`Analyzing: ${options.title}\\n`));
    
    try {
      // Create custom finding
      const finding: SecurityFinding & { timestamp?: Date } = {
        id: `custom_${Date.now()}`,
        severity: options.severity as any,
        category: options.category,
        title: options.title,
        description: options.description || `${options.severity} ${options.category} vulnerability`,
        evidence: {
          internet_facing: options.internetFacing,
          user_count: parseInt(options.userCount)
        },
        recommendation: 'Address this security finding according to severity level',
        timestamp: new Date()
      };

      // Create business context
      const businessContext = {
        asset_criticality: options.assetCriticality as any,
        data_sensitivity: options.dataSensitivity as any,
        compliance_requirements: ['SOC2'], // Default compliance
        business_hours: true,
        internet_facing: options.internetFacing,
        user_count: parseInt(options.userCount)
      };

      // Calculate risk score
      let riskScore;
      if (options.enhanced) {
        const enhancedEngine = new EnhancedMLRiskScoringEngine();
        riskScore = await enhancedEngine.calculateEnhancedRiskScore(
          finding, 
          businessContext, 
          [], 
          options.industry
        );
        console.log(chalk.yellow('Using Enhanced ML Engine'));
      } else {
        const originalEngine = new MLRiskScoringEngine();
        riskScore = await originalEngine.calculateRiskScore(finding, businessContext);
        console.log(chalk.yellow('Using Original ML Engine'));
      }

      // Display results
      const riskColor = {
        critical: chalk.red,
        high: chalk.redBright,
        medium: chalk.yellow,
        low: chalk.blue
      }[riskScore.risk_level];

      console.log('\\n' + chalk.bold('Risk Assessment Results:'));
      console.log(`Overall Score: ${riskColor(riskScore.overall_score)}/100`);
      console.log(`Risk Level: ${riskColor(riskScore.risk_level.toUpperCase())}`);
      console.log(`Confidence: ${(riskScore.confidence * 100).toFixed(1)}%`);
      console.log('');
      
      console.log(chalk.bold('Detailed Scores:'));
      console.log(`  Severity Score: ${riskScore.severity_score}/100`);
      console.log(`  Exploitability: ${riskScore.exploitability_score}/100`);
      console.log(`  Business Impact: ${riskScore.business_impact_score}/100`);
      console.log(`  Compliance Impact: ${riskScore.compliance_score}/100`);
      console.log(`  Temporal Factors: ${riskScore.temporal_score}/100`);
      console.log('');
      
      if (riskScore.reasoning.length > 0) {
        console.log(chalk.bold('Risk Factors:'));
        riskScore.reasoning.forEach((reason, index) => {
          console.log(`  ${index + 1}. ${reason}`);
        });
        console.log('');
      }

    } catch (error) {
      console.error(chalk.red('❌ Risk scoring failed:'), error);
      process.exit(1);
    }
  });

/**
 * Benchmark different scenarios
 */
mlRiskCommands
  .command('benchmark')
  .description('Benchmark risk scoring across different scenarios')
  .option('--scenarios <count>', 'Number of scenarios to test', '10')
  .option('--enhanced', 'Use enhanced ML engine')
  .action(async (options) => {
    console.log(chalk.blue('🎯 ML Risk Scoring Benchmark'));
    console.log(chalk.gray(`Testing ${options.scenarios} different scenarios\\n`));
    
    try {
      const engine = options.enhanced ? 
        new EnhancedMLRiskScoringEngine() : 
        new MLRiskScoringEngine();

      const scenarios = generateBenchmarkScenarios(parseInt(options.scenarios));
      const results = [];

      for (const scenario of scenarios) {
        const startTime = Date.now();
        
        let riskScore;
        if (options.enhanced) {
          riskScore = await (engine as EnhancedMLRiskScoringEngine).calculateEnhancedRiskScore(
            scenario.finding, 
            scenario.context, 
            [],
            scenario.industry || 'technology'
          );
        } else {
          riskScore = await (engine as MLRiskScoringEngine).calculateRiskScore(
            scenario.finding, 
            scenario.context
          );
        }
        
        const duration = Date.now() - startTime;
        
        results.push({
          scenario: scenario.name,
          score: riskScore.overall_score,
          level: riskScore.risk_level,
          confidence: riskScore.confidence,
          duration
        });

        console.log(`${scenario.name}: ${riskScore.risk_level.toUpperCase()} (${riskScore.overall_score}/100) - ${duration}ms`);
      }

      // Summary statistics
      const avgScore = results.reduce((sum, r) => sum + r.score, 0) / results.length;
      const avgConfidence = results.reduce((sum, r) => sum + r.confidence, 0) / results.length;
      const avgDuration = results.reduce((sum, r) => sum + r.duration, 0) / results.length;

      console.log('\\n' + chalk.bold('Benchmark Summary:'));
      console.log(`Average Score: ${avgScore.toFixed(1)}/100`);
      console.log(`Average Confidence: ${(avgConfidence * 100).toFixed(1)}%`);
      console.log(`Average Processing Time: ${avgDuration.toFixed(1)}ms`);
      console.log(`Total Processing Time: ${results.reduce((sum, r) => sum + r.duration, 0)}ms`);

      // Risk level distribution
      const distribution: { [key: string]: number } = {};
      results.forEach(r => {
        distribution[r.level] = (distribution[r.level] || 0) + 1;
      });

      console.log('\\n' + chalk.bold('Risk Level Distribution:'));
      Object.entries(distribution).forEach(([level, count]) => {
        const percentage = (count / results.length * 100).toFixed(1);
        console.log(`  ${level.charAt(0).toUpperCase() + level.slice(1)}: ${count} (${percentage}%)`);
      });

    } catch (error) {
      console.error(chalk.red('❌ Benchmark failed:'), error);
      process.exit(1);
    }
  });

/**
 * Generate benchmark test scenarios
 */
function generateBenchmarkScenarios(count: number): Array<{
  name: string;
  finding: SecurityFinding & { timestamp?: Date };
  context: any;
  industry?: string;
}> {
  const severities = ['critical', 'high', 'medium', 'low'];
  const categories = ['injection', 'authentication', 'access-control', 'encryption', 'configuration'];
  const criticalities = ['critical', 'high', 'medium', 'low'];
  const sensitivities = ['restricted', 'confidential', 'internal', 'public'];
  const industries = ['financial', 'healthcare', 'government', 'retail', 'technology'];

  const scenarios = [];
  
  for (let i = 0; i < count; i++) {
    const severity = severities[i % severities.length];
    const category = categories[i % categories.length];
    const criticality = criticalities[i % criticalities.length];
    const sensitivity = sensitivities[i % sensitivities.length];
    const industry = industries[i % industries.length];

    scenarios.push({
      name: `Scenario ${i + 1}: ${severity} ${category}`,
      finding: {
        id: `bench_${i}`,
        severity: severity as any,
        category,
        title: `${severity.charAt(0).toUpperCase() + severity.slice(1)} ${category} vulnerability`,
        description: `Benchmark test ${category} vulnerability`,
        evidence: {
          test_scenario: true,
          scenario_id: i
        },
        recommendation: `Address ${severity} ${category} issue`,
        timestamp: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000) // Random age up to 30 days
      },
      context: {
        asset_criticality: criticality as any,
        data_sensitivity: sensitivity as any,
        compliance_requirements: ['SOC2'],
        business_hours: Math.random() > 0.5,
        internet_facing: Math.random() > 0.5,
        user_count: Math.floor(Math.random() * 100000) + 100
      },
      industry
    });
  }

  return scenarios;
}

export default mlRiskCommands;
