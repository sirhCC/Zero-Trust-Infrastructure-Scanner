/**
 * CLI Commands for ML Risk Scoring Engine
 * Command-line interface for risk assessment and prioritization
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { MLRiskScoringEngine, BusinessContext, RiskScore } from '../analytics/ml-risk-scoring';
import { SecurityFinding } from '../core/scanner';

export function addRiskScoringCommands(program: Command): void {
  const riskCommand = program
    .command('risk')
    .description('🎯 ML-powered risk scoring and vulnerability prioritization');

  // Score individual finding
  riskCommand
    .command('score')
    .description('Calculate ML risk score for a security finding')
    .option('-f, --finding <file>', 'JSON file containing security finding')
    .option('-c, --context <file>', 'JSON file containing business context')
    .option('--severity <level>', 'Finding severity (critical|high|medium|low|info)', 'medium')
    .option('--category <type>', 'Finding category', 'general')
    .option('--title <title>', 'Finding title', 'Security finding')
    .option('--asset-criticality <level>', 'Asset criticality (critical|high|medium|low)', 'medium')
    .option('--data-sensitivity <level>', 'Data sensitivity (restricted|confidential|internal|public)', 'internal')
    .option('--internet-facing', 'Asset is internet-facing')
    .option('--user-count <number>', 'Number of users affected', '100')
    .action(async (options) => {
      await handleRiskScore(options);
    });

  // Batch prioritization
  riskCommand
    .command('prioritize')
    .description('Prioritize multiple security findings using ML risk scoring')
    .option('-f, --findings <file>', 'JSON file containing array of security findings')
    .option('-c, --context <file>', 'JSON file containing business context')
    .option('-o, --output <file>', 'Output file for prioritized findings')
    .option('--format <type>', 'Output format (json|yaml|table)', 'table')
    .action(async (options) => {
      await handlePrioritizeFindings(options);
    });

  // Risk trends prediction
  riskCommand
    .command('trends')
    .description('Predict future risk trends based on historical data')
    .option('-d, --data <file>', 'JSON file containing historical risk scores')
    .option('--days <number>', 'Number of days to predict', '30')
    .option('-o, --output <file>', 'Output file for trend analysis')
    .action(async (options) => {
      await handleRiskTrends(options);
    });

  // Generate risk report
  riskCommand
    .command('report')
    .description('Generate comprehensive risk assessment report')
    .option('-f, --findings <file>', 'JSON file containing scored findings')
    .option('-o, --output <file>', 'Output file for risk report')
    .option('--format <type>', 'Report format (json|html|pdf)', 'json')
    .action(async (options) => {
      await handleRiskReport(options);
    });

  // Demo risk scoring
  riskCommand
    .command('demo')
    .description('Run ML risk scoring demonstration with sample data')
    .option('--findings-count <number>', 'Number of sample findings to generate', '20')
    .action(async (options) => {
      await handleRiskDemo(options);
    });
}

async function handleRiskScore(options: any): Promise<void> {
  try {
    console.log(chalk.blue('🎯 ML Risk Scoring Engine\n'));

    const riskEngine = new MLRiskScoringEngine();
    
    let finding: SecurityFinding;
    let businessContext: BusinessContext;

    // Load or create finding
    if (options.finding) {
      const fs = await import('fs/promises');
      const findingData = JSON.parse(await fs.readFile(options.finding, 'utf-8'));
      finding = findingData;
    } else {
      finding = {
        id: `finding_${Date.now()}`,
        severity: options.severity as any,
        category: options.category,
        title: options.title,
        description: `Sample ${options.severity} severity finding in ${options.category} category`,
        evidence: { sample: true },
        recommendation: 'Review and remediate this security finding',
        compliance_impact: []
      };
    }

    // Load or create business context
    if (options.context) {
      const fs = await import('fs/promises');
      const contextData = JSON.parse(await fs.readFile(options.context, 'utf-8'));
      businessContext = contextData;
    } else {
      businessContext = {
        asset_criticality: options.assetCriticality as any,
        data_sensitivity: options.dataSensitivity as any,
        compliance_requirements: ['SOC2', 'GDPR'],
        business_hours: true,
        internet_facing: !!options.internetFacing,
        user_count: parseInt(options.userCount)
      };
    }

    console.log(chalk.yellow('📋 Input Details:'));
    console.log(`Finding: ${finding.severity.toUpperCase()} - ${finding.title}`);
    console.log(`Category: ${finding.category}`);
    console.log(`Asset Criticality: ${businessContext.asset_criticality}`);
    console.log(`Data Sensitivity: ${businessContext.data_sensitivity}`);
    console.log(`Internet Facing: ${businessContext.internet_facing}`);
    console.log(`User Count: ${businessContext.user_count}\n`);

    // Calculate risk score
    const riskScore = await riskEngine.calculateRiskScore(finding, businessContext);

    // Display results
    displayRiskScore(riskScore, finding);

  } catch (error) {
    console.error(chalk.red('❌ Error calculating risk score:'), error);
    process.exit(1);
  }
}

async function handlePrioritizeFindings(options: any): Promise<void> {
  try {
    console.log(chalk.blue('🔥 ML Finding Prioritization\n'));

    if (!options.findings) {
      console.error(chalk.red('❌ Please provide findings file with -f option'));
      process.exit(1);
    }

    const fs = await import('fs/promises');
    const riskEngine = new MLRiskScoringEngine();

    // Load findings
    const findingsData = JSON.parse(await fs.readFile(options.findings, 'utf-8'));
    const findings: SecurityFinding[] = Array.isArray(findingsData) ? findingsData : [findingsData];

    // Load or create business context
    let businessContext: BusinessContext;
    if (options.context) {
      businessContext = JSON.parse(await fs.readFile(options.context, 'utf-8'));
    } else {
      businessContext = {
        asset_criticality: 'high',
        data_sensitivity: 'confidential',
        compliance_requirements: ['SOC2', 'PCI', 'GDPR'],
        business_hours: true,
        internet_facing: true,
        user_count: 1000
      };
    }

    console.log(chalk.yellow(`📊 Processing ${findings.length} findings...`));

    // Prioritize findings
    const prioritizedFindings = await riskEngine.prioritizeFindings(findings, businessContext);

    // Display results based on format
    if (options.format === 'table' || !options.output) {
      displayPrioritizedFindings(prioritizedFindings);
    }

    // Save output if specified
    if (options.output) {
      if (options.format === 'yaml') {
        const yaml = await import('yaml');
        await fs.writeFile(options.output, yaml.stringify(prioritizedFindings));
      } else {
        await fs.writeFile(options.output, JSON.stringify(prioritizedFindings, null, 2));
      }
      console.log(chalk.green(`\n✅ Results saved to ${options.output}`));
    }

  } catch (error) {
    console.error(chalk.red('❌ Error prioritizing findings:'), error);
    process.exit(1);
  }
}

async function handleRiskTrends(options: any): Promise<void> {
  try {
    console.log(chalk.blue('📈 Risk Trend Prediction\n'));

    if (!options.data) {
      console.error(chalk.red('❌ Please provide historical data file with -d option'));
      process.exit(1);
    }

    const fs = await import('fs/promises');
    const riskEngine = new MLRiskScoringEngine();

    // Load historical data
    const historicalData = JSON.parse(await fs.readFile(options.data, 'utf-8'));
    const historicalScores: number[] = Array.isArray(historicalData) ? historicalData : historicalData.scores;

    const days = parseInt(options.days);

    console.log(chalk.yellow(`📊 Analyzing ${historicalScores.length} historical data points...`));
    console.log(chalk.yellow(`🔮 Predicting trends for next ${days} days...\n`));

    // Predict trends
    const trendPrediction = riskEngine.predictRiskTrends(historicalScores, days);

    // Display results
    console.log(chalk.blue('📈 Trend Analysis Results:'));
    console.log(`Trend Direction: ${getTrendIcon(trendPrediction.trend)} ${trendPrediction.trend.toUpperCase()}`);
    console.log(`Confidence: ${(trendPrediction.confidence * 100).toFixed(1)}%\n`);

    if (trendPrediction.predicted_scores.length > 0) {
      console.log(chalk.yellow('🔮 Predicted Risk Scores:'));
      const sample = trendPrediction.predicted_scores.slice(0, 10); // Show first 10 days
      sample.forEach((score, index) => {
        const day = index + 1;
        const riskLevel = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
        const color = score >= 80 ? chalk.red : score >= 60 ? chalk.yellow : score >= 40 ? chalk.blue : chalk.green;
        console.log(color(`Day ${day}: ${score.toFixed(1)} (${riskLevel})`));
      });
      
      if (trendPrediction.predicted_scores.length > 10) {
        console.log(chalk.gray(`... and ${trendPrediction.predicted_scores.length - 10} more days`));
      }
    }

    // Save output if specified
    if (options.output) {
      await fs.writeFile(options.output, JSON.stringify(trendPrediction, null, 2));
      console.log(chalk.green(`\n✅ Trend analysis saved to ${options.output}`));
    }

  } catch (error) {
    console.error(chalk.red('❌ Error predicting risk trends:'), error);
    process.exit(1);
  }
}

async function handleRiskReport(options: any): Promise<void> {
  try {
    console.log(chalk.blue('📊 Risk Assessment Report Generation\n'));

    if (!options.findings) {
      console.error(chalk.red('❌ Please provide findings file with -f option'));
      process.exit(1);
    }

    const fs = await import('fs/promises');
    const riskEngine = new MLRiskScoringEngine();

    // Load findings (should be already scored)
    const findingsData = JSON.parse(await fs.readFile(options.findings, 'utf-8'));
    
    if (!findingsData.every((f: any) => f.risk_score)) {
      console.error(chalk.red('❌ Findings must include risk_score property. Run prioritization first.'));
      process.exit(1);
    }

    console.log(chalk.yellow(`📊 Generating report for ${findingsData.length} findings...`));

    // Generate report
    const report = riskEngine.generateRiskReport(findingsData);

    // Display summary
    displayRiskReport(report);

    // Save output if specified
    if (options.output) {
      if (options.format === 'html') {
        const htmlReport = generateHTMLReport(report);
        await fs.writeFile(options.output, htmlReport);
      } else {
        await fs.writeFile(options.output, JSON.stringify(report, null, 2));
      }
      console.log(chalk.green(`\n✅ Report saved to ${options.output}`));
    }

  } catch (error) {
    console.error(chalk.red('❌ Error generating risk report:'), error);
    process.exit(1);
  }
}

async function handleRiskDemo(options: any): Promise<void> {
  try {
    console.log(chalk.blue('🎮 ML Risk Scoring Demo\n'));

    const findingsCount = parseInt(options.findingsCount);
    const riskEngine = new MLRiskScoringEngine();

    // Generate sample findings
    const sampleFindings = generateSampleFindings(findingsCount);
    const businessContext: BusinessContext = {
      asset_criticality: 'high',
      data_sensitivity: 'confidential',
      compliance_requirements: ['SOC2', 'PCI', 'GDPR'],
      business_hours: true,
      internet_facing: true,
      user_count: 2500
    };

    console.log(chalk.yellow(`🎯 Scoring ${findingsCount} sample findings...`));
    console.log(chalk.gray('Business Context: High criticality, confidential data, internet-facing\n'));

    // Process findings
    const prioritizedFindings = await riskEngine.prioritizeFindings(sampleFindings, businessContext);

    // Show top 10 risks
    console.log(chalk.blue('🔥 Top 10 Highest Risk Findings:\n'));
    prioritizedFindings.slice(0, 10).forEach((finding, index) => {
      const rank = index + 1;
      const score = finding.risk_score.overall_score;
      const level = finding.risk_score.risk_level.toUpperCase();
      const color = score >= 80 ? chalk.red : score >= 60 ? chalk.yellow : score >= 40 ? chalk.blue : chalk.green;
      
      console.log(color(`${rank}. ${finding.title}`));
      console.log(color(`   Score: ${score} | Level: ${level} | Category: ${finding.category}`));
      console.log(chalk.gray(`   Confidence: ${(finding.risk_score.confidence * 100).toFixed(1)}%`));
      console.log();
    });

    // Generate report
    const report = riskEngine.generateRiskReport(prioritizedFindings);
    displayRiskReport(report);

    // Show sample trend prediction
    const historicalScores = prioritizedFindings.map(f => f.risk_score.overall_score).slice(0, 15);
    const trends = riskEngine.predictRiskTrends(historicalScores, 7);
    
    console.log(chalk.blue('\n📈 7-Day Risk Trend Prediction:'));
    console.log(`Trend: ${getTrendIcon(trends.trend)} ${trends.trend.toUpperCase()}`);
    console.log(`Confidence: ${(trends.confidence * 100).toFixed(1)}%`);

  } catch (error) {
    console.error(chalk.red('❌ Error running risk demo:'), error);
    process.exit(1);
  }
}

// Helper functions

function displayRiskScore(riskScore: RiskScore, _finding: SecurityFinding): void {
  console.log(chalk.blue('🎯 ML Risk Score Results:\n'));
  
  const scoreColor = riskScore.overall_score >= 80 ? chalk.red : 
                    riskScore.overall_score >= 60 ? chalk.yellow : 
                    riskScore.overall_score >= 40 ? chalk.blue : chalk.green;
  
  console.log(scoreColor(`Overall Risk Score: ${riskScore.overall_score}/100`));
  console.log(scoreColor(`Risk Level: ${riskScore.risk_level.toUpperCase()}`));
  console.log(`Confidence: ${(riskScore.confidence * 100).toFixed(1)}%\n`);
  
  console.log(chalk.yellow('Component Scores:'));
  console.log(`├─ Severity Score: ${riskScore.severity_score.toFixed(1)}`);
  console.log(`├─ Exploitability Score: ${riskScore.exploitability_score.toFixed(1)}`);
  console.log(`├─ Business Impact Score: ${riskScore.business_impact_score.toFixed(1)}`);
  console.log(`├─ Compliance Score: ${riskScore.compliance_score.toFixed(1)}`);
  console.log(`└─ Temporal Score: ${riskScore.temporal_score.toFixed(1)}\n`);
  
  if (riskScore.reasoning.length > 0) {
    console.log(chalk.yellow('🧠 ML Analysis Reasoning:'));
    riskScore.reasoning.forEach((reason, index) => {
      console.log(`${index + 1}. ${reason}`);
    });
  }
}

function displayPrioritizedFindings(findings: Array<any>): void {
  console.log(chalk.blue('\n🔥 Prioritized Security Findings:\n'));
  
  findings.forEach((finding, index) => {
    const rank = index + 1;
    const score = finding.risk_score.overall_score;
    const level = finding.risk_score.risk_level.toUpperCase();
    const color = score >= 80 ? chalk.red : score >= 60 ? chalk.yellow : score >= 40 ? chalk.blue : chalk.green;
    
    console.log(color(`${rank}. [${level}] ${finding.title}`));
    console.log(color(`   Risk Score: ${score} | Category: ${finding.category} | Severity: ${finding.severity}`));
    console.log(chalk.gray(`   Confidence: ${(finding.risk_score.confidence * 100).toFixed(1)}%`));
    console.log();
  });
}

function displayRiskReport(report: any): void {
  console.log(chalk.blue('\n📊 Risk Assessment Summary:\n'));
  
  const summary = report.summary;
  const overallColor = summary.average_risk_score >= 70 ? chalk.red : 
                      summary.average_risk_score >= 50 ? chalk.yellow : chalk.green;
  
  console.log(`Total Findings: ${summary.total_findings}`);
  console.log(overallColor(`Average Risk Score: ${summary.average_risk_score}`));
  console.log(overallColor(`Overall Risk Level: ${summary.overall_risk_level.toUpperCase()}\n`));
  
  console.log(chalk.yellow('Risk Distribution:'));
  console.log(chalk.red(`├─ Critical: ${summary.critical_risks}`));
  console.log(chalk.yellow(`├─ High: ${summary.high_risks}`));
  console.log(chalk.blue(`├─ Medium: ${summary.medium_risks}`));
  console.log(chalk.green(`└─ Low: ${summary.low_risks}\n`));
  
  if (report.recommendations.length > 0) {
    console.log(chalk.yellow('🎯 Recommendations:'));
    report.recommendations.forEach((rec: string, index: number) => {
      console.log(`${index + 1}. ${rec}`);
    });
  }
}

function getTrendIcon(trend: string): string {
  switch (trend) {
    case 'increasing': return '📈';
    case 'decreasing': return '📉';
    case 'stable': return '➡️';
    default: return '❓';
  }
}

function generateSampleFindings(count: number): SecurityFinding[] {
  const severities: Array<'critical' | 'high' | 'medium' | 'low' | 'info'> = ['critical', 'high', 'medium', 'low', 'info'];
  const categories = ['injection', 'authentication', 'authorization', 'cryptography', 'network-security', 'configuration'];
  const titles = [
    'SQL Injection vulnerability',
    'Weak authentication mechanism',
    'Missing authorization checks',
    'Weak cryptographic implementation',
    'Open network port',
    'Misconfigured security settings',
    'Unpatched software component',
    'Sensitive data exposure',
    'Cross-site scripting vulnerability',
    'Insecure direct object reference'
  ];

  const findings: SecurityFinding[] = [];
  
  for (let i = 0; i < count; i++) {
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const category = categories[Math.floor(Math.random() * categories.length)];
    const title = titles[Math.floor(Math.random() * titles.length)];
    
    findings.push({
      id: `finding_${i + 1}`,
      severity,
      category,
      title: `${title} #${i + 1}`,
      description: `Sample ${severity} severity finding in ${category} category`,
      evidence: { sample: true, scan_id: `scan_${Date.now()}` },
      recommendation: `Review and remediate this ${severity} ${category} finding`,
      compliance_impact: severity === 'critical' || severity === 'high' ? [
        { standard: 'SOC2' as any, control: 'CC6.1', impact: severity as any }
      ] : []
    });
  }
  
  return findings;
}

function generateHTMLReport(report: any): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ML Risk Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #0d6efd; }
        .low { color: #198754; }
        .recommendations { background: #e3f2fd; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .recommendations h3 { margin-top: 0; color: #1976d2; }
        .recommendations ul { margin: 10px 0; padding-left: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 ML Risk Assessment Report</h1>
            <p>Generated on ${new Date().toLocaleDateString()}</p>
        </div>
        
        <div class="summary">
            <div class="metric">
                <h3>Total Findings</h3>
                <div class="value">${report.summary.total_findings}</div>
            </div>
            <div class="metric">
                <h3>Average Risk Score</h3>
                <div class="value">${report.summary.average_risk_score}</div>
            </div>
            <div class="metric">
                <h3>Critical Risks</h3>
                <div class="value critical">${report.summary.critical_risks}</div>
            </div>
            <div class="metric">
                <h3>High Risks</h3>
                <div class="value high">${report.summary.high_risks}</div>
            </div>
        </div>
        
        <div class="recommendations">
            <h3>🎯 Key Recommendations</h3>
            <ul>
                ${report.recommendations.map((rec: string) => `<li>${rec}</li>`).join('')}
            </ul>
        </div>
    </div>
</body>
</html>`;
}
