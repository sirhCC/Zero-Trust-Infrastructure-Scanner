/**
 * ML Risk Scoring Demo
 * Demonstration of advanced risk assessment and prioritization capabilities
 */

import chalk from 'chalk';
import { MLRiskScoringEngine, BusinessContext, RiskScore } from '../analytics/ml-risk-scoring';
import { SecurityFinding } from '../core/scanner';

export class RiskScoringDemo {
  private riskEngine: MLRiskScoringEngine;

  constructor() {
    this.riskEngine = new MLRiskScoringEngine();
  }

  async runDemo(): Promise<void> {
    console.log(chalk.blue.bold('\n🎯 ML Risk Scoring Engine Demo'));
    console.log(chalk.gray('Demonstrating advanced risk assessment and vulnerability prioritization\n'));

    await this.demonstrateBasicRiskScoring();
    await this.demonstrateBatchPrioritization();
    await this.demonstrateRiskTrends();
    await this.demonstrateRiskReport();
    await this.demonstrateBusinessContextImpact();

    console.log(chalk.green.bold('\n✅ ML Risk Scoring Demo Complete!'));
    console.log(chalk.blue('🚀 Ready to enhance your zero-trust security with intelligent risk assessment'));
  }

  private async demonstrateBasicRiskScoring(): Promise<void> {
    console.log(chalk.yellow.bold('🎯 1. Basic Risk Scoring Demonstration\n'));

    const criticalFinding: SecurityFinding = {
      id: 'finding_sql_injection_001',
      severity: 'critical',
      category: 'injection',
      title: 'SQL Injection vulnerability in user authentication',
      description: 'Critical SQL injection flaw allowing unauthorized database access',
      evidence: {
        url: '/api/login',
        parameter: 'username',
        payload: "' OR 1=1 --",
        response_code: 200
      },
      recommendation: 'Implement parameterized queries and input validation',
      compliance_impact: [
        { standard: 'SOC2', control: 'CC6.1', impact: 'critical' },
        { standard: 'PCI', control: '6.5.1', impact: 'high' }
      ]
    };

    const businessContext: BusinessContext = {
      asset_criticality: 'critical',
      data_sensitivity: 'restricted',
      compliance_requirements: ['SOC2', 'PCI', 'GDPR'],
      business_hours: true,
      internet_facing: true,
      user_count: 50000
    };

    console.log(chalk.blue('Finding Details:'));
    console.log(`├─ Severity: ${chalk.red(criticalFinding.severity.toUpperCase())}`);
    console.log(`├─ Category: ${criticalFinding.category}`);
    console.log(`├─ Title: ${criticalFinding.title}`);
    console.log(`└─ Compliance Impact: ${criticalFinding.compliance_impact?.length || 0} standards affected\n`);

    console.log(chalk.blue('Business Context:'));
    console.log(`├─ Asset Criticality: ${chalk.red(businessContext.asset_criticality.toUpperCase())}`);
    console.log(`├─ Data Sensitivity: ${chalk.yellow(businessContext.data_sensitivity.toUpperCase())}`);
    console.log(`├─ Internet Facing: ${businessContext.internet_facing ? '✅ Yes' : '❌ No'}`);
    console.log(`└─ User Count: ${businessContext.user_count.toLocaleString()}\n`);

    console.log(chalk.yellow('🧠 Calculating ML Risk Score...\n'));

    const riskScore = await this.riskEngine.calculateRiskScore(
      criticalFinding,
      businessContext
    );

    this.displayRiskScore(riskScore);
    console.log('\n' + '─'.repeat(80) + '\n');
  }

  private async demonstrateBatchPrioritization(): Promise<void> {
    console.log(chalk.yellow.bold('🔥 2. Batch Finding Prioritization\n'));

    const sampleFindings = this.generateSampleFindings(15);
    const businessContext: BusinessContext = {
      asset_criticality: 'high',
      data_sensitivity: 'confidential',
      compliance_requirements: ['SOC2', 'PCI'],
      business_hours: true,
      internet_facing: true,
      user_count: 10000
    };

    console.log(chalk.blue(`Processing ${sampleFindings.length} security findings...\n`));

    const prioritizedFindings = await this.riskEngine.prioritizeFindings(
      sampleFindings,
      businessContext
    );

    console.log(chalk.yellow('🏆 Top 10 Highest Risk Findings:\n'));

    prioritizedFindings.slice(0, 10).forEach((finding, index) => {
      const rank = index + 1;
      const score = finding.risk_score.overall_score;
      const level = finding.risk_score.risk_level.toUpperCase();
      const confidence = (finding.risk_score.confidence * 100).toFixed(1);

      const scoreColor = score >= 80 ? chalk.red : 
                        score >= 60 ? chalk.yellow : 
                        score >= 40 ? chalk.blue : chalk.green;

      console.log(scoreColor(`${rank.toString().padStart(2)}. [${level}] ${finding.title}`));
      console.log(scoreColor(`    Risk Score: ${score} | Confidence: ${confidence}% | Category: ${finding.category}`));
      
      if (finding.risk_score.reasoning.length > 0) {
        console.log(chalk.gray(`    💡 ${finding.risk_score.reasoning[0]}`));
      }
      console.log();
    });

    console.log('\n' + '─'.repeat(80) + '\n');
  }

  private async demonstrateRiskTrends(): Promise<void> {
    console.log(chalk.yellow.bold('📈 3. Risk Trend Prediction\n'));

    // Simulate historical risk scores with an increasing trend
    const historicalScores = [
      45, 48, 52, 49, 55, 58, 62, 59, 65, 68, 72, 75, 71, 78, 82
    ];

    console.log(chalk.blue('Historical Risk Scores (15 data points):'));
    console.log(chalk.gray(historicalScores.join(' → ')));
    console.log();

    const trendPrediction = this.riskEngine.predictRiskTrends(historicalScores, 14);

    console.log(chalk.yellow('🔮 14-Day Risk Trend Forecast:\n'));
    console.log(`Trend Direction: ${this.getTrendIcon(trendPrediction.trend)} ${chalk.bold(trendPrediction.trend.toUpperCase())}`);
    console.log(`Prediction Confidence: ${(trendPrediction.confidence * 100).toFixed(1)}%\n`);

    if (trendPrediction.predicted_scores.length > 0) {
      console.log(chalk.blue('Predicted Scores (Next 14 Days):'));
      
      const weeklyGroups = [];
      for (let i = 0; i < trendPrediction.predicted_scores.length; i += 7) {
        weeklyGroups.push(trendPrediction.predicted_scores.slice(i, i + 7));
      }

      weeklyGroups.forEach((week, weekIndex) => {
        console.log(chalk.gray(`Week ${weekIndex + 1}:`));
        week.forEach((score, dayIndex) => {
          const day = weekIndex * 7 + dayIndex + 1;
          const riskLevel = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
          const color = score >= 80 ? chalk.red : score >= 60 ? chalk.yellow : score >= 40 ? chalk.blue : chalk.green;
          console.log(color(`  Day ${day}: ${score.toFixed(1)} (${riskLevel})`));
        });
        console.log();
      });

      // Trend analysis
      if (trendPrediction.trend === 'increasing') {
        console.log(chalk.red('⚠️  ALERT: Risk scores are trending upward - increased security attention needed'));
      } else if (trendPrediction.trend === 'decreasing') {
        console.log(chalk.green('✅ POSITIVE: Risk scores are trending downward - security measures are effective'));
      } else {
        console.log(chalk.blue('ℹ️  STABLE: Risk scores are stable - maintain current security posture'));
      }
    }

    console.log('\n' + '─'.repeat(80) + '\n');
  }

  private async demonstrateRiskReport(): Promise<void> {
    console.log(chalk.yellow.bold('📊 4. Comprehensive Risk Assessment Report\n'));

    const sampleFindings = this.generateSampleFindings(25);
    const businessContext: BusinessContext = {
      asset_criticality: 'critical',
      data_sensitivity: 'restricted',
      compliance_requirements: ['SOC2', 'PCI', 'HIPAA', 'GDPR'],
      business_hours: true,
      internet_facing: true,
      user_count: 75000
    };

    const prioritizedFindings = await this.riskEngine.prioritizeFindings(
      sampleFindings,
      businessContext
    );

    const report = this.riskEngine.generateRiskReport(prioritizedFindings);

    console.log(chalk.blue('📋 Executive Risk Summary:\n'));
    
    const summary = report.summary;
    const overallColor = summary.average_risk_score >= 70 ? chalk.red : 
                        summary.average_risk_score >= 50 ? chalk.yellow : chalk.green;

    console.log(`Total Security Findings: ${summary.total_findings}`);
    console.log(overallColor(`Average Risk Score: ${summary.average_risk_score}/100`));
    console.log(overallColor(`Overall Risk Level: ${summary.overall_risk_level.toUpperCase()}\n`));

    console.log(chalk.yellow('Risk Distribution:'));
    console.log(chalk.red(`├─ Critical Risk: ${summary.critical_risks} findings`));
    console.log(chalk.yellow(`├─ High Risk: ${summary.high_risks} findings`));
    console.log(chalk.blue(`├─ Medium Risk: ${summary.medium_risks} findings`));
    console.log(chalk.green(`└─ Low Risk: ${summary.low_risks} findings\n`));

    console.log(chalk.yellow('🎯 Strategic Recommendations:\n'));
    report.recommendations.forEach((rec, index) => {
      console.log(`${index + 1}. ${rec}`);
    });

    // Risk heat map simulation
    console.log(chalk.blue('\n🔥 Risk Heat Map (Top Categories):\n'));
    const categoryRisks = this.calculateCategoryRisks(prioritizedFindings);
    Object.entries(categoryRisks)
      .sort(([,a], [,b]) => b.averageScore - a.averageScore)
      .slice(0, 5)
      .forEach(([category, data]) => {
        const heatLevel = data.averageScore >= 70 ? '🔴' : 
                         data.averageScore >= 50 ? '🟡' : '🟢';
        console.log(`${heatLevel} ${category.padEnd(20)} | Avg Score: ${data.averageScore.toFixed(1)} | Count: ${data.count}`);
      });

    console.log('\n' + '─'.repeat(80) + '\n');
  }

  private async demonstrateBusinessContextImpact(): Promise<void> {
    console.log(chalk.yellow.bold('🏢 5. Business Context Impact Analysis\n'));

    const testFinding: SecurityFinding = {
      id: 'finding_demo_context',
      severity: 'high',
      category: 'authentication',
      title: 'Weak password policy implementation',
      description: 'Password policy allows weak passwords, increasing breach risk',
      evidence: { policy_strength: 'weak', min_length: 6, complexity: false },
      recommendation: 'Implement strong password policy with complexity requirements',
      compliance_impact: [
        { standard: 'SOC2', control: 'CC6.1', impact: 'medium' }
      ]
    };

    const contexts: Array<{ name: string; context: BusinessContext }> = [
      {
        name: 'Startup (Low Risk)',
        context: {
          asset_criticality: 'low',
          data_sensitivity: 'internal',
          compliance_requirements: [],
          business_hours: true,
          internet_facing: false,
          user_count: 50
        }
      },
      {
        name: 'Enterprise (Medium Risk)',
        context: {
          asset_criticality: 'medium',
          data_sensitivity: 'confidential',
          compliance_requirements: ['SOC2'],
          business_hours: true,
          internet_facing: true,
          user_count: 5000
        }
      },
      {
        name: 'Financial Institution (High Risk)',
        context: {
          asset_criticality: 'critical',
          data_sensitivity: 'restricted',
          compliance_requirements: ['SOC2', 'PCI', 'GDPR'],
          business_hours: true,
          internet_facing: true,
          user_count: 100000
        }
      }
    ];

    console.log(chalk.blue('Same vulnerability, different business contexts:\n'));

    for (const { name, context } of contexts) {
      const riskScore = await this.riskEngine.calculateRiskScore(testFinding, context);
      
      const scoreColor = riskScore.overall_score >= 80 ? chalk.red : 
                        riskScore.overall_score >= 60 ? chalk.yellow : 
                        riskScore.overall_score >= 40 ? chalk.blue : chalk.green;

      console.log(chalk.cyan(name));
      console.log(scoreColor(`├─ Risk Score: ${riskScore.overall_score}/100 (${riskScore.risk_level.toUpperCase()})`));
      console.log(`├─ Business Impact: ${riskScore.business_impact_score.toFixed(1)}`);
      console.log(`├─ Compliance Score: ${riskScore.compliance_score.toFixed(1)}`);
      console.log(`└─ Confidence: ${(riskScore.confidence * 100).toFixed(1)}%\n`);
    }

    console.log(chalk.yellow('Key Insights:'));
    console.log('• Same vulnerability severity, but risk scores vary significantly based on business context');
    console.log('• Critical assets and sensitive data increase risk multipliers');
    console.log('• Compliance requirements add regulatory risk factors');
    console.log('• User count affects potential blast radius calculations');
    console.log('• Internet-facing systems increase exploitability scores\n');

    console.log('\n' + '─'.repeat(80) + '\n');
  }

  private displayRiskScore(riskScore: RiskScore): void {
    const scoreColor = riskScore.overall_score >= 80 ? chalk.red : 
                      riskScore.overall_score >= 60 ? chalk.yellow : 
                      riskScore.overall_score >= 40 ? chalk.blue : chalk.green;

    console.log(chalk.blue('🎯 ML Risk Assessment Results:\n'));
    console.log(scoreColor(`Overall Risk Score: ${riskScore.overall_score}/100`));
    console.log(scoreColor(`Risk Level: ${riskScore.risk_level.toUpperCase()}`));
    console.log(`Model Confidence: ${(riskScore.confidence * 100).toFixed(1)}%\n`);

    console.log(chalk.yellow('📊 Component Breakdown:'));
    console.log(`├─ Severity Score: ${riskScore.severity_score.toFixed(1)}/100`);
    console.log(`├─ Exploitability Score: ${riskScore.exploitability_score.toFixed(1)}/100`);
    console.log(`├─ Business Impact Score: ${riskScore.business_impact_score.toFixed(1)}/100`);
    console.log(`├─ Compliance Score: ${riskScore.compliance_score.toFixed(1)}/100`);
    console.log(`└─ Temporal Score: ${riskScore.temporal_score.toFixed(1)}/100\n`);

    if (riskScore.reasoning.length > 0) {
      console.log(chalk.yellow('🧠 AI Analysis Reasoning:'));
      riskScore.reasoning.forEach((reason, index) => {
        console.log(`${index + 1}. ${reason}`);
      });
    }
  }

  private generateSampleFindings(count: number): SecurityFinding[] {
    const severities: Array<'critical' | 'high' | 'medium' | 'low' | 'info'> = ['critical', 'high', 'medium', 'low', 'info'];
    const categories = ['injection', 'authentication', 'authorization', 'cryptography', 'network-security', 'configuration'];
    
    const titleTemplates: Record<string, string[]> = {
      injection: ['SQL Injection vulnerability', 'XSS vulnerability', 'Command injection flaw', 'LDAP injection risk'],
      authentication: ['Weak authentication mechanism', 'Missing MFA requirement', 'Password policy violation', 'Session management flaw'],
      authorization: ['Missing authorization checks', 'Privilege escalation vulnerability', 'RBAC misconfiguration', 'Access control bypass'],
      cryptography: ['Weak encryption implementation', 'Hardcoded encryption keys', 'Insecure random number generation', 'Deprecated cipher usage'],
      'network-security': ['Open network port', 'Unencrypted communication', 'Network segmentation issue', 'Firewall misconfiguration'],
      configuration: ['Security misconfiguration', 'Default credentials', 'Exposed admin interface', 'Debug mode enabled']
    };

    const findings: SecurityFinding[] = [];

    for (let i = 0; i < count; i++) {
      const category = categories[Math.floor(Math.random() * categories.length)];
      const severity = severities[Math.floor(Math.random() * severities.length)];
      const templates = titleTemplates[category];
      const title = templates[Math.floor(Math.random() * templates.length)];

      findings.push({
        id: `finding_${i + 1}`,
        severity,
        category,
        title: `${title} #${i + 1}`,
        description: `${severity.charAt(0).toUpperCase() + severity.slice(1)} severity ${category} finding discovered during security scan`,
        evidence: {
          scan_id: `scan_${Date.now()}`,
          location: `/path/to/vulnerable/component${i}`,
          discovery_method: 'automated_scan'
        },
        recommendation: `Review and remediate this ${severity} ${category} finding according to security best practices`,
        compliance_impact: (severity === 'critical' || severity === 'high') ? [
          { standard: 'SOC2', control: 'CC6.1', impact: severity }
        ] : []
      });
    }

    return findings;
  }

  private getTrendIcon(trend: string): string {
    switch (trend) {
      case 'increasing': return '📈';
      case 'decreasing': return '📉';
      case 'stable': return '➡️';
      default: return '❓';
    }
  }

  private calculateCategoryRisks(findings: Array<SecurityFinding & { risk_score: RiskScore }>): Record<string, { averageScore: number; count: number }> {
    const categoryData: Record<string, { scores: number[]; count: number }> = {};

    findings.forEach(finding => {
      if (!categoryData[finding.category]) {
        categoryData[finding.category] = { scores: [], count: 0 };
      }
      categoryData[finding.category].scores.push(finding.risk_score.overall_score);
      categoryData[finding.category].count++;
    });

    const result: Record<string, { averageScore: number; count: number }> = {};
    Object.entries(categoryData).forEach(([category, data]) => {
      const averageScore = data.scores.reduce((sum, score) => sum + score, 0) / data.scores.length;
      result[category] = { averageScore, count: data.count };
    });

    return result;
  }
}

// CLI integration
export async function runRiskScoringDemo(): Promise<void> {
  const demo = new RiskScoringDemo();
  await demo.runDemo();
}
