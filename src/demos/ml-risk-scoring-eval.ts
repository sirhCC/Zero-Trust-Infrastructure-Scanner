/**
 * ML Risk Scoring Test Suite and Evaluation
 * Test scenarios to validate and improve the ML risk scoring engine
 */

import chalk from 'chalk';
import { MLRiskScoringEngine, BusinessContext } from '../analytics/ml-risk-scoring';
import { SecurityFinding } from '../core/scanner';

// Test data generators
function generateTestFindings(): SecurityFinding[] {
  return [
    {
      id: 'test_001',
      severity: 'critical',
      category: 'injection',
      title: 'SQL Injection in Authentication',
      description: 'Critical SQL injection vulnerability allowing database access bypass',
      evidence: {
        endpoint: '/api/auth/login',
        parameter: 'username',
        payload: "' OR 1=1 --"
      },
      recommendation: 'Implement parameterized queries and input validation',
      compliance_impact: [
        { standard: 'SOC2', control: 'CC6.1', impact: 'critical' },
        { standard: 'PCI', control: '6.5.1', impact: 'high' }
      ]
    },
    {
      id: 'test_002',
      severity: 'high',
      category: 'authentication',
      title: 'Weak Password Policy',
      description: 'Password policy allows weak passwords (minimum 6 characters)',
      evidence: {
        policy: 'min_length: 6, no_complexity_requirements',
        affected_users: 1500
      },
      recommendation: 'Enforce strong password policy with complexity requirements',
      compliance_impact: [
        { standard: 'SOC2', control: 'CC6.1', impact: 'medium' }
      ]
    },
    {
      id: 'test_003',
      severity: 'medium',
      category: 'encryption',
      title: 'Unencrypted Data in Transit',
      description: 'API endpoints not using HTTPS for sensitive data transmission',
      evidence: {
        endpoints: ['/api/user/profile', '/api/payment/process'],
        protocol: 'HTTP'
      },
      recommendation: 'Enable HTTPS/TLS for all API endpoints',
      compliance_impact: [
        { standard: 'PCI', control: '4.1', impact: 'high' },
        { standard: 'HIPAA', control: '164.312(e)(1)', impact: 'medium' }
      ]
    },
    {
      id: 'test_004',
      severity: 'low',
      category: 'configuration',
      title: 'Missing Security Headers',
      description: 'Web application missing security headers (CSP, HSTS)',
      evidence: {
        missing_headers: ['Content-Security-Policy', 'Strict-Transport-Security'],
        endpoints: ['/dashboard', '/admin']
      },
      recommendation: 'Add security headers to prevent XSS and other attacks'
    },
    {
      id: 'test_005',
      severity: 'critical',
      category: 'access-control',
      title: 'Admin Panel Publicly Accessible',
      description: 'Administrative interface accessible without authentication',
      evidence: {
        url: '/admin',
        authentication_required: false,
        exposed_functions: ['user_management', 'system_configuration']
      },
      recommendation: 'Implement proper authentication and authorization for admin panel',
      compliance_impact: [
        { standard: 'SOC2', control: 'CC6.2', impact: 'critical' },
        { standard: 'PCI', control: '7.1', impact: 'critical' }
      ]
    }
  ];
}

function generateBusinessContexts(): BusinessContext[] {
  return [
    {
      asset_criticality: 'critical',
      data_sensitivity: 'restricted',
      compliance_requirements: ['SOC2', 'PCI', 'HIPAA'],
      business_hours: true,
      internet_facing: true,
      user_count: 100000
    },
    {
      asset_criticality: 'medium',
      data_sensitivity: 'internal',
      compliance_requirements: ['SOC2'],
      business_hours: false,
      internet_facing: false,
      user_count: 500
    },
    {
      asset_criticality: 'high',
      data_sensitivity: 'confidential',
      compliance_requirements: ['GDPR', 'SOC2'],
      business_hours: true,
      internet_facing: true,
      user_count: 50000
    }
  ];
}

async function runRiskScoringTests(): Promise<void> {
  console.log(chalk.bold.blue('\\n🎯 ML Risk Scoring Engine - Test Suite'));
  console.log(chalk.gray('Testing and evaluating risk scoring accuracy and performance\\n'));

  const engine = new MLRiskScoringEngine();
  const testFindings = generateTestFindings();
  const businessContexts = generateBusinessContexts();

  console.log(chalk.yellow('📊 Test 1: Individual Risk Score Calculation'));
  console.log(chalk.gray('Testing risk scoring for individual findings across different contexts\\n'));

  // Test individual findings across different business contexts
  for (const context of businessContexts) {
    console.log(chalk.cyan(`Context: ${context.asset_criticality} criticality, ${context.data_sensitivity} data`));
    
    for (const finding of testFindings) {
      const riskScore = await engine.calculateRiskScore(finding, context);
      
      const severityColor = {
        critical: chalk.red,
        high: chalk.redBright,
        medium: chalk.yellow,
        low: chalk.blue
      }[riskScore.risk_level];
      
      console.log(`  ${finding.id}: ${severityColor(riskScore.risk_level.toUpperCase())} (${riskScore.overall_score}/100)`);
      console.log(`    Severity: ${riskScore.severity_score}, Exploitability: ${riskScore.exploitability_score}`);
      console.log(`    Business Impact: ${riskScore.business_impact_score}, Compliance: ${riskScore.compliance_score}`);
      console.log(`    Confidence: ${riskScore.confidence}, Reasoning: ${riskScore.reasoning.length} factors`);
      console.log('');
    }
    console.log('');
  }

  console.log(chalk.yellow('📊 Test 2: Batch Prioritization'));
  console.log(chalk.gray('Testing batch processing and finding prioritization\\n'));

  const criticalContext = businessContexts[0]; // Critical business context
  const prioritizedFindings = await engine.prioritizeFindings(testFindings, criticalContext);

  console.log(chalk.cyan('Risk-Prioritized Findings (High to Low):'));
  prioritizedFindings.forEach((finding, index) => {
    const riskColor = {
      critical: chalk.red,
      high: chalk.redBright,
      medium: chalk.yellow,
      low: chalk.blue
    }[finding.risk_score.risk_level];
    
    console.log(`  ${index + 1}. ${finding.title}`);
    console.log(`     ${riskColor(finding.risk_score.risk_level.toUpperCase())} - Score: ${finding.risk_score.overall_score}/100`);
    console.log(`     Original Severity: ${finding.severity} → ML Risk Level: ${finding.risk_score.risk_level}`);
    console.log('');
  });

  console.log(chalk.yellow('📊 Test 3: Risk Trend Prediction'));
  console.log(chalk.gray('Testing predictive risk trend analysis\\n'));

  // Generate mock historical risk scores
  const historicalScores = [45, 52, 48, 55, 62, 58, 65, 70, 68, 75, 73, 78];
  const trendPrediction = engine.predictRiskTrends(historicalScores, 14);

  console.log(chalk.cyan('Historical Risk Trend Analysis:'));
  console.log(`  Current scores: [${historicalScores.join(', ')}]`);
  console.log(`  Trend: ${trendPrediction.trend.toUpperCase()}`);
  console.log(`  Confidence: ${(trendPrediction.confidence * 100).toFixed(1)}%`);
  console.log(`  14-day prediction: [${trendPrediction.predicted_scores.slice(0, 5).map(s => s.toFixed(1)).join(', ')}...]`);
  console.log('');

  console.log(chalk.yellow('📊 Test 4: Risk Report Generation'));
  console.log(chalk.gray('Testing comprehensive risk reporting\\n'));

  const riskReport = engine.generateRiskReport(prioritizedFindings);
  
  console.log(chalk.cyan('Risk Assessment Summary:'));
  console.log(`  Total Findings: ${riskReport.summary.total_findings}`);
  console.log(`  Average Risk Score: ${riskReport.summary.average_risk_score.toFixed(1)}/100`);
  console.log(`  Overall Risk Level: ${riskReport.summary.overall_risk_level.toUpperCase()}`);
  console.log('');
  
  console.log(chalk.cyan('Risk Distribution:'));
  console.log(`  🔴 Critical: ${riskReport.summary.critical_risks}`);
  console.log(`  🟠 High: ${riskReport.summary.high_risks}`);
  console.log(`  🟡 Medium: ${riskReport.summary.medium_risks}`);
  console.log(`  🟢 Low: ${riskReport.summary.low_risks}`);
  console.log('');

  console.log(chalk.cyan('Top 3 Critical Risks:'));
  riskReport.top_risks.slice(0, 3).forEach((risk, index) => {
    console.log(`  ${index + 1}. ${risk.title} (${risk.risk_score.overall_score}/100)`);
    console.log(`     ${risk.risk_score.reasoning.slice(0, 2).join('; ')}`);
    console.log('');
  });

  console.log(chalk.yellow('🔍 Test 5: Edge Case Analysis'));
  console.log(chalk.gray('Testing edge cases and boundary conditions\\n'));

  // Test with minimal data
  const minimalFinding: SecurityFinding = {
    id: 'minimal_001',
    severity: 'info',
    category: 'informational',
    title: 'Minimal Test Finding',
    description: 'Testing with minimal required fields',
    evidence: {},
    recommendation: 'No action required'
  };

  const minimalContext: BusinessContext = {
    asset_criticality: 'low',
    data_sensitivity: 'public',
    compliance_requirements: [],
    business_hours: false,
    internet_facing: false,
    user_count: 1
  };

  const minimalScore = await engine.calculateRiskScore(minimalFinding, minimalContext);
  console.log(chalk.cyan('Minimal Data Test:'));
  console.log(`  Risk Score: ${minimalScore.overall_score}/100`);
  console.log(`  Risk Level: ${minimalScore.risk_level}`);
  console.log(`  Confidence: ${minimalScore.confidence}`);
  console.log('');

  console.log(chalk.green('✅ ML Risk Scoring Test Suite Complete!'));
  console.log(chalk.gray('All tests executed successfully. Review results for accuracy and performance.\\n'));
}

async function evaluateRiskScoringAccuracy(): Promise<void> {
  console.log(chalk.bold.magenta('\\n🔬 Risk Scoring Accuracy Evaluation'));
  console.log(chalk.gray('Evaluating ML model accuracy against expected outcomes\\n'));

  const engine = new MLRiskScoringEngine();
  
  // Expected vs Actual risk assessment
  const testCases = [
    {
      finding: {
        id: 'accuracy_001',
        severity: 'critical' as const,
        category: 'injection',
        title: 'SQL Injection in Payment System',
        description: 'SQL injection allowing financial data access',
        evidence: { sensitive_data: true, external_access: true },
        recommendation: 'Immediate patching required',
        compliance_impact: [
          { standard: 'PCI' as const, control: '6.5.1', impact: 'critical' as const }
        ]
      },
      context: {
        asset_criticality: 'critical' as const,
        data_sensitivity: 'restricted' as const,
        compliance_requirements: ['PCI', 'SOC2'],
        business_hours: true,
        internet_facing: true,
        user_count: 100000
      },
      expectedRiskLevel: 'critical' as const,
      expectedScoreRange: [85, 100]
    },
    {
      finding: {
        id: 'accuracy_002',
        severity: 'low' as const,
        category: 'configuration',
        title: 'Missing Cache Headers',
        description: 'Static assets missing cache headers',
        evidence: { performance_impact: 'minimal' },
        recommendation: 'Configure cache headers for better performance'
      },
      context: {
        asset_criticality: 'low' as const,
        data_sensitivity: 'public' as const,
        compliance_requirements: [],
        business_hours: false,
        internet_facing: false,
        user_count: 50
      },
      expectedRiskLevel: 'low' as const,
      expectedScoreRange: [0, 25]
    }
  ];

  let correctRiskLevels = 0;
  let correctScoreRanges = 0;

  for (const testCase of testCases) {
    const actualScore = await engine.calculateRiskScore(testCase.finding, testCase.context);
    
    const riskLevelCorrect = actualScore.risk_level === testCase.expectedRiskLevel;
    const scoreInRange = actualScore.overall_score >= testCase.expectedScoreRange[0] && 
                        actualScore.overall_score <= testCase.expectedScoreRange[1];

    if (riskLevelCorrect) correctRiskLevels++;
    if (scoreInRange) correctScoreRanges++;

    console.log(chalk.cyan(`Test Case: ${testCase.finding.title}`));
    console.log(`  Expected Risk Level: ${testCase.expectedRiskLevel} | Actual: ${actualScore.risk_level} ${riskLevelCorrect ? '✅' : '❌'}`);
    console.log(`  Expected Score Range: ${testCase.expectedScoreRange[0]}-${testCase.expectedScoreRange[1]} | Actual: ${actualScore.overall_score} ${scoreInRange ? '✅' : '❌'}`);
    console.log(`  Confidence: ${actualScore.confidence}`);
    console.log('');
  }

  const riskLevelAccuracy = (correctRiskLevels / testCases.length) * 100;
  const scoreRangeAccuracy = (correctScoreRanges / testCases.length) * 100;

  console.log(chalk.bold.green('📊 Accuracy Results:'));
  console.log(`  Risk Level Accuracy: ${riskLevelAccuracy.toFixed(1)}%`);
  console.log(`  Score Range Accuracy: ${scoreRangeAccuracy.toFixed(1)}%`);
  console.log(`  Overall Model Performance: ${((riskLevelAccuracy + scoreRangeAccuracy) / 2).toFixed(1)}%`);
  console.log('');
}

async function suggestImprovements(): Promise<void> {
  console.log(chalk.bold.cyan('\\n💡 ML Risk Scoring Improvement Suggestions'));
  console.log(chalk.gray('Based on test results, here are potential improvements:\\n'));

  const improvements = [
    {
      area: 'Feature Engineering',
      suggestions: [
        'Add temporal decay factors for vulnerability age',
        'Incorporate external threat intelligence feeds',
        'Include network topology and asset relationships',
        'Add historical exploit data correlation'
      ]
    },
    {
      area: 'Model Enhancement',
      suggestions: [
        'Implement ensemble methods (Random Forest + Gradient Boosting)',
        'Add deep learning models for pattern recognition',
        'Include reinforcement learning for adaptive scoring',
        'Implement active learning for continuous improvement'
      ]
    },
    {
      area: 'Business Logic',
      suggestions: [
        'Dynamic weight adjustment based on threat landscape',
        'Industry-specific risk factor customization',
        'Real-time context awareness (incident response mode)',
        'Integration with SIEM and threat intelligence platforms'
      ]
    },
    {
      area: 'Validation & Testing',
      suggestions: [
        'Implement cross-validation with historical incident data',
        'Add A/B testing framework for model improvements',
        'Create benchmark datasets for consistent evaluation',
        'Implement explainable AI for decision transparency'
      ]
    }
  ];

  improvements.forEach(improvement => {
    console.log(chalk.yellow(`🔧 ${improvement.area}:`));
    improvement.suggestions.forEach(suggestion => {
      console.log(chalk.gray(`  • ${suggestion}`));
    });
    console.log('');
  });

  console.log(chalk.bold.green('🎯 Next Steps:'));
  console.log(chalk.gray('1. Implement A/B testing framework'));
  console.log(chalk.gray('2. Collect more historical data for training'));
  console.log(chalk.gray('3. Add external threat intelligence integration'));
  console.log(chalk.gray('4. Implement ensemble methods for improved accuracy'));
  console.log(chalk.gray('5. Create industry-specific risk models\\n'));
}

// Main execution function
async function runMLRiskScoringEvaluation(): Promise<void> {
  try {
    await runRiskScoringTests();
    await evaluateRiskScoringAccuracy();
    await suggestImprovements();
    
    console.log(chalk.bold.green('🎉 ML Risk Scoring Evaluation Complete!'));
    console.log(chalk.gray('All tests and evaluations have been completed successfully.'));
    
  } catch (error) {
    console.error(chalk.red('❌ Evaluation failed:'), error);
  }
}

// Export for external use
export {
  runMLRiskScoringEvaluation,
  runRiskScoringTests,
  evaluateRiskScoringAccuracy,
  suggestImprovements,
  generateTestFindings,
  generateBusinessContexts
};

// Run if called directly
if (require.main === module) {
  runMLRiskScoringEvaluation().catch(console.error);
}
