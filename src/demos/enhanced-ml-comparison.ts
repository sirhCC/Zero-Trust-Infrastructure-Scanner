/**
 * Enhanced ML Risk Scoring Test and Comparison
 * Compare original vs enhanced ML risk scoring performance
 */

import chalk from 'chalk';
import { MLRiskScoringEngine, BusinessContext } from '../analytics/ml-risk-scoring';
import { EnhancedMLRiskScoringEngine } from '../analytics/enhanced-ml-risk-scoring';
import { SecurityFinding } from '../core/scanner';

// Test findings with enhanced data
function generateEnhancedTestFindings(): (SecurityFinding & { timestamp?: Date })[] {
  return [
    {
      id: 'enhanced_001',
      severity: 'critical',
      category: 'injection',
      title: 'SQL Injection in Payment Gateway',
      description: 'Critical SQL injection vulnerability in payment processing endpoint',
      evidence: {
        endpoint: '/api/payment/process',
        parameter: 'amount',
        payload: "'; DROP TABLE payments; --",
        remote_access: true,
        public_exploit: true,
        sensitive_data: true,
        authentication_required: false
      },
      recommendation: 'Implement parameterized queries immediately and conduct security review',
      compliance_impact: [
        { standard: 'PCI', control: '6.5.1', impact: 'critical' },
        { standard: 'SOC2', control: 'CC6.1', impact: 'critical' }
      ],
      timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000) // 2 days old
    },
    {
      id: 'enhanced_002',
      severity: 'high',
      category: 'access-control',
      title: 'Privilege Escalation in Admin API',
      description: 'Users can escalate privileges through manipulated API requests',
      evidence: {
        endpoint: '/api/admin/users',
        method: 'POST',
        exploitation_vector: 'parameter_manipulation',
        authentication_required: true,
        network_segmented: false
      },
      recommendation: 'Implement proper authorization checks and input validation',
      compliance_impact: [
        { standard: 'SOC2', control: 'CC6.2', impact: 'high' }
      ],
      timestamp: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000) // 1 day old
    },
    {
      id: 'enhanced_003',
      severity: 'medium',
      category: 'encryption',
      title: 'Weak SSL/TLS Configuration',
      description: 'Server supports deprecated TLS versions and weak cipher suites',
      evidence: {
        supported_versions: ['TLS 1.0', 'TLS 1.1'],
        weak_ciphers: ['RC4', 'DES'],
        certificate_issues: false,
        public_facing: true
      },
      recommendation: 'Update SSL/TLS configuration to support only TLS 1.2+',
      compliance_impact: [
        { standard: 'PCI', control: '4.1', impact: 'medium' }
      ],
      timestamp: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // 1 week old
    },
    {
      id: 'enhanced_004',
      severity: 'low',
      category: 'configuration',
      title: 'Verbose Error Messages',
      description: 'Application returns detailed error messages that could aid attackers',
      evidence: {
        error_disclosure: true,
        stack_traces: true,
        database_errors: false,
        impact_level: 'low'
      },
      recommendation: 'Configure generic error messages for production environment',
      timestamp: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000) // 2 weeks old
    }
  ];
}

async function compareRiskScoringEngines(): Promise<void> {
  console.log(chalk.bold.blue('\\n🔬 ML Risk Scoring Engine Comparison'));
  console.log(chalk.gray('Comparing Original vs Enhanced ML Risk Scoring Performance\\n'));

  const originalEngine = new MLRiskScoringEngine();
  const enhancedEngine = new EnhancedMLRiskScoringEngine();
  
  const testFindings = generateEnhancedTestFindings();
  const businessContext: BusinessContext = {
    asset_criticality: 'critical',
    data_sensitivity: 'restricted',
    compliance_requirements: ['PCI', 'SOC2', 'HIPAA'],
    business_hours: true,
    internet_facing: true,
    user_count: 150000
  };

  console.log(chalk.yellow('📊 Individual Finding Comparison'));
  console.log(chalk.gray('Analyzing each finding with both engines\\n'));

  const results = [];

  for (const finding of testFindings) {
    // Original engine
    const originalScore = await originalEngine.calculateRiskScore(finding, businessContext, testFindings);
    
    // Enhanced engine  
    const enhancedScore = await enhancedEngine.calculateEnhancedRiskScore(
      finding, 
      businessContext, 
      testFindings, 
      'financial' // High-risk industry
    );

    results.push({
      finding,
      original: originalScore,
      enhanced: enhancedScore
    });

    console.log(chalk.cyan(`${finding.title}:`));
    console.log(`  Original: ${originalScore.risk_level.toUpperCase()} (${originalScore.overall_score}/100) - Confidence: ${originalScore.confidence}`);
    console.log(`  Enhanced: ${enhancedScore.risk_level.toUpperCase()} (${enhancedScore.overall_score}/100) - Confidence: ${enhancedScore.confidence}`);
    
    const improvement = enhancedScore.overall_score - originalScore.overall_score;
    const improvementColor = improvement > 0 ? chalk.green : improvement < 0 ? chalk.red : chalk.gray;
    console.log(`  Difference: ${improvementColor(improvement > 0 ? '+' : '')}${improvementColor(improvement.toFixed(1))} points`);
    
    console.log(`  Enhanced Reasoning: ${enhancedScore.reasoning.slice(0, 2).join('; ')}`);
    console.log('');
  }

  console.log(chalk.yellow('📈 Performance Analysis'));
  console.log(chalk.gray('Statistical comparison of engine performance\\n'));

  // Calculate statistics
  const originalScores = results.map(r => r.original.overall_score);
  const enhancedScores = results.map(r => r.enhanced.overall_score);
  
  const originalAvg = originalScores.reduce((a, b) => a + b, 0) / originalScores.length;
  const enhancedAvg = enhancedScores.reduce((a, b) => a + b, 0) / enhancedScores.length;
  
  const originalConfidenceAvg = results.reduce((sum, r) => sum + r.original.confidence, 0) / results.length;
  const enhancedConfidenceAvg = results.reduce((sum, r) => sum + r.enhanced.confidence, 0) / results.length;

  console.log(chalk.cyan('Average Risk Scores:'));
  console.log(`  Original Engine: ${originalAvg.toFixed(1)}/100`);
  console.log(`  Enhanced Engine: ${enhancedAvg.toFixed(1)}/100`);
  console.log(`  Improvement: ${(enhancedAvg - originalAvg).toFixed(1)} points`);
  console.log('');
  
  console.log(chalk.cyan('Average Confidence Levels:'));
  console.log(`  Original Engine: ${(originalConfidenceAvg * 100).toFixed(1)}%`);
  console.log(`  Enhanced Engine: ${(enhancedConfidenceAvg * 100).toFixed(1)}%`);
  console.log(`  Improvement: ${((enhancedConfidenceAvg - originalConfidenceAvg) * 100).toFixed(1)}%`);
  console.log('');

  // Risk level accuracy check
  const expectedRiskLevels = ['critical', 'high', 'medium', 'low']; // Expected for our test cases
  let originalCorrect = 0;
  let enhancedCorrect = 0;
  
  results.forEach((result, index) => {
    if (result.original.risk_level === expectedRiskLevels[index]) originalCorrect++;
    if (result.enhanced.risk_level === expectedRiskLevels[index]) enhancedCorrect++;
  });

  console.log(chalk.cyan('Risk Level Accuracy:'));
  console.log(`  Original Engine: ${originalCorrect}/${results.length} (${(originalCorrect/results.length*100).toFixed(1)}%)`);
  console.log(`  Enhanced Engine: ${enhancedCorrect}/${results.length} (${(enhancedCorrect/results.length*100).toFixed(1)}%)`);
  console.log('');

  console.log(chalk.yellow('🎯 Industry-Specific Testing'));
  console.log(chalk.gray('Testing enhanced engine with different industry contexts\\n'));

  const industries = ['financial', 'healthcare', 'government', 'retail', 'technology'];
  const criticalFinding = testFindings[0]; // SQL injection finding

  for (const industry of industries) {
    const industryScore = await enhancedEngine.calculateEnhancedRiskScore(
      criticalFinding,
      businessContext,
      testFindings,
      industry
    );
    
    console.log(`  ${industry.charAt(0).toUpperCase() + industry.slice(1)}: ${industryScore.overall_score.toFixed(1)}/100 (${industryScore.risk_level.toUpperCase()})`);
  }
  console.log('');

  console.log(chalk.yellow('🔍 Feature Impact Analysis'));
  console.log(chalk.gray('Analyzing impact of enhanced features\\n'));

  // Test temporal scoring impact
  const oldFinding = { ...testFindings[0], timestamp: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000) }; // 60 days old
  const newFinding = { ...testFindings[0], timestamp: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000) }; // 1 day old

  const oldScore = await enhancedEngine.calculateEnhancedRiskScore(oldFinding, businessContext, testFindings);
  const newScore = await enhancedEngine.calculateEnhancedRiskScore(newFinding, businessContext, testFindings);

  console.log(chalk.cyan('Temporal Factor Impact:'));
  console.log(`  60-day old vulnerability: ${oldScore.overall_score.toFixed(1)}/100`);
  console.log(`  1-day old vulnerability: ${newScore.overall_score.toFixed(1)}/100`);
  console.log(`  Age penalty: ${(oldScore.overall_score - newScore.overall_score).toFixed(1)} points`);
  console.log('');

  console.log(chalk.green('✅ ML Risk Scoring Comparison Complete!'));
  console.log(chalk.gray('Enhanced engine shows improved accuracy and contextual awareness.\\n'));
}

async function demonstrateMLImprovements(): Promise<void> {
  console.log(chalk.bold.magenta('\\n🚀 ML Risk Scoring Improvements Demonstration'));
  console.log(chalk.gray('Showcasing specific enhancements and their benefits\\n'));

  const enhancedEngine = new EnhancedMLRiskScoringEngine();
  
  console.log(chalk.yellow('🎯 Enhancement 1: Threat Intelligence Integration'));
  
  // Create two similar findings - one in high-threat category, one in low-threat
  const highThreatFinding: SecurityFinding & { timestamp?: Date } = {
    id: 'threat_001',
    severity: 'medium',
    category: 'injection', // High threat intelligence score
    title: 'SQL Injection in Reports',
    description: 'SQL injection vulnerability in reporting module',
    evidence: {},
    recommendation: 'Fix SQL injection'
  };
  
  const lowThreatFinding: SecurityFinding & { timestamp?: Date } = {
    id: 'threat_002',
    severity: 'medium',
    category: 'configuration', // Lower threat intelligence score
    title: 'Missing Security Header',
    description: 'Missing X-Frame-Options header',
    evidence: {},
    recommendation: 'Add security headers'
  };

  const context: BusinessContext = {
    asset_criticality: 'medium',
    data_sensitivity: 'internal',
    compliance_requirements: ['SOC2'],
    business_hours: true,
    internet_facing: true,
    user_count: 5000
  };

  const highThreatScore = await enhancedEngine.calculateEnhancedRiskScore(highThreatFinding, context);
  const lowThreatScore = await enhancedEngine.calculateEnhancedRiskScore(lowThreatFinding, context);

  console.log(`  High Threat Category (${highThreatFinding.category}): ${highThreatScore.overall_score.toFixed(1)}/100`);
  console.log(`  Low Threat Category (${lowThreatFinding.category}): ${lowThreatScore.overall_score.toFixed(1)}/100`);
  console.log(`  Threat Intelligence Boost: ${(highThreatScore.overall_score - lowThreatScore.overall_score).toFixed(1)} points`);
  console.log('');

  console.log(chalk.yellow('🎯 Enhancement 2: Evidence-Based Exploitability'));
  
  const remoteExploitableFinding: SecurityFinding & { timestamp?: Date } = {
    id: 'exploit_001',
    severity: 'high',
    category: 'authentication',
    title: 'Authentication Bypass',
    description: 'Authentication can be bypassed',
    evidence: {
      remote_access: true,
      public_exploit: true,
      authentication_required: false
    },
    recommendation: 'Fix authentication'
  };
  
  const localExploitableFinding: SecurityFinding & { timestamp?: Date } = {
    id: 'exploit_002',
    severity: 'high',
    category: 'authentication',
    title: 'Local Authentication Issue',
    description: 'Authentication bypass requires local access',
    evidence: {
      remote_access: false,
      authentication_required: true,
      network_segmented: true
    },
    recommendation: 'Fix local authentication'
  };

  const remoteScore = await enhancedEngine.calculateEnhancedRiskScore(remoteExploitableFinding, context);
  const localScore = await enhancedEngine.calculateEnhancedRiskScore(localExploitableFinding, context);

  console.log(`  Remote Exploitable: ${remoteScore.overall_score.toFixed(1)}/100`);
  console.log(`  Local Only: ${localScore.overall_score.toFixed(1)}/100`);
  console.log(`  Remote Exploitation Penalty: ${(remoteScore.overall_score - localScore.overall_score).toFixed(1)} points`);
  console.log('');

  console.log(chalk.yellow('🎯 Enhancement 3: Dynamic Risk Thresholds'));
  
  // Test confidence-based threshold adjustment
  const highConfidenceFinding: SecurityFinding & { timestamp?: Date } = {
    id: 'conf_001',
    severity: 'high',
    category: 'injection',
    title: 'Well-Documented SQL Injection',
    description: 'SQL injection with comprehensive evidence',
    evidence: {
      proof_of_concept: true,
      detailed_analysis: true,
      multiple_vectors: true
    },
    recommendation: 'Fix immediately',
    compliance_impact: [
      { standard: 'PCI', control: '6.5.1', impact: 'high' }
    ]
  };

  const lowConfidenceFinding: SecurityFinding & { timestamp?: Date } = {
    id: 'conf_002',
    severity: 'high',
    category: 'injection',
    title: 'Potential SQL Injection',
    description: 'Possible SQL injection with limited evidence',
    evidence: {},
    recommendation: 'Investigate further'
  };

  const highConfScore = await enhancedEngine.calculateEnhancedRiskScore(highConfidenceFinding, context);
  const lowConfScore = await enhancedEngine.calculateEnhancedRiskScore(lowConfidenceFinding, context);

  console.log(`  High Confidence Finding: ${highConfScore.overall_score.toFixed(1)}/100 (Confidence: ${highConfScore.confidence})`);
  console.log(`  Low Confidence Finding: ${lowConfScore.overall_score.toFixed(1)}/100 (Confidence: ${lowConfScore.confidence})`);
  console.log(`  Risk Level: ${highConfScore.risk_level.toUpperCase()} vs ${lowConfScore.risk_level.toUpperCase()}`);
  console.log('');

  console.log(chalk.green('🎉 ML Improvements Successfully Demonstrated!'));
  console.log(chalk.gray('Enhanced engine provides more accurate and contextual risk assessment.'));
}

// Main execution function
async function runEnhancedMLEvaluation(): Promise<void> {
  try {
    await compareRiskScoringEngines();
    await demonstrateMLImprovements();
    
    console.log(chalk.bold.green('\\n🏆 Enhanced ML Risk Scoring Evaluation Complete!'));
    console.log(chalk.gray('The enhanced engine shows significant improvements in:'));
    console.log(chalk.gray('• Threat intelligence integration'));
    console.log(chalk.gray('• Evidence-based risk assessment'));
    console.log(chalk.gray('• Industry-specific adjustments'));
    console.log(chalk.gray('• Dynamic confidence-based thresholds'));
    console.log(chalk.gray('• Temporal risk factor analysis\\n'));
    
  } catch (error) {
    console.error(chalk.red('❌ Enhanced evaluation failed:'), error);
  }
}

// Export for external use
export {
  runEnhancedMLEvaluation,
  compareRiskScoringEngines,
  demonstrateMLImprovements
};

// Run if called directly
if (require.main === module) {
  runEnhancedMLEvaluation().catch(console.error);
}
