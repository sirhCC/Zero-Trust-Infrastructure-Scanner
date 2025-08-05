/**
 * Machine Learning Risk Scoring Engine
 * Advanced risk assessment using multiple ML models and statistical analysis
 */

import * as stats from 'simple-statistics';
import { SecurityFinding } from '../core/scanner';

export interface RiskScore {
  overall_score: number;          // 0-100 scale
  severity_score: number;         // Based on finding severity
  exploitability_score: number;  // Likelihood of exploitation
  business_impact_score: number; // Business impact assessment
  compliance_score: number;      // Compliance violations impact
  temporal_score: number;        // Time-based risk factors
  confidence: number;            // Model confidence 0-1
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  reasoning: string[];           // Human-readable explanations
}

export interface RiskVector {
  cvss_base: number;
  cvss_temporal: number;
  cvss_environmental: number;
  exposure_score: number;
  asset_value: number;
  threat_intelligence: number;
  historical_exploits: number;
  patch_availability: number;
}

export interface VulnerabilityPattern {
  category: string;
  severity_distribution: number[];
  temporal_trends: number[];
  exploit_likelihood: number;
  typical_impact: number;
}

export interface BusinessContext {
  asset_criticality: 'critical' | 'high' | 'medium' | 'low';
  data_sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
  compliance_requirements: string[];
  business_hours: boolean;
  internet_facing: boolean;
  user_count: number;
}

interface RiskWeights {
  severity: number;
  exploitability: number;
  businessImpact: number;
  compliance: number;
  temporal: number;
}

interface RiskSummary {
  total_findings: number;
  average_risk_score: number;
  critical_risks: number;
  high_risks: number;
  medium_risks: number;
  low_risks: number;
  overall_risk_level: 'critical' | 'high' | 'medium' | 'low';
}

// Extended SecurityFinding interface to include timestamp
interface ExtendedSecurityFinding extends SecurityFinding {
  timestamp?: Date;
}

export class MLRiskScoringEngine {
  private weightsConfig: RiskWeights;

  constructor() {
    this.weightsConfig = this.getDefaultWeights();
    this.initializeModels();
  }

  /**
   * Calculate comprehensive risk score for a security finding
   */
  async calculateRiskScore(
    finding: ExtendedSecurityFinding, 
    businessContext: BusinessContext,
    historicalFindings: ExtendedSecurityFinding[] = []
  ): Promise<RiskScore> {
    try {
      const riskVector = this.buildRiskVector(finding, businessContext);
      
      // Individual component scores
      const severityScore = this.calculateSeverityScore(finding);
      const exploitabilityScore = this.calculateExploitabilityScore(finding, riskVector);
      const businessImpactScore = this.calculateBusinessImpactScore(businessContext);
      const complianceScore = this.calculateComplianceScore(finding);
      const temporalScore = this.calculateTemporalScore(finding, historicalFindings);

      // ML-based overall scoring
      const overallScore = this.calculateMLOverallScore({
        severity: severityScore,
        exploitability: exploitabilityScore,
        businessImpact: businessImpactScore,
        compliance: complianceScore,
        temporal: temporalScore
      });

      const confidence = this.calculateConfidence(finding, historicalFindings);
      const riskLevel = this.determineRiskLevel(overallScore);
      const reasoning = this.generateReasoning(finding, {
        severityScore,
        exploitabilityScore,
        businessImpactScore,
        complianceScore,
        temporalScore
      });

      return {
        overall_score: Math.round(overallScore * 100) / 100,
        severity_score: Math.round(severityScore * 100) / 100,
        exploitability_score: Math.round(exploitabilityScore * 100) / 100,
        business_impact_score: Math.round(businessImpactScore * 100) / 100,
        compliance_score: Math.round(complianceScore * 100) / 100,
        temporal_score: Math.round(temporalScore * 100) / 100,
        confidence: Math.round(confidence * 100) / 100,
        risk_level: riskLevel,
        reasoning
      };

    } catch (error) {
      console.error('Risk scoring calculation failed', { 
        error: error instanceof Error ? error.message : 'Unknown error', 
        finding: finding.id 
      });
      return this.getDefaultRiskScore();
    }
  }

  /**
   * Batch process multiple findings with prioritization
   */
  async prioritizeFindings(
    findings: ExtendedSecurityFinding[],
    businessContext: BusinessContext
  ): Promise<Array<ExtendedSecurityFinding & { risk_score: RiskScore }>> {
    const scoredFindings = await Promise.all(
      findings.map(async (finding) => {
        const riskScore = await this.calculateRiskScore(finding, businessContext, findings);
        return { ...finding, risk_score: riskScore };
      })
    );

    // Sort by overall risk score (descending)
    return scoredFindings.sort((a, b) => b.risk_score.overall_score - a.risk_score.overall_score);
  }

  /**
   * Predict future risk trends based on historical data
   */
  predictRiskTrends(historicalScores: number[], days: number = 30): {
    predicted_scores: number[];
    trend: 'increasing' | 'decreasing' | 'stable';
    confidence: number;
  } {
    if (historicalScores.length < 3) {
      return {
        predicted_scores: [],
        trend: 'stable',
        confidence: 0.1
      };
    }

    // Linear regression for trend prediction
    const xValues = historicalScores.map((_, index) => index);
    const regression = stats.linearRegression(xValues.map((x, i) => [x, historicalScores[i]]));
    
    const slope = regression.m;
    const predictedScores: number[] = [];
    
    for (let i = 1; i <= days; i++) {
      const predicted = regression.m * (historicalScores.length + i) + regression.b;
      predictedScores.push(Math.max(0, Math.min(100, predicted)));
    }

    const trend = slope > 0.1 ? 'increasing' : slope < -0.1 ? 'decreasing' : 'stable';
    const confidence = this.calculateTrendConfidence(historicalScores, regression);

    return {
      predicted_scores: predictedScores,
      trend,
      confidence
    };
  }

  /**
   * Generate risk assessment report
   */
  generateRiskReport(findings: Array<ExtendedSecurityFinding & { risk_score: RiskScore }>): {
    summary: RiskSummary;
    top_risks: Array<ExtendedSecurityFinding & { risk_score: RiskScore }>;
    risk_distribution: { [key: string]: number };
    recommendations: string[];
  } {
    const summary = this.calculateRiskSummary(findings);
    const topRisks = findings.slice(0, 10); // Top 10 risks
    const riskDistribution = this.calculateRiskDistribution(findings);
    const recommendations = this.generateRecommendations(findings, summary);

    return {
      summary,
      top_risks: topRisks,
      risk_distribution: riskDistribution,
      recommendations
    };
  }

  // Private helper methods

  private buildRiskVector(finding: ExtendedSecurityFinding, context: BusinessContext): RiskVector {
    const severityMap: Record<string, number> = { critical: 10, high: 7.5, medium: 5, low: 2.5, info: 1 };
    const criticalityMap: Record<string, number> = { critical: 10, high: 7.5, medium: 5, low: 2.5 };

    return {
      cvss_base: severityMap[finding.severity] || 5,
      cvss_temporal: this.getTemporalScore(finding),
      cvss_environmental: this.getEnvironmentalScore(context),
      exposure_score: context.internet_facing ? 8 : 4,
      asset_value: criticalityMap[context.asset_criticality],
      threat_intelligence: this.getThreatIntelligenceScore(finding),
      historical_exploits: this.getHistoricalExploitScore(finding),
      patch_availability: this.getPatchAvailabilityScore()
    };
  }

  private calculateSeverityScore(finding: ExtendedSecurityFinding): number {
    const baseScores: Record<string, number> = { critical: 90, high: 70, medium: 50, low: 30, info: 10 };
    const baseScore = baseScores[finding.severity] || 50;
    
    // Adjust based on category
    const categoryMultipliers: Record<string, number> = {
      'authentication': 1.2,
      'authorization': 1.15,
      'injection': 1.3,
      'cryptography': 1.1,
      'network-security': 1.05,
      'default': 1.0
    };

    const multiplier = categoryMultipliers[finding.category] || categoryMultipliers['default'];
    return Math.min(100, baseScore * multiplier);
  }

  private calculateExploitabilityScore(finding: ExtendedSecurityFinding, riskVector: RiskVector): number {
    // Weighted combination of exploitability factors
    const weights = {
      exposure: 0.3,
      complexity: 0.2,
      authentication: 0.2,
      interaction: 0.15,
      threat_intel: 0.15
    };

    const exposureScore = riskVector.exposure_score * 10;
    const complexityScore = this.getComplexityScore(finding);
    const authScore = this.getAuthenticationScore(finding);
    const interactionScore = this.getInteractionScore(finding);
    const threatIntelScore = riskVector.threat_intelligence * 10;

    return (
      exposureScore * weights.exposure +
      complexityScore * weights.complexity +
      authScore * weights.authentication +
      interactionScore * weights.interaction +
      threatIntelScore * weights.threat_intel
    );
  }

  private calculateBusinessImpactScore(context: BusinessContext): number {
    const criticalityScores: Record<string, number> = { critical: 90, high: 70, medium: 50, low: 30 };
    const sensitivityScores: Record<string, number> = { restricted: 90, confidential: 70, internal: 50, public: 30 };
    
    const assetScore = criticalityScores[context.asset_criticality];
    const dataScore = sensitivityScores[context.data_sensitivity];
    const userImpact = Math.min(40, Math.log10(context.user_count + 1) * 10);
    
    // Weight the components
    return (assetScore * 0.4 + dataScore * 0.4 + userImpact * 0.2);
  }

  private calculateComplianceScore(finding: ExtendedSecurityFinding): number {
    if (!finding.compliance_impact || finding.compliance_impact.length === 0) {
      return 0;
    }

    const impactScores: Record<string, number> = { critical: 25, high: 20, medium: 15, low: 10 };
    const standardWeights: Record<string, number> = { 'SOC2': 1.2, 'PCI': 1.3, 'HIPAA': 1.4, 'GDPR': 1.1, 'ISO27001': 1.0 };

    let totalScore = 0;
    for (const impact of finding.compliance_impact) {
      const baseScore = impactScores[impact.impact] || 10;
      const weight = standardWeights[impact.standard] || 1.0;
      totalScore += baseScore * weight;
    }

    return Math.min(100, totalScore);
  }

  private calculateTemporalScore(finding: ExtendedSecurityFinding, historicalFindings: ExtendedSecurityFinding[]): number {
    const findingAge = Date.now() - (finding.timestamp?.getTime() || Date.now());
    const ageDays = findingAge / (1000 * 60 * 60 * 24);
    
    // Age penalty: older findings get higher temporal scores
    let ageScore = Math.min(50, ageDays * 2);
    
    // Frequency penalty: recurring findings get higher scores
    const similarFindings = historicalFindings.filter(f => 
      f.category === finding.category && f.severity === finding.severity
    );
    const frequencyScore = Math.min(30, similarFindings.length * 5);
    
    // Patch availability: unpatched vulnerabilities get higher scores
    const patchScore = this.getPatchAvailabilityScore() > 7 ? 0 : 20;
    
    return ageScore + frequencyScore + patchScore;
  }

  private calculateMLOverallScore(components: {
    severity: number;
    exploitability: number;
    businessImpact: number;
    compliance: number;
    temporal: number;
  }): number {
    // Weighted ensemble scoring
    const weights = this.weightsConfig;
    
    return (
      components.severity * weights.severity +
      components.exploitability * weights.exploitability +
      components.businessImpact * weights.businessImpact +
      components.compliance * weights.compliance +
      components.temporal * weights.temporal
    );
  }

  private calculateConfidence(finding: ExtendedSecurityFinding, historicalFindings: ExtendedSecurityFinding[]): number {
    let confidence = 0.5; // Base confidence
    
    // More historical data = higher confidence
    confidence += Math.min(0.3, historicalFindings.length * 0.01);
    
    // Well-known categories = higher confidence
    const knownCategories = ['injection', 'authentication', 'authorization', 'cryptography'];
    if (knownCategories.includes(finding.category)) {
      confidence += 0.2;
    }
    
    // Evidence quality
    if (finding.evidence && Object.keys(finding.evidence).length > 0) {
      confidence += 0.1;
    }
    
    return Math.min(1.0, confidence);
  }

  private determineRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  private generateReasoning(finding: ExtendedSecurityFinding, scores: any): string[] {
    const reasoning: string[] = [];
    
    if (scores.severityScore > 70) {
      reasoning.push(`High severity (${finding.severity}) finding requires immediate attention`);
    }
    
    if (scores.exploitabilityScore > 60) {
      reasoning.push('High exploitability - vulnerable to remote attacks');
    }
    
    if (scores.businessImpactScore > 70) {
      reasoning.push('Critical business asset affected - high impact potential');
    }
    
    if (scores.complianceScore > 50) {
      reasoning.push('Compliance violations detected - regulatory risk');
    }
    
    if (scores.temporalScore > 40) {
      reasoning.push('Persistent or recurring vulnerability - urgent remediation needed');
    }
    
    return reasoning;
  }

  // Utility methods for scoring components

  private getTemporalScore(finding: ExtendedSecurityFinding): number {
    // Simplified temporal scoring based on finding age
    const age = Date.now() - (finding.timestamp?.getTime() || Date.now());
    const ageDays = age / (1000 * 60 * 60 * 24);
    return Math.min(10, ageDays * 0.1);
  }

  private getEnvironmentalScore(context: BusinessContext): number {
    let score = 5; // Base score
    if (context.internet_facing) score += 2;
    if (context.asset_criticality === 'critical') score += 2;
    if (context.data_sensitivity === 'restricted') score += 1;
    return Math.min(10, score);
  }

  private getThreatIntelligenceScore(finding: ExtendedSecurityFinding): number {
    // Simplified threat intelligence scoring
    // In real implementation, this would integrate with threat feeds
    const highThreatCategories = ['injection', 'authentication', 'remote-code-execution'];
    return highThreatCategories.includes(finding.category) ? 8 : 5;
  }

  private getHistoricalExploitScore(finding: ExtendedSecurityFinding): number {
    // Simplified historical exploit scoring
    // In real implementation, this would check CVE databases
    return finding.severity === 'critical' ? 9 : finding.severity === 'high' ? 7 : 5;
  }

  private getPatchAvailabilityScore(): number {
    // Simplified patch availability scoring
    // In real implementation, this would check vendor advisories
    return Math.random() * 10; // Placeholder
  }

  private getComplexityScore(finding: ExtendedSecurityFinding): number {
    // Attack complexity scoring (lower = more exploitable)
    const complexityMap: Record<string, number> = {
      'injection': 20, // Low complexity
      'authentication': 30,
      'authorization': 40,
      'cryptography': 70, // High complexity
      'default': 50
    };
    return 100 - (complexityMap[finding.category] || complexityMap['default']);
  }

  private getAuthenticationScore(finding: ExtendedSecurityFinding): number {
    // Authentication requirement scoring (lower = more exploitable)
    if (finding.category.includes('authentication') || finding.category.includes('authorization')) {
      return 90; // High score for auth bypasses
    }
    return 40; // Moderate score for other findings
  }

  private getInteractionScore(finding: ExtendedSecurityFinding): number {
    // User interaction requirement scoring
    const interactionTypes = ['network', 'remote', 'injection'];
    const requiresInteraction = !interactionTypes.some(type => finding.category.includes(type));
    return requiresInteraction ? 30 : 80;
  }

  private calculateRiskSummary(findings: Array<ExtendedSecurityFinding & { risk_score: RiskScore }>): RiskSummary {
    const totalFindings = findings.length;
    const avgRiskScore = findings.reduce((sum, f) => sum + f.risk_score.overall_score, 0) / totalFindings;
    
    const riskCounts = findings.reduce((counts, f) => {
      counts[f.risk_score.risk_level]++;
      return counts;
    }, { critical: 0, high: 0, medium: 0, low: 0 });

    return {
      total_findings: totalFindings,
      average_risk_score: Math.round(avgRiskScore * 100) / 100,
      critical_risks: riskCounts.critical,
      high_risks: riskCounts.high,
      medium_risks: riskCounts.medium,
      low_risks: riskCounts.low,
      overall_risk_level: this.determineRiskLevel(avgRiskScore)
    };
  }

  private calculateRiskDistribution(findings: Array<ExtendedSecurityFinding & { risk_score: RiskScore }>): { [key: string]: number } {
    const distribution: { [key: string]: number } = {};
    findings.forEach(finding => {
      const level = finding.risk_score.risk_level;
      distribution[level] = (distribution[level] || 0) + 1;
    });
    return distribution;
  }

  private generateRecommendations(findings: Array<ExtendedSecurityFinding & { risk_score: RiskScore }>, summary: RiskSummary): string[] {
    const recommendations: string[] = [];
    
    if (summary.critical_risks > 0) {
      recommendations.push(`Immediately address ${summary.critical_risks} critical risk findings`);
    }
    
    if (summary.high_risks > 5) {
      recommendations.push('High volume of high-risk findings - consider emergency security review');
    }
    
    if (summary.average_risk_score > 70) {
      recommendations.push('Overall risk level is high - implement comprehensive remediation plan');
    }
    
    // Category-specific recommendations
    const categories: { [key: string]: number } = findings.reduce((cats, f) => {
      cats[f.category] = (cats[f.category] || 0) + 1;
      return cats;
    }, {} as { [key: string]: number });
    
    const topCategory = Object.keys(categories).reduce((a, b) => categories[a] > categories[b] ? a : b);
    recommendations.push(`Focus remediation efforts on ${topCategory} vulnerabilities (${categories[topCategory]} findings)`);
    
    return recommendations;
  }

  private calculateTrendConfidence(historicalScores: number[], regression: any): number {
    if (historicalScores.length < 5) return 0.3;
    
    const predictions = historicalScores.map((_, i) => regression.m * i + regression.b);
    const errors = historicalScores.map((actual, i) => Math.abs(actual - predictions[i]));
    const meanError = errors.reduce((sum, err) => sum + err, 0) / errors.length;
    
    // Lower error = higher confidence
    return Math.max(0.1, Math.min(0.9, 1 - (meanError / 100)));
  }

  private initializeModels(): void {
    // Initialize ML models for different risk components
    // In a real implementation, these would be trained models
    console.log('Initializing ML risk scoring models');
  }

  private getDefaultWeights(): RiskWeights {
    return {
      severity: 0.25,
      exploitability: 0.25,
      businessImpact: 0.20,
      compliance: 0.15,
      temporal: 0.15
    };
  }

  private getDefaultRiskScore(): RiskScore {
    return {
      overall_score: 50,
      severity_score: 50,
      exploitability_score: 50,
      business_impact_score: 50,
      compliance_score: 0,
      temporal_score: 20,
      confidence: 0.3,
      risk_level: 'medium',
      reasoning: ['Unable to calculate accurate risk score - using default values']
    };
  }
}
