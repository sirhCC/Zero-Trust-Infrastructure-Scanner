/**
 * Enhanced ML Risk Scoring Engine
 * Improved version based on evaluation results
 */

import { SecurityFinding } from '../core/scanner';
import { RiskScore, BusinessContext } from './ml-risk-scoring';

export class EnhancedMLRiskScoringEngine {
  private weightsConfig: any;
  private threatIntelligence: Map<string, number> = new Map();
  private industryFactors: Map<string, number> = new Map();
  
  constructor() {
    this.initializeEnhancedModels();
    this.loadThreatIntelligence();
    this.setupIndustryFactors();
  }

  private initializeEnhancedModels(): void {
    // Enhanced weight configuration with dynamic adjustment
    this.weightsConfig = {
      severity: { base: 0.35, dynamic_range: [0.25, 0.45] },
      exploitability: { base: 0.25, dynamic_range: [0.15, 0.35] },
      businessImpact: { base: 0.20, dynamic_range: [0.15, 0.30] },
      compliance: { base: 0.15, dynamic_range: [0.10, 0.25] },
      temporal: { base: 0.05, dynamic_range: [0.02, 0.10] }
    };
  }

  private loadThreatIntelligence(): void {
    // Simulated threat intelligence data (CVE-like scoring)
    this.threatIntelligence.set('injection', 9.8);
    this.threatIntelligence.set('authentication', 8.5);
    this.threatIntelligence.set('access-control', 9.2);
    this.threatIntelligence.set('encryption', 7.8);
    this.threatIntelligence.set('configuration', 5.2);
    this.threatIntelligence.set('xss', 8.1);
    this.threatIntelligence.set('csrf', 6.9);
  }

  private setupIndustryFactors(): void {
    // Industry-specific risk multipliers
    this.industryFactors.set('financial', 1.3);
    this.industryFactors.set('healthcare', 1.25);
    this.industryFactors.set('government', 1.4);
    this.industryFactors.set('retail', 1.1);
    this.industryFactors.set('technology', 1.0);
  }

  /**
   * Enhanced risk calculation with improved accuracy
   */
  async calculateEnhancedRiskScore(
    finding: SecurityFinding & { timestamp?: Date },
    businessContext: BusinessContext,
    historicalFindings: (SecurityFinding & { timestamp?: Date })[] = [],
    industry: string = 'technology'
  ): Promise<RiskScore> {
    // Calculate base components with enhancements
    const severityScore = this.calculateEnhancedSeverityScore(finding);
    const exploitabilityScore = this.calculateEnhancedExploitabilityScore(finding);
    const businessImpactScore = this.calculateEnhancedBusinessImpactScore(businessContext, finding);
    const complianceScore = this.calculateEnhancedComplianceScore(finding);
    const temporalScore = this.calculateEnhancedTemporalScore(finding, historicalFindings);

    // Apply industry-specific adjustments
    const industryMultiplier = this.industryFactors.get(industry) || 1.0;
    
    // Dynamic weight adjustment based on context
    const adjustedWeights = this.getDynamicWeights(finding, businessContext);
    
    // Enhanced ML scoring with ensemble approach
    const overallScore = this.calculateEnsembleScore({
      severity: severityScore,
      exploitability: exploitabilityScore,
      businessImpact: businessImpactScore,
      compliance: complianceScore,
      temporal: temporalScore
    }, adjustedWeights, industryMultiplier);

    const confidence = this.calculateEnhancedConfidence(finding, historicalFindings, businessContext);
    const riskLevel = this.determineEnhancedRiskLevel(overallScore, confidence);
    const reasoning = this.generateEnhancedReasoning(finding, {
      severityScore,
      exploitabilityScore,
      businessImpactScore,
      complianceScore,
      temporalScore,
      industryMultiplier,
      confidence
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
  }

  private calculateEnhancedSeverityScore(finding: SecurityFinding): number {
    const baseSeverityScores = {
      'critical': 95,
      'high': 80,
      'medium': 55,
      'low': 25,
      'info': 10
    };

    let score = baseSeverityScores[finding.severity] || 50;
    
    // Apply threat intelligence enhancement
    const threatScore = this.threatIntelligence.get(finding.category) || 5.0;
    const threatMultiplier = 1 + ((threatScore - 5.0) / 10); // Scale threat intelligence
    
    return Math.min(100, score * threatMultiplier);
  }

  private calculateEnhancedExploitabilityScore(finding: SecurityFinding): number {
    let baseScore = 50;
    
    const exploitabilityScores: { [key: string]: number } = {
      'injection': 90,
      'authentication': 85,
      'access-control': 80,
      'xss': 75,
      'csrf': 70,
      'encryption': 60,
      'configuration': 45
    };
    
    baseScore = exploitabilityScores[finding.category] || 50;
    
    // Evidence-based adjustments
    if (finding.evidence) {
      const ev = finding.evidence as Record<string, unknown>;
      // Remote exploitation possible
      if ((ev.remote_access as boolean) || (ev.external_access as boolean)) {
        baseScore += 15;
      }
      
      // Public exploits available
      if ((ev.public_exploit as boolean) || (ev.exploit_code as boolean)) {
        baseScore += 20;
      }
      
      // Authentication required reduces exploitability
      if (ev.authentication_required as boolean) {
        baseScore -= 10;
      }
      
      // Network segmentation reduces exploitability
      if (ev.network_segmented as boolean) {
        baseScore -= 15;
      }
    }
    
    return Math.max(0, Math.min(100, baseScore));
  }

  private calculateEnhancedBusinessImpactScore(businessContext: BusinessContext, finding: SecurityFinding): number {
    const criticalityScores = {
      'critical': 90,
      'high': 70,
      'medium': 50,
      'low': 30
    };
    
    const sensitivityScores = {
      'restricted': 90,
      'confidential': 70,
      'internal': 50,
      'public': 20
    };
    
    let baseScore = (criticalityScores[businessContext.asset_criticality] + 
                    sensitivityScores[businessContext.data_sensitivity]) / 2;
    
    // User count impact
    if (businessContext.user_count > 50000) baseScore += 15;
    else if (businessContext.user_count > 10000) baseScore += 10;
    else if (businessContext.user_count > 1000) baseScore += 5;
    
    // Internet facing increases impact
    if (businessContext.internet_facing) baseScore += 10;
    
    // Business hours operation increases impact
    if (businessContext.business_hours) baseScore += 5;
    
    // Specific finding impact adjustments
    if (finding.category === 'injection' && businessContext.data_sensitivity === 'restricted') {
      baseScore += 20; // SQL injection on restricted data is extremely high impact
    }
    
    return Math.max(0, Math.min(100, baseScore));
  }

  private calculateEnhancedComplianceScore(finding: SecurityFinding): number {
    if (!finding.compliance_impact || finding.compliance_impact.length === 0) {
      return 0;
    }
    
    const complianceWeights = {
      'SOC2': 1.0,
      'PCI': 1.3,
      'HIPAA': 1.2,
      'GDPR': 1.1,
      'ISO27001': 0.9
    };
    
    const impactScores = {
      'critical': 90,
      'high': 70,
      'medium': 45,
      'low': 20
    };
    
    let totalScore = 0;
    let totalWeight = 0;
    
    for (const impact of finding.compliance_impact) {
      const weight = complianceWeights[impact.standard] || 1.0;
      const score = impactScores[impact.impact] || 20;
      totalScore += score * weight;
      totalWeight += weight;
    }
    
    return totalWeight > 0 ? Math.min(100, totalScore / totalWeight) : 0;
  }

  private calculateEnhancedTemporalScore(
    finding: SecurityFinding & { timestamp?: Date }, 
    historicalFindings: (SecurityFinding & { timestamp?: Date })[]
  ): number {
    let temporalScore = 50; // Base temporal score
    
    // Age factor (if timestamp is available)
    if (finding.timestamp) {
      const ageInDays = (Date.now() - finding.timestamp.getTime()) / (1000 * 60 * 60 * 24);
      if (ageInDays > 30) temporalScore += 20; // Old vulnerabilities are more risky
      else if (ageInDays > 7) temporalScore += 10;
    }
    
    // Frequency analysis
    const similarFindings = historicalFindings.filter(f => f.category === finding.category);
    if (similarFindings.length > 3) {
      temporalScore += 15; // Frequent similar findings indicate systemic issues
    }
    
    // Trend analysis
    const recentFindings = historicalFindings.filter(f => {
      if (!f.timestamp) return false;
      const daysSince = (Date.now() - f.timestamp.getTime()) / (1000 * 60 * 60 * 24);
      return daysSince <= 30;
    });
    
    if (recentFindings.length > historicalFindings.length * 0.7) {
      temporalScore += 10; // Increasing trend
    }
    
    return Math.max(0, Math.min(100, temporalScore));
  }

  private getDynamicWeights(finding: SecurityFinding, businessContext: BusinessContext): any {
    const weights = { ...this.weightsConfig };
    
    // Adjust weights based on context
    if (businessContext.compliance_requirements.length > 2) {
      weights.compliance.base += 0.05; // Increase compliance weight for highly regulated environments
    }
    
    if (businessContext.internet_facing && finding.category === 'injection') {
      weights.exploitability.base += 0.1; // Higher exploitability weight for internet-facing injection vulnerabilities
    }
    
    if (businessContext.asset_criticality === 'critical') {
      weights.businessImpact.base += 0.05; // Increase business impact weight for critical assets
    }
    
    return weights;
  }

  private calculateEnsembleScore(scores: any, weights: any, industryMultiplier: number): number {
    // Weighted linear combination
    const linearScore = (
      scores.severity * weights.severity.base +
      scores.exploitability * weights.exploitability.base +
      scores.businessImpact * weights.businessImpact.base +
      scores.compliance * weights.compliance.base +
      scores.temporal * weights.temporal.base
    );
    
    // Non-linear ensemble component (geometric mean for critical factors)
    const criticalFactors = [scores.severity, scores.exploitability, scores.businessImpact];
    const geometricMean = Math.pow(criticalFactors.reduce((a, b) => a * b, 1), 1/criticalFactors.length);
    
    // Combine linear and non-linear components
    const ensembleScore = (linearScore * 0.7) + (geometricMean * 0.3);
    
    // Apply industry adjustment
    return Math.min(100, ensembleScore * industryMultiplier);
  }

  private calculateEnhancedConfidence(
    finding: SecurityFinding, 
    historicalFindings: SecurityFinding[],
    businessContext: BusinessContext
  ): number {
    let confidence = 0.7; // Base confidence
    
    // More evidence increases confidence
    if (finding.evidence && Object.keys(finding.evidence).length > 2) {
      confidence += 0.1;
    }
    
    // Compliance impact data increases confidence
    if (finding.compliance_impact && finding.compliance_impact.length > 0) {
      confidence += 0.1;
    }
    
    // Historical data availability increases confidence
    if (historicalFindings.length > 10) {
      confidence += 0.1;
    }
    
    // Well-defined business context increases confidence
    if (businessContext.compliance_requirements.length > 0) {
      confidence += 0.05;
    }
    
    return Math.min(1.0, confidence);
  }

  private determineEnhancedRiskLevel(score: number, confidence: number): 'critical' | 'high' | 'medium' | 'low' {
    // Adjust thresholds based on confidence
    const confidenceAdjustment = (confidence - 0.5) * 10; // Adjust thresholds by up to ±5 points
    
    const adjustedThresholds = {
      critical: 85 - confidenceAdjustment,
      high: 65 - confidenceAdjustment,
      medium: 40 - confidenceAdjustment
    };
    
    if (score >= adjustedThresholds.critical) return 'critical';
    if (score >= adjustedThresholds.high) return 'high';
    if (score >= adjustedThresholds.medium) return 'medium';
    return 'low';
  }

  private generateEnhancedReasoning(finding: SecurityFinding, scores: any): string[] {
    const reasoning: string[] = [];
    
    // Severity reasoning
    if (scores.severityScore >= 80) {
      reasoning.push(`Critical severity (${finding.severity}) with threat intelligence enhancement`);
    } else if (scores.severityScore >= 60) {
      reasoning.push(`High severity finding requires prompt attention`);
    }
    
    // Exploitability reasoning
    if (scores.exploitabilityScore >= 80) {
      reasoning.push('High exploitability - vulnerable to remote attacks');
    } else if (scores.exploitabilityScore >= 60) {
      reasoning.push('Moderate exploitability with potential for automated attacks');
    }
    
    // Business impact reasoning
    if (scores.businessImpactScore >= 70) {
      reasoning.push('Critical business asset affected - high impact potential');
    }
    
    // Compliance reasoning
    if (scores.complianceScore >= 60) {
      reasoning.push('Significant compliance violations - regulatory risk');
    }
    
    // Industry-specific reasoning
    if (scores.industryMultiplier > 1.1) {
      reasoning.push('Industry-specific risk factors increase overall risk');
    }
    
    // Confidence reasoning
    if (scores.confidence >= 0.8) {
      reasoning.push('High confidence assessment based on comprehensive data');
    } else if (scores.confidence < 0.6) {
      reasoning.push('Lower confidence - additional validation recommended');
    }
    
    return reasoning;
  }
}
