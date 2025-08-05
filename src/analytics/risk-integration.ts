/**
 * Risk Scoring Integration
 * Integrates ML Risk Scoring Engine with existing scanner modules
 */

import { SecurityFinding, ScanResult } from '../core/scanner';
import { MLRiskScoringEngine, BusinessContext, RiskScore } from '../analytics/ml-risk-scoring';

export interface EnhancedSecurityFinding extends SecurityFinding {
  risk_score?: RiskScore;
  timestamp?: Date;
}

export interface EnhancedScanResult extends Omit<ScanResult, 'findings'> {
  findings: EnhancedSecurityFinding[];
  risk_summary?: {
    average_risk_score: number;
    highest_risk_finding: EnhancedSecurityFinding;
    critical_count: number;
    high_count: number;
    prioritized_findings: EnhancedSecurityFinding[];
  };
}

export class RiskScoringIntegration {
  private riskEngine: MLRiskScoringEngine;
  private defaultBusinessContext: BusinessContext;

  constructor(businessContext?: Partial<BusinessContext>) {
    this.riskEngine = new MLRiskScoringEngine();
    this.defaultBusinessContext = {
      asset_criticality: 'medium',
      data_sensitivity: 'internal',
      compliance_requirements: ['SOC2'],
      business_hours: true,
      internet_facing: false,
      user_count: 1000,
      ...businessContext
    };
  }

  /**
   * Enhance scan results with ML risk scoring
   */
  async enhanceScanResults(
    scanResult: ScanResult,
    businessContext?: BusinessContext
  ): Promise<EnhancedScanResult> {
    const context = businessContext || this.defaultBusinessContext;
    
    // Add timestamps to findings if not present
    const findingsWithTimestamp: EnhancedSecurityFinding[] = scanResult.findings.map(finding => ({
      ...finding,
      timestamp: new Date()
    }));

    // Calculate risk scores for all findings
    const enhancedFindings = await this.riskEngine.prioritizeFindings(
      findingsWithTimestamp,
      context
    );

    // Calculate risk summary
    const riskSummary = this.calculateRiskSummary(enhancedFindings);

    return {
      ...scanResult,
      findings: enhancedFindings,
      risk_summary: riskSummary
    };
  }

  /**
   * Enhance individual finding with risk score
   */
  async enhanceFinding(
    finding: SecurityFinding,
    businessContext?: BusinessContext,
    historicalFindings?: SecurityFinding[]
  ): Promise<EnhancedSecurityFinding> {
    const context = businessContext || this.defaultBusinessContext;
    const enhancedFinding: EnhancedSecurityFinding = {
      ...finding,
      timestamp: new Date()
    };

    const riskScore = await this.riskEngine.calculateRiskScore(
      enhancedFinding,
      context,
      historicalFindings || []
    );

    return {
      ...enhancedFinding,
      risk_score: riskScore
    };
  }

  /**
   * Get risk-based recommendations for scan results
   */
  async getRecommendations(enhancedFindings: EnhancedSecurityFinding[]): Promise<{
    immediate_actions: string[];
    strategic_improvements: string[];
    risk_trends: string[];
  }> {
    const criticalFindings = enhancedFindings.filter(f => f.risk_score?.risk_level === 'critical');
    const highFindings = enhancedFindings.filter(f => f.risk_score?.risk_level === 'high');
    
    const immediate_actions: string[] = [];
    const strategic_improvements: string[] = [];
    const risk_trends: string[] = [];

    // Immediate actions for critical risks
    if (criticalFindings.length > 0) {
      immediate_actions.push(`Address ${criticalFindings.length} critical risk findings immediately`);
      
      // Group by category for specific recommendations
      const criticalCategories = this.groupFindingsByCategory(criticalFindings);
      Object.entries(criticalCategories).forEach(([category, count]) => {
        immediate_actions.push(`Focus on ${category} vulnerabilities (${count} critical findings)`);
      });
    }

    // Strategic improvements for high-volume issues
    if (highFindings.length > 5) {
      strategic_improvements.push('Implement automated vulnerability management program');
      strategic_improvements.push('Establish regular security training for development teams');
    }

    // Category-specific strategic recommendations
    const allCategories = this.groupFindingsByCategory(enhancedFindings);
    Object.entries(allCategories).forEach(([category, count]) => {
      if (count > 3) {
        switch (category) {
          case 'injection':
            strategic_improvements.push('Implement parameterized queries and input validation framework');
            break;
          case 'authentication':
            strategic_improvements.push('Deploy multi-factor authentication and password policies');
            break;
          case 'authorization':
            strategic_improvements.push('Review and strengthen access control mechanisms');
            break;
          case 'cryptography':
            strategic_improvements.push('Audit and update cryptographic implementations');
            break;
          case 'network-security':
            strategic_improvements.push('Review network segmentation and firewall policies');
            break;
          case 'configuration':
            strategic_improvements.push('Implement infrastructure as code and configuration management');
            break;
        }
      }
    });

    // Risk trend analysis
    const averageRiskScore = enhancedFindings.reduce((sum, f) => 
      sum + (f.risk_score?.overall_score || 0), 0) / enhancedFindings.length;

    if (averageRiskScore > 70) {
      risk_trends.push('Overall risk level is HIGH - comprehensive security review needed');
    } else if (averageRiskScore > 50) {
      risk_trends.push('Overall risk level is MEDIUM - monitor trends and improve controls');
    } else {
      risk_trends.push('Overall risk level is ACCEPTABLE - maintain current security posture');
    }

    // Compliance risk trends
    const complianceFindings = enhancedFindings.filter(f => 
      f.compliance_impact && f.compliance_impact.length > 0
    );
    if (complianceFindings.length > 0) {
      risk_trends.push(`${complianceFindings.length} findings have compliance implications`);
    }

    return {
      immediate_actions: immediate_actions.slice(0, 5), // Top 5
      strategic_improvements: strategic_improvements.slice(0, 5), // Top 5
      risk_trends
    };
  }

  /**
   * Generate executive risk dashboard data
   */
  generateExecutiveDashboard(enhancedFindings: EnhancedSecurityFinding[]): {
    risk_metrics: {
      total_findings: number;
      average_risk_score: number;
      critical_risks: number;
      high_risks: number;
      trend_direction: 'increasing' | 'stable' | 'decreasing';
    };
    top_risks: EnhancedSecurityFinding[];
    category_breakdown: { [category: string]: number };
    compliance_status: {
      total_violations: number;
      standards_affected: string[];
      critical_compliance_gaps: number;
    };
  } {
    const riskCounts = this.calculateRiskCounts(enhancedFindings);
    const averageRiskScore = enhancedFindings.reduce((sum, f) => 
      sum + (f.risk_score?.overall_score || 0), 0) / enhancedFindings.length;
    
    const topRisks = enhancedFindings
      .sort((a, b) => (b.risk_score?.overall_score || 0) - (a.risk_score?.overall_score || 0))
      .slice(0, 10);

    const categoryBreakdown = this.groupFindingsByCategory(enhancedFindings);

    const complianceFindings = enhancedFindings.filter(f => 
      f.compliance_impact && f.compliance_impact.length > 0
    );
    const standardsAffected = new Set(
      complianceFindings.flatMap(f => 
        f.compliance_impact?.map(impact => impact.standard) || []
      )
    );

    return {
      risk_metrics: {
        total_findings: enhancedFindings.length,
        average_risk_score: Math.round(averageRiskScore * 100) / 100,
        critical_risks: riskCounts.critical,
        high_risks: riskCounts.high,
        trend_direction: 'stable' // Would be calculated from historical data
      },
      top_risks: topRisks,
      category_breakdown: categoryBreakdown,
      compliance_status: {
        total_violations: complianceFindings.length,
        standards_affected: Array.from(standardsAffected),
        critical_compliance_gaps: complianceFindings.filter(f => 
          f.risk_score?.risk_level === 'critical'
        ).length
      }
    };
  }

  /**
   * Update business context for future risk calculations
   */
  updateBusinessContext(updates: Partial<BusinessContext>): void {
    this.defaultBusinessContext = {
      ...this.defaultBusinessContext,
      ...updates
    };
  }

  /**
   * Get risk scoring engine for advanced operations
   */
  getRiskEngine(): MLRiskScoringEngine {
    return this.riskEngine;
  }

  // Private helper methods

  private calculateRiskSummary(enhancedFindings: EnhancedSecurityFinding[]) {
    if (enhancedFindings.length === 0) {
      return {
        average_risk_score: 0,
        highest_risk_finding: {} as EnhancedSecurityFinding,
        critical_count: 0,
        high_count: 0,
        prioritized_findings: []
      };
    }

    const riskScores = enhancedFindings.map(f => f.risk_score?.overall_score || 0);
    const averageRiskScore = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
    
    const highestRiskFinding = enhancedFindings.reduce((highest, current) => 
      (current.risk_score?.overall_score || 0) > (highest.risk_score?.overall_score || 0) 
        ? current : highest
    );

    const riskCounts = this.calculateRiskCounts(enhancedFindings);

    return {
      average_risk_score: Math.round(averageRiskScore * 100) / 100,
      highest_risk_finding: highestRiskFinding,
      critical_count: riskCounts.critical,
      high_count: riskCounts.high,
      prioritized_findings: enhancedFindings.slice(0, 10) // Top 10
    };
  }

  private calculateRiskCounts(enhancedFindings: EnhancedSecurityFinding[]): {
    critical: number;
    high: number;
    medium: number;
    low: number;
  } {
    return enhancedFindings.reduce((counts, finding) => {
      const level = finding.risk_score?.risk_level;
      if (level) {
        counts[level]++;
      }
      return counts;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
  }

  private groupFindingsByCategory(findings: EnhancedSecurityFinding[]): { [category: string]: number } {
    return findings.reduce((categories, finding) => {
      categories[finding.category] = (categories[finding.category] || 0) + 1;
      return categories;
    }, {} as { [category: string]: number });
  }
}
