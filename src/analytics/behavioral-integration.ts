/**
 * Behavioral Analysis Integration for Real-Time Monitor
 * Integrates behavioral analysis engine with the real-time monitoring system
 * 
 * Features:
 * - Real-time anomaly detection during monitoring
 * - Behavioral baseline updates from continuous scans
 * - WebSocket updates for anomaly events
 * - Enhanced alerting with behavioral context
 */

import { EventEmitter } from 'events';
import { BehavioralAnalysisEngine, AnomalyIndicator, BehaviorProfile } from './behavioral-analysis';
import { ScanResult } from '../core/scanner';
import { Logger } from '../utils/logger';

// Create logger instance
const logger = Logger.getInstance();

// Integration types
export interface BehavioralMonitoringConfig {
  enabled: boolean;
  analysis_interval: number; // milliseconds
  anomaly_threshold: number; // 0-1 scale
  real_time_updates: boolean;
  baseline_update_frequency: number; // hours
  profile_retention_days: number;
}

export interface BehavioralAlertContext {
  anomaly_score: number;
  confidence_level: number;
  behavioral_patterns: string[];
  entity_profile_age: number;
  similar_entities: number;
}

export interface EnhancedSecurityEvent {
  event_id: string;
  timestamp: Date;
  event_type: 'security_finding' | 'behavioral_anomaly' | 'pattern_change';
  severity: 'critical' | 'high' | 'medium' | 'low';
  entity_id: string;
  entity_type: 'user' | 'service' | 'network' | 'system';
  behavioral_context: BehavioralAlertContext;
  scan_result?: ScanResult;
  anomaly_indicators?: AnomalyIndicator[];
  recommended_actions: string[];
}

export class BehavioralMonitoringIntegration extends EventEmitter {
  private analysisEngine: BehavioralAnalysisEngine;
  private config: BehavioralMonitoringConfig;
  private lastBaselineUpdate: Date = new Date();
  private analysisTimer?: NodeJS.Timeout | null;
  private profileCleanupTimer?: NodeJS.Timeout | null;

  constructor(config: Partial<BehavioralMonitoringConfig> = {}) {
    super();

    this.config = {
      enabled: true,
      analysis_interval: 30000, // 30 seconds
      anomaly_threshold: 0.6,
      real_time_updates: true,
      baseline_update_frequency: 24, // 24 hours
      profile_retention_days: 90,
      ...config
    };

    // Initialize behavioral analysis engine
    this.analysisEngine = new BehavioralAnalysisEngine({
      statistical_methods: {
        z_score_threshold: 3.0,
        iqr_multiplier: 1.5,
        enable_seasonal_decomposition: true,
        rolling_window_size: 200
      },
      machine_learning: {
        isolation_forest_contamination: 0.1,
        enable_clustering: true,
        feature_importance_threshold: 0.15
      },
      behavioral_thresholds: {
        frequency_deviation_threshold: 0.4,
        temporal_shift_threshold: 2.5,
        resource_access_anomaly_threshold: 0.6
      },
      context_awareness: {
        enable_contextual_scoring: true,
        business_hours: { start: 8, end: 18 },
        weekend_weight: 0.4,
        holiday_weight: 0.2
      }
    });

    this.setupEventHandlers();
    this.startBackgroundTasks();

    logger.info('Behavioral Monitoring Integration initialized', {
      enabled: this.config.enabled,
      analysis_interval: this.config.analysis_interval,
      anomaly_threshold: this.config.anomaly_threshold
    });
  }

  /**
   * Setup event handlers for behavioral analysis
   */
  private setupEventHandlers(): void {
    // Listen for anomalies from the analysis engine
    this.analysisEngine.on('anomalies_detected', (anomalies: AnomalyIndicator[]) => {
      this.handleAnomaliesDetected(anomalies);
    });

    // Listen for baseline updates
    this.analysisEngine.on('baseline_updated', (entityId: string) => {
      logger.debug(`Behavioral baseline updated for entity: ${entityId}`);
    });
  }

  /**
   * Start background tasks for continuous analysis
   */
  private startBackgroundTasks(): void {
    if (!this.config.enabled) return;

    // Profile cleanup task
    this.profileCleanupTimer = setInterval(() => {
      this.analysisEngine.cleanupOldProfiles(this.config.profile_retention_days);
    }, 24 * 60 * 60 * 1000); // Daily cleanup

    logger.info('Background tasks started for behavioral monitoring');
  }

  /**
   * Process scan results through behavioral analysis
   */
  async processScanResults(scanResults: ScanResult[]): Promise<EnhancedSecurityEvent[]> {
    if (!this.config.enabled || scanResults.length === 0) {
      return [];
    }

    const events: EnhancedSecurityEvent[] = [];

    try {
      // Run behavioral analysis
      const anomalies = await this.analysisEngine.processScanResults(scanResults);

      // Create enhanced security events
      for (const scanResult of scanResults) {
        const entityId = this.extractEntityId(scanResult);
        const profile = this.analysisEngine.getBehaviorProfile(entityId);

        if (profile) {
          // Create events for security findings with behavioral context
          const securityEvent = this.createSecurityEvent(scanResult, profile, anomalies);
          if (securityEvent) {
            events.push(securityEvent);
          }

          // Create separate events for high-confidence anomalies
          const entityAnomalies = anomalies.filter(a => 
            this.extractEntityIdFromAnomaly(a, scanResult) === entityId
          );

          for (const anomaly of entityAnomalies) {
            if (anomaly.score > this.config.anomaly_threshold) {
              const anomalyEvent = this.createAnomalyEvent(anomaly, profile, scanResult);
              events.push(anomalyEvent);
            }
          }
        }
      }

      // Emit real-time updates if enabled
      if (this.config.real_time_updates && events.length > 0) {
        this.emit('behavioral_events', events);
      }

      // Update baseline if needed
      this.checkBaselineUpdate();

    } catch (error) {
      logger.error('Error processing scan results for behavioral analysis', error);
    }

    return events;
  }

  /**
   * Handle detected anomalies
   */
  private handleAnomaliesDetected(anomalies: AnomalyIndicator[]): void {
    const highSeverityAnomalies = anomalies.filter(
      a => a.severity === 'high' || a.severity === 'critical'
    );

    if (highSeverityAnomalies.length > 0) {
      logger.warn(`High-severity behavioral anomalies detected`, {
        count: highSeverityAnomalies.length,
        critical_count: anomalies.filter(a => a.severity === 'critical').length
      });

      // Emit high-priority alert
      this.emit('high_severity_anomalies', highSeverityAnomalies);
    }
  }

  /**
   * Create enhanced security event from scan result
   */
  private createSecurityEvent(
    scanResult: ScanResult, 
    profile: BehaviorProfile, 
    anomalies: AnomalyIndicator[]
  ): EnhancedSecurityEvent | null {
    
    if (scanResult.findings.length === 0) return null;

    const entityAnomalies = anomalies.filter(a => 
      this.extractEntityIdFromAnomaly(a, scanResult) === profile.entity_id
    );

    return {
      event_id: `security_${scanResult.id}_${Date.now()}`,
      timestamp: new Date(),
      event_type: 'security_finding',
      severity: this.calculateEventSeverity(scanResult, profile, entityAnomalies),
      entity_id: profile.entity_id,
      entity_type: profile.entity_type,
      behavioral_context: {
        anomaly_score: profile.anomaly_score,
        confidence_level: profile.confidence_level,
        behavioral_patterns: profile.baseline.behavioral_patterns.map(p => p.description),
        entity_profile_age: profile.profile_age_days,
        similar_entities: this.countSimilarEntities(profile)
      },
      scan_result: scanResult,
      anomaly_indicators: entityAnomalies,
      recommended_actions: this.generateRecommendedActions(scanResult, profile, entityAnomalies)
    };
  }

  /**
   * Create anomaly-specific event
   */
  private createAnomalyEvent(
    anomaly: AnomalyIndicator, 
    profile: BehaviorProfile, 
    scanResult: ScanResult
  ): EnhancedSecurityEvent {
    
    return {
      event_id: `anomaly_${profile.entity_id}_${Date.now()}`,
      timestamp: new Date(),
      event_type: 'behavioral_anomaly',
      severity: anomaly.severity,
      entity_id: profile.entity_id,
      entity_type: profile.entity_type,
      behavioral_context: {
        anomaly_score: anomaly.score,
        confidence_level: profile.confidence_level,
        behavioral_patterns: [anomaly.description],
        entity_profile_age: profile.profile_age_days,
        similar_entities: this.countSimilarEntities(profile)
      },
      scan_result: scanResult,
      anomaly_indicators: [anomaly],
      recommended_actions: this.generateAnomalyActions(anomaly, profile)
    };
  }

  /**
   * Calculate event severity considering behavioral context
   */
  private calculateEventSeverity(
    scanResult: ScanResult, 
    profile: BehaviorProfile, 
    anomalies: AnomalyIndicator[]
  ): 'critical' | 'high' | 'medium' | 'low' {
    
    // Get highest severity from scan findings
    const findingSeverities = scanResult.findings.map(f => f.severity);
    const hasHighFindings = findingSeverities.includes('critical') || findingSeverities.includes('high');

    // Consider anomaly indicators
    const hasHighAnomalies = anomalies.some(a => a.severity === 'critical' || a.severity === 'high');

    // Behavioral risk factors
    const highAnomalyScore = profile.anomaly_score > 0.8;
    const lowConfidence = profile.confidence_level < 0.5;
    const newEntity = profile.profile_age_days < 7;

    // Calculate severity
    if (hasHighFindings && (hasHighAnomalies || highAnomalyScore)) {
      return 'critical';
    }
    
    if (hasHighFindings || hasHighAnomalies || (highAnomalyScore && !newEntity)) {
      return 'high';
    }
    
    if (profile.anomaly_score > 0.5 || lowConfidence || newEntity) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Count entities with similar behavioral patterns
   */
  private countSimilarEntities(profile: BehaviorProfile): number {
    const allProfiles = this.analysisEngine.getBehaviorProfiles();
    
    return allProfiles.filter(p => 
      p.entity_id !== profile.entity_id &&
      p.entity_type === profile.entity_type &&
      Math.abs(p.anomaly_score - profile.anomaly_score) < 0.2
    ).length;
  }

  /**
   * Generate recommended actions for security events
   */
  private generateRecommendedActions(
    scanResult: ScanResult, 
    profile: BehaviorProfile, 
    anomalies: AnomalyIndicator[]
  ): string[] {
    
    const actions: string[] = [];

    // Security finding recommendations
    const highFindings = scanResult.findings.filter(f => f.severity === 'high' || f.severity === 'critical');
    if (highFindings.length > 0) {
      actions.push('Immediately review and remediate high-severity security findings');
      actions.push('Isolate affected resources if compromise is suspected');
    }

    // Behavioral anomaly recommendations
    if (anomalies.length > 0) {
      actions.push('Investigate unusual behavioral patterns for potential insider threats');
      
      const statisticalAnomalies = anomalies.filter(a => a.indicator_type === 'statistical');
      if (statisticalAnomalies.length > 0) {
        actions.push('Review activity frequency and resource access patterns');
      }

      const temporalAnomalies = anomalies.filter(a => a.indicator_type === 'temporal');
      if (temporalAnomalies.length > 0) {
        actions.push('Verify legitimacy of off-hours or unusual timing activities');
      }
    }

    // Profile-based recommendations
    if (profile.confidence_level < 0.5) {
      actions.push('Continue monitoring to establish reliable behavioral baseline');
    }

    if (profile.anomaly_score > 0.7) {
      actions.push('Consider additional authentication requirements for this entity');
      actions.push('Enable enhanced logging and monitoring');
    }

    // New entity recommendations
    if (profile.profile_age_days < 7) {
      actions.push('Apply new entity monitoring protocols');
      actions.push('Verify entity legitimacy and authorization');
    }

    return actions;
  }

  /**
   * Generate recommended actions for anomalies
   */
  private generateAnomalyActions(anomaly: AnomalyIndicator, profile: BehaviorProfile): string[] {
    const actions: string[] = [];

    switch (anomaly.indicator_type) {
      case 'statistical':
        actions.push('Investigate statistical deviation from baseline behavior');
        actions.push('Review recent changes in activity patterns');
        break;

      case 'behavioral':
        actions.push('Analyze new or changed behavioral patterns');
        actions.push('Verify if behavior change is legitimate business activity');
        break;

      case 'temporal':
        actions.push('Investigate unusual timing of activities');
        actions.push('Check if off-hours access is authorized');
        break;

      case 'contextual':
        actions.push('Review contextual factors affecting behavior');
        actions.push('Validate business justification for activity');
        break;
    }

    // Severity-specific actions
    if (anomaly.severity === 'critical') {
      actions.unshift('URGENT: Immediate investigation required');
      actions.push('Consider temporary access restrictions');
    } else if (anomaly.severity === 'high') {
      actions.unshift('High priority investigation needed');
    }

    // Profile-specific actions
    if (profile.confidence_level > 0.8) {
      actions.push('High-confidence behavioral model indicates significant deviation');
    }

    return actions;
  }

  /**
   * Check if baseline update is needed
   */
  private checkBaselineUpdate(): void {
    const now = new Date();
    const hoursSinceUpdate = (now.getTime() - this.lastBaselineUpdate.getTime()) / (1000 * 60 * 60);

    if (hoursSinceUpdate >= this.config.baseline_update_frequency) {
      logger.info('Performing scheduled behavioral baseline update');
      this.lastBaselineUpdate = now;
      
      // Emit baseline update event
      this.emit('baseline_update_completed', {
        timestamp: now,
        profiles_count: this.analysisEngine.getBehaviorProfiles().length
      });
    }
  }

  /**
   * Extract entity ID from scan result
   */
  private extractEntityId(scanResult: ScanResult): string {
    if (scanResult.target.target) {
      return `${scanResult.target.type}_${scanResult.target.target}`;
    }
    return scanResult.id || `entity_${Date.now()}`;
  }

  /**
   * Extract entity ID from anomaly indicator
   */
  private extractEntityIdFromAnomaly(_anomaly: AnomalyIndicator, scanResult: ScanResult): string {
    // For now, associate anomaly with the scan result entity
    return this.extractEntityId(scanResult);
  }

  /**
   * Get behavioral analysis statistics
   */
  getBehavioralStats(): {
    total_profiles: number;
    high_risk_profiles: number;
    new_profiles: number;
    average_confidence: number;
    anomaly_detection_rate: number;
  } {
    const profiles = this.analysisEngine.getBehaviorProfiles();
    
    const highRiskProfiles = profiles.filter(p => p.anomaly_score > 0.7).length;
    const newProfiles = profiles.filter(p => p.profile_age_days < 7).length;
    const avgConfidence = profiles.length > 0 
      ? profiles.reduce((sum, p) => sum + p.confidence_level, 0) / profiles.length 
      : 0;
    const anomalyRate = profiles.length > 0
      ? profiles.filter(p => p.anomaly_score > this.config.anomaly_threshold).length / profiles.length
      : 0;

    return {
      total_profiles: profiles.length,
      high_risk_profiles: highRiskProfiles,
      new_profiles: newProfiles,
      average_confidence: avgConfidence,
      anomaly_detection_rate: anomalyRate
    };
  }

  /**
   * Get profiles with highest anomaly scores
   */
  getTopAnomalousProfiles(limit: number = 10): BehaviorProfile[] {
    return this.analysisEngine.getBehaviorProfiles()
      .sort((a, b) => b.anomaly_score - a.anomaly_score)
      .slice(0, limit);
  }

  /**
   * Export behavioral data for analysis
   */
  exportBehavioralData(): {
    timestamp: string;
    config: BehavioralMonitoringConfig;
    statistics: any;
    profiles: string;
  } {
    return {
      timestamp: new Date().toISOString(),
      config: this.config,
      statistics: this.getBehavioralStats(),
      profiles: this.analysisEngine.exportProfiles()
    };
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<BehavioralMonitoringConfig>): void {
    this.config = { ...this.config, ...newConfig };
    
    logger.info('Behavioral monitoring configuration updated', {
      enabled: this.config.enabled,
      anomaly_threshold: this.config.anomaly_threshold
    });

    // Restart background tasks if needed
    if (this.config.enabled && !this.analysisTimer) {
      this.startBackgroundTasks();
    } else if (!this.config.enabled && this.analysisTimer) {
      this.stopBackgroundTasks();
    }
  }

  /**
   * Stop background tasks
   */
  private stopBackgroundTasks(): void {
    if (this.analysisTimer) {
      clearInterval(this.analysisTimer);
      this.analysisTimer = null;
    }

    if (this.profileCleanupTimer) {
      clearInterval(this.profileCleanupTimer);
      this.profileCleanupTimer = null;
    }

    logger.info('Background tasks stopped for behavioral monitoring');
  }

  /**
   * Cleanup and shutdown
   */
  shutdown(): void {
    this.stopBackgroundTasks();
    this.removeAllListeners();
    
    logger.info('Behavioral Monitoring Integration shutdown complete');
  }
}

export default BehavioralMonitoringIntegration;
