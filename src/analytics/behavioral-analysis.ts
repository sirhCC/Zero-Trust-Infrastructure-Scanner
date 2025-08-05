/**
 * Behavioral Analysis Engine
 * Advanced anomaly detection using statistical models and machine learning techniques
 * 
 * Features:
 * - Statistical baseline modeling (Z-score, IQR, seasonal decomposition)
 * - Anomaly detection using isolation forests and statistical methods
 * - Behavioral fingerprinting for users, services, and network patterns
 * - Time-series analysis with trend detection
 * - Dynamic threshold adjustment based on historical data
 * - Context-aware anomaly scoring
 */

import { EventEmitter } from 'events';
import { Logger } from '../utils/logger';
import { SecurityFinding, ScanResult } from '../core/scanner';

// Create logger instance
const logger = Logger.getInstance();

// Behavioral Analysis Types
export interface BehaviorProfile {
  entity_id: string;
  entity_type: 'user' | 'service' | 'network' | 'system';
  baseline: BaselineModel;
  current_behavior: BehaviorMetrics;
  anomaly_score: number;
  confidence_level: number;
  last_updated: Date;
  profile_age_days: number;
}

export interface BaselineModel {
  statistical_profile: StatisticalProfile;
  behavioral_patterns: BehaviorPattern[];
  seasonal_patterns: SeasonalPattern[];
  context_features: ContextFeature[];
}

export interface StatisticalProfile {
  metrics: {
    [key: string]: {
      mean: number;
      std_dev: number;
      median: number;
      percentile_95: number;
      percentile_99: number;
      min: number;
      max: number;
      trend: 'increasing' | 'decreasing' | 'stable';
    };
  };
  time_series: TimeSeriesData[];
  correlation_matrix: { [key: string]: { [key: string]: number } };
}

export interface BehaviorPattern {
  pattern_id: string;
  pattern_type: 'temporal' | 'frequency' | 'sequential' | 'contextual';
  description: string;
  confidence: number;
  occurrences: number;
  last_seen: Date;
  parameters: { [key: string]: any };
}

export interface SeasonalPattern {
  period: 'hourly' | 'daily' | 'weekly' | 'monthly';
  amplitude: number;
  phase: number;
  trend_component: number;
  seasonal_component: number[];
  confidence: number;
}

export interface ContextFeature {
  feature_name: string;
  feature_value: any;
  importance_score: number;
  feature_type: 'categorical' | 'numerical' | 'temporal' | 'geospatial';
}

export interface BehaviorMetrics {
  activity_frequency: number;
  resource_access_patterns: ResourceAccessPattern[];
  temporal_patterns: TemporalPattern[];
  network_behavior: NetworkBehavior;
  anomaly_indicators: AnomalyIndicator[];
}

export interface ResourceAccessPattern {
  resource_type: string;
  access_frequency: number;
  access_times: Date[];
  permission_levels: string[];
  success_rate: number;
}

export interface TemporalPattern {
  time_of_day: number; // 0-23
  day_of_week: number; // 0-6
  activity_level: number;
  variance: number;
}

export interface NetworkBehavior {
  connection_patterns: ConnectionPattern[];
  data_transfer_volume: number;
  protocol_usage: { [protocol: string]: number };
  geolocation_patterns: GeolocationPattern[];
}

export interface ConnectionPattern {
  source_ip: string;
  destination_ip: string;
  port: number;
  frequency: number;
  duration_avg: number;
  last_connection: Date;
}

export interface GeolocationPattern {
  country: string;
  region: string;
  frequency: number;
  risk_score: number;
}

export interface AnomalyIndicator {
  indicator_type: 'statistical' | 'behavioral' | 'contextual' | 'temporal';
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  description: string;
  evidence: any[];
  detected_at: Date;
}

export interface TimeSeriesData {
  timestamp: Date;
  value: number;
  context: { [key: string]: any };
}

export interface AnomalyDetectionConfig {
  statistical_methods: {
    z_score_threshold: number;
    iqr_multiplier: number;
    enable_seasonal_decomposition: boolean;
    rolling_window_size: number;
  };
  machine_learning: {
    isolation_forest_contamination: number;
    enable_clustering: boolean;
    feature_importance_threshold: number;
  };
  behavioral_thresholds: {
    frequency_deviation_threshold: number;
    temporal_shift_threshold: number;
    resource_access_anomaly_threshold: number;
  };
  context_awareness: {
    enable_contextual_scoring: boolean;
    business_hours: { start: number; end: number };
    weekend_weight: number;
    holiday_weight: number;
  };
}

// Statistical Analysis Utilities
export class StatisticalAnalyzer {
  /**
   * Calculate Z-score for anomaly detection
   */
  static calculateZScore(value: number, mean: number, stdDev: number): number {
    if (stdDev === 0) return 0;
    return Math.abs((value - mean) / stdDev);
  }

  /**
   * Calculate Interquartile Range (IQR) outliers
   */
  static calculateIQROutliers(values: number[]): { lower: number; upper: number; outliers: number[] } {
    const sorted = values.slice().sort((a, b) => a - b);
    const q1 = this.percentile(sorted, 25);
    const q3 = this.percentile(sorted, 75);
    const iqr = q3 - q1;
    const lower = q1 - 1.5 * iqr;
    const upper = q3 + 1.5 * iqr;
    const outliers = values.filter(v => v < lower || v > upper);
    
    return { lower, upper, outliers };
  }

  /**
   * Calculate percentile
   */
  static percentile(arr: number[], p: number): number {
    const sorted = arr.slice().sort((a, b) => a - b);
    const index = (p / 100) * (sorted.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    const weight = index % 1;

    if (upper >= sorted.length) return sorted[sorted.length - 1];
    return sorted[lower] * (1 - weight) + sorted[upper] * weight;
  }

  /**
   * Calculate moving average
   */
  static movingAverage(values: number[], windowSize: number): number[] {
    const result: number[] = [];
    for (let i = 0; i < values.length; i++) {
      const start = Math.max(0, i - windowSize + 1);
      const window = values.slice(start, i + 1);
      const avg = window.reduce((sum, val) => sum + val, 0) / window.length;
      result.push(avg);
    }
    return result;
  }

  /**
   * Calculate correlation coefficient
   */
  static correlation(x: number[], y: number[]): number {
    if (x.length !== y.length || x.length === 0) return 0;

    const n = x.length;
    const sumX = x.reduce((a, b) => a + b, 0);
    const sumY = y.reduce((a, b) => a + b, 0);
    const sumXY = x.reduce((sum, xi, i) => sum + xi * y[i], 0);
    const sumX2 = x.reduce((sum, xi) => sum + xi * xi, 0);
    const sumY2 = y.reduce((sum, yi) => sum + yi * yi, 0);

    const numerator = n * sumXY - sumX * sumY;
    const denominator = Math.sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));

    return denominator === 0 ? 0 : numerator / denominator;
  }

  /**
   * Detect seasonal patterns using simple decomposition
   */
  static detectSeasonality(timeSeries: TimeSeriesData[], period: number): SeasonalPattern {
    const values = timeSeries.map(ts => ts.value);
    
    // Calculate trend using moving average
    const trendWindow = Math.max(3, Math.floor(period / 2));
    const trend = this.movingAverage(values, trendWindow);
    
    // Calculate seasonal component
    const seasonalComponent: number[] = [];
    for (let i = 0; i < period; i++) {
      const seasonalValues: number[] = [];
      for (let j = i; j < values.length; j += period) {
        if (j < trend.length) {
          seasonalValues.push(values[j] - trend[j]);
        }
      }
      const seasonalMean = seasonalValues.reduce((a, b) => a + b, 0) / seasonalValues.length;
      seasonalComponent.push(seasonalMean || 0);
    }

    // Calculate amplitude and phase
    const amplitude = Math.max(...seasonalComponent) - Math.min(...seasonalComponent);
    const maxIndex = seasonalComponent.indexOf(Math.max(...seasonalComponent));
    const phase = (maxIndex / period) * 2 * Math.PI;

    // Calculate confidence based on consistency
    const residuals = values.map((val, i) => {
      const trendVal = trend[i] || trend[trend.length - 1];
      const seasonalVal = seasonalComponent[i % period];
      return Math.abs(val - trendVal - seasonalVal);
    });
    const avgResidual = residuals.reduce((a, b) => a + b, 0) / residuals.length;
    const confidence = Math.max(0, 1 - (avgResidual / amplitude));

    return {
      period: period === 24 ? 'daily' : period === 168 ? 'weekly' : 'hourly',
      amplitude,
      phase,
      trend_component: trend[trend.length - 1] || 0,
      seasonal_component: seasonalComponent,
      confidence
    };
  }
}

// Isolation Forest implementation for anomaly detection
export class IsolationForest {
  private trees: IsolationTree[] = [];
  private numTrees: number;
  private sampleSize: number;

  constructor(numTrees: number = 100, sampleSize?: number, _contamination: number = 0.1) {
    this.numTrees = numTrees;
    this.sampleSize = sampleSize || 256;
  }

  /**
   * Train the isolation forest
   */
  fit(data: number[][]): void {
    this.trees = [];
    
    for (let i = 0; i < this.numTrees; i++) {
      // Sample data for this tree
      const sample = this.sampleData(data, this.sampleSize);
      const tree = new IsolationTree();
      tree.fit(sample, 0, sample.length);
      this.trees.push(tree);
    }
  }

  /**
   * Calculate anomaly scores for data points
   */
  predict(data: number[][]): number[] {
    return data.map(point => this.anomalyScore(point));
  }

  /**
   * Calculate anomaly score for a single point
   */
  private anomalyScore(point: number[]): number {
    const paths = this.trees.map(tree => tree.pathLength(point, 0));
    const avgPath = paths.reduce((a, b) => a + b, 0) / paths.length;
    
    // Normalize score using expected path length
    const expectedPath = this.expectedPathLength(this.sampleSize);
    return Math.pow(2, -avgPath / expectedPath);
  }

  /**
   * Sample data randomly
   */
  private sampleData(data: number[][], size: number): number[][] {
    const shuffled = [...data].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, Math.min(size, data.length));
  }

  /**
   * Calculate expected path length for isolation tree
   */
  private expectedPathLength(n: number): number {
    if (n <= 1) return 0;
    return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
  }
}

// Simple Isolation Tree implementation
class IsolationTree {
  private splitFeature?: number;
  private splitValue?: number;
  private left?: IsolationTree;
  private right?: IsolationTree;
  private size: number = 0;

  fit(data: number[][], depth: number, maxDepth: number = 10): void {
    this.size = data.length;

    // Stop conditions
    if (depth >= maxDepth || data.length <= 1 || this.allSame(data)) {
      return;
    }

    // Random feature and split value
    this.splitFeature = Math.floor(Math.random() * data[0].length);
    const featureValues = data.map(row => row[this.splitFeature!]);
    const min = Math.min(...featureValues);
    const max = Math.max(...featureValues);
    
    if (min === max) return;
    
    this.splitValue = Math.random() * (max - min) + min;

    // Split data
    const leftData = data.filter(row => row[this.splitFeature!] < this.splitValue!);
    const rightData = data.filter(row => row[this.splitFeature!] >= this.splitValue!);

    // Create child nodes
    if (leftData.length > 0) {
      this.left = new IsolationTree();
      this.left.fit(leftData, depth + 1, maxDepth);
    }

    if (rightData.length > 0) {
      this.right = new IsolationTree();
      this.right.fit(rightData, depth + 1, maxDepth);
    }
  }

  pathLength(point: number[], depth: number): number {
    // If leaf node, return depth + expected path length
    if (this.splitFeature === undefined || this.splitValue === undefined) {
      return depth + this.expectedPathLength(this.size);
    }

    // Continue down the tree
    if (point[this.splitFeature] < this.splitValue) {
      return this.left ? this.left.pathLength(point, depth + 1) : depth + 1;
    } else {
      return this.right ? this.right.pathLength(point, depth + 1) : depth + 1;
    }
  }

  private allSame(data: number[][]): boolean {
    if (data.length <= 1) return true;
    const first = data[0];
    return data.every(row => row.every((val, i) => val === first[i]));
  }

  private expectedPathLength(n: number): number {
    if (n <= 1) return 0;
    return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
  }
}

// Main Behavioral Analysis Engine
export class BehavioralAnalysisEngine extends EventEmitter {
  private config: AnomalyDetectionConfig;
  private behaviorProfiles: Map<string, BehaviorProfile> = new Map();

  constructor(config: Partial<AnomalyDetectionConfig> = {}) {
    super();
    
    this.config = {
      statistical_methods: {
        z_score_threshold: 3.0,
        iqr_multiplier: 1.5,
        enable_seasonal_decomposition: true,
        rolling_window_size: 100,
        ...config.statistical_methods
      },
      machine_learning: {
        isolation_forest_contamination: 0.1,
        enable_clustering: true,
        feature_importance_threshold: 0.1,
        ...config.machine_learning
      },
      behavioral_thresholds: {
        frequency_deviation_threshold: 0.3,
        temporal_shift_threshold: 2.0,
        resource_access_anomaly_threshold: 0.5,
        ...config.behavioral_thresholds
      },
      context_awareness: {
        enable_contextual_scoring: true,
        business_hours: { start: 9, end: 17 },
        weekend_weight: 0.5,
        holiday_weight: 0.3,
        ...config.context_awareness
      }
    };

    logger.info('Behavioral Analysis Engine initialized', {
      statistical_methods: this.config.statistical_methods,
      ml_enabled: this.config.machine_learning.enable_clustering
    });
  }

  /**
   * Process scan results to update behavioral profiles and detect anomalies
   */
  async processScanResults(scanResults: ScanResult[]): Promise<AnomalyIndicator[]> {
    const anomalies: AnomalyIndicator[] = [];

    try {
      for (const result of scanResults) {
        const entityId = this.extractEntityId(result);
        const profile = await this.getOrCreateProfile(entityId, result);
        
        // Update behavior metrics
        const currentMetrics = this.extractBehaviorMetrics(result);
        profile.current_behavior = currentMetrics;

        // Detect anomalies
        const entityAnomalies = await this.detectAnomalies(profile, result);
        anomalies.push(...entityAnomalies);

        // Update baseline if behavior is normal
        if (entityAnomalies.length === 0 || entityAnomalies.every(a => a.severity === 'low')) {
          await this.updateBaseline(profile, currentMetrics);
        }

        // Update profile
        profile.last_updated = new Date();
        profile.profile_age_days = Math.floor(
          (Date.now() - profile.baseline.statistical_profile.time_series[0]?.timestamp.getTime() || 0) / (1000 * 60 * 60 * 24)
        );

        this.behaviorProfiles.set(entityId, profile);
      }

      // Emit anomalies event
      if (anomalies.length > 0) {
        this.emit('anomalies_detected', anomalies);
        logger.warn(`Detected ${anomalies.length} behavioral anomalies`, {
          high_severity: anomalies.filter(a => a.severity === 'high' || a.severity === 'critical').length,
          entities_affected: new Set(anomalies.map(a => this.extractEntityIdFromAnomaly(a))).size
        });
      }

    } catch (error) {
      logger.error('Error processing scan results for behavioral analysis', error);
    }

    return anomalies;
  }

  /**
   * Detect anomalies in current behavior compared to baseline
   */
  private async detectAnomalies(profile: BehaviorProfile, scanResult: ScanResult): Promise<AnomalyIndicator[]> {
    const anomalies: AnomalyIndicator[] = [];
    const current = profile.current_behavior;
    const baseline = profile.baseline;

    try {
      // Statistical anomaly detection
      const statisticalAnomalies = this.detectStatisticalAnomalies(current, baseline);
      anomalies.push(...statisticalAnomalies);

      // Behavioral pattern anomalies
      const behavioralAnomalies = this.detectBehavioralAnomalies(current, baseline);
      anomalies.push(...behavioralAnomalies);

      // Temporal anomalies
      const temporalAnomalies = this.detectTemporalAnomalies(current, baseline);
      anomalies.push(...temporalAnomalies);

      // Context-aware scoring
      if (this.config.context_awareness.enable_contextual_scoring) {
        anomalies.forEach(anomaly => {
          anomaly.score = this.adjustContextualScore(anomaly, scanResult);
        });
      }

      // Calculate overall anomaly score for profile
      profile.anomaly_score = this.calculateOverallAnomalyScore(anomalies);
      profile.confidence_level = this.calculateConfidenceLevel(profile);

    } catch (error) {
      logger.error('Error detecting anomalies', error);
    }

    return anomalies;
  }

  /**
   * Detect statistical anomalies using Z-score and IQR methods
   */
  private detectStatisticalAnomalies(current: BehaviorMetrics, baseline: BaselineModel): AnomalyIndicator[] {
    const anomalies: AnomalyIndicator[] = [];

    try {
      // Activity frequency anomaly
      const freqProfile = baseline.statistical_profile.metrics['activity_frequency'];
      if (freqProfile) {
        const zScore = StatisticalAnalyzer.calculateZScore(
          current.activity_frequency,
          freqProfile.mean,
          freqProfile.std_dev
        );

        if (zScore > this.config.statistical_methods.z_score_threshold) {
          anomalies.push({
            indicator_type: 'statistical',
            severity: zScore > 5 ? 'critical' : zScore > 4 ? 'high' : 'medium',
            score: zScore,
            description: `Unusual activity frequency detected (Z-score: ${zScore.toFixed(2)})`,
            evidence: [
              `Current frequency: ${current.activity_frequency}`,
              `Baseline mean: ${freqProfile.mean.toFixed(2)}`,
              `Standard deviation: ${freqProfile.std_dev.toFixed(2)}`
            ],
            detected_at: new Date()
          });
        }
      }

      // Network behavior anomalies
      if (current.network_behavior.data_transfer_volume > 0) {
        const volumeProfile = baseline.statistical_profile.metrics['data_transfer_volume'];
        if (volumeProfile) {
          const zScore = StatisticalAnalyzer.calculateZScore(
            current.network_behavior.data_transfer_volume,
            volumeProfile.mean,
            volumeProfile.std_dev
          );

          if (zScore > this.config.statistical_methods.z_score_threshold) {
            anomalies.push({
              indicator_type: 'statistical',
              severity: zScore > 6 ? 'critical' : zScore > 4 ? 'high' : 'medium',
              score: zScore,
              description: `Abnormal data transfer volume (Z-score: ${zScore.toFixed(2)})`,
              evidence: [
                `Current volume: ${current.network_behavior.data_transfer_volume} bytes`,
                `Baseline mean: ${volumeProfile.mean.toFixed(2)} bytes`
              ],
              detected_at: new Date()
            });
          }
        }
      }

    } catch (error) {
      logger.error('Error detecting statistical anomalies', error);
    }

    return anomalies;
  }

  /**
   * Detect behavioral pattern anomalies
   */
  private detectBehavioralAnomalies(current: BehaviorMetrics, baseline: BaselineModel): AnomalyIndicator[] {
    const anomalies: AnomalyIndicator[] = [];

    try {
      // Resource access pattern changes
      for (const currentPattern of current.resource_access_patterns) {
        const baselinePattern = baseline.behavioral_patterns.find(
          p => p.pattern_type === 'frequency' && 
              p.parameters.resource_type === currentPattern.resource_type
        );

        if (baselinePattern) {
          const frequencyDeviation = Math.abs(
            currentPattern.access_frequency - baselinePattern.parameters.frequency
          ) / baselinePattern.parameters.frequency;

          if (frequencyDeviation > this.config.behavioral_thresholds.frequency_deviation_threshold) {
            anomalies.push({
              indicator_type: 'behavioral',
              severity: frequencyDeviation > 0.8 ? 'high' : 'medium',
              score: frequencyDeviation,
              description: `Unusual resource access pattern for ${currentPattern.resource_type}`,
              evidence: [
                `Current frequency: ${currentPattern.access_frequency}`,
                `Baseline frequency: ${baselinePattern.parameters.frequency}`,
                `Deviation: ${(frequencyDeviation * 100).toFixed(1)}%`
              ],
              detected_at: new Date()
            });
          }
        }
      }

      // New resource types accessed
      const baselineResourceTypes = new Set(
        baseline.behavioral_patterns
          .filter(p => p.pattern_type === 'frequency')
          .map(p => p.parameters.resource_type)
      );

      const newResourceTypes = current.resource_access_patterns
        .map(p => p.resource_type)
        .filter(type => !baselineResourceTypes.has(type));

      if (newResourceTypes.length > 0) {
        anomalies.push({
          indicator_type: 'behavioral',
          severity: 'medium',
          score: newResourceTypes.length,
          description: `Access to new resource types detected`,
          evidence: [`New resources: ${newResourceTypes.join(', ')}`],
          detected_at: new Date()
        });
      }

    } catch (error) {
      logger.error('Error detecting behavioral anomalies', error);
    }

    return anomalies;
  }

  /**
   * Detect temporal anomalies
   */
  private detectTemporalAnomalies(current: BehaviorMetrics, baseline: BaselineModel): AnomalyIndicator[] {
    const anomalies: AnomalyIndicator[] = [];

    try {
      const currentHour = new Date().getHours();
      const currentDay = new Date().getDay();

      // Find matching temporal patterns
      for (const currentTemporal of current.temporal_patterns) {
        const baselineTemporal = baseline.behavioral_patterns.find(
          p => p.pattern_type === 'temporal' &&
              p.parameters.time_of_day === currentTemporal.time_of_day &&
              p.parameters.day_of_week === currentTemporal.day_of_week
        );

        if (baselineTemporal) {
          const activityDeviation = Math.abs(
            currentTemporal.activity_level - baselineTemporal.parameters.activity_level
          ) / baselineTemporal.parameters.activity_level;

          if (activityDeviation > this.config.behavioral_thresholds.temporal_shift_threshold) {
            anomalies.push({
              indicator_type: 'temporal',
              severity: activityDeviation > 3 ? 'high' : 'medium',
              score: activityDeviation,
              description: `Unusual activity timing pattern detected`,
              evidence: [
                `Time: ${currentTemporal.time_of_day}:00 on ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][currentTemporal.day_of_week]}`,
                `Current activity: ${currentTemporal.activity_level}`,
                `Baseline activity: ${baselineTemporal.parameters.activity_level}`
              ],
              detected_at: new Date()
            });
          }
        }
      }

      // Off-hours activity detection
      const isBusinessHours = currentHour >= this.config.context_awareness.business_hours.start &&
                            currentHour <= this.config.context_awareness.business_hours.end &&
                            currentDay >= 1 && currentDay <= 5; // Monday to Friday

      if (!isBusinessHours && current.activity_frequency > 0) {
        const offHoursPattern = baseline.behavioral_patterns.find(
          p => p.pattern_type === 'temporal' && p.parameters.off_hours
        );

        if (!offHoursPattern || current.activity_frequency > offHoursPattern.parameters.frequency * 2) {
          anomalies.push({
            indicator_type: 'temporal',
            severity: 'medium',
            score: current.activity_frequency,
            description: 'Unusual off-hours activity detected',
            evidence: [
              `Activity at ${currentHour}:00`,
              `Business hours: ${this.config.context_awareness.business_hours.start}-${this.config.context_awareness.business_hours.end}`
            ],
            detected_at: new Date()
          });
        }
      }

    } catch (error) {
      logger.error('Error detecting temporal anomalies', error);
    }

    return anomalies;
  }

  /**
   * Adjust anomaly score based on context
   */
  private adjustContextualScore(anomaly: AnomalyIndicator, scanResult: ScanResult): number {
    let adjustedScore = anomaly.score;

    const now = new Date();
    const hour = now.getHours();
    const day = now.getDay();

    // Weekend adjustment
    if (day === 0 || day === 6) {
      adjustedScore *= (1 + (1 - this.config.context_awareness.weekend_weight));
    }

    // Business hours adjustment
    const isBusinessHours = hour >= this.config.context_awareness.business_hours.start &&
                          hour <= this.config.context_awareness.business_hours.end;
    
    if (!isBusinessHours) {
      adjustedScore *= 1.5; // Increase severity for off-hours activity
    }

    // Severity-based findings adjustment
    const highSeverityFindings = scanResult.findings.filter(f => f.severity === 'high' || f.severity === 'critical');
    if (highSeverityFindings.length > 0) {
      adjustedScore *= 1.3; // Increase score if high-severity security findings are present
    }

    return adjustedScore;
  }

  /**
   * Calculate overall anomaly score for a profile
   */
  private calculateOverallAnomalyScore(anomalies: AnomalyIndicator[]): number {
    if (anomalies.length === 0) return 0;

    const weights = {
      'critical': 4,
      'high': 3,
      'medium': 2,
      'low': 1
    };

    const weightedSum = anomalies.reduce((sum, anomaly) => {
      return sum + (anomaly.score * weights[anomaly.severity]);
    }, 0);

    const maxPossibleScore = anomalies.length * 4 * 10; // Assuming max score of 10
    return Math.min(1, weightedSum / maxPossibleScore);
  }

  /**
   * Calculate confidence level for a profile
   */
  private calculateConfidenceLevel(profile: BehaviorProfile): number {
    const minDataPoints = 50;
    const dataPoints = profile.baseline.statistical_profile.time_series.length;
    const ageBonus = Math.min(0.3, profile.profile_age_days / 30 * 0.3); // Max 30% bonus for 30+ days
    
    const dataConfidence = Math.min(1, dataPoints / minDataPoints);
    return Math.min(1, dataConfidence + ageBonus);
  }

  /**
   * Update baseline model with new behavior data
   */
  private async updateBaseline(profile: BehaviorProfile, metrics: BehaviorMetrics): Promise<void> {
    try {
      // Update statistical profile
      this.updateStatisticalProfile(profile.baseline.statistical_profile, metrics);

      // Update behavioral patterns
      this.updateBehavioralPatterns(profile.baseline.behavioral_patterns, metrics);

      // Update seasonal patterns if enabled
      if (this.config.statistical_methods.enable_seasonal_decomposition) {
        this.updateSeasonalPatterns(profile.baseline.seasonal_patterns, profile.baseline.statistical_profile.time_series);
      }

    } catch (error) {
      logger.error('Error updating baseline model', error);
    }
  }

  /**
   * Update statistical profile with new metrics
   */
  private updateStatisticalProfile(profile: StatisticalProfile, metrics: BehaviorMetrics): void {
    const now = new Date();

    // Add new time series data
    profile.time_series.push({
      timestamp: now,
      value: metrics.activity_frequency,
      context: {
        resource_accesses: metrics.resource_access_patterns.length,
        network_volume: metrics.network_behavior.data_transfer_volume
      }
    });

    // Limit time series size
    const maxSize = this.config.statistical_methods.rolling_window_size;
    if (profile.time_series.length > maxSize) {
      profile.time_series = profile.time_series.slice(-maxSize);
    }

    // Recalculate statistics
    const values = profile.time_series.map(ts => ts.value);
    if (values.length > 0) {
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
      const stdDev = Math.sqrt(variance);

      profile.metrics['activity_frequency'] = {
        mean,
        std_dev: stdDev,
        median: StatisticalAnalyzer.percentile(values, 50),
        percentile_95: StatisticalAnalyzer.percentile(values, 95),
        percentile_99: StatisticalAnalyzer.percentile(values, 99),
        min: Math.min(...values),
        max: Math.max(...values),
        trend: this.calculateTrend(values)
      };
    }

    // Update network volume statistics
    const networkVolumes = profile.time_series.map(ts => ts.context.network_volume || 0);
    if (networkVolumes.length > 0 && networkVolumes.some(v => v > 0)) {
      const mean = networkVolumes.reduce((a, b) => a + b, 0) / networkVolumes.length;
      const variance = networkVolumes.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / networkVolumes.length;
      const stdDev = Math.sqrt(variance);

      profile.metrics['data_transfer_volume'] = {
        mean,
        std_dev: stdDev,
        median: StatisticalAnalyzer.percentile(networkVolumes, 50),
        percentile_95: StatisticalAnalyzer.percentile(networkVolumes, 95),
        percentile_99: StatisticalAnalyzer.percentile(networkVolumes, 99),
        min: Math.min(...networkVolumes),
        max: Math.max(...networkVolumes),
        trend: this.calculateTrend(networkVolumes)
      };
    }
  }

  /**
   * Calculate trend direction
   */
  private calculateTrend(values: number[]): 'increasing' | 'decreasing' | 'stable' {
    if (values.length < 2) return 'stable';

    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));

    const firstMean = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const secondMean = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    const change = (secondMean - firstMean) / firstMean;

    if (change > 0.1) return 'increasing';
    if (change < -0.1) return 'decreasing';
    return 'stable';
  }

  /**
   * Update behavioral patterns
   */
  private updateBehavioralPatterns(patterns: BehaviorPattern[], metrics: BehaviorMetrics): void {
    const now = new Date();

    // Update resource access patterns
    for (const resourcePattern of metrics.resource_access_patterns) {
      let pattern = patterns.find(
        p => p.pattern_type === 'frequency' && 
            p.parameters.resource_type === resourcePattern.resource_type
      );

      if (!pattern) {
        pattern = {
          pattern_id: `freq_${resourcePattern.resource_type}_${Date.now()}`,
          pattern_type: 'frequency',
          description: `Frequency pattern for ${resourcePattern.resource_type}`,
          confidence: 0.5,
          occurrences: 0,
          last_seen: now,
          parameters: {
            resource_type: resourcePattern.resource_type,
            frequency: resourcePattern.access_frequency
          }
        };
        patterns.push(pattern);
      }

      // Update pattern
      pattern.occurrences++;
      pattern.last_seen = now;
      pattern.confidence = Math.min(1, pattern.confidence + 0.1);
      
      // Smooth frequency update
      const alpha = 0.1; // Learning rate
      pattern.parameters.frequency = 
        alpha * resourcePattern.access_frequency + 
        (1 - alpha) * pattern.parameters.frequency;
    }

    // Update temporal patterns
    for (const temporalPattern of metrics.temporal_patterns) {
      let pattern = patterns.find(
        p => p.pattern_type === 'temporal' &&
            p.parameters.time_of_day === temporalPattern.time_of_day &&
            p.parameters.day_of_week === temporalPattern.day_of_week
      );

      if (!pattern) {
        pattern = {
          pattern_id: `temp_${temporalPattern.time_of_day}_${temporalPattern.day_of_week}_${Date.now()}`,
          pattern_type: 'temporal',
          description: `Temporal pattern for ${temporalPattern.time_of_day}:00 on day ${temporalPattern.day_of_week}`,
          confidence: 0.3,
          occurrences: 0,
          last_seen: now,
          parameters: {
            time_of_day: temporalPattern.time_of_day,
            day_of_week: temporalPattern.day_of_week,
            activity_level: temporalPattern.activity_level
          }
        };
        patterns.push(pattern);
      }

      // Update pattern
      pattern.occurrences++;
      pattern.last_seen = now;
      pattern.confidence = Math.min(1, pattern.confidence + 0.05);
      
      // Smooth activity level update
      const alpha = 0.15;
      pattern.parameters.activity_level = 
        alpha * temporalPattern.activity_level + 
        (1 - alpha) * pattern.parameters.activity_level;
    }

    // Remove old patterns (older than 30 days with low confidence)
    const cutoffDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    patterns = patterns.filter(p => p.last_seen > cutoffDate || p.confidence > 0.5);
  }

  /**
   * Update seasonal patterns
   */
  private updateSeasonalPatterns(seasonalPatterns: SeasonalPattern[], timeSeries: TimeSeriesData[]): void {
    if (timeSeries.length < 48) return; // Need at least 48 data points

    // Daily pattern (24 hours)
    const dailyPattern = StatisticalAnalyzer.detectSeasonality(timeSeries, 24);
    this.updateOrAddSeasonalPattern(seasonalPatterns, dailyPattern);

    // Weekly pattern (7 days)
    if (timeSeries.length >= 168) {
      const weeklyPattern = StatisticalAnalyzer.detectSeasonality(timeSeries, 168);
      this.updateOrAddSeasonalPattern(seasonalPatterns, weeklyPattern);
    }
  }

  /**
   * Update or add seasonal pattern
   */
  private updateOrAddSeasonalPattern(patterns: SeasonalPattern[], newPattern: SeasonalPattern): void {
    const existingIndex = patterns.findIndex(p => p.period === newPattern.period);
    
    if (existingIndex >= 0) {
      // Smooth update of existing pattern
      const alpha = 0.2;
      const existing = patterns[existingIndex];
      
      existing.amplitude = alpha * newPattern.amplitude + (1 - alpha) * existing.amplitude;
      existing.phase = alpha * newPattern.phase + (1 - alpha) * existing.phase;
      existing.confidence = Math.max(existing.confidence, newPattern.confidence);
      
      // Update seasonal components
      for (let i = 0; i < Math.min(existing.seasonal_component.length, newPattern.seasonal_component.length); i++) {
        existing.seasonal_component[i] = 
          alpha * newPattern.seasonal_component[i] + 
          (1 - alpha) * existing.seasonal_component[i];
      }
    } else {
      patterns.push(newPattern);
    }
  }

  /**
   * Get or create behavior profile for entity
   */
  private async getOrCreateProfile(entityId: string, scanResult: ScanResult): Promise<BehaviorProfile> {
    let profile = this.behaviorProfiles.get(entityId);
    
    if (!profile) {
      profile = {
        entity_id: entityId,
        entity_type: this.determineEntityType(scanResult),
        baseline: {
          statistical_profile: {
            metrics: {},
            time_series: [],
            correlation_matrix: {}
          },
          behavioral_patterns: [],
          seasonal_patterns: [],
          context_features: []
        },
        current_behavior: this.extractBehaviorMetrics(scanResult),
        anomaly_score: 0,
        confidence_level: 0,
        last_updated: new Date(),
        profile_age_days: 0
      };

      logger.info(`Created new behavior profile for entity: ${entityId}`, {
        entity_type: profile.entity_type
      });
    }

    return profile;
  }

  /**
   * Extract entity ID from scan result
   */
  private extractEntityId(scanResult: ScanResult): string {
    // Use target as primary identifier
    if (scanResult.target.target) {
      return `${scanResult.target.type}_${scanResult.target.target}`;
    }
    
    // Fallback to scan ID or generate one
    return scanResult.id || `entity_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Extract entity ID from anomaly indicator
   */
  private extractEntityIdFromAnomaly(_anomaly: AnomalyIndicator): string {
    // This would need to be implemented based on how anomaly evidence stores entity info
    return 'unknown_entity';
  }

  /**
   * Determine entity type from scan result
   */
  private determineEntityType(scanResult: ScanResult): 'user' | 'service' | 'network' | 'system' {
    const targetType = scanResult.target.type;
    
    switch (targetType) {
      case 'network':
        return 'network';
      case 'identity':
        return 'user';
      case 'supply-chain':
        return 'service';
      case 'compliance':
        return 'system';
      default:
        return 'system';
    }
  }

  /**
   * Extract behavior metrics from scan result
   */
  private extractBehaviorMetrics(scanResult: ScanResult): BehaviorMetrics {
    const now = new Date();
    
    return {
      activity_frequency: scanResult.findings.length,
      resource_access_patterns: this.extractResourceAccessPatterns(scanResult),
      temporal_patterns: [{
        time_of_day: now.getHours(),
        day_of_week: now.getDay(),
        activity_level: scanResult.findings.length,
        variance: 0
      }],
      network_behavior: {
        connection_patterns: this.extractConnectionPatterns(scanResult),
        data_transfer_volume: this.extractDataTransferVolume(scanResult),
        protocol_usage: this.extractProtocolUsage(scanResult),
        geolocation_patterns: []
      },
      anomaly_indicators: []
    };
  }

  /**
   * Extract resource access patterns from scan result
   */
  private extractResourceAccessPatterns(scanResult: ScanResult): ResourceAccessPattern[] {
    const patterns: ResourceAccessPattern[] = [];
    
    // Group findings by category to determine resource types
    const resourceGroups = new Map<string, SecurityFinding[]>();
    
    for (const finding of scanResult.findings) {
      const resourceType = finding.category || 'unknown';
      if (!resourceGroups.has(resourceType)) {
        resourceGroups.set(resourceType, []);
      }
      resourceGroups.get(resourceType)!.push(finding);
    }

    // Create patterns for each resource type
    for (const [resourceType, findings] of resourceGroups) {
      patterns.push({
        resource_type: resourceType,
        access_frequency: findings.length,
        access_times: [new Date()],
        permission_levels: [...new Set(findings.map(f => f.severity))],
        success_rate: 1.0 // Assume successful access for now
      });
    }

    return patterns;
  }

  /**
   * Extract connection patterns from scan result
   */
  private extractConnectionPatterns(scanResult: ScanResult): ConnectionPattern[] {
    const patterns: ConnectionPattern[] = [];
    
    // Extract network-related findings
    const networkFindings = scanResult.findings.filter(f => 
      f.category === 'network-security' || 
      f.title.toLowerCase().includes('network') ||
      f.title.toLowerCase().includes('connection')
    );

    for (const finding of networkFindings) {
      // Extract IP patterns from finding description
      const ipPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
      const ips = finding.description.match(ipPattern) || [];
      
      if (ips.length >= 2) {
        patterns.push({
          source_ip: ips[0] || 'unknown',
          destination_ip: ips[1] || 'unknown',
          port: this.extractPortFromDescription(finding.description),
          frequency: 1,
          duration_avg: 0,
          last_connection: new Date()
        });
      }
    }

    return patterns;
  }

  /**
   * Extract data transfer volume from scan result
   */
  private extractDataTransferVolume(scanResult: ScanResult): number {
    // For now, estimate based on number of findings and their complexity
    // In a real implementation, this would come from actual network monitoring
    return scanResult.findings.length * 1024; // 1KB per finding as baseline
  }

  /**
   * Extract protocol usage from scan result
   */
  private extractProtocolUsage(scanResult: ScanResult): { [protocol: string]: number } {
    const protocols: { [protocol: string]: number } = {};
    
    for (const finding of scanResult.findings) {
      const description = finding.description.toLowerCase();
      
      // Simple protocol detection
      if (description.includes('tcp')) protocols['tcp'] = (protocols['tcp'] || 0) + 1;
      if (description.includes('udp')) protocols['udp'] = (protocols['udp'] || 0) + 1;
      if (description.includes('http')) protocols['http'] = (protocols['http'] || 0) + 1;
      if (description.includes('https')) protocols['https'] = (protocols['https'] || 0) + 1;
      if (description.includes('ssh')) protocols['ssh'] = (protocols['ssh'] || 0) + 1;
      if (description.includes('ftp')) protocols['ftp'] = (protocols['ftp'] || 0) + 1;
    }

    return protocols;
  }

  /**
   * Extract port number from description text
   */
  private extractPortFromDescription(description: string): number {
    const portPattern = /port\s+(\d+)/i;
    const match = description.match(portPattern);
    return match ? parseInt(match[1]) : 80; // Default to port 80
  }

  /**
   * Get all behavior profiles
   */
  getBehaviorProfiles(): BehaviorProfile[] {
    return Array.from(this.behaviorProfiles.values());
  }

  /**
   * Get profile for specific entity
   */
  getBehaviorProfile(entityId: string): BehaviorProfile | undefined {
    return this.behaviorProfiles.get(entityId);
  }

  /**
   * Get profiles with high anomaly scores
   */
  getAnomalousProfiles(threshold: number = 0.7): BehaviorProfile[] {
    return this.getBehaviorProfiles().filter(profile => profile.anomaly_score > threshold);
  }

  /**
   * Export behavior profiles for analysis
   */
  exportProfiles(): string {
    const exportData = {
      timestamp: new Date().toISOString(),
      total_profiles: this.behaviorProfiles.size,
      profiles: Array.from(this.behaviorProfiles.values()).map(profile => ({
        ...profile,
        baseline: {
          ...profile.baseline,
          statistical_profile: {
            ...profile.baseline.statistical_profile,
            time_series: profile.baseline.statistical_profile.time_series.slice(-10) // Last 10 points only
          }
        }
      }))
    };

    return JSON.stringify(exportData, null, 2);
  }

  /**
   * Clear old profiles to manage memory
   */
  cleanupOldProfiles(maxAgeDays: number = 90): void {
    const cutoffDate = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000);
    let removedCount = 0;

    for (const [entityId, profile] of this.behaviorProfiles) {
      if (profile.last_updated < cutoffDate && profile.confidence_level < 0.3) {
        this.behaviorProfiles.delete(entityId);
        removedCount++;
      }
    }

    if (removedCount > 0) {
      logger.info(`Cleaned up ${removedCount} old behavior profiles`, {
        remaining_profiles: this.behaviorProfiles.size,
        max_age_days: maxAgeDays
      });
    }
  }
}

export default BehavioralAnalysisEngine;
