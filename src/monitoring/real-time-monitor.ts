/**
 * Real-Time Monitoring Engine
 * Provides continuous security monitoring with WebSocket-based live updates
 *
 * Features:
 * - Continuous scanning with configurable intervals
 * - Real-time threat detection and alerting
 * - WebSocket-based live dashboard updates
 * - Event-driven architecture for scalability
 * - Intelligent change detection and delta reporting
 */

import WebSocket from 'ws';
import { randomUUID } from 'crypto';
import { EventEmitter } from 'events';
import { ZeroTrustScanner } from '../core/scanner';
import { ScanTarget, SecurityFinding, ScanResult } from '../core/scanner';
import { Logger } from '../utils/logger';
import BehavioralMonitoringIntegration, {
  EnhancedSecurityEvent,
} from '../analytics/behavioral-integration';

// Create logger instance
const logger = Logger.getInstance();

// Real-time monitoring types
export interface MonitoringConfig {
  scan_interval: number; // milliseconds
  targets: MonitoringTarget[];
  alerting: AlertingConfig;
  websocket: WebSocketConfig;
  change_detection: ChangeDetectionConfig;
}

export interface MonitoringTarget {
  id: string;
  name: string;
  scan_target: ScanTarget;
  priority: 'critical' | 'high' | 'medium' | 'low';
  enabled: boolean;
  last_scan?: Date;
  baseline?: SecurityFinding[];
}

export interface AlertingConfig {
  enabled: boolean;
  channels: AlertChannel[];
  severity_threshold: 'critical' | 'high' | 'medium' | 'low';
  rate_limiting: {
    max_alerts_per_minute: number;
    cooldown_period: number;
  };
}

export interface AlertChannel {
  type: 'slack' | 'teams' | 'webhook' | 'email' | 'sms';
  config: any;
  enabled: boolean;
}

export interface WebSocketConfig {
  port: number;
  path: string;
  authentication: boolean;
  max_connections: number;
  token?: string; // optional static token for simple auth
  token_header?: string; // optional header name for token (default: x-ztis-token)
  jwt_secret?: string; // optional shared secret for verifying JWTs
  jwt_issuer?: string; // optional expected JWT issuer
  jwt_audience?: string; // optional expected JWT audience
  // Hardened settings
  require_jwt?: boolean; // when true (default), JWT is required if authentication is enabled
  allowed_origins?: string[]; // optional list of allowed Origin values
  allowed_ips?: string[]; // optional list of allowed client IPs
  max_token_length?: number; // default 4096
  ping_interval_ms?: number; // default 30000
  pong_timeout_ms?: number; // default 10000
  // Auth rate limiting (per IP)
  auth_rate_limit?: {
    window_ms?: number; // sliding window size; default 60000
    max_attempts?: number; // max failed attempts per window; default 10
    block_duration_ms?: number; // temporary block duration; default 300000 (5m)
  };
  // Backpressure handling
  backpressure?: {
    max_buffered_bytes?: number; // drop when client.bufferedAmount exceeds; default 1_000_000
    warn_buffered_bytes?: number; // warn when exceeding; default half of max
    drop_if_exceeds?: boolean; // default true (drop msg to slow client)
    close_after_drops?: number; // close slow client after consecutive drops; default 5
  };
}

export interface ChangeDetectionConfig {
  enabled: boolean;
  delta_threshold: number; // percentage change to trigger alert
  baseline_update_frequency: number; // hours
  ignore_transient_changes: boolean;
}

export interface MonitoringEvent {
  id: string;
  timestamp: Date;
  type:
    | 'scan_started'
    | 'scan_completed'
    | 'finding_detected'
    | 'finding_resolved'
    | 'target_changed'
    | 'alert_triggered'
    | 'behavioral_anomaly';
  target_id: string;
  data: any;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface LiveUpdate {
  event_id: string;
  timestamp: Date;
  type: 'status' | 'finding' | 'metric' | 'alert' | 'behavioral_baseline_update';
  target: string;
  data: any;
  // Optional top-level severity to simplify client rendering
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export class RealTimeMonitor extends EventEmitter {
  private scanner: ZeroTrustScanner;
  private config: MonitoringConfig;
  private wsServer: WebSocket.Server | null = null;
  private connectedClients: Set<WebSocket> = new Set();
  private monitoringIntervals: Map<string, NodeJS.Timeout> = new Map();
  private alertQueue: MonitoringEvent[] = [];
  private isRunning: boolean = false;
  private targetBaselines: Map<string, SecurityFinding[]> = new Map();
  private behavioralAnalysis: BehavioralMonitoringIntegration;
  private heartbeatMap: Map<
    WebSocket,
    { isAlive: boolean; interval: NodeJS.Timeout; lastPong: number }
  > = new Map();
  // Per-IP auth attempt tracking for rate limiting
  private authAttemptMap: Map<string, { attempts: number[]; blockedUntil?: number }> = new Map();
  // Backpressure metrics/state
  private slowClientDropCounts: WeakMap<WebSocket, number> = new WeakMap();
  private wsDroppedMessages: number = 0;

  constructor(config: MonitoringConfig) {
    super();
    this.config = config;
    this.scanner = new ZeroTrustScanner();

    // Initialize behavioral analysis integration
    this.behavioralAnalysis = new BehavioralMonitoringIntegration({
      enabled: true,
      analysis_interval: config.scan_interval,
      anomaly_threshold: 0.6,
      real_time_updates: true,
      baseline_update_frequency: 24,
      profile_retention_days: 90,
    });

    this.setupBehavioralEventHandlers();

    logger.info('🔴 Real-Time Monitor initialized with Behavioral Analysis', {
      targets: config.targets.length,
      scan_interval: config.scan_interval,
      websocket_port: config.websocket.port,
      behavioral_analysis: true,
    });
  }

  /**
   * Setup behavioral analysis event handlers
   */
  private setupBehavioralEventHandlers(): void {
    // Listen for behavioral events
    this.behavioralAnalysis.on('behavioral_events', (events: EnhancedSecurityEvent[]) => {
      this.handleBehavioralEvents(events);
    });

    // Listen for high-severity anomalies
    this.behavioralAnalysis.on('high_severity_anomalies', (anomalies: any[]) => {
      logger.warn('High-severity behavioral anomalies detected', {
        count: anomalies.length,
        critical_count: anomalies.filter((a) => a.severity === 'critical').length,
      });

      // Send immediate alerts for critical anomalies
      for (const anomaly of anomalies.filter((a) => a.severity === 'critical')) {
        this.emitEvent({
          id: this.generateEventId(),
          timestamp: new Date(),
          type: 'behavioral_anomaly',
          target_id: 'behavioral_analysis',
          data: {
            anomaly_type: anomaly.indicator_type,
            severity: anomaly.severity,
            score: anomaly.score,
            description: anomaly.description,
            evidence: anomaly.evidence,
          },
          severity: 'critical',
        });
      }
    });

    // Listen for baseline updates
    this.behavioralAnalysis.on('baseline_update_completed', (data: any) => {
      logger.info('Behavioral baseline update completed', data);

      this.broadcastLiveUpdate({
        event_id: this.generateEventId(),
        timestamp: new Date(),
        type: 'behavioral_baseline_update',
        target: 'behavioral_analysis',
        data: {
          profiles_count: data.profiles_count,
          update_timestamp: data.timestamp,
        },
      });
    });
  }

  /**
   * Start real-time monitoring
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Real-time monitor is already running');
      return;
    }

    try {
      // Initialize scanner
      await this.scanner.initialize();

      // Start WebSocket server
      await this.startWebSocketServer();

      // Load target baselines
      await this.loadTargetBaselines();

      // Start monitoring targets
      await this.startTargetMonitoring();

      // Start alert processing
      this.startAlertProcessing();

      this.isRunning = true;

      logger.info('🚀 Real-time monitoring started successfully');
      this.emitEvent({
        id: this.generateEventId(),
        timestamp: new Date(),
        type: 'scan_started',
        target_id: 'system',
        data: { message: 'Real-time monitoring started' },
        severity: 'info',
      });
    } catch (error) {
      logger.error('❌ Failed to start real-time monitoring:', error);
      throw error;
    }
  }

  /**
   * Stop real-time monitoring
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      return;
    }

    try {
      // Stop target monitoring
      for (const [targetId, interval] of this.monitoringIntervals) {
        clearInterval(interval);
        logger.debug(`Stopped monitoring for target: ${targetId}`);
      }
      this.monitoringIntervals.clear();

      // Close WebSocket server
      if (this.wsServer) {
        this.wsServer.close();
        this.connectedClients.clear();
      }

      this.isRunning = false;

      logger.info('⏹️ Real-time monitoring stopped');
    } catch (error) {
      logger.error('❌ Error stopping real-time monitoring:', error);
      throw error;
    }
  }

  /**
   * Start WebSocket server for live updates
   */
  private async startWebSocketServer(): Promise<void> {
    this.wsServer = new WebSocket.Server({
      port: this.config.websocket.port,
      path: this.config.websocket.path,
      // Limit compression window to reduce risk of compression side-channel issues
      perMessageDeflate: { threshold: 1024 },
    });

    // Helper closures for origin/IP checks
    const isOriginAllowed = (req: any): boolean => {
      const allowed = this.config.websocket.allowed_origins;
      if (!allowed || allowed.length === 0) return true;
      const origin = (
        req.headers?.origin ||
        req.headers?.['sec-websocket-origin'] ||
        ''
      ).toString();
      if (!origin) return false; // if allowlist present, require origin
      return allowed.includes('*') || allowed.some((o) => o === origin);
    };
    const normalizeIp = (ip: string | undefined): string => {
      if (!ip) return '';
      // Strip IPv6 mapped IPv4 prefix
      if (ip.startsWith('::ffff:')) return ip.slice(7);
      return ip;
    };
    const isIpAllowed = (req: any): boolean => {
      const allowed = this.config.websocket.allowed_ips;
      if (!allowed || allowed.length === 0) return true;
      const ip = normalizeIp(req.socket?.remoteAddress);
      return !!ip && (allowed.includes('*') || allowed.includes(ip));
    };

    this.wsServer.on('connection', async (ws: WebSocket, request: any) => {
      const clientIp = normalizeIp(request.socket?.remoteAddress);

      // Enforce connection limits
      const max = this.config.websocket.max_connections || 100;
      if (this.connectedClients.size >= max) {
        try {
          ws.close(1013, 'Server busy');
        } catch {
          /* ignore */
        }
        logger.warn(`WebSocket connection refused (limit ${max}) from ${clientIp}`);
        return;
      }

      // Enforce origin/IP allowlists when configured
      if (!isOriginAllowed(request)) {
        try {
          ws.close(1008, 'Origin not allowed');
        } catch {
          /* ignore */
        }
        logger.warn(
          `❌ WebSocket origin not allowed: ${request.headers?.origin || request.headers?.['sec-websocket-origin']}`
        );
        return;
      }
      if (!isIpAllowed(request)) {
        try {
          ws.close(1008, 'IP not allowed');
        } catch {
          /* ignore */
        }
        logger.warn(`❌ WebSocket IP not allowed: ${clientIp}`);
        return;
      }

      // Simple token/JWT auth if enabled
      if (this.config.websocket.authentication) {
        try {
          // Per-IP auth rate limiting: check temporary block first
          const rlCfg = this.config.websocket.auth_rate_limit || {};
          const rlWindow = rlCfg.window_ms ?? 60_000;
          const rlMax = rlCfg.max_attempts ?? 10;
          const rlBlock = rlCfg.block_duration_ms ?? 300_000; // 5 minutes
          if (clientIp) {
            const entry = this.authAttemptMap.get(clientIp);
            if (entry && entry.blockedUntil && Date.now() < entry.blockedUntil) {
              try {
                ws.close(1013, 'Temporarily blocked');
              } catch {
                /* ignore */
              }
              logger.warn(`❌ WebSocket auth temporarily blocked for ${clientIp}`);
              return;
            }
          }

          const headerName = (
            this.config.websocket.token_header ||
            process.env.ZTIS_WS_TOKEN_HEADER ||
            'x-ztis-token'
          ).toLowerCase();
          const headerToken = (request.headers && (request.headers[headerName] as string)) || '';
          const authzHeader =
            (request.headers && (request.headers['authorization'] as string)) || '';
          let urlToken = '';
          try {
            const fullUrl = new URL(request.url || '/', 'http://localhost');
            urlToken = fullUrl.searchParams.get('token') || '';
          } catch {
            /* ignore URL parse errors */
          }

          const staticExpected = this.config.websocket.token || process.env.ZTIS_WS_TOKEN || '';
          const jwtSecret =
            this.config.websocket.jwt_secret || process.env.ZTIS_WS_JWT_SECRET || '';
          const provided =
            (authzHeader && authzHeader.toLowerCase().startsWith('bearer ')
              ? authzHeader.slice(7).trim()
              : '') ||
            headerToken ||
            urlToken;

          // Enforce token length bounds
          const maxLen = this.config.websocket.max_token_length ?? 4096;
          if (provided && provided.length > maxLen) {
            try {
              ws.close(1008, 'Token too long');
            } catch {
              /* ignore */
            }
            logger.warn(
              `❌ WebSocket auth token exceeded max length (${provided.length} > ${maxLen}) from ${clientIp}`
            );
            return;
          }

          // Determine requirement: default require JWT when auth enabled
          const requireJwt = this.config.websocket.require_jwt !== false;

          let authorized = false;
          if (requireJwt) {
            if (!jwtSecret) {
              logger.error('WebSocket auth requires JWT but no jwt_secret configured');
              try {
                ws.close(1008, 'Auth misconfiguration');
              } catch {
                /* ignore */
              }
              return;
            }
            if (provided && provided.split('.').length === 3) {
              try {
                // Lazy import to avoid cost if not used
                const jwt = await import('jsonwebtoken');
                const verifyOpts: any = {};
                if (this.config.websocket.jwt_issuer || process.env.ZTIS_WS_JWT_ISSUER)
                  verifyOpts.issuer =
                    this.config.websocket.jwt_issuer || process.env.ZTIS_WS_JWT_ISSUER;
                if (this.config.websocket.jwt_audience || process.env.ZTIS_WS_JWT_AUDIENCE)
                  verifyOpts.audience =
                    this.config.websocket.jwt_audience || process.env.ZTIS_WS_JWT_AUDIENCE;
                (jwt as any).verify(provided, jwtSecret, verifyOpts);
                authorized = true;
              } catch (_e) {
                authorized = false;
              }
            }
          } else {
            // Legacy static token path (discouraged)
            if (staticExpected && provided && provided === staticExpected) {
              authorized = true;
              logger.warn(
                'WebSocket using static token authentication; enable require_jwt for stronger security'
              );
            }
          }

          if (!authorized) {
            // Record failed attempt and possibly block further attempts
            if (clientIp) {
              const now = Date.now();
              const entry = this.authAttemptMap.get(clientIp) || { attempts: [] };
              // prune old attempts outside window
              entry.attempts = entry.attempts.filter((t) => now - t <= rlWindow);
              entry.attempts.push(now);
              if (entry.attempts.length >= rlMax) {
                entry.blockedUntil = now + rlBlock;
                logger.warn(
                  `⛔ WebSocket auth rate limit exceeded for ${clientIp} (blocked for ${rlBlock}ms)`
                );
              }
              this.authAttemptMap.set(clientIp, entry);
            }
            try {
              ws.close(1008, 'Invalid or missing auth token');
            } catch {
              /* ignore close error */
            }
            logger.warn(`❌ WebSocket auth failed for ${clientIp}`);
            return;
          }
          // On successful auth, reset attempt counters for this IP
          if (clientIp) {
            this.authAttemptMap.delete(clientIp);
          }
        } catch (e) {
          try {
            ws.close(1008, 'Auth error');
          } catch {
            /* ignore close error */
          }
          logger.error('WebSocket auth processing failed', e);
          return;
        }
      }

      logger.info(`🔌 WebSocket client connected from ${clientIp}`);

      // Heartbeat: ping/pong
      const pingInterval = this.config.websocket.ping_interval_ms ?? 30000;
      const pongTimeout = this.config.websocket.pong_timeout_ms ?? 10000;
      const hb = {
        isAlive: true,
        interval: setInterval(() => {
          const meta = this.heartbeatMap.get(ws);
          if (!meta) return;
          if (!meta.isAlive) {
            try {
              ws.terminate();
            } catch {
              /* ignore */
            }
            clearInterval(meta.interval);
            this.heartbeatMap.delete(ws);
            return;
          }
          meta.isAlive = false;
          try {
            ws.ping();
          } catch {
            /* ignore */
          }
          // Fallback termination if no pong within timeout
          setTimeout(() => {
            const m = this.heartbeatMap.get(ws);
            if (m && !m.isAlive) {
              try {
                ws.terminate();
              } catch {
                /* ignore */
              }
              clearInterval(m.interval);
              this.heartbeatMap.delete(ws);
            }
          }, pongTimeout);
        }, pingInterval),
        lastPong: Date.now(),
      };
      this.heartbeatMap.set(ws, hb);
      try {
        ws.on('pong', () => {
          const m = this.heartbeatMap.get(ws);
          if (m) {
            m.isAlive = true;
            m.lastPong = Date.now();
          }
        });
      } catch {
        /* noop */
      }

      // Add to connected clients
      this.connectedClients.add(ws);

      // Send initial status
      this.sendToClient(ws, {
        event_id: this.generateEventId(),
        timestamp: new Date(),
        type: 'status',
        target: 'system',
        data: {
          status: 'connected',
          targets: this.config.targets.length,
          monitoring_active: this.isRunning,
          active_scans: this.monitoringIntervals.size,
          connected_clients: this.connectedClients.size,
          alerts_queued: this.alertQueue.length,
        },
        severity: 'info',
      });

      // Handle client disconnect
      ws.on('close', () => {
        this.connectedClients.delete(ws);
        const meta = this.heartbeatMap.get(ws);
        if (meta) {
          clearInterval(meta.interval);
          this.heartbeatMap.delete(ws);
        }
        logger.info(`🔌 WebSocket client disconnected from ${clientIp}`);
      });

      // Handle client errors
      ws.on('error', (error: any) => {
        logger.error(`WebSocket error for client ${clientIp}:`, error);
        this.connectedClients.delete(ws);
        const meta = this.heartbeatMap.get(ws);
        if (meta) {
          clearInterval(meta.interval);
          this.heartbeatMap.delete(ws);
        }
      });
    });

    logger.info(`🌐 WebSocket server started on port ${this.config.websocket.port}`);
  }

  /**
   * Load existing baselines for all targets
   */
  private async loadTargetBaselines(): Promise<void> {
    for (const target of this.config.targets) {
      if (target.baseline && target.baseline.length > 0) {
        this.targetBaselines.set(target.id, target.baseline);
        logger.debug(`Loaded baseline for target ${target.id}: ${target.baseline.length} findings`);
      }
    }
  }

  /**
   * Start monitoring all enabled targets
   */
  private async startTargetMonitoring(): Promise<void> {
    for (const target of this.config.targets) {
      if (target.enabled) {
        await this.startMonitoringTarget(target);
      }
    }
  }

  /**
   * Start monitoring a specific target
   */
  private async startMonitoringTarget(target: MonitoringTarget): Promise<void> {
    // Perform initial scan
    await this.scanTarget(target);

    // Set up interval scanning
    const interval = setInterval(async () => {
      if (this.isRunning) {
        await this.scanTarget(target);
      }
    }, this.config.scan_interval);

    this.monitoringIntervals.set(target.id, interval);

    logger.info(`📡 Started monitoring target: ${target.name} (${target.id})`);
  }

  /**
   * Scan a specific target and process results
   */
  private async scanTarget(target: MonitoringTarget): Promise<void> {
    try {
      logger.debug(`🔍 Scanning target: ${target.name}`);

      // Emit scan started event
      this.emitEvent({
        id: this.generateEventId(),
        timestamp: new Date(),
        type: 'scan_started',
        target_id: target.id,
        data: { target_name: target.name },
        severity: 'info',
      });

      // Perform scan
      const result = await this.scanner.scan(target.scan_target);

      // Update target last scan time
      target.last_scan = new Date();

      // Process scan results
      await this.processScanResults(target, result);

      // Emit scan completed event
      this.emitEvent({
        id: this.generateEventId(),
        timestamp: new Date(),
        type: 'scan_completed',
        target_id: target.id,
        data: {
          target_name: target.name,
          findings_count: result.findings.length,
          duration: result.duration,
          status: result.status,
        },
        severity: 'info',
      });
    } catch (error) {
      logger.error(`❌ Error scanning target ${target.name}:`, error);

      this.emitEvent({
        id: this.generateEventId(),
        timestamp: new Date(),
        type: 'scan_completed',
        target_id: target.id,
        data: {
          target_name: target.name,
          error: error instanceof Error ? error.message : 'Unknown error',
          status: 'failed',
        },
        severity: 'high',
      });
    }
  }

  /**
   * Process scan results and detect changes
   */
  private async processScanResults(target: MonitoringTarget, result: ScanResult): Promise<void> {
    const currentFindings = result.findings;
    const baseline = this.targetBaselines.get(target.id) || [];

    // Run behavioral analysis on scan results
    try {
      const behavioralEvents = await this.behavioralAnalysis.processScanResults([result]);
      if (behavioralEvents.length > 0) {
        this.handleBehavioralEvents(behavioralEvents);
      }
    } catch (error) {
      logger.error('Error in behavioral analysis processing', error);
    }

    if (this.config.change_detection.enabled) {
      // Detect new findings
      const newFindings = this.detectNewFindings(currentFindings, baseline);

      // Detect resolved findings
      const resolvedFindings = this.detectResolvedFindings(currentFindings, baseline);

      // Process new findings
      for (const finding of newFindings) {
        await this.processNewFinding(target, finding);
      }

      // Process resolved findings
      for (const finding of resolvedFindings) {
        await this.processResolvedFinding(target, finding);
      }

      // Update baseline if needed
      if (this.shouldUpdateBaseline(target)) {
        this.updateTargetBaseline(target.id, currentFindings);
      }
    }

    // Send live update to connected clients
    this.broadcastLiveUpdate({
      event_id: this.generateEventId(),
      timestamp: new Date(),
      type: 'metric',
      target: target.name,
      data: {
        findings_count: currentFindings.length,
        critical_count: currentFindings.filter((f) => f.severity === 'critical').length,
        high_count: currentFindings.filter((f) => f.severity === 'high').length,
        scan_duration: result.duration,
        status: result.status,
      },
    });
  }

  /**
   * Detect new findings compared to baseline
   */
  private detectNewFindings(
    current: SecurityFinding[],
    baseline: SecurityFinding[]
  ): SecurityFinding[] {
    return current.filter(
      (finding) => !baseline.some((baselineFinding) => baselineFinding.id === finding.id)
    );
  }

  /**
   * Detect resolved findings compared to baseline
   */
  private detectResolvedFindings(
    current: SecurityFinding[],
    baseline: SecurityFinding[]
  ): SecurityFinding[] {
    return baseline.filter(
      (baselineFinding) => !current.some((finding) => finding.id === baselineFinding.id)
    );
  }

  /**
   * Process a new finding
   */
  private async processNewFinding(
    target: MonitoringTarget,
    finding: SecurityFinding
  ): Promise<void> {
    logger.info(`🚨 New ${finding.severity} finding detected in ${target.name}: ${finding.title}`);

    // Emit finding detected event
    this.emitEvent({
      id: this.generateEventId(),
      timestamp: new Date(),
      type: 'finding_detected',
      target_id: target.id,
      data: {
        target_name: target.name,
        finding: finding,
      },
      severity: finding.severity,
    });

    // Send live update
    this.broadcastLiveUpdate({
      event_id: this.generateEventId(),
      timestamp: new Date(),
      type: 'finding',
      target: target.name,
      data: {
        action: 'new',
        finding: finding,
      },
      severity: finding.severity,
    });

    // Trigger alert if severity meets threshold
    if (this.shouldTriggerAlert(finding.severity)) {
      await this.triggerAlert(target, finding, 'new');
    }
  }

  /**
   * Process a resolved finding
   */
  private async processResolvedFinding(
    target: MonitoringTarget,
    finding: SecurityFinding
  ): Promise<void> {
    logger.info(`✅ ${finding.severity} finding resolved in ${target.name}: ${finding.title}`);

    // Emit finding resolved event
    this.emitEvent({
      id: this.generateEventId(),
      timestamp: new Date(),
      type: 'finding_resolved',
      target_id: target.id,
      data: {
        target_name: target.name,
        finding: finding,
      },
      severity: 'info',
    });

    // Send live update
    this.broadcastLiveUpdate({
      event_id: this.generateEventId(),
      timestamp: new Date(),
      type: 'finding',
      target: target.name,
      data: {
        action: 'resolved',
        finding: finding,
      },
      severity: 'info',
    });
  }

  /**
   * Handle behavioral analysis events
   */
  private handleBehavioralEvents(events: EnhancedSecurityEvent[]): void {
    for (const event of events) {
      logger.info(`🧠 Behavioral event detected: ${event.event_type} for ${event.entity_id}`, {
        severity: event.severity,
        entity_type: event.entity_type,
        anomaly_score: event.behavioral_context.anomaly_score,
        confidence: event.behavioral_context.confidence_level,
      });

      // Emit behavioral event
      this.emitEvent({
        id: this.generateEventId(),
        timestamp: new Date(),
        type: event.event_type === 'behavioral_anomaly' ? 'behavioral_anomaly' : 'finding_detected',
        target_id: event.entity_id,
        data: {
          entity_type: event.entity_type,
          behavioral_context: event.behavioral_context,
          anomaly_indicators: event.anomaly_indicators,
          recommended_actions: event.recommended_actions,
          scan_result: event.scan_result,
        },
        severity: event.severity,
      });

      // Send live update for behavioral events
      this.broadcastLiveUpdate({
        event_id: this.generateEventId(),
        timestamp: new Date(),
        type: 'alert',
        target: event.entity_id,
        data: {
          event_type: event.event_type,
          behavioral_score: event.behavioral_context.anomaly_score,
          confidence_level: event.behavioral_context.confidence_level,
          patterns: event.behavioral_context.behavioral_patterns,
          recommended_actions: event.recommended_actions.slice(0, 3), // First 3 actions
          severity: event.severity,
        },
        severity: event.severity,
      });

      // Process high-severity behavioral events for alerting
      if (
        (event.severity === 'high' || event.severity === 'critical') &&
        this.shouldTriggerAlert(event.severity)
      ) {
        this.alertQueue.push({
          id: this.generateEventId(),
          timestamp: new Date(),
          type: 'alert_triggered',
          target_id: event.entity_id,
          data: {
            alert_type: 'behavioral_anomaly',
            entity_type: event.entity_type,
            anomaly_score: event.behavioral_context.anomaly_score,
            confidence: event.behavioral_context.confidence_level,
            description: `Behavioral anomaly detected for ${event.entity_type}: ${event.entity_id}`,
            recommended_actions: event.recommended_actions,
          },
          severity: event.severity,
        });
      }
    }
  }

  /**
   * Check if we should trigger an alert for this severity
   */
  private shouldTriggerAlert(severity: string): boolean {
    if (!this.config.alerting.enabled) return false;

    const severityLevels = ['critical', 'high', 'medium', 'low'];
    const thresholdIndex = severityLevels.indexOf(this.config.alerting.severity_threshold);
    const findingSeverityIndex = severityLevels.indexOf(severity);

    return findingSeverityIndex <= thresholdIndex;
  }

  /**
   * Trigger an alert
   */
  private async triggerAlert(
    target: MonitoringTarget,
    finding: SecurityFinding,
    action: 'new' | 'resolved'
  ): Promise<void> {
    const event: MonitoringEvent = {
      id: this.generateEventId(),
      timestamp: new Date(),
      type: 'alert_triggered',
      target_id: target.id,
      data: {
        target_name: target.name,
        finding: finding,
        action: action,
        priority: target.priority,
      },
      severity: finding.severity,
    };

    // Add to alert queue for processing
    this.alertQueue.push(event);

    logger.warn(`🚨 Alert triggered for ${target.name}: ${finding.title}`);
  }

  /**
   * Start processing alerts
   */
  private startAlertProcessing(): void {
    // Process alerts every 5 seconds
    setInterval(() => {
      this.processAlertQueue();
    }, 5000);
  }

  /**
   * Process pending alerts
   */
  private async processAlertQueue(): Promise<void> {
    if (this.alertQueue.length === 0) return;

    const alertsToProcess = this.alertQueue.splice(
      0,
      this.config.alerting.rate_limiting.max_alerts_per_minute
    );

    for (const alert of alertsToProcess) {
      await this.sendAlert(alert);
    }
  }

  /**
   * Send alert through configured channels
   */
  private async sendAlert(event: MonitoringEvent): Promise<void> {
    for (const channel of this.config.alerting.channels) {
      if (channel.enabled) {
        try {
          await this.sendAlertToChannel(channel, event);
        } catch (error) {
          logger.error(`Failed to send alert to ${channel.type}:`, error);
        }
      }
    }
  }

  /**
   * Send alert to specific channel
   */
  private async sendAlertToChannel(channel: AlertChannel, event: MonitoringEvent): Promise<void> {
    // This would integrate with actual services
    logger.info(
      `📢 Sending ${event.severity} alert to ${channel.type}: ${event.data.finding.title}`
    );

    // Simulate alert sending
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  /**
   * Update target baseline
   */
  private updateTargetBaseline(targetId: string, findings: SecurityFinding[]): void {
    this.targetBaselines.set(targetId, [...findings]);
    logger.debug(`Updated baseline for target ${targetId}: ${findings.length} findings`);
  }

  /**
   * Check if baseline should be updated
   */
  private shouldUpdateBaseline(target: MonitoringTarget): boolean {
    // Update baseline every configured hours
    const updateFrequency = this.config.change_detection.baseline_update_frequency * 60 * 60 * 1000;
    const lastUpdate = target.last_scan || new Date(0);
    return Date.now() - lastUpdate.getTime() > updateFrequency;
  }

  /**
   * Emit monitoring event
   */
  private emitEvent(event: MonitoringEvent): void {
    this.emit('monitoring_event', event);

    // Send to connected WebSocket clients
    this.broadcastLiveUpdate({
      event_id: event.id,
      timestamp: event.timestamp,
      type: 'status',
      target: event.target_id,
      // Include event_type and preserve original event data for richer clients
      data: { ...event.data, event_type: event.type },
      severity: event.severity,
    });
  }

  /**
   * Broadcast live update to all connected clients
   */
  private broadcastLiveUpdate(update: LiveUpdate): void {
    const message = JSON.stringify(update);
    const bp = this.config.websocket.backpressure || {};
    const maxBuffered = bp.max_buffered_bytes ?? 1_000_000; // 1MB
    const warnBuffered = bp.warn_buffered_bytes ?? Math.floor(maxBuffered / 2);
    const dropIfExceeds = bp.drop_if_exceeds !== false; // default true
    const closeAfterDrops = bp.close_after_drops ?? 5;

    for (const client of this.connectedClients) {
      if (client.readyState !== WebSocket.OPEN) continue;
      try {
        const buffered = (client as any).bufferedAmount || 0;
        if (buffered > warnBuffered) {
          logger.warn(
            `WebSocket client bufferedAmount high: ${buffered} bytes (warn=${warnBuffered}, max=${maxBuffered})`
          );
        }
        if (dropIfExceeds && buffered > maxBuffered) {
          // Drop message for this slow client
          this.wsDroppedMessages += 1;
          const drops = (this.slowClientDropCounts.get(client) || 0) + 1;
          this.slowClientDropCounts.set(client, drops);
          if (drops >= closeAfterDrops) {
            try {
              client.close(1011, 'Slow consumer');
            } catch {
              /* ignore */
            }
            this.connectedClients.delete(client);
            logger.warn(
              `Closed slow WebSocket client after ${drops} consecutive drops (buffered=${buffered})`
            );
          } else {
            logger.debug(
              `Dropped broadcast to slow client (drop ${drops}/${closeAfterDrops}, buffered=${buffered})`
            );
          }
          continue;
        }
        // Send normally
        client.send(message);
        // Reset drop counter on successful send
        if (this.slowClientDropCounts.has(client)) this.slowClientDropCounts.delete(client);
      } catch (error) {
        logger.error('Error sending WebSocket message:', error);
        this.connectedClients.delete(client);
      }
    }
  }

  /**
   * Send message to specific client
   */
  private sendToClient(client: WebSocket, update: LiveUpdate): void {
    if (client.readyState !== WebSocket.OPEN) return;
    const bp = this.config.websocket.backpressure || {};
    const maxBuffered = bp.max_buffered_bytes ?? 1_000_000; // 1MB
    const warnBuffered = bp.warn_buffered_bytes ?? Math.floor(maxBuffered / 2);
    const dropIfExceeds = bp.drop_if_exceeds !== false; // default true
    const closeAfterDrops = bp.close_after_drops ?? 5;

    try {
      const buffered = (client as any).bufferedAmount || 0;
      if (buffered > warnBuffered) {
        logger.warn(
          `WebSocket client bufferedAmount high: ${buffered} bytes (warn=${warnBuffered}, max=${maxBuffered})`
        );
      }
      if (dropIfExceeds && buffered > maxBuffered) {
        // Drop this message to avoid pressure
        this.wsDroppedMessages += 1;
        const drops = (this.slowClientDropCounts.get(client) || 0) + 1;
        this.slowClientDropCounts.set(client, drops);
        if (drops >= closeAfterDrops) {
          try {
            client.close(1011, 'Slow consumer');
          } catch {
            /* ignore */
          }
          logger.warn(
            `Closed slow WebSocket client after ${drops} consecutive drops (buffered=${buffered})`
          );
        } else {
          logger.debug(
            `Dropped message to slow client (drop ${drops}/${closeAfterDrops}, buffered=${buffered})`
          );
        }
        return;
      }
      client.send(JSON.stringify(update));
      if (this.slowClientDropCounts.has(client)) this.slowClientDropCounts.delete(client);
    } catch (error) {
      logger.error('Error sending WebSocket message to client:', error);
    }
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    try {
      return `evt_${randomUUID()}`;
    } catch {
      return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 12)}`;
    }
  }

  /**
   * Get monitoring status
   */
  getStatus(): any {
    return {
      running: this.isRunning,
      targets: this.config.targets.length,
      active_targets: this.config.targets.filter((t) => t.enabled).length,
      connected_clients: this.connectedClients.size,
      scan_interval: this.config.scan_interval,
      last_activity: new Date(),
    };
  }

  /**
   * Add new monitoring target
   */
  async addTarget(target: MonitoringTarget): Promise<void> {
    this.config.targets.push(target);

    if (target.enabled && this.isRunning) {
      await this.startMonitoringTarget(target);
    }

    logger.info(`➕ Added monitoring target: ${target.name}`);
  }

  /**
   * Remove monitoring target
   */
  removeTarget(targetId: string): void {
    // Stop monitoring if active
    const interval = this.monitoringIntervals.get(targetId);
    if (interval) {
      clearInterval(interval);
      this.monitoringIntervals.delete(targetId);
    }

    // Remove from config
    this.config.targets = this.config.targets.filter((t) => t.id !== targetId);

    // Remove baseline
    this.targetBaselines.delete(targetId);

    logger.info(`➖ Removed monitoring target: ${targetId}`);
  }

  /**
   * Get comprehensive monitoring statistics including behavioral analysis
   */
  getMonitoringStats(): {
    targets: number;
    active_scans: number;
    connected_clients: number;
    alerts_queued: number;
    behavioral_stats: any;
    ws_dropped_messages?: number;
  } {
    return {
      targets: this.config.targets.length,
      active_scans: this.monitoringIntervals.size,
      connected_clients: this.connectedClients.size,
      alerts_queued: this.alertQueue.length,
      behavioral_stats: this.behavioralAnalysis.getBehavioralStats(),
      ws_dropped_messages: this.wsDroppedMessages,
    };
  }

  /**
   * Get top anomalous behavioral profiles
   */
  getTopAnomalousProfiles(limit: number = 5): any[] {
    return this.behavioralAnalysis.getTopAnomalousProfiles(limit);
  }

  /**
   * Export behavioral analysis data
   */
  exportBehavioralData(): any {
    return this.behavioralAnalysis.exportBehavioralData();
  }

  /**
   * Update behavioral analysis configuration
   */
  updateBehavioralConfig(config: any): void {
    this.behavioralAnalysis.updateConfig(config);
    logger.info('Behavioral analysis configuration updated');
  }

  /**
   * Shutdown monitoring with proper cleanup
   */
  async shutdown(): Promise<void> {
    logger.info('🛑 Shutting down Real-Time Monitor...');

    this.isRunning = false;

    // Stop all monitoring intervals
    for (const [targetId, interval] of this.monitoringIntervals) {
      clearInterval(interval);
      logger.debug(`Stopped monitoring for target: ${targetId}`);
    }
    this.monitoringIntervals.clear();

    // Close WebSocket server
    if (this.wsServer) {
      // Close all client connections
      this.connectedClients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.close(1000, 'Server shutting down');
        }
      });

      // Close server
      this.wsServer.close();
      this.wsServer = null;
      logger.info('🔌 WebSocket server closed');
    }

    // Shutdown behavioral analysis
    this.behavioralAnalysis.shutdown();

    // Clear alert queue
    this.alertQueue = [];

    // Remove all event listeners
    this.removeAllListeners();

    logger.info('✅ Real-Time Monitor shutdown complete');
  }
}
