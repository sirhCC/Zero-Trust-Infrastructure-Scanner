/**
 * Enterprise Logger for Zero-Trust Infrastructure Scanner
 * Provides structured logging with multiple outputs and levels
 */

import * as winston from 'winston';
import * as path from 'path';
import * as fs from 'fs';

export interface LogMetadata {
  component?: string;
  scanId?: string;
  userId?: string;
  sessionId?: string;
  [key: string]: any;
}

export class Logger {
  private static instance: Logger;
  private winston: winston.Logger;

  private constructor() {
    const isTest = process.env.NODE_ENV === 'test';

    // Console transport (always enabled)
    const consoleTransport = new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
          return `${timestamp} [${level}]: ${message} ${metaStr}`;
        })
      )
    });

    // File transports (disabled in test to avoid open handles)
    const fileTransports: winston.transport[] = isTest
      ? []
      : [
          new winston.transports.File({
            filename: path.join(process.cwd(), 'logs', 'ztis-error.log'),
            level: 'error'
          }),
          new winston.transports.File({
            filename: path.join(process.cwd(), 'logs', 'ztis-combined.log')
          })
        ];

    this.winston = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        winston.format.colorize({ all: true })
      ),
      defaultMeta: {
        service: 'zero-trust-scanner',
        version: process.env.npm_package_version || '1.0.0'
      },
      transports: [consoleTransport, ...fileTransports],
      exceptionHandlers: isTest
        ? []
        : [
            new winston.transports.File({
              filename: path.join(process.cwd(), 'logs', 'ztis-exceptions.log')
            })
          ],
      rejectionHandlers: isTest
        ? []
        : [
            new winston.transports.File({
              filename: path.join(process.cwd(), 'logs', 'ztis-rejections.log')
            })
          ]
    });

    // Create logs directory only when file transports are used
    if (!isTest) {
      this.ensureLogDirectory();
    }
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  /**
   * Ensure logs directory exists
   */
  private ensureLogDirectory(): void {
    const logsDir = path.join(process.cwd(), 'logs');
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
  }

  /**
   * Log info message
   */
  public info(message: string, meta?: LogMetadata): void {
    this.winston.info(message, meta);
  }

  /**
   * Log error message
   */
  public error(message: string, error?: Error | any, meta?: LogMetadata): void {
    const errorMeta = error instanceof Error ? {
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      }
    } : { error };
    
    this.winston.error(message, { ...errorMeta, ...meta });
  }

  /**
   * Log warning message
   */
  public warn(message: string, meta?: LogMetadata): void {
    this.winston.warn(message, meta);
  }

  /**
   * Log debug message
   */
  public debug(message: string, meta?: LogMetadata): void {
    this.winston.debug(message, meta);
  }

  /**
   * Log security event
   */
  public security(message: string, meta?: LogMetadata): void {
    this.winston.info(message, { 
      ...meta, 
      category: 'security',
      severity: 'high'
    });
  }

  /**
   * Log audit event
   */
  public audit(action: string, resource: string, meta?: LogMetadata): void {
    this.winston.info(`Audit: ${action} on ${resource}`, {
      ...meta,
      category: 'audit',
      action,
      resource,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Log scan event
   */
  public scan(message: string, scanId: string, meta?: LogMetadata): void {
    this.winston.info(message, {
      ...meta,
      category: 'scan',
      scanId
    });
  }

  /**
   * Log compliance event
   */
  public compliance(message: string, standard: string, control: string, meta?: LogMetadata): void {
    this.winston.info(message, {
      ...meta,
      category: 'compliance',
      standard,
      control
    });
  }

  /**
   * Log performance metrics
   */
  public performance(operation: string, duration: number, meta?: LogMetadata): void {
    this.winston.info(`Performance: ${operation} completed in ${duration}ms`, {
      ...meta,
      category: 'performance',
      operation,
      duration
    });
  }

  /**
   * Set log level
   */
  public setLevel(level: string): void {
    this.winston.level = level;
  }

  /**
   * Get current log level
   */
  public getLevel(): string {
    return this.winston.level;
  }

  /**
   * Create child logger with default metadata
   */
  public child(defaultMeta: LogMetadata): Logger {
    const childLogger = new Logger();
    childLogger.winston = this.winston.child(defaultMeta);
    return childLogger;
  }

  /**
   * Close all logger transports to release resources (useful for tests)
   */
  public close(): void {
    // winston@3 logger exposes close() to close all transports
    try {
      this.winston.close();
    } catch {
      // no-op
    }
    // Best-effort: ensure each transport is closed
    for (const t of this.winston.transports) {
      // Some transports expose close()
      try {
        const maybeAny: unknown = t as unknown;
        if (maybeAny && typeof (maybeAny as { close?: () => void }).close === 'function') {
          (maybeAny as { close: () => void }).close();
        }
      } catch {
        // ignore
      }
    }
  }
}
