/**
 * Configuration Manager for Zero-Trust Infrastructure Scanner
 * Handles configuration loading, validation, and management
 */

import * as fs from 'fs';
import * as yaml from 'yaml';
import Joi from 'joi';
import Ajv, { ErrorObject } from 'ajv';
import addFormats from 'ajv-formats';
import * as path from 'path';

export interface ZTISConfig {
  scanner: ScannerConfig;
  network: NetworkConfig;
  identity: IdentityConfig;
  supplyChain: SupplyChainConfig;
  compliance: ComplianceConfig;
  logging: LoggingConfig;
  server: ServerConfig;
  security: SecurityConfig;
}

export interface ScannerConfig {
  parallelScans: number;
  scanTimeout: number;
  retryAttempts: number;
  outputDirectory: string;
  reportFormats: string[];
}

export interface NetworkConfig {
  defaultScanDepth: number;
  includedNetworks: string[];
  excludedNetworks: string[];
  portScanEnabled: boolean;
  serviceScanEnabled: boolean;
  cloudProviders: CloudProviderConfig[];
}

export interface CloudProviderConfig {
  name: 'aws' | 'azure' | 'gcp';
  enabled: boolean;
  regions: string[];
  credentials?: {
    accessKeyId?: string;
    secretAccessKey?: string;
    tenantId?: string;
    clientId?: string;
    clientSecret?: string;
    projectId?: string;
    keyFile?: string;
  };
}

export interface IdentityConfig {
  providers: IdentityProviderConfig[];
  privilegeThresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  includeServiceAccounts: boolean;
  analyzePermissionBoundaries: boolean;
}

export interface IdentityProviderConfig {
  type: 'aws-iam' | 'azure-ad' | 'k8s-rbac' | 'local' | 'ldap';
  name: string;
  enabled: boolean;
  endpoint?: string;
  credentials?: Record<string, any>;
}

export interface SupplyChainConfig {
  registries: ContainerRegistryConfig[];
  packageManagers: string[];
  vulnerabilityDatabases: string[];
  severityThreshold: 'low' | 'medium' | 'high' | 'critical';
  includeDevelopmentDependencies: boolean;
  licenseChecking: boolean;
}

export interface ContainerRegistryConfig {
  name: string;
  url: string;
  type: 'docker' | 'ecr' | 'acr' | 'gcr' | 'harbor';
  credentials?: {
    username?: string;
    password?: string;
    token?: string;
  };
}

export interface ComplianceConfig {
  standards: ComplianceStandardConfig[];
  reportingFormats: string[];
  evidenceCollection: boolean;
  autoRemediation: boolean;
}

export interface ComplianceStandardConfig {
  name: 'SOC2' | 'PCI' | 'HIPAA' | 'GDPR' | 'ISO27001';
  enabled: boolean;
  controls: string[];
  excludedControls: string[];
  customRules?: string[];
}

export interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  outputs: string[];
  structuredLogging: boolean;
  retentionDays: number;
  auditLogging: boolean;
}

export interface ServerConfig {
  port: number;
  host: string;
  apiEnabled: boolean;
  webInterfaceEnabled: boolean;
  authentication: {
    enabled: boolean;
    type: 'jwt' | 'oauth' | 'basic';
    secret?: string;
    providers?: any[];
  };
  rateLimit: {
    enabled: boolean;
    windowMs: number;
    maxRequests: number;
  };
}

export interface SecurityConfig {
  encryption: {
    algorithm: string;
    keyLength: number;
  };
  dataRetention: {
    scanResults: number;
    logs: number;
    reports: number;
  };
  accessControl: {
    enabled: boolean;
    defaultRole: string;
    roles: Record<string, string[]>;
  };
}

/**
 * Configuration validation schema
 */
const configSchema = Joi.object({
  scanner: Joi.object({
    parallelScans: Joi.number().min(1).max(10).default(3),
    scanTimeout: Joi.number().min(30000).default(300000),
    retryAttempts: Joi.number().min(0).max(5).default(3),
    outputDirectory: Joi.string().default('./reports'),
    reportFormats: Joi.array().items(Joi.string().valid('json', 'yaml', 'html', 'pdf')).default(['json', 'html'])
  }).default(),

  network: Joi.object({
    defaultScanDepth: Joi.number().min(1).max(5).default(3),
    includedNetworks: Joi.array().items(Joi.string()).default([]),
    excludedNetworks: Joi.array().items(Joi.string()).default([]),
    portScanEnabled: Joi.boolean().default(true),
    serviceScanEnabled: Joi.boolean().default(true),
    cloudProviders: Joi.array().items(Joi.object({
      name: Joi.string().valid('aws', 'azure', 'gcp').required(),
      enabled: Joi.boolean().default(false),
      regions: Joi.array().items(Joi.string()).default([]),
      credentials: Joi.object().optional()
    })).default([])
  }).default(),

  identity: Joi.object({
    providers: Joi.array().items(Joi.object({
      type: Joi.string().valid('aws-iam', 'azure-ad', 'k8s-rbac', 'local', 'ldap').required(),
      name: Joi.string().required(),
      enabled: Joi.boolean().default(true),
      endpoint: Joi.string().optional(),
      credentials: Joi.object().optional()
    })).default([]),
    privilegeThresholds: Joi.object({
      low: Joi.number().default(20),
      medium: Joi.number().default(50),
      high: Joi.number().default(80),
      critical: Joi.number().default(95)
    }).default(),
    includeServiceAccounts: Joi.boolean().default(true),
    analyzePermissionBoundaries: Joi.boolean().default(true)
  }).default(),

  supplyChain: Joi.object({
    registries: Joi.array().items(Joi.object({
      name: Joi.string().required(),
      url: Joi.string().uri().required(),
      type: Joi.string().valid('docker', 'ecr', 'acr', 'gcr', 'harbor').required(),
      credentials: Joi.object().optional()
    })).default([]),
    packageManagers: Joi.array().items(Joi.string().valid('npm', 'yarn', 'pip', 'maven', 'gradle', 'nuget')).default(['npm', 'pip']),
    vulnerabilityDatabases: Joi.array().items(Joi.string()).default(['nvd', 'snyk', 'github']),
    severityThreshold: Joi.string().valid('low', 'medium', 'high', 'critical').default('medium'),
    includeDevelopmentDependencies: Joi.boolean().default(false),
    licenseChecking: Joi.boolean().default(true)
  }).default(),

  compliance: Joi.object({
    standards: Joi.array().items(Joi.object({
      name: Joi.string().valid('SOC2', 'PCI', 'HIPAA', 'GDPR', 'ISO27001').required(),
      enabled: Joi.boolean().default(true),
      controls: Joi.array().items(Joi.string()).default([]),
      excludedControls: Joi.array().items(Joi.string()).default([]),
      customRules: Joi.array().items(Joi.string()).optional()
    })).default([]),
    reportingFormats: Joi.array().items(Joi.string().valid('json', 'html', 'pdf', 'xml')).default(['html', 'pdf']),
    evidenceCollection: Joi.boolean().default(true),
    autoRemediation: Joi.boolean().default(false)
  }).default(),

  logging: Joi.object({
    level: Joi.string().valid('debug', 'info', 'warn', 'error').default('info'),
    outputs: Joi.array().items(Joi.string().valid('console', 'file', 'syslog')).default(['console', 'file']),
    structuredLogging: Joi.boolean().default(true),
    retentionDays: Joi.number().min(1).default(30),
    auditLogging: Joi.boolean().default(true)
  }).default(),

  server: Joi.object({
    port: Joi.number().min(1).max(65535).default(3000),
    host: Joi.string().default('localhost'),
    apiEnabled: Joi.boolean().default(true),
    webInterfaceEnabled: Joi.boolean().default(true),
    authentication: Joi.object({
      enabled: Joi.boolean().default(false),
      type: Joi.string().valid('jwt', 'oauth', 'basic').default('jwt'),
      secret: Joi.string().optional(),
      providers: Joi.array().optional()
    }).default(),
    rateLimit: Joi.object({
      enabled: Joi.boolean().default(true),
      windowMs: Joi.number().default(900000), // 15 minutes
      maxRequests: Joi.number().default(100)
    }).default()
  }).default(),

  security: Joi.object({
    encryption: Joi.object({
      algorithm: Joi.string().default('aes-256-gcm'),
      keyLength: Joi.number().default(256)
    }).default(),
    dataRetention: Joi.object({
      scanResults: Joi.number().default(90), // days
      logs: Joi.number().default(30),
      reports: Joi.number().default(365)
    }).default(),
    accessControl: Joi.object({
      enabled: Joi.boolean().default(false),
      defaultRole: Joi.string().default('viewer'),
      roles: Joi.object().default({
        admin: ['read', 'write', 'delete', 'configure'],
        operator: ['read', 'write'],
        viewer: ['read']
      })
    }).default()
  }).default()
});

export class ConfigManager {
  private static instance: ConfigManager;
  private config: ZTISConfig | null = null;
  private configPath: string = './ztis.config.json';
  private ajv?: Ajv;
  private jsonSchema: any;

  private constructor() {}

  /**
   * Get singleton instance
   */
  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  /**
   * Initialize configuration
   */
  public async initialize(configPath?: string): Promise<void> {
    if (configPath) {
      this.configPath = configPath;
    }
    // Initialize AJV
    this.ajv = new Ajv({ allErrors: true, strict: false, useDefaults: false });
    addFormats(this.ajv);

    // Load JSON Schema
    const schemaPath = path.resolve(__dirname, 'ztis.schema.json');
    try {
      const schemaRaw = fs.readFileSync(schemaPath, 'utf8');
      this.jsonSchema = JSON.parse(schemaRaw);
    } catch (e) {
      // If schema missing, proceed with Joi-only validation but warn
      console.warn('⚠️  JSON Schema not found; falling back to Joi validation only');
      this.jsonSchema = null;
    }

    await this.loadConfig();
  }

  /**
   * Load configuration from file
   */
  private async loadConfig(): Promise<void> {
    try {
      let configData: any = {};

      if (fs.existsSync(this.configPath)) {
        const fileContent = fs.readFileSync(this.configPath, 'utf8');
        
        if (this.configPath.endsWith('.yaml') || this.configPath.endsWith('.yml')) {
          configData = yaml.parse(fileContent);
        } else {
          configData = JSON.parse(fileContent);
        }
      } else {
        console.log(`Config file not found at ${this.configPath}, using defaults`);
      }

      // Apply environment overrides
      configData = this.applyEnvOverrides(configData);

      // Validate and set defaults with Joi (provides defaults)
      const { error, value } = configSchema.validate(configData, {
        allowUnknown: false,
        stripUnknown: true,
      });

      if (error) {
        throw new Error(`Configuration validation failed: ${error.message}`);
      }

      const candidate = value as ZTISConfig;

      // Validate against JSON Schema via Ajv (structure/compat)
      if (this.ajv && this.jsonSchema) {
        const validate = this.ajv.compile(this.jsonSchema);
        const valid = validate(candidate);
        if (!valid) {
          const errs = (validate.errors || []).map(this.formatAjvError).join('; ');
          throw new Error(`Configuration failed JSON Schema validation: ${errs}`);
        }
      }

      this.config = candidate;
      console.log('✅ Configuration loaded successfully');

    } catch (error) {
      console.error('❌ Failed to load configuration:', error);
      throw error;
    }
  }

  /**
   * Apply environment variable overrides using ZTIS_* variables
   * Example:
   *  ZTIS_SERVER_PORT=4000
   *  ZTIS_LOGGING_LEVEL=debug
   */
  private applyEnvOverrides(configData: any): any {
    const out = { ...configData };

    const set = (pathKeys: string[], value: any) => {
      let cur: any = out;
      for (let i = 0; i < pathKeys.length - 1; i++) {
        const k = pathKeys[i];
        if (cur[k] == null || typeof cur[k] !== 'object') cur[k] = {};
        cur = cur[k];
      }
      cur[pathKeys[pathKeys.length - 1]] = value;
    };

    const env = process.env;
    const mapNumber = (v?: string) => (v != null ? Number(v) : undefined);
    const mapBool = (v?: string) => (v != null ? v === 'true' || v === '1' : undefined);

    if (env.ZTIS_SERVER_PORT) set(['server', 'port'], mapNumber(env.ZTIS_SERVER_PORT));
    if (env.ZTIS_SERVER_HOST) set(['server', 'host'], env.ZTIS_SERVER_HOST);
    if (env.ZTIS_API_ENABLED) set(['server', 'apiEnabled'], mapBool(env.ZTIS_API_ENABLED));
    if (env.ZTIS_WEB_ENABLED) set(['server', 'webInterfaceEnabled'], mapBool(env.ZTIS_WEB_ENABLED));
    if (env.ZTIS_LOGGING_LEVEL) set(['logging', 'level'], env.ZTIS_LOGGING_LEVEL);
    if (env.ZTIS_LOG_RETENTION_DAYS) set(['logging', 'retentionDays'], mapNumber(env.ZTIS_LOG_RETENTION_DAYS));
    if (env.ZTIS_SCANNER_PARALLEL) set(['scanner', 'parallelScans'], mapNumber(env.ZTIS_SCANNER_PARALLEL));
    if (env.ZTIS_SCANNER_TIMEOUT) set(['scanner', 'scanTimeout'], mapNumber(env.ZTIS_SCANNER_TIMEOUT));
    if (env.ZTIS_SCANNER_RETRIES) set(['scanner', 'retryAttempts'], mapNumber(env.ZTIS_SCANNER_RETRIES));

    return out;
  }

  /**
   * Get configuration
   */
  public getConfig(): ZTISConfig {
    if (!this.config) {
      throw new Error('Configuration not initialized. Call initialize() first.');
    }
    return this.config;
  }

  /**
   * Get specific configuration section
   */
  public getSection<K extends keyof ZTISConfig>(section: K): ZTISConfig[K] {
    return this.getConfig()[section];
  }

  /**
   * Update configuration
   */
  public updateConfig(updates: Partial<ZTISConfig>): void {
    if (!this.config) {
      throw new Error('Configuration not initialized');
    }

    this.config = { ...this.config, ...updates };
  }

  /**
   * Save configuration to file
   */
  public async saveConfig(): Promise<void> {
    if (!this.config) {
      throw new Error('Configuration not initialized');
    }

    try {
      let content: string;
      
      if (this.configPath.endsWith('.yaml') || this.configPath.endsWith('.yml')) {
        content = yaml.stringify(this.config);
      } else {
        content = JSON.stringify(this.config, null, 2);
      }

      fs.writeFileSync(this.configPath, content, 'utf8');
      console.log('✅ Configuration saved successfully');
    } catch (error) {
      console.error('❌ Failed to save configuration:', error);
      throw error;
    }
  }

  /**
   * Create default configuration file
   */
  public async createDefaultConfig(filePath?: string): Promise<void> {
    const path = filePath || this.configPath;
    
    const { value } = configSchema.validate({}, { allowUnknown: false });
    
    let content: string;
    if (path.endsWith('.yaml') || path.endsWith('.yml')) {
      content = yaml.stringify(value);
    } else {
      content = JSON.stringify(value, null, 2);
    }

    fs.writeFileSync(path, content, 'utf8');
    console.log(`✅ Default configuration created: ${path}`);
  }

  /**
   * Validate current configuration
   */
  public validateConfig(): { valid: boolean; errors?: string[] } {
    if (!this.config) {
      return { valid: false, errors: ['Configuration not loaded'] };
    }

    const { error } = configSchema.validate(this.config);
    
    if (error) {
      return { 
        valid: false, 
        errors: error.details.map(detail => detail.message) 
      };
    }

    if (this.ajv && this.jsonSchema) {
      const validate = this.ajv.compile(this.jsonSchema);
      const valid = validate(this.config);
      if (!valid) {
        return {
          valid: false,
          errors: (validate.errors || []).map(this.formatAjvError),
        };
      }
    }

    return { valid: true };
  }

  private formatAjvError(err: ErrorObject): string {
    const instancePath = err.instancePath || '(root)';
    return `${instancePath} ${err.message || ''}`.trim();
  }
}
