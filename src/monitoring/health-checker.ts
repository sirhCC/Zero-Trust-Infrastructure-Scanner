/**
 * Health Checker for Zero-Trust Infrastructure Scanner
 * Monitors system health, resource usage, and component status
 */

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  uptime: number;
  components: ComponentHealth[];
  system: SystemHealth;
  version: string;
}

export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  message: string;
  lastCheck: Date;
  responseTime?: number;
  details?: Record<string, any>;
}

export interface SystemHealth {
  memory: MemoryUsage;
  cpu: CpuUsage;
  disk: DiskUsage;
  network: NetworkStatus;
}

export interface MemoryUsage {
  total: number;
  used: number;
  free: number;
  percentage: number;
}

export interface CpuUsage {
  percentage: number;
  loadAverage: number[];
}

export interface DiskUsage {
  total: number;
  used: number;
  free: number;
  percentage: number;
}

export interface NetworkStatus {
  connected: boolean;
  latency?: number;
}

export class HealthChecker {
  private startTime: Date = new Date();
  private checkInterval: NodeJS.Timeout | null = null;
  private components: Map<string, ComponentHealth> = new Map();

  constructor(private intervalMs: number = 30000) {}

  /**
   * Start health monitoring
   */
  public async start(): Promise<void> {
    this.startTime = new Date();
    
    // Register core components
    this.registerComponent('scanner-core', 'Core scanning engine');
    this.registerComponent('config-manager', 'Configuration management');
    this.registerComponent('logger', 'Logging system');
    
    // Initial health check
    await this.performHealthCheck();
    
    // Start periodic health checks
    this.checkInterval = setInterval(async () => {
      await this.performHealthCheck();
    }, this.intervalMs);

    console.log('💚 Health monitoring started');
  }

  /**
   * Stop health monitoring
   */
  public stop(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }

    console.log('🔴 Health monitoring stopped');
  }

  /**
   * Register a component for health monitoring
   */
  public registerComponent(name: string, description: string): void {
    this.components.set(name, {
      name,
      status: 'healthy',
      message: description,
      lastCheck: new Date()
    });
  }

  /**
   * Update component health status
   */
  public updateComponentHealth(
    name: string, 
    status: 'healthy' | 'degraded' | 'unhealthy',
    message: string,
    details?: Record<string, any>
  ): void {
    const component = this.components.get(name);
    if (component) {
      component.status = status;
      component.message = message;
      component.lastCheck = new Date();
      if (details !== undefined) {
        component.details = details;
      }
      this.components.set(name, component);
    }
  }

  /**
   * Get current health status
   */
  public async getHealthStatus(): Promise<HealthStatus> {
    const systemHealth = await this.getSystemHealth();
    const componentArray = Array.from(this.components.values());
    
    // Determine overall status
    const overallStatus = this.calculateOverallStatus(componentArray, systemHealth);
    
    return {
      status: overallStatus,
      timestamp: new Date(),
      uptime: Date.now() - this.startTime.getTime(),
      components: componentArray,
      system: systemHealth,
      version: process.env.npm_package_version || '1.0.0'
    };
  }

  /**
   * Perform health check on all components
   */
  private async performHealthCheck(): Promise<void> {
    // Check core components
    await this.checkScannerCore();
    await this.checkConfigManager();
    await this.checkLogger();
    
    // Check system resources
    await this.checkSystemResources();
  }

  /**
   * Check scanner core health
   */
  private async checkScannerCore(): Promise<void> {
    try {
      const startTime = Date.now();
      
      // Basic functionality check
      // TODO: Add actual scanner health check
      const responseTime = Date.now() - startTime;
      
      this.updateComponentHealth(
        'scanner-core',
        'healthy',
        'Scanner core is operational',
        { responseTime }
      );
    } catch (error) {
      this.updateComponentHealth(
        'scanner-core',
        'unhealthy',
        `Scanner core error: ${(error as Error).message}`
      );
    }
  }

  /**
   * Check configuration manager health
   */
  private async checkConfigManager(): Promise<void> {
    try {
      // TODO: Check if config is loaded and valid
      this.updateComponentHealth(
        'config-manager',
        'healthy',
        'Configuration manager is operational'
      );
    } catch (error) {
      this.updateComponentHealth(
        'config-manager',
        'unhealthy',
        `Configuration manager error: ${(error as Error).message}`
      );
    }
  }

  /**
   * Check logger health
   */
  private async checkLogger(): Promise<void> {
    try {
      // TODO: Check if logging is working
      this.updateComponentHealth(
        'logger',
        'healthy',
        'Logging system is operational'
      );
    } catch (error) {
      this.updateComponentHealth(
        'logger',
        'unhealthy',
        `Logger error: ${(error as Error).message}`
      );
    }
  }

  /**
   * Check system resources
   */
  private async checkSystemResources(): Promise<void> {
    const system = await this.getSystemHealth();
    
    // Check memory usage
    if (system.memory.percentage > 90) {
      this.updateComponentHealth(
        'system-memory',
        'unhealthy',
        `High memory usage: ${system.memory.percentage}%`
      );
    } else if (system.memory.percentage > 75) {
      this.updateComponentHealth(
        'system-memory',
        'degraded',
        `Elevated memory usage: ${system.memory.percentage}%`
      );
    } else {
      this.updateComponentHealth(
        'system-memory',
        'healthy',
        `Memory usage normal: ${system.memory.percentage}%`
      );
    }

    // Check CPU usage
    if (system.cpu.percentage > 90) {
      this.updateComponentHealth(
        'system-cpu',
        'unhealthy',
        `High CPU usage: ${system.cpu.percentage}%`
      );
    } else if (system.cpu.percentage > 75) {
      this.updateComponentHealth(
        'system-cpu',
        'degraded',
        `Elevated CPU usage: ${system.cpu.percentage}%`
      );
    } else {
      this.updateComponentHealth(
        'system-cpu',
        'healthy',
        `CPU usage normal: ${system.cpu.percentage}%`
      );
    }
  }

  /**
   * Get system health metrics
   */
  private async getSystemHealth(): Promise<SystemHealth> {
    const memoryUsage = process.memoryUsage();
    const totalMemory = memoryUsage.heapTotal + memoryUsage.external;
    const usedMemory = memoryUsage.heapUsed;
    
    return {
      memory: {
        total: totalMemory,
        used: usedMemory,
        free: totalMemory - usedMemory,
        percentage: Math.round((usedMemory / totalMemory) * 100)
      },
      cpu: {
        percentage: 0, // TODO: Implement actual CPU usage calculation
        loadAverage: [0, 0, 0] // TODO: Implement load average
      },
      disk: {
        total: 0, // TODO: Implement disk usage
        used: 0,
        free: 0,
        percentage: 0
      },
      network: {
        connected: true // TODO: Implement network connectivity check
      }
    };
  }

  /**
   * Calculate overall system status
   */
  private calculateOverallStatus(
    components: ComponentHealth[], 
    system: SystemHealth
  ): 'healthy' | 'degraded' | 'unhealthy' {
    const unhealthyComponents = components.filter(c => c.status === 'unhealthy');
    const degradedComponents = components.filter(c => c.status === 'degraded');
    
    // System is unhealthy if any component is unhealthy
    if (unhealthyComponents.length > 0) {
      return 'unhealthy';
    }
    
    // System is degraded if any component is degraded or system resources are high
    if (degradedComponents.length > 0 || 
        system.memory.percentage > 75 || 
        system.cpu.percentage > 75) {
      return 'degraded';
    }
    
    return 'healthy';
  }

  /**
   * Get component health by name
   */
  public getComponentHealth(name: string): ComponentHealth | undefined {
    return this.components.get(name);
  }

  /**
   * Check if system is healthy
   */
  public async isHealthy(): Promise<boolean> {
    const status = await this.getHealthStatus();
    return status.status === 'healthy';
  }
}
