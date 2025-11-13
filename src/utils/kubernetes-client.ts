/**
 * Kubernetes Client Utility
 * Provides abstraction layer for Kubernetes API interactions
 */

import * as k8s from '@kubernetes/client-node';
import { Logger } from './logger';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const logger = Logger.getInstance();

export interface KubernetesConfig {
  useKubeConfig?: boolean;
  kubeConfigPath?: string;
  context?: string;
  namespace?: string;
}

export interface NetworkPolicySpec {
  apiVersion: string;
  kind: string;
  metadata: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    creationTimestamp?: string;
  };
  spec: {
    podSelector: {
      matchLabels?: Record<string, string>;
      matchExpressions?: Array<{
        key: string;
        operator: string;
        values?: string[];
      }>;
    };
    policyTypes?: string[];
    ingress?: Array<{
      from?: Array<{
        podSelector?: {
          matchLabels?: Record<string, string>;
        };
        namespaceSelector?: {
          matchLabels?: Record<string, string>;
        };
        ipBlock?: {
          cidr: string;
          except?: string[];
        };
      }>;
      ports?: Array<{
        protocol?: string;
        port?: number | string;
        endPort?: number;
      }>;
    }>;
    egress?: Array<{
      to?: Array<{
        podSelector?: {
          matchLabels?: Record<string, string>;
        };
        namespaceSelector?: {
          matchLabels?: Record<string, string>;
        };
        ipBlock?: {
          cidr: string;
          except?: string[];
        };
      }>;
      ports?: Array<{
        protocol?: string;
        port?: number | string;
        endPort?: number;
      }>;
    }>;
  };
}

export interface PodInfo {
  name: string;
  namespace: string;
  labels: Record<string, string>;
  phase: string;
  hostNetwork?: boolean;
  containers: Array<{
    name: string;
    image: string;
    ports?: Array<{
      containerPort: number;
      protocol: string;
    }>;
  }>;
}

export interface NamespaceInfo {
  name: string;
  labels: Record<string, string>;
  phase: string;
  creationTimestamp: string;
}

export class KubernetesClient {
  private kc: k8s.KubeConfig;
  private k8sApi: k8s.CoreV1Api;
  private networkingApi: k8s.NetworkingV1Api;
  private connected: boolean = false;

  constructor(config?: KubernetesConfig) {
    this.kc = new k8s.KubeConfig();
    this.k8sApi = this.kc.makeApiClient(k8s.CoreV1Api);
    this.networkingApi = this.kc.makeApiClient(k8s.NetworkingV1Api);

    try {
      if (config?.kubeConfigPath && existsSync(config.kubeConfigPath)) {
        logger.info(`Loading kubeconfig from: ${config.kubeConfigPath}`);
        this.kc.loadFromFile(config.kubeConfigPath);
      } else {
        // Try default kubeconfig locations
        const defaultKubeConfig = join(homedir(), '.kube', 'config');
        if (existsSync(defaultKubeConfig)) {
          logger.info(`Loading default kubeconfig from: ${defaultKubeConfig}`);
          this.kc.loadFromFile(defaultKubeConfig);
        } else {
          // Try in-cluster config (for running inside Kubernetes)
          logger.info('Attempting to load in-cluster config');
          this.kc.loadFromCluster();
        }
      }

      // Set context if specified
      if (config?.context) {
        this.kc.setCurrentContext(config.context);
      }

      // Recreate API clients with loaded config
      this.k8sApi = this.kc.makeApiClient(k8s.CoreV1Api);
      this.networkingApi = this.kc.makeApiClient(k8s.NetworkingV1Api);
      this.connected = true;

      logger.info(
        `✅ Connected to Kubernetes cluster: ${this.kc.getCurrentCluster()?.name || 'unknown'}`
      );
    } catch (error) {
      logger.warn(
        '⚠️ Could not connect to Kubernetes cluster:',
        error instanceof Error ? { error: error.message } : {}
      );
      this.connected = false;
      // API clients already created with default config above
    }
  }

  /**
   * Check if client is connected to a cluster
   */
  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Get current cluster information
   */
  getClusterInfo(): { name: string; server: string; context: string } | null {
    if (!this.connected) return null;

    const cluster = this.kc.getCurrentCluster();
    const context = this.kc.getCurrentContext();

    return {
      name: cluster?.name || 'unknown',
      server: cluster?.server || 'unknown',
      context: context || 'unknown',
    };
  }

  /**
   * List all namespaces
   */
  async listNamespaces(): Promise<NamespaceInfo[]> {
    if (!this.connected) {
      throw new Error('Not connected to Kubernetes cluster');
    }

    try {
      const response = await this.k8sApi.listNamespace();
      return response.items.map((ns: any) => ({
        name: ns.metadata?.name || 'unknown',
        labels: ns.metadata?.labels || {},
        phase: ns.status?.phase || 'unknown',
        creationTimestamp: ns.metadata?.creationTimestamp?.toISOString() || '',
      }));
    } catch (error) {
      logger.error('Failed to list namespaces:', error);
      throw error;
    }
  }

  /**
   * List network policies in a namespace
   */
  async listNetworkPolicies(namespace: string = 'default'): Promise<NetworkPolicySpec[]> {
    if (!this.connected) {
      throw new Error('Not connected to Kubernetes cluster');
    }

    try {
      const response = await this.networkingApi.listNamespacedNetworkPolicy({ namespace });
      return response.items.map((policy: any) => ({
        apiVersion: policy.apiVersion || 'networking.k8s.io/v1',
        kind: policy.kind || 'NetworkPolicy',
        metadata: {
          name: policy.metadata?.name || 'unknown',
          namespace: policy.metadata?.namespace || namespace,
          labels: policy.metadata?.labels,
          annotations: policy.metadata?.annotations,
          creationTimestamp: policy.metadata?.creationTimestamp?.toISOString(),
        },
        spec: policy.spec || { podSelector: {} },
      }));
    } catch (error) {
      logger.error(`Failed to list network policies in namespace ${namespace}:`, error);
      throw error;
    }
  }

  /**
   * List all network policies across all namespaces
   */
  async listAllNetworkPolicies(): Promise<NetworkPolicySpec[]> {
    if (!this.connected) {
      throw new Error('Not connected to Kubernetes cluster');
    }

    try {
      const response = await this.networkingApi.listNetworkPolicyForAllNamespaces();
      return response.items.map((policy: any) => ({
        apiVersion: policy.apiVersion || 'networking.k8s.io/v1',
        kind: policy.kind || 'NetworkPolicy',
        metadata: {
          name: policy.metadata?.name || 'unknown',
          namespace: policy.metadata?.namespace || 'default',
          labels: policy.metadata?.labels,
          annotations: policy.metadata?.annotations,
          creationTimestamp: policy.metadata?.creationTimestamp?.toISOString(),
        },
        spec: policy.spec || { podSelector: {} },
      }));
    } catch (error) {
      logger.error('Failed to list all network policies:', error);
      throw error;
    }
  }

  /**
   * List pods in a namespace
   */
  async listPods(namespace: string = 'default'): Promise<PodInfo[]> {
    if (!this.connected) {
      throw new Error('Not connected to Kubernetes cluster');
    }

    try {
      const response = await this.k8sApi.listNamespacedPod({ namespace });
      return response.items.map((pod: any) => ({
        name: pod.metadata?.name || 'unknown',
        namespace: pod.metadata?.namespace || namespace,
        labels: pod.metadata?.labels || {},
        phase: pod.status?.phase || 'unknown',
        hostNetwork: pod.spec?.hostNetwork,
        containers: (pod.spec?.containers || []).map((container: any) => ({
          name: container.name,
          image: container.image || 'unknown',
          ports: container.ports?.map((p: any) => ({
            containerPort: p.containerPort,
            protocol: p.protocol || 'TCP',
          })),
        })),
      }));
    } catch (error) {
      logger.error(`Failed to list pods in namespace ${namespace}:`, error);
      throw error;
    }
  }

  /**
   * List all pods across all namespaces
   */
  async listAllPods(): Promise<PodInfo[]> {
    if (!this.connected) {
      throw new Error('Not connected to Kubernetes cluster');
    }

    try {
      const response = await this.k8sApi.listPodForAllNamespaces();
      return response.items.map((pod: any) => ({
        name: pod.metadata?.name || 'unknown',
        namespace: pod.metadata?.namespace || 'default',
        labels: pod.metadata?.labels || {},
        phase: pod.status?.phase || 'unknown',
        hostNetwork: pod.spec?.hostNetwork,
        containers: (pod.spec?.containers || []).map((container: any) => ({
          name: container.name,
          image: container.image || 'unknown',
          ports: container.ports?.map((p: any) => ({
            containerPort: p.containerPort,
            protocol: p.protocol || 'TCP',
          })),
        })),
      }));
    } catch (error) {
      logger.error('Failed to list all pods:', error);
      throw error;
    }
  }

  /**
   * Check if kubectl is available
   */
  static async isKubectlAvailable(): Promise<boolean> {
    try {
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      const execAsync = promisify(exec);

      await execAsync('kubectl version --client --short');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get default kubeconfig path
   */
  static getDefaultKubeConfigPath(): string {
    return join(homedir(), '.kube', 'config');
  }

  /**
   * Check if kubeconfig exists
   */
  static hasKubeConfig(): boolean {
    return existsSync(KubernetesClient.getDefaultKubeConfigPath());
  }
}
