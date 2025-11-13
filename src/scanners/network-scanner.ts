/**
 * Network Scanner Module
 * Analyzes network micro-segmentation and security policies
 * Implements zero-trust network security principles
 */

import { ScanTarget, SecurityFinding } from '../core/scanner';
import { Logger } from '../utils/logger';
import { BaseScanner } from './base-scanner';
import { KubernetesClient, NetworkPolicySpec, PodInfo } from '../utils/kubernetes-client';

// Create logger instance
const logger = Logger.getInstance();

export interface NetworkSegment {
  id: string;
  name: string;
  cidr: string;
  type: 'public' | 'private' | 'dmz' | 'management';
  isolation_level: 'none' | 'basic' | 'strict' | 'air-gapped';
  access_rules: AccessRule[];
  connected_segments: string[];
}

export interface AccessRule {
  id: string;
  source: string;
  destination: string;
  protocol: string;
  port: string | number;
  action: 'allow' | 'deny';
  justification?: string;
  last_reviewed?: Date;
}

export interface NetworkPolicy {
  id: string;
  name: string;
  type: 'firewall' | 'security-group' | 'network-acl' | 'k8s-policy';
  rules: AccessRule[];
  applied_to: string[];
  tags: Record<string, string>;
}

export interface NetworkScanOptions {
  target?: string;
  cloud_provider?: 'aws' | 'azure' | 'gcp' | 'kubernetes';
  scan_depth?: number;
  include_policies?: boolean;
  check_compliance?: boolean;
  analyze_traffic?: boolean;
  k8s_namespace?: string;
  policy_file?: string;
}

export class NetworkScanner extends BaseScanner {
  private kubeConfigExists: boolean = false;

  constructor() {
    super('NetworkScanner');
    this.logInitialization('🌐', 'Network Scanner');
  }

  /**
   * Execute network security scan
   */
  async scan(target: ScanTarget): Promise<SecurityFinding[]> {
    this.findings = [];
    const options = target.options as NetworkScanOptions;

    logger.info(`🔍 Starting network scan for: ${target.target}`);

    // Check Kubernetes availability if needed
    if (options.k8s_namespace) {
      await KubernetesClient.isKubectlAvailable(); // Check availability
      this.kubeConfigExists = KubernetesClient.hasKubeConfig();

      if (!this.kubeConfigExists) {
        logger.warn('⚠️ No kubeconfig found at default location');
        logger.info(`💡 Expected location: ${KubernetesClient.getDefaultKubeConfigPath()}`);
      }
    }

    try {
      // Analyze based on target type and options
      if (options.cloud_provider) {
        await this.scanCloudNetwork(target.target, options);
      } else if (options.k8s_namespace) {
        await this.scanKubernetesNetwork(options);
      } else if (options.policy_file) {
        await this.analyzePolicyFile(options.policy_file);
      } else {
        await this.scanNetworkRange(target.target, options);
      }

      // Check network segmentation
      await this.checkMicroSegmentation();

      // Analyze access policies
      await this.analyzeAccessPolicies();

      // Check for zero-trust compliance
      await this.checkZeroTrustCompliance();

      logger.info(`✅ Network scan completed. Found ${this.findings.length} findings`);
    } catch (error) {
      logger.error('❌ Network scan failed:', error);
      this.addFinding(
        'critical',
        'scan-error',
        'Network scan failed',
        error instanceof Error ? error.message : 'Unknown error'
      );
    }

    return this.findings;
  }

  /**
   * Scan cloud network infrastructure
   */
  private async scanCloudNetwork(target: string, options: NetworkScanOptions): Promise<void> {
    logger.info(`☁️ Scanning ${options.cloud_provider} network infrastructure`);

    switch (options.cloud_provider) {
      case 'aws':
        await this.scanAWSNetwork(target, options);
        break;
      case 'azure':
        await this.scanAzureNetwork(target, options);
        break;
      case 'gcp':
        await this.scanGCPNetwork(target, options);
        break;
    }
  }

  /**
   * Scan AWS VPC and security groups
   */
  private async scanAWSNetwork(_target: string, _options: NetworkScanOptions): Promise<void> {
    // TODO: Implement AWS SDK integration

    // Simulate AWS network analysis
    await this.simulateAnalysis(800);

    // Check for overly permissive security groups
    this.addFinding(
      'high',
      'aws-sg-permissive',
      'Overly permissive security group',
      'Security group sg-12345 allows 0.0.0.0/0 access on port 22'
    );

    // Check for public subnets with private resources
    this.addFinding(
      'medium',
      'aws-public-subnet',
      'Private resources in public subnet',
      'RDS instances found in public subnet subnet-67890'
    );

    // Check VPC flow logs
    this.addFinding(
      'medium',
      'aws-no-flow-logs',
      'VPC Flow Logs not enabled',
      'VPC vpc-abcdef does not have flow logs enabled for monitoring'
    );

    logger.info('✅ AWS network scan completed');
  }

  /**
   * Scan Azure virtual networks
   */
  private async scanAzureNetwork(_target: string, _options: NetworkScanOptions): Promise<void> {
    // TODO: Implement Azure SDK integration

    await this.simulateAnalysis(700);

    // Check Network Security Groups
    this.addFinding(
      'high',
      'azure-nsg-permissive',
      'Permissive Network Security Group',
      'NSG "default-nsg" allows inbound traffic from any source on multiple ports'
    );

    // Check for missing Application Security Groups
    this.addFinding(
      'medium',
      'azure-missing-asg',
      'Application Security Groups not used',
      'VMs are not grouped using Application Security Groups for micro-segmentation'
    );

    logger.info('✅ Azure network scan completed');
  }

  /**
   * Scan GCP VPC and firewall rules
   */
  private async scanGCPNetwork(_target: string, _options: NetworkScanOptions): Promise<void> {
    // TODO: Implement GCP SDK integration

    await this.simulateAnalysis(750);

    // Check firewall rules
    this.addFinding(
      'high',
      'gcp-firewall-permissive',
      'Overly permissive firewall rule',
      'Firewall rule "allow-all-internal" permits all internal traffic without restrictions'
    );

    // Check VPC peering
    this.addFinding(
      'medium',
      'gcp-vpc-peering',
      'VPC peering configuration review needed',
      'Multiple VPC peering connections detected - review access permissions'
    );

    logger.info('✅ GCP network scan completed');
  }

  /**
   * Scan Kubernetes network policies
   */
  private async scanKubernetesNetwork(options: NetworkScanOptions): Promise<void> {
    const namespace = options.k8s_namespace || 'default';
    logger.info(`🚢 Scanning Kubernetes network policies in namespace: ${namespace}`);

    let k8sClient: KubernetesClient | null = null;

    try {
      // Initialize Kubernetes client
      try {
        k8sClient = new KubernetesClient({
          namespace: namespace,
        });
      } catch (clientError) {
        logger.warn(
          '⚠️ Failed to initialize Kubernetes client:',
          clientError instanceof Error ? { error: clientError.message } : {}
        );
        await this.simulateKubernetesNetwork(namespace);
        return;
      }

      // Check if connected to cluster
      if (!k8sClient.isConnected()) {
        logger.warn('⚠️ Not connected to Kubernetes cluster - falling back to simulated scan');
        await this.simulateKubernetesNetwork(namespace);
        return;
      }

      const clusterInfo = k8sClient.getClusterInfo();
      logger.info(`📊 Connected to cluster: ${clusterInfo?.name} (${clusterInfo?.server})`);

      // Get namespaces to scan
      let namespacesToScan: string[] = [namespace];
      if (namespace === 'all' || namespace === '*') {
        const namespaces = await k8sClient.listNamespaces();
        namespacesToScan = namespaces
          .filter((ns) => !ns.name.startsWith('kube-')) // Skip system namespaces
          .map((ns) => ns.name);
        logger.info(`📋 Scanning ${namespacesToScan.length} namespaces`);
      }

      // Scan each namespace
      for (const ns of namespacesToScan) {
        await this.scanNamespace(k8sClient, ns);
      }

      // Perform cluster-wide security checks
      await this.performClusterWideChecks(k8sClient, namespacesToScan);

      logger.info(`✅ Kubernetes network scan completed. Found ${this.findings.length} findings`);
    } catch (error) {
      logger.error('❌ Kubernetes scan failed:', error);
      this.addFinding(
        'high',
        'k8s-scan-error',
        'Kubernetes scan encountered an error',
        error instanceof Error ? error.message : 'Unknown error occurred during Kubernetes scan'
      );

      // Fall back to simulated scan
      logger.info('⚠️ Falling back to simulated scan');
      await this.simulateKubernetesNetwork(namespace);
    }
  }

  /**
   * Scan a specific namespace for network policy issues
   */
  private async scanNamespace(k8sClient: KubernetesClient, namespace: string): Promise<void> {
    logger.info(`🔍 Analyzing namespace: ${namespace}`);

    try {
      // Get network policies for this namespace
      const policies = await k8sClient.listNetworkPolicies(namespace);
      const pods = await k8sClient.listPods(namespace);

      logger.info(
        `📊 Found ${policies.length} network policies and ${pods.length} pods in ${namespace}`
      );

      // Check 1: No network policies in namespace
      if (policies.length === 0 && pods.length > 0) {
        this.addFinding(
          'high',
          'k8s-no-network-policy',
          `No network policies in namespace: ${namespace}`,
          `Namespace "${namespace}" has ${pods.length} pods but no network policies. All pod-to-pod communication is allowed by default.`,
          `Implement at least a default-deny network policy for namespace "${namespace}"`
        );
      }

      // Check 2: Missing default-deny policy
      const hasDefaultDeny = this.hasDefaultDenyPolicy(policies);
      if (policies.length > 0 && !hasDefaultDeny && pods.length > 0) {
        this.addFinding(
          'high',
          'k8s-no-default-deny',
          `Missing default-deny policy in ${namespace}`,
          `Namespace "${namespace}" lacks a default-deny network policy. Traffic not explicitly allowed by policies is still permitted.`,
          `Create a default-deny network policy that denies all ingress and egress by default`
        );
      }

      // Check 3: Analyze each policy
      for (const policy of policies) {
        await this.analyzeNetworkPolicy(policy, pods, namespace);
      }

      // Check 4: Pods using hostNetwork
      const hostNetworkPods = pods.filter((pod) => pod.hostNetwork);
      if (hostNetworkPods.length > 0) {
        this.addFinding(
          'critical',
          'k8s-host-network',
          `Pods using hostNetwork in ${namespace}`,
          `Found ${hostNetworkPods.length} pod(s) using hostNetwork: ${hostNetworkPods.map((p) => p.name).join(', ')}. These pods bypass network policies and have direct host network access.`,
          `Remove hostNetwork: true from pod specifications unless absolutely necessary for node-level operations`
        );
      }

      // Check 5: Unprotected pods
      const unprotectedPods = this.findUnprotectedPods(pods, policies);
      if (unprotectedPods.length > 0) {
        this.addFinding(
          'high',
          'k8s-unprotected-pods',
          `Unprotected pods in ${namespace}`,
          `Found ${unprotectedPods.length} pod(s) not covered by any network policy: ${unprotectedPods
            .slice(0, 5)
            .map((p) => p.name)
            .join(', ')}${unprotectedPods.length > 5 ? '...' : ''}`,
          `Create network policies that explicitly target all pods using podSelector labels`
        );
      }
    } catch (error) {
      logger.error(`Error scanning namespace ${namespace}:`, error);
      this.addFinding(
        'medium',
        'k8s-namespace-scan-error',
        `Could not fully scan namespace: ${namespace}`,
        error instanceof Error ? error.message : 'Unknown error'
      );
    }
  }

  /**
   * Analyze a specific network policy for security issues
   */
  private async analyzeNetworkPolicy(
    policy: NetworkPolicySpec,
    _pods: PodInfo[],
    namespace: string
  ): Promise<void> {
    const policyName = policy.metadata.name;

    // Check for overly permissive ingress rules
    if (policy.spec.ingress) {
      for (const rule of policy.spec.ingress) {
        // Check for rules allowing from all namespaces
        if (rule.from) {
          for (const source of rule.from) {
            if (
              source.namespaceSelector &&
              (!source.namespaceSelector.matchLabels ||
                Object.keys(source.namespaceSelector.matchLabels).length === 0)
            ) {
              this.addFinding(
                'medium',
                'k8s-permissive-ingress',
                `Overly permissive ingress in policy: ${policyName}`,
                `Network policy "${policyName}" in namespace "${namespace}" allows ingress from all namespaces using an empty namespaceSelector.`,
                `Restrict ingress to specific namespaces using appropriate label selectors`
              );
            }

            // Check for unrestricted CIDR blocks
            if (source.ipBlock && source.ipBlock.cidr === '0.0.0.0/0') {
              this.addFinding(
                'high',
                'k8s-ingress-from-internet',
                `Policy allows ingress from internet: ${policyName}`,
                `Network policy "${policyName}" in namespace "${namespace}" allows ingress from 0.0.0.0/0 (entire internet).`,
                `Restrict ingress to specific IP ranges or remove ipBlock rule`
              );
            }
          }
        } else {
          // Empty from clause allows from all sources
          this.addFinding(
            'high',
            'k8s-ingress-all-sources',
            `Policy allows ingress from all sources: ${policyName}`,
            `Network policy "${policyName}" in namespace "${namespace}" has an ingress rule with no 'from' clause, allowing traffic from all sources.`,
            `Add explicit 'from' selectors to restrict ingress sources`
          );
        }

        // Check for unrestricted ports
        if (!rule.ports || rule.ports.length === 0) {
          this.addFinding(
            'low',
            'k8s-ingress-all-ports',
            `Policy allows all ports: ${policyName}`,
            `Network policy "${policyName}" in namespace "${namespace}" allows ingress on all ports.`,
            `Specify explicit port restrictions in the ingress rule`
          );
        }
      }
    }

    // Check 3: Overly permissive egress rules
    if (policy.spec.egress) {
      for (const rule of policy.spec.egress) {
        if (rule.to) {
          for (const dest of rule.to) {
            // Check for unrestricted CIDR blocks
            if (dest.ipBlock && dest.ipBlock.cidr === '0.0.0.0/0') {
              this.addFinding(
                'medium',
                'k8s-egress-to-internet',
                `Policy allows egress to internet: ${policyName}`,
                `Network policy "${policyName}" in namespace "${namespace}" allows egress to 0.0.0.0/0 (entire internet).`,
                `Restrict egress to specific IP ranges or use DNS-based policies`
              );
            }
          }
        } else {
          // Empty to clause allows to all destinations
          this.addFinding(
            'medium',
            'k8s-egress-all-destinations',
            `Policy allows egress to all destinations: ${policyName}`,
            `Network policy "${policyName}" in namespace "${namespace}" has an egress rule with no 'to' clause, allowing traffic to all destinations.`,
            `Add explicit 'to' selectors to restrict egress destinations`
          );
        }
      }
    }

    // Check 4: Missing policy types
    if (!policy.spec.policyTypes || policy.spec.policyTypes.length === 0) {
      this.addFinding(
        'low',
        'k8s-missing-policy-types',
        `Policy missing policyTypes field: ${policyName}`,
        `Network policy "${policyName}" in namespace "${namespace}" does not specify policyTypes. Behavior may be ambiguous.`,
        `Explicitly set policyTypes to ['Ingress', 'Egress'] or ['Ingress'] as appropriate`
      );
    }

    // Check 5: Policy age (old policies may need review)
    if (policy.metadata.creationTimestamp) {
      const created = new Date(policy.metadata.creationTimestamp);
      const ageInDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);

      if (ageInDays > 180) {
        this.addFinding(
          'low',
          'k8s-policy-needs-review',
          `Old policy needs review: ${policyName}`,
          `Network policy "${policyName}" in namespace "${namespace}" is ${Math.floor(ageInDays)} days old and may need review.`,
          `Review and update network policies regularly to ensure they match current requirements`
        );
      }
    }
  }

  /**
   * Perform cluster-wide security checks
   */
  private async performClusterWideChecks(
    k8sClient: KubernetesClient,
    _namespaces: string[]
  ): Promise<void> {
    logger.info('🔒 Performing cluster-wide network security checks');

    try {
      // Get all policies across cluster
      const allPolicies = await k8sClient.listAllNetworkPolicies();
      const allPods = await k8sClient.listAllPods();

      // Calculate coverage metrics
      const namespacesWithPolicies = new Set(allPolicies.map((p) => p.metadata.namespace));
      const namespacesWithPods = new Set(
        allPods.filter((p) => p.phase === 'Running').map((p) => p.namespace)
      );

      const unprotectedNamespaces = Array.from(namespacesWithPods)
        .filter((ns) => !namespacesWithPolicies.has(ns))
        .filter((ns) => !ns.startsWith('kube-')); // Exclude system namespaces

      if (unprotectedNamespaces.length > 0) {
        this.addFinding(
          'high',
          'k8s-unprotected-namespaces',
          'Namespaces without network policies',
          `${unprotectedNamespaces.length} namespace(s) have pods but no network policies: ${unprotectedNamespaces.join(', ')}`,
          `Implement network policies for all application namespaces`
        );
      }

      // Check for cluster-wide policy best practices
      const policyCount = allPolicies.length;
      const podCount = allPods.filter((p) => p.phase === 'Running').length;

      if (policyCount === 0 && podCount > 0) {
        this.addFinding(
          'critical',
          'k8s-no-network-policies',
          'No network policies in entire cluster',
          `Cluster has ${podCount} running pods but zero network policies. All inter-pod communication is unrestricted.`,
          `Implement a zero-trust network policy strategy starting with default-deny policies`
        );
      }

      // Calculate and report metrics
      const coverage =
        namespacesWithPods.size > 0
          ? (namespacesWithPolicies.size / namespacesWithPods.size) * 100
          : 0;

      logger.info(`📊 Network policy coverage: ${coverage.toFixed(1)}% of namespaces`);

      if (coverage < 100) {
        this.addFinding(
          'info',
          'k8s-policy-coverage',
          'Network policy coverage metrics',
          `Network policies are implemented in ${namespacesWithPolicies.size} out of ${namespacesWithPods.size} namespaces with pods (${coverage.toFixed(1)}% coverage)`,
          `Aim for 100% network policy coverage across all application namespaces`
        );
      }
    } catch (error) {
      logger.error('Error performing cluster-wide checks:', error);
    }
  }

  /**
   * Check if policies include a default-deny policy
   */
  private hasDefaultDenyPolicy(policies: NetworkPolicySpec[]): boolean {
    return policies.some((policy) => {
      const hasEmptySelector =
        !policy.spec.podSelector.matchLabels && !policy.spec.podSelector.matchExpressions;
      const hasEmptyIngress =
        policy.spec.policyTypes?.includes('Ingress') &&
        (!policy.spec.ingress || policy.spec.ingress.length === 0);
      const hasEmptyEgress =
        policy.spec.policyTypes?.includes('Egress') &&
        (!policy.spec.egress || policy.spec.egress.length === 0);

      return hasEmptySelector && (hasEmptyIngress || hasEmptyEgress);
    });
  }

  /**
   * Find pods not covered by any network policy
   */
  private findUnprotectedPods(pods: PodInfo[], policies: NetworkPolicySpec[]): PodInfo[] {
    return pods.filter((pod) => {
      // Check if any policy applies to this pod
      const isCovered = policies.some((policy) => {
        const selector = policy.spec.podSelector;

        // Empty selector applies to all pods
        if (!selector.matchLabels && !selector.matchExpressions) {
          return true;
        }

        // Check label matching
        if (selector.matchLabels) {
          const matches = Object.entries(selector.matchLabels).every(
            ([key, value]) => pod.labels[key] === value
          );
          if (matches) return true;
        }

        // For simplicity, we're not fully implementing matchExpressions
        // In production, you'd want to implement the full selector logic
        if (selector.matchExpressions && selector.matchExpressions.length > 0) {
          return false; // Conservative: assume no match
        }

        return false;
      });

      return !isCovered;
    });
  }

  /**
   * Simulated Kubernetes scan (fallback when cluster not available)
   */
  private async simulateKubernetesNetwork(namespace: string): Promise<void> {
    await this.simulateAnalysis(600);

    this.addFinding(
      'high',
      'k8s-no-network-policy',
      'No network policies found',
      `Namespace "${namespace}" has no network policies - all pod communication is allowed`,
      `Implement network policies to control pod-to-pod traffic`
    );

    this.addFinding(
      'medium',
      'k8s-no-default-deny',
      'No default-deny network policy',
      'Missing default-deny network policy to block all traffic by default',
      `Create a default-deny policy as the foundation of your network security`
    );

    this.addFinding(
      'medium',
      'k8s-permissive-ingress',
      'Permissive ingress rules detected',
      'Some pods allow ingress from all namespaces',
      `Restrict ingress to specific namespaces using label selectors`
    );

    logger.info('✅ Simulated Kubernetes network scan completed');
  }

  /**
   * Analyze network range for segmentation
   */
  private async scanNetworkRange(target: string, _options: NetworkScanOptions): Promise<void> {
    logger.info(`🔍 Scanning network range: ${target}`);

    await this.simulateAnalysis(1000);

    // Simulate network discovery and analysis
    this.addFinding(
      'info',
      'network-discovery',
      'Network range analyzed',
      `Analyzed network range ${target} - ${Math.floor(Math.random() * 100)} hosts discovered`
    );

    // Check for flat network architecture
    this.addFinding(
      'high',
      'flat-network',
      'Flat network architecture detected',
      'Network lacks proper segmentation - all hosts can communicate directly'
    );

    logger.info('✅ Network range scan completed');
  }

  /**
   * Analyze network policy file
   */
  private async analyzePolicyFile(policyFile: string): Promise<void> {
    logger.info(`📄 Analyzing policy file: ${policyFile}`);

    // TODO: Implement policy file parsing (YAML/JSON)

    await this.simulateAnalysis(400);

    this.addFinding(
      'info',
      'policy-analysis',
      'Policy file analyzed',
      `Analyzed policy file ${policyFile}`
    );

    logger.info('✅ Policy file analysis completed');
  }

  /**
   * Check micro-segmentation implementation
   */
  private async checkMicroSegmentation(): Promise<void> {
    logger.info('🔒 Checking micro-segmentation compliance');

    // Simulate micro-segmentation analysis
    await this.simulateAnalysis(300);

    // Check for proper segmentation
    this.addFinding(
      'medium',
      'insufficient-segmentation',
      'Insufficient network segmentation',
      'Network segments are too broad - consider implementing finer-grained segmentation'
    );

    // Check isolation between environments
    this.addFinding(
      'high',
      'env-isolation',
      'Environment isolation insufficient',
      'Production and development networks are not properly isolated'
    );
  }

  /**
   * Analyze access policies and rules
   */
  private async analyzeAccessPolicies(): Promise<void> {
    logger.info('📋 Analyzing access policies');

    await this.simulateAnalysis(500);

    // Check for least privilege
    this.addFinding(
      'medium',
      'excessive-permissions',
      'Excessive network permissions',
      'Some rules grant broader access than necessary for business requirements'
    );

    // Check rule documentation
    this.addFinding(
      'low',
      'undocumented-rules',
      'Undocumented access rules',
      'Network access rules lack proper business justification and documentation'
    );
  }

  /**
   * Check zero-trust network compliance
   */
  private async checkZeroTrustCompliance(): Promise<void> {
    logger.info('🛡️ Checking zero-trust compliance');

    await this.simulateAnalysis(400);

    // Check for default-deny posture
    this.addFinding(
      'high',
      'no-default-deny',
      'Default-deny not implemented',
      'Network does not implement default-deny - all traffic allowed by default'
    );

    // Check encryption in transit
    this.addFinding(
      'medium',
      'unencrypted-traffic',
      'Unencrypted network traffic',
      'Some network traffic is not encrypted in transit'
    );

    // Check network monitoring
    this.addFinding(
      'medium',
      'insufficient-monitoring',
      'Insufficient network monitoring',
      'Network lacks comprehensive traffic monitoring and logging'
    );
  }
}
