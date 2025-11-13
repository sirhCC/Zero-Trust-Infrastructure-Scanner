/**
 * Base Scanner Class
 * Provides common functionality for all security scanners
 */

import { SecurityFinding, ComplianceImpact } from '../core/scanner';
import { Logger } from '../utils/logger';

const logger = Logger.getInstance();

/**
 * Base class for all scanners with shared functionality
 */
export abstract class BaseScanner {
  protected findings: SecurityFinding[] = [];
  protected scannerName: string;
  protected scannerVersion: string = '1.0.0';

  constructor(scannerName: string) {
    this.scannerName = scannerName;
  }

  /**
   * Add a security finding to the results
   */
  protected addFinding(
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
    category: string,
    title: string,
    description: string,
    recommendation?: string
  ): void {
    const finding: SecurityFinding = {
      id: `${category}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      severity,
      category,
      title,
      description,
      recommendation: recommendation || this.getDefaultRemediation(category),
      evidence: {
        scan_time: new Date(),
        scanner_version: this.scannerVersion,
        scanner_name: this.scannerName,
      },
      compliance_impact: this.getComplianceImpact(category),
    };

    this.findings.push(finding);
  }

  /**
   * Get default remediation for a check
   * Can be overridden by subclasses for scanner-specific remediations
   */
  protected getDefaultRemediation(check_id: string): string {
    const remediations = this.getRemediationCatalog();
    return remediations[check_id] || 'Review and remediate the identified security issue';
  }

  /**
   * Get remediation catalog
   * Should be overridden by subclasses to provide scanner-specific remediations
   */
  protected getRemediationCatalog(): Record<string, string> {
    return {
      // Network-related
      'aws-sg-permissive': 'Restrict security group rules to specific IP ranges and ports',
      'aws-public-subnet': 'Move private resources to private subnets',
      'aws-no-flow-logs': 'Enable VPC Flow Logs for network monitoring',
      'azure-nsg-permissive': 'Implement more restrictive Network Security Group rules',
      'azure-no-flow-logs': 'Enable Network Watcher flow logs',
      'gcp-firewall-permissive': 'Restrict firewall rules to specific IP ranges',
      'k8s-no-network-policy':
        'Implement Kubernetes Network Policies for pod communication control',
      'k8s-permissive-ingress': 'Restrict ingress rules to specific namespaces or pods',
      'flat-network': 'Implement network segmentation using VLANs or subnets',
      'no-default-deny': 'Implement default-deny network policies',
      'insufficient-segmentation': 'Implement micro-segmentation for better network isolation',
      'excessive-permissions': 'Review and restrict overly broad network permissions',
      'undocumented-rules': 'Document business justification for all network access rules',
      'unencrypted-traffic': 'Enable encryption for network traffic (TLS/SSL)',
      'insufficient-monitoring': 'Implement comprehensive network traffic monitoring and logging',
      'env-isolation': 'Separate production and development networks with proper isolation',

      // Identity-related
      'aws-admin-access': 'Remove unnecessary administrative privileges',
      'aws-root-account': 'Avoid using root account for daily operations',
      'azure-global-admin': 'Minimize users with Global Administrator role',
      'gcp-owner-role': 'Avoid assigning Owner role unless absolutely necessary',
      'k8s-cluster-admin': 'Restrict cluster-admin role binding to specific users',
      'overprivileged-account': 'Apply principle of least privilege to reduce permissions',
      'unused-account': 'Disable or remove accounts that have not been used recently',
      'no-mfa': 'Enable multi-factor authentication for all user accounts',
      'privilege-escalation': 'Review and remove permissions that allow privilege escalation',
      'stale-credentials': 'Rotate credentials that have not been changed recently',
      'service-account-key': 'Use workload identity instead of long-lived service account keys',

      // Supply chain-related
      'vulnerable-dependency': 'Update to a patched version of the dependency',
      'outdated-image': 'Update base image to the latest version',
      'high-severity-vuln': 'Immediate patching required for high-severity vulnerabilities',
      'unlicensed-package': 'Review and ensure proper licensing for all packages',
      'malicious-package': 'Remove potentially malicious packages immediately',
      'unverified-source': 'Use only trusted and verified package sources',

      // Compliance-related
      'missing-encryption': 'Enable encryption at rest and in transit',
      'insufficient-logging': 'Enable comprehensive audit logging',
      'missing-backup': 'Implement regular backup procedures',
      'inadequate-access-control': 'Implement proper access control mechanisms',
      'missing-documentation': 'Document security controls and procedures',
    };
  }

  /**
   * Get compliance impact for a check
   * Can be overridden by subclasses for scanner-specific mappings
   */
  protected getComplianceImpact(category: string): ComplianceImpact[] {
    const impacts = this.getComplianceImpactCatalog();
    return impacts[category] || [];
  }

  /**
   * Get compliance impact catalog
   * Should be overridden by subclasses to add scanner-specific mappings
   */
  protected getComplianceImpactCatalog(): Record<string, ComplianceImpact[]> {
    return {
      // Network security impacts
      'aws-sg-permissive': [
        { standard: 'PCI', control: 'Requirement 1.2', impact: 'high' },
        { standard: 'SOC2', control: 'CC6.1', impact: 'high' },
        { standard: 'ISO27001', control: 'A.13.1.1', impact: 'high' },
      ],
      'insufficient-segmentation': [
        { standard: 'PCI', control: 'Requirement 1.1', impact: 'high' },
        { standard: 'HIPAA', control: '164.312(a)(1)', impact: 'medium' },
        { standard: 'SOC2', control: 'CC6.1', impact: 'high' },
      ],
      'no-default-deny': [
        { standard: 'SOC2', control: 'CC6.1', impact: 'high' },
        { standard: 'PCI', control: 'Requirement 1.2.1', impact: 'high' },
      ],
      'unencrypted-traffic': [
        { standard: 'PCI', control: 'Requirement 4.1', impact: 'critical' },
        { standard: 'HIPAA', control: '164.312(e)(1)', impact: 'high' },
        { standard: 'SOC2', control: 'CC6.7', impact: 'high' },
      ],

      // Identity and access impacts
      'overprivileged-account': [
        { standard: 'SOC2', control: 'CC6.2', impact: 'high' },
        { standard: 'PCI', control: 'Requirement 7.1', impact: 'high' },
        { standard: 'ISO27001', control: 'A.9.2.3', impact: 'medium' },
      ],
      'no-mfa': [
        { standard: 'PCI', control: 'Requirement 8.3', impact: 'critical' },
        { standard: 'SOC2', control: 'CC6.1', impact: 'high' },
        { standard: 'HIPAA', control: '164.312(a)(2)(i)', impact: 'high' },
      ],
      'unused-account': [
        { standard: 'PCI', control: 'Requirement 8.1.4', impact: 'medium' },
        { standard: 'SOC2', control: 'CC6.1', impact: 'medium' },
      ],

      // Supply chain impacts
      'vulnerable-dependency': [
        { standard: 'SOC2', control: 'CC7.1', impact: 'high' },
        { standard: 'PCI', control: 'Requirement 6.2', impact: 'high' },
      ],
      'high-severity-vuln': [
        { standard: 'PCI', control: 'Requirement 6.2', impact: 'critical' },
        { standard: 'SOC2', control: 'CC7.1', impact: 'critical' },
        { standard: 'ISO27001', control: 'A.12.6.1', impact: 'high' },
      ],

      // General compliance
      'insufficient-logging': [
        { standard: 'PCI', control: 'Requirement 10', impact: 'high' },
        { standard: 'HIPAA', control: '164.312(b)', impact: 'high' },
        { standard: 'SOC2', control: 'CC7.2', impact: 'high' },
      ],
      'missing-encryption': [
        { standard: 'PCI', control: 'Requirement 3.4', impact: 'critical' },
        { standard: 'HIPAA', control: '164.312(a)(2)(iv)', impact: 'high' },
        { standard: 'GDPR', control: 'Article 32', impact: 'high' },
      ],
    };
  }

  /**
   * Simulate analysis work with delay (for testing/demo purposes)
   */
  protected async simulateAnalysis(duration: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, duration));
  }

  /**
   * Get all findings from the scan
   */
  public getFindings(): SecurityFinding[] {
    return this.findings;
  }

  /**
   * Clear all findings (useful for re-running scans)
   */
  protected clearFindings(): void {
    this.findings = [];
  }

  /**
   * Log scanner initialization
   */
  protected logInitialization(icon: string, name: string): void {
    logger.info(`${icon} ${name} initialized`);
  }
}
