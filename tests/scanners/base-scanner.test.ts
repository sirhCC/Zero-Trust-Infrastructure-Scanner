/**
 * BaseScanner tests
 */

import { BaseScanner } from '../../src/scanners/base-scanner';

// Create a concrete test implementation
class TestScanner extends BaseScanner {
  constructor() {
    super('TestScanner');
  }

  // Expose protected methods for testing
  public testAddFinding(
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
    category: string,
    title: string,
    description: string,
    recommendation?: string
  ): void {
    this.addFinding(severity, category, title, description, recommendation);
  }

  public testGetDefaultRemediation(check_id: string): string {
    return this.getDefaultRemediation(check_id);
  }

  public testGetComplianceImpact(category: string) {
    return this.getComplianceImpact(category);
  }
}

describe('BaseScanner', () => {
  let scanner: TestScanner;

  beforeEach(() => {
    scanner = new TestScanner();
  });

  describe('addFinding', () => {
    it('should create a finding with all required fields', () => {
      scanner.testAddFinding('high', 'test-category', 'Test Finding', 'Test description');

      const findings = scanner.getFindings();
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: 'high',
        category: 'test-category',
        title: 'Test Finding',
        description: 'Test description',
      });
      expect(findings[0].id).toBeTruthy();
      expect(findings[0].recommendation).toBeTruthy();
    });

    it('should use custom recommendation if provided', () => {
      scanner.testAddFinding('medium', 'test', 'Test', 'Desc', 'Custom remediation');

      const findings = scanner.getFindings();
      expect(findings[0].recommendation).toBe('Custom remediation');
    });

    it('should include evidence with timestamp and scanner info', () => {
      scanner.testAddFinding('low', 'test', 'Test', 'Desc');

      const findings = scanner.getFindings();
      expect(findings[0].evidence).toMatchObject({
        scanner_version: '1.0.0',
        scanner_name: 'TestScanner',
      });
      expect((findings[0].evidence as any).scan_time).toBeInstanceOf(Date);
    });
  });

  describe('getDefaultRemediation', () => {
    it('should return known remediation for network issues', () => {
      const remediation = scanner.testGetDefaultRemediation('aws-sg-permissive');
      expect(remediation).toBe('Restrict security group rules to specific IP ranges and ports');
    });

    it('should return known remediation for identity issues', () => {
      const remediation = scanner.testGetDefaultRemediation('no-mfa');
      expect(remediation).toBe('Enable multi-factor authentication for all user accounts');
    });

    it('should return default message for unknown categories', () => {
      const remediation = scanner.testGetDefaultRemediation('unknown-check');
      expect(remediation).toBe('Review and remediate the identified security issue');
    });
  });

  describe('getComplianceImpact', () => {
    it('should return compliance impacts for known categories', () => {
      const impact = scanner.testGetComplianceImpact('aws-sg-permissive');
      expect(impact).toHaveLength(3);
      expect(impact).toContainEqual({
        standard: 'PCI',
        control: 'Requirement 1.2',
        impact: 'high',
      });
    });

    it('should return empty array for unknown categories', () => {
      const impact = scanner.testGetComplianceImpact('unknown-category');
      expect(impact).toEqual([]);
    });

    it('should include multiple compliance frameworks', () => {
      const impact = scanner.testGetComplianceImpact('no-mfa');
      expect(impact.length).toBeGreaterThan(1);
      const standards = impact.map((i) => i.standard);
      expect(standards).toContain('PCI');
      expect(standards).toContain('SOC2');
    });
  });

  describe('getFindings', () => {
    it('should return empty array when no findings added', () => {
      expect(scanner.getFindings()).toEqual([]);
    });

    it('should return all added findings', () => {
      scanner.testAddFinding('high', 'test1', 'Finding 1', 'Desc 1');
      scanner.testAddFinding('low', 'test2', 'Finding 2', 'Desc 2');
      scanner.testAddFinding('critical', 'test3', 'Finding 3', 'Desc 3');

      const findings = scanner.getFindings();
      expect(findings).toHaveLength(3);
      expect(findings[0].title).toBe('Finding 1');
      expect(findings[1].title).toBe('Finding 2');
      expect(findings[2].title).toBe('Finding 3');
    });
  });
});
