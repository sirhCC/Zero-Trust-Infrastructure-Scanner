import { ComplianceImpact } from '../core/scanner';

type Standard = ComplianceImpact['standard'];

// Simple category-to-controls mapping. Extend as needed.
const MAPPINGS: Record<string, Array<{ standard: Standard; control: string; impact: ComplianceImpact['impact'] }>> = {
  'network': [
    { standard: 'SOC2', control: 'CC6.6', impact: 'high' },
    { standard: 'PCI', control: '1.2', impact: 'high' },
    { standard: 'ISO27001', control: 'A.13.1', impact: 'medium' }
  ],
  'micro-segmentation': [
    { standard: 'SOC2', control: 'CC6.6', impact: 'high' },
    { standard: 'PCI', control: '1.3', impact: 'high' }
  ],
  'identity': [
    { standard: 'SOC2', control: 'CC6.3', impact: 'high' },
    { standard: 'ISO27001', control: 'A.9.2', impact: 'high' },
    { standard: 'HIPAA', control: '164.312(a)(1)', impact: 'medium' }
  ],
  'privilege': [
    { standard: 'SOC2', control: 'CC6.3', impact: 'high' },
    { standard: 'ISO27001', control: 'A.9.4', impact: 'high' }
  ],
  'supply-chain': [
    { standard: 'SOC2', control: 'CC7.1', impact: 'medium' },
    { standard: 'ISO27001', control: 'A.15.1', impact: 'medium' },
    { standard: 'HIPAA', control: '164.308(a)(1)(ii)(B)', impact: 'medium' }
  ],
  'vulnerability': [
    { standard: 'SOC2', control: 'CC7.2', impact: 'high' },
    { standard: 'PCI', control: '6.2', impact: 'high' }
  ],
  'compliance': [
    { standard: 'SOC2', control: 'CC4.1', impact: 'low' }
  ]
};

export function mapCategoryToCompliance(category: string): ComplianceImpact[] {
  const key = category.toLowerCase();
  const matches = Object.keys(MAPPINGS).filter((k) => key.includes(k));
  const impacts: ComplianceImpact[] = [];
  for (const m of matches) {
    for (const entry of MAPPINGS[m]) {
      impacts.push({ standard: entry.standard, control: entry.control, impact: entry.impact });
    }
  }
  return impacts;
}

export function applyComplianceMapping<T extends { category: string; compliance_impact?: ComplianceImpact[] }>(
  findings: T[]
): T[] {
  return findings.map((f) => {
    const impacts = mapCategoryToCompliance(f.category);
    return { ...f, compliance_impact: impacts.length > 0 ? impacts : f.compliance_impact || [] };
  });
}
