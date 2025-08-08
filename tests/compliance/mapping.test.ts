import { applyComplianceMapping } from '../../src/compliance/mapping';

describe('Compliance mapping', () => {
  it('maps network category to SOC2/PCI/ISO controls', () => {
    const out = applyComplianceMapping([{ category: 'network micro-segmentation' } as any]);
    expect(out[0].compliance_impact?.some((i: any) => i.standard === 'SOC2')).toBeTruthy();
    expect(out[0].compliance_impact?.length).toBeGreaterThan(0);
  });
});
