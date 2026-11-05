import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeExternal } from '../../skills/secops-alert-analysis/scripts/analysis/analyze-external.js';

describe('analyzeExternal', () => {
  const parsed = {
    stats: {
      total_alerts: 1000,
      unique_external_ips: 45,
      external_alerts: 1000,
      attack_types: [
        { type: '暴力猜测', count: 600 },
        { type: '代理工具', count: 400 },
      ],
      hourly_distribution: [
        { hour: '2026-07-15 00:00:00', count: 10 },
        { hour: '2026-07-15 01:00:00', count: 50 },
        { hour: '2026-07-15 02:00:00', count: 5 },
      ],
    },
    ips: [
      { ip: '1.1.1.1', attack_types: [{ type: '暴力猜测', count: 600 }] },
      { ip: '2.2.2.2', attack_types: [{ type: '代理工具', count: 400 }] },
    ],
    compromised_hosts: [{ ip: '10.0.0.1' }],
  };

  it('computes attackTypes percentage and ipCount', () => {
    const r = analyzeExternal(parsed);
    assert.equal(r.attackTypes.length, 2);
    const brute = r.attackTypes[0];
    assert.equal(brute.type, '暴力猜测');
    assert.equal(brute.count, 600);
    assert.equal(brute.percentage, '60.0%');
    assert.equal(brute.ipCount, 1);
  });

  it('computes hourly total, peak and high-risk hours', () => {
    const r = analyzeExternal(parsed);
    assert.equal(r.hourly.total, 65);
    assert.equal(r.hourly.peakHour, '2026-07-15 01:00:00');
    assert.equal(r.hourly.peakCount, 50);
    // avg = 65/3 ≈ 21.67; high-risk > avg*1.5 ≈ 32.5 → only the 50 bucket qualifies
    assert.ok(r.hourly.highRiskHours.includes('50次'), 'high-risk should mention the 50-count bucket');
  });

  it('summarizes top-level stats', () => {
    const r = analyzeExternal(parsed);
    assert.equal(r.stats.total_alerts, 1000);
    assert.equal(r.stats.unique_external_ips, 45);
    assert.equal(r.stats.compromised_alerts, 1);
  });

  it('handles empty parsed gracefully', () => {
    const r = analyzeExternal({});
    assert.equal(r.stats.total_alerts, 0);
    assert.equal(r.attackTypes.length, 0);
    assert.equal(r.hourly.peakHour, '');
    assert.equal(r.hourly.highRiskHours, '无');
  });
});
