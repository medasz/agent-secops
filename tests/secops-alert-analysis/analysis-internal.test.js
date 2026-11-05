import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeInternal } from '../../skills/secops-alert-analysis/scripts/analysis/analyze-internal.js';

describe('analyzeInternal', () => {
  it('passes lateral through and summarizes stats', () => {
    const parsed = {
      stats: {
        total_alerts: 150,
        internal_alerts: 150,
        lateral_alerts: 45,
        unique_internal_sources: 2,
        unique_internal_targets: 2,
        host_states: [{ type: '失陷', count: 50 }],
      },
      lateral: {
        sources: [{ ip: '192.0.2.12', count: 20 }],
        targets: [{ ip: '192.0.2.32', count: 20 }],
        pairs: [{ source: 'a', target: 'b', count: 20 }],
        hourly_distribution: [{ hour: 'h', count: 3 }],
        host_states: [{ type: '失陷', count: 50 }],
      },
    };
    const r = analyzeInternal(parsed);
    assert.equal(r.stats.internal_alerts, 150);
    assert.equal(r.stats.lateral_alerts, 45);
    assert.equal(r.lateral.sources.length, 1);
    assert.equal(r.lateral.targets[0].ip, '192.0.2.32');
    assert.equal(r.lateral.pairs.length, 1);
    // 涉及内部主机数 = 横向移动源 ∪ 目标 IP 去重并集（192.0.2.12 ∪ 192.0.2.32 = 2）
    assert.equal(r.stats.unique_internal_hosts, 2);
  });

  it('returns lateral: null when not present and does not throw', () => {
    const parsed = { stats: { total_alerts: 10, internal_alerts: 10 } };
    const r = analyzeInternal(parsed);
    assert.equal(r.lateral, null);
    assert.equal(r.stats.internal_alerts, 10);
    assert.equal(r.stats.lateral_alerts, 0);
    // 无 lateral 时涉及内部主机数为 0
    assert.equal(r.stats.unique_internal_hosts, 0);
  });
});
