import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCompromised, classifyAttackSource } from '../../skills/secops-alert-analysis/scripts/analysis/analyze-compromised.js';

describe('classifyAttackSource', () => {
  it("returns '外部' when any non-局域网 non-empty address exists", () => {
    assert.equal(classifyAttackSource(['222.90.96.237', '局域网']), '外部');
    assert.equal(classifyAttackSource(['英国--英格兰--罗瑟勒姆(...)']), '外部');
  });

  it("returns '内网' when all addresses are 局域网", () => {
    assert.equal(classifyAttackSource(['局域网', '局域网']), '内网');
  });

  it("returns '未知' when missing / non-array / all empty (定案口径)", () => {
    assert.equal(classifyAttackSource(undefined), '未知');
    assert.equal(classifyAttackSource(null), '未知');
    assert.equal(classifyAttackSource([]), '未知');
    assert.equal(classifyAttackSource(['', '  ']), '未知');
  });
});

describe('analyzeCompromised', () => {
  const hosts = [
    { ip: '10.1.1.1', count: 5, attack_types: [], states: ['攻击成功'], risk_desc: '弱口令(5)', opinion: 'o1', reason: 'r1', sip_addrs: ['222.90.96.237'] },
    { ip: '10.1.1.2', count: 3, attack_types: [], states: ['失陷'], risk_desc: 'x', opinion: 'o2', reason: 'r2', sip_addrs: ['局域网', '局域网'] },
    { ip: '10.1.1.3', count: 2, attack_types: [], states: ['失陷'], risk_desc: 'y', opinion: 'o3', reason: 'r3', sip_addrs: [] },
  ];

  it('classifies attack_source correctly for the three sip_addrs shapes', () => {
    const r = analyzeCompromised(hosts);
    assert.equal(r[0].attack_source, '外部');
    assert.equal(r[1].attack_source, '内网');
    assert.equal(r[2].attack_source, '未知');
  });

  it('preserves existing risk_desc / opinion / reason and other fields', () => {
    const r = analyzeCompromised(hosts);
    assert.equal(r[0].risk_desc, '弱口令(5)');
    assert.equal(r[0].opinion, 'o1');
    assert.equal(r[0].reason, 'r1');
    assert.equal(r[0].ip, '10.1.1.1');
    assert.equal(r[0].count, 5);
  });

  it('returns empty array for empty input', () => {
    assert.deepEqual(analyzeCompromised([]), []);
    assert.deepEqual(analyzeCompromised(undefined), []);
  });
});
