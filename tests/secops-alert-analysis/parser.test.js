import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { execFileSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCRIPT = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'scripts', 'reporting/parse-mcp.js');

const FIXTURE_DIR = join(__dirname, 'fixtures');

function ensureFixtures() {
  if (!fs.existsSync(FIXTURE_DIR)) {
    fs.mkdirSync(FIXTURE_DIR, { recursive: true });
  }
}

function createMalformedFixture() {
  const path = join(FIXTURE_DIR, 'malformed-mcp.json');
  fs.writeFileSync(path, 'not valid json at all {{{', 'utf-8');
  return path;
}

function createLegacyHitsFixture() {
  const path = join(FIXTURE_DIR, 'legacy-hits-mcp.json');
  const data = [
    {
      type: 'text',
      text: JSON.stringify([
        {
          _index: 'logfmt_746_20260505',
          _source: {
            field_values: {
              sip: '222.90.96.237',
              dip: '192.0.2.60',
              sip_addr: '222.90.96.237',
              host_state: '攻击成功',
              attack_type: 'SQL注入',
              hazard_rating: '高危',
              access_time: '2026-05-05T14:32:01+08:00',
            },
          },
        },
      ]),
    },
  ];
  fs.writeFileSync(path, JSON.stringify(data), 'utf-8');
  return path;
}

describe('reporting/parse-mcp.js', () => {
  let aggFixture;
  let malformedFixture;
  let legacyFixture;

  before(() => {
    ensureFixtures();
    aggFixture = join(FIXTURE_DIR, 'agg-response-mcp.json');
    malformedFixture = createMalformedFixture();
    legacyFixture = createLegacyHitsFixture();
  });

  // ============================================================
  // US1: Parse aggregation response — stats extraction
  // ============================================================
  describe('US1 - Stats extraction', () => {
    it('should extract total_alerts from hits.total.value', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.total_alerts, 3318);
    });

    it('should extract unique_external_ips from cardinality agg', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.unique_external_ips, 45);
    });

    it('should extract attack_types as {type, count} array', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.attack_types.length, 3);
      assert.equal(result.stats.attack_types[0].type, '暴力猜测');
      assert.equal(result.stats.attack_types[0].count, 1974);
    });

    it('should extract hazard_ratings and top_targets', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.hazard_ratings.length, 2);
      assert.equal(result.stats.hazard_ratings[0].type, '高危');
      assert.equal(result.stats.top_targets.length, 2);
      assert.equal(result.stats.top_targets[0].type, '192.0.2.32');
    });

    it('should extract hourly_distribution with hour and count', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.hourly_distribution.length, 3);
      assert.equal(result.stats.hourly_distribution[0].hour, '2025-12-27T00:00:00.000+08:00');
      assert.equal(result.stats.hourly_distribution[0].count, 15);
      assert.equal(result.stats.hourly_distribution[2].count, 0);
    });
  });

  // ============================================================
  // US2: Parse aggregation response — ips array (ban-ip-table.js compatibility)
  // ============================================================
  describe('US2 - IPs array (ban-ip-table.js --input compatible)', () => {
    it('should extract ips with correct count', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.ips.length, 3);
    });

    it('should have ip, total_alerts, attack_types, hazard_rating, max_timestamp, sip_addr fields', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      const ip = result.ips[0];
      assert.equal(ip.ip, '185.206.149.182');
      assert.equal(ip.total_alerts, 782);
      assert.equal(ip.hazard_rating, '');
      assert.equal(ip.max_timestamp, '2025-12-27T10:03:09.430Z');
      assert.equal(ip.sip_addr, '英国--英格兰--罗瑟勒姆(53.425861/-1.360846)');
      assert.ok(Array.isArray(ip.attack_types));
      assert.equal(ip.attack_types[0].type, '暴力猜测');
      assert.equal(ip.attack_types[0].count, 782);
    });

    it('should handle IPs with multiple attack types', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      const ip = result.ips.find(i => i.ip === '203.0.113.150');
      assert.equal(ip.attack_types.length, 2);
      assert.equal(ip.attack_types[0].type, '代理工具');
      assert.equal(ip.attack_types[0].count, 136);
      assert.equal(ip.attack_types[1].type, '流氓推广');
    });

    it('should produce output consumable by ban-ip-table.js --input', () => {
      const tmpOut = join(FIXTURE_DIR, 'tmp-parsed-output.json');
      try {
        execFileSync('node', [SCRIPT, aggFixture, '--format', 'json', '--output', tmpOut], { encoding: 'utf-8' });
        const banScript = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'scripts', 'reporting/ban-ip-table.js');
        const banOutput = execFileSync('node', [banScript, '--input', tmpOut, '--format', 'markdown'], { encoding: 'utf-8' });
        assert.ok(banOutput.includes('告警日期时间戳'), 'ban-ip-table.js should produce table header');
        assert.ok(banOutput.includes('185.206.149.182'), 'ban-ip-table.js should contain first IP');
      } finally {
        if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut);
      }
    });
  });

  // ============================================================
  // US3: Parse aggregation response — domains array (ban-domain-table.js compatibility)
  // ============================================================
  describe('US3 - Domains array (ban-domain-table.js --input compatible)', () => {
    it('should extract domains with correct count', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.domains.length, 2);
    });

    it('should have ioc, total_alerts, attack_types, max_timestamp fields', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      const dom = result.domains[0];
      assert.equal(dom.ioc, '*xip.io');
      assert.equal(dom.total_alerts, 1);
      assert.equal(dom.max_timestamp, '2025-12-27T04:01:31.170Z');
      assert.ok(Array.isArray(dom.attack_types));
      assert.equal(dom.attack_types[0].type, '其他');
    });

    it('should produce output consumable by ban-domain-table.js --input', () => {
      const tmpOut = join(FIXTURE_DIR, 'tmp-parsed-domains.json');
      try {
        execFileSync('node', [SCRIPT, aggFixture, '--format', 'json', '--output', tmpOut], { encoding: 'utf-8' });
        const banScript = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'scripts', 'reporting/ban-domain-table.js');
        const banOutput = execFileSync('node', [banScript, '--input', tmpOut, '--format', 'markdown'], { encoding: 'utf-8' });
        assert.ok(banOutput.includes('风险域名'), 'ban-domain-table.js should produce table header');
      } finally {
        if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut);
      }
    });
  });

  // ============================================================
  // US4: Parse aggregation response — compromised_hosts
  // ============================================================
  describe('US4 - Compromised hosts', () => {
    it('should extract compromised hosts from filter agg', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.compromised_hosts.length, 1);
    });

    it('should have ip, count, attack_types, states, first_seen, last_seen fields', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      const host = result.compromised_hosts[0];
      assert.equal(host.ip, '192.0.2.32');
      assert.equal(host.count, 2);
      assert.equal(host.first_seen, '2025-12-26T23:57:44.624Z');
      assert.equal(host.last_seen, '2025-12-27T06:30:35.131Z');
      assert.ok(host.states.includes('攻击成功'));
      assert.equal(host.attack_types[0].type, '弱口令');
    });
  });

  // ============================================================
  // US5: Error handling
  // ============================================================
  describe('US5 - Error handling', () => {
    it('should reject legacy document-level hits with exit code 3', () => {
      try {
        execFileSync('node', [SCRIPT, legacyFixture, '--format', 'json'], {
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        assert.fail('Should have exited with error');
      } catch (e) {
        assert.equal(e.status, 3);
        assert.ok(e.stderr.includes('no longer supported'), 'Should mention format no longer supported');
      }
    });

    it('should handle malformed JSON with exit code 3', () => {
      try {
        execFileSync('node', [SCRIPT, malformedFixture, '--format', 'json'], {
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        assert.fail('Should have exited with error');
      } catch (e) {
        assert.equal(e.status, 3);
      }
    });

    it('should exit with code 1 when no input file provided', () => {
      try {
        execFileSync('node', [SCRIPT], {
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        assert.fail('Should have exited with error');
      } catch (e) {
        assert.equal(e.status, 1);
      }
    });
  });

  // ============================================================
  // US6: Output format
  // ============================================================
  describe('US6 - Output format', () => {
    it('should output markdown format when requested', () => {
      const output = execFileSync('node', [SCRIPT, aggFixture, '--format', 'markdown'], { encoding: 'utf-8' });
      assert.ok(output.includes('MCP Aggregation Parse Results'), 'Should have markdown header');
      assert.ok(output.includes('Attack IPs'), 'Should have attack IPs section');
      assert.ok(output.includes('Compromised Hosts'), 'Should have compromised hosts section');
    });

    it('should write to --output file when specified', () => {
      const tmpOut = join(FIXTURE_DIR, 'tmp-output.json');
      try {
        execFileSync('node', [SCRIPT, aggFixture, '--format', 'json', '--output', tmpOut], { encoding: 'utf-8' });
        const content = fs.readFileSync(tmpOut, 'utf-8');
        const result = JSON.parse(content);
        assert.equal(result.stats.total_alerts, 3318);
      } finally {
        if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut);
      }
    });
  });

  // ============================================================
  // US7: attack_type encoding normalization (ISS-018)
  // ============================================================
  describe('US7 - attack_type normalization', () => {
    it('should normalize U+FFFD variant to correct character', async () => {
      const { normalizeAttackType } = await import('../../skills/secops-alert-analysis/scripts/reporting/parse-mcp.js');
      assert.equal(normalizeAttackType('暴力\ufffd解'), '暴力猜解');
      assert.equal(normalizeAttackType('\ufffd码执行'), '代码执行');
    });

    it('should pass through already-correct values', async () => {
      const { normalizeAttackType } = await import('../../skills/secops-alert-analysis/scripts/reporting/parse-mcp.js');
      assert.equal(normalizeAttackType('暴力猜解'), '暴力猜解');
      assert.equal(normalizeAttackType('代码执行'), '代码执行');
      assert.equal(normalizeAttackType('SQL注入'), 'SQL注入');
    });

    it('should warn on unknown variants and preserve original', async () => {
      const { normalizeAttackType } = await import('../../skills/secops-alert-analysis/scripts/reporting/parse-mcp.js');
      assert.equal(normalizeAttackType('未知\ufffd攻击'), '未知\ufffd攻击');
    });

    it('should merge duplicate attack_types after normalization', () => {
      const encodingFixture = join(FIXTURE_DIR, 'agg-response-mcp-encoding.json');
      const output = execFileSync('node', [SCRIPT, encodingFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      const brute = result.stats.attack_types.find(a => a.type === '暴力猜解');
      assert.ok(brute, 'Should have 暴力猜解');
      assert.equal(brute.count, 638, 'Should merge counts: 637 + 1');
      assert.equal(result.stats.attack_types.filter(a => a.type === '暴力猜解').length, 1, 'Should have exactly one entry');
    });

    it('should normalize ip_attack_types in attack_ips buckets', () => {
      const encodingFixture = join(FIXTURE_DIR, 'agg-response-mcp-encoding.json');
      const output = execFileSync('node', [SCRIPT, encodingFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      const ip = result.ips[0];
      const brute = ip.attack_types.find(a => a.type === '暴力猜解');
      assert.ok(brute, 'Should have 暴力猜解 (normalized from U+FFFD variant)');
      assert.equal(ip.attack_types.filter(a => a.type.includes('\ufffd')).length, 0, 'No U+FFFD variants should remain');
    });
  });

  // ============================================================
  // US8: MCP content wrapper format
  // ============================================================
  describe('US8 - MCP content wrapper format', () => {
    it('should parse {content: [{type:"text", text:"..."}]} format', () => {
      const wrapperFixture = join(FIXTURE_DIR, 'mcp-content-wrapper.json');
      const output = execFileSync('node', [SCRIPT, wrapperFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.total_alerts, 3318);
      assert.equal(result.ips.length, 3);
    });

    it('should produce same output as array format', () => {
      const wrapperFixture = join(FIXTURE_DIR, 'mcp-content-wrapper.json');
      const arrayFixture = join(FIXTURE_DIR, 'agg-response-mcp.json');
      const wrapperOutput = execFileSync('node', [SCRIPT, wrapperFixture, '--format', 'json'], { encoding: 'utf-8' });
      const arrayOutput = execFileSync('node', [SCRIPT, arrayFixture, '--format', 'json'], { encoding: 'utf-8' });
      const wrapperResult = JSON.parse(wrapperOutput);
      const arrayResult = JSON.parse(arrayOutput);
      assert.deepEqual(wrapperResult.stats, arrayResult.stats);
      assert.deepEqual(wrapperResult.ips, arrayResult.ips);
    });
  });

  // ============================================================
  // US9: Flat ES response (no MCP envelope)
  // ============================================================
  describe('US9 - Flat ES response', () => {
    it('should parse bare {took:..., aggregations:{...}} format', () => {
      const flatFixture = join(FIXTURE_DIR, 'flat-es-response.json');
      const output = execFileSync('node', [SCRIPT, flatFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.total_alerts, 3318);
      assert.equal(result.ips.length, 3);
    });

    it('should produce same output as array format', () => {
      const flatFixture = join(FIXTURE_DIR, 'flat-es-response.json');
      const arrayFixture = join(FIXTURE_DIR, 'agg-response-mcp.json');
      const flatOutput = execFileSync('node', [SCRIPT, flatFixture, '--format', 'json'], { encoding: 'utf-8' });
      const arrayOutput = execFileSync('node', [SCRIPT, arrayFixture, '--format', 'json'], { encoding: 'utf-8' });
      const flatResult = JSON.parse(flatOutput);
      const arrayResult = JSON.parse(arrayOutput);
      assert.deepEqual(flatResult.stats, arrayResult.stats);
    });
  });

  // ============================================================
  // US10: Internal query (--internal flag)
  // ============================================================
  describe('US10 - Internal query (--internal flag)', () => {
    const internalFixture = join(FIXTURE_DIR, 'internal-agg-response.json');

    it('should populate internal_alerts with total_alerts', () => {
      const output = execFileSync('node', [SCRIPT, internalFixture, '--internal', '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.internal_alerts, 150);
    });

    it('should populate lateral_alerts from lateral_movement.doc_count', () => {
      const output = execFileSync('node', [SCRIPT, internalFixture, '--internal', '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.lateral_alerts, 45);
    });

    it('should populate unique_internal_sources and unique_internal_targets', () => {
      const output = execFileSync('node', [SCRIPT, internalFixture, '--internal', '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.unique_internal_sources, 2);
      assert.equal(result.stats.unique_internal_targets, 2);
    });

    it('should populate host_states array', () => {
      const output = execFileSync('node', [SCRIPT, internalFixture, '--internal', '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.stats.host_states.length, 3);
      assert.equal(result.stats.host_states[0].type, '失陷');
      assert.equal(result.stats.host_states[0].count, 50);
    });

    it('should include lateral field with sources, targets, pairs, hourly_distribution, host_states', () => {
      const output = execFileSync('node', [SCRIPT, internalFixture, '--internal', '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.ok(result.lateral, 'Should have lateral field');
      assert.equal(result.lateral.sources.length, 2);
      assert.equal(result.lateral.targets.length, 2);
      assert.equal(result.lateral.pairs.length, 3);
      assert.equal(result.lateral.hourly_distribution.length, 3);
      assert.equal(result.lateral.host_states.length, 2);
    });

    it('should extract lateral pairs with source, target, count, attack_types, max_timestamp', () => {
      const output = execFileSync('node', [SCRIPT, internalFixture, '--internal', '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      const pair = result.lateral.pairs[0];
      assert.equal(pair.source, '192.0.2.12');
      assert.equal(pair.target, '192.0.2.32');
      assert.equal(pair.count, 20);
      assert.equal(pair.attack_types[0].type, 'APT事件');
      assert.equal(pair.max_timestamp, '2025-12-27T10:03:09.430Z');
    });

    it('should not include lateral field without --internal flag', () => {
      const output = execFileSync('node', [SCRIPT, internalFixture, '--format', 'json'], { encoding: 'utf-8' });
      const result = JSON.parse(output);
      assert.equal(result.lateral, undefined);
      assert.equal(result.stats.internal_alerts, null);
    });

    it('should output markdown with lateral sections when --internal', () => {
      const output = execFileSync('node', [SCRIPT, internalFixture, '--internal', '--format', 'markdown'], { encoding: 'utf-8' });
      assert.ok(output.includes('Internal Alert Parse Results'), 'Should have internal title');
      assert.ok(output.includes('Lateral Sources'), 'Should have lateral sources section');
      assert.ok(output.includes('Lateral Targets'), 'Should have lateral targets section');
      assert.ok(output.includes('Lateral Pairs'), 'Should have lateral pairs section');
    });
  });
});
