import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { loadWhitelist, isExternal } from '../../skills/secops-alert-analysis/scripts/shared/whitelist.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const WHITELIST_PATH = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'references', 'ipWhite.md');

describe('whitelist module', () => {
  const entries = loadWhitelist(WHITELIST_PATH);

  describe('loadWhitelist', () => {
    it('should load entries from ipWhite.md', () => {
      assert.ok(entries.length > 0, `Expected entries, got ${entries.length}`);
      assert.ok(entries.length >= 10, `Expected at least 10 entries, got ${entries.length}`);
    });

    it('should handle empty/missing file gracefully', () => {
      const result = loadWhitelist('/nonexistent/path/ipWhite.md');
      assert.deepEqual(result, []);
    });

    it('should parse CIDR entries', () => {
      const cidr = entries.find(e => e.format === 'cidr');
      assert.ok(cidr, 'Should have at least one CIDR entry');
      assert.equal(cidr.format, 'cidr');
      assert.ok(cidr.maskBits >= 0 && cidr.maskBits <= 32);
    });

    it('should parse single IP entries', () => {
      const single = entries.find(e => e.format === 'single');
      assert.ok(single, 'Should have at least one single IP entry');
      assert.equal(single.format, 'single');
    });

    it('should parse short range entries', () => {
      const short = entries.find(e => e.format === 'range-short');
      assert.ok(short, 'Should have at least one short range entry');
      assert.equal(short.format, 'range-short');
    });

    it('should parse full range entries', () => {
      const full = entries.find(e => e.format === 'range-full');
      assert.ok(full, 'Should have at least one full range entry');
      assert.equal(full.format, 'range-full');
    });
  });

  describe('CIDR data integrity', () => {
    it('all CIDR entries in ipWhite.md must be network-aligned', () => {
      const cidrEntries = entries.filter(e => e.format === 'cidr');
      assert.ok(cidrEntries.length > 0, 'Expected at least one CIDR entry in ipWhite.md');
      for (const e of cidrEntries) {
        const network = (e.baseLong & e.maskLong) >>> 0;
        assert.equal(
          e.baseLong,
          network,
          `CIDR entry "${e.raw}" base IP is not aligned to its /${e.maskBits} network (network should be ${network})`
        );
      }
    });
  });

  describe('CIDR matching', () => {
    it('should whitelist 10.1.2.3 (RFC1918 10.0.0.0/8, stored as range-full)', () => {
      const result = isExternal('10.1.2.3', entries);
      assert.equal(result.external, false, '10.1.2.3 should be whitelisted (RFC1918 10.0.0.0/8)');
      assert.ok(result.matched);
      assert.equal(result.matched.raw, '10.0.0.0-10.255.255.255');
    });

    it('should whitelist 172.16.0.1 (RFC1918 172.16.0.0/12, stored as range-full)', () => {
      const result = isExternal('172.16.0.1', entries);
      assert.equal(result.external, false, '172.16.0.1 should be whitelisted (RFC1918 172.16.0.0/12)');
      assert.ok(result.matched);
      assert.equal(result.matched.raw, '172.16.0.0-172.31.255.255');
    });

    it('should whitelist 192.168.1.100 (RFC1918 192.168.0.0/16, stored as range-full)', () => {
      const result = isExternal('192.168.1.100', entries);
      assert.equal(result.external, false, '192.168.1.100 should be whitelisted (RFC1918 192.168.0.0/16)');
      assert.ok(result.matched);
      assert.equal(result.matched.raw, '192.168.0.0-192.168.255.255');
    });

    it('should match 198.51.100.50 against the CIDR entry 198.51.100.0/24', () => {
      const result = isExternal('198.51.100.50', entries);
      assert.equal(result.external, false, '198.51.100.50 should be whitelisted (in 198.51.100.0/24)');
      assert.ok(result.matched);
      assert.equal(result.matched.format, 'cidr');
      assert.equal(result.matched.raw, '198.51.100.0/24');
    });

    it('should match 203.0.113.150 against 203.0.113.128-203.0.113.191 (full range)', () => {
      const result = isExternal('203.0.113.150', entries);
      assert.equal(result.external, false, '203.0.113.150 should be whitelisted');
    });
  });

  describe('Short range matching', () => {
    it('should match 192.0.2.50 in 192.0.2.0-63', () => {
      const result = isExternal('192.0.2.50', entries);
      assert.equal(result.external, false, '192.0.2.50 should be whitelisted');
    });

    it('should reject 192.0.2.100 from 192.0.2.0-63', () => {
      const result = isExternal('192.0.2.100', entries);
      assert.equal(result.external, true, '192.0.2.100 should be external (outside 0-63 range)');
    });

    it('should match 203.0.113.30 in 203.0.113.0-63', () => {
      const result = isExternal('203.0.113.30', entries);
      assert.equal(result.external, false, '203.0.113.30 should be whitelisted');
    });

    it('should reject 203.0.113.100 from 203.0.113.0-63', () => {
      const result = isExternal('203.0.113.100', entries);
      assert.equal(result.external, true, '203.0.113.100 should be external');
    });
  });

  describe('Single IP matching', () => {
    it('should match 8.8.8.8 as whitelisted', () => {
      const result = isExternal('8.8.8.8', entries);
      assert.equal(result.external, false, '8.8.8.8 should be whitelisted');
    });

    it('should NOT match 222.90.96.237 as whitelisted', () => {
      const result = isExternal('222.90.96.237', entries);
      assert.equal(result.external, true, '222.90.96.237 should be external');
    });
  });

  describe('Edge cases', () => {
    it('should handle empty IP gracefully', () => {
      const result = isExternal('', entries);
      assert.equal(result.external, true);
    });

    it('should reject IPv6 addresses', () => {
      const result = isExternal('2001:db8::1', entries);
      assert.equal(result.external, true, 'IPv6 should be treated as external');
    });

    it('should handle null/undefined gracefully', () => {
      const result1 = isExternal(null, entries);
      assert.equal(result1.external, true);
      const result2 = isExternal(undefined, entries);
      assert.equal(result2.external, true);
    });

    it('should handle malformed IP gracefully', () => {
      const result = isExternal('not.an.ip', entries);
      assert.equal(result.external, true);
    });
  });
});
