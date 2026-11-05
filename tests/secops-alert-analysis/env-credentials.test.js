import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCRIPTS_DIR = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'scripts');
const POST_TO_PORTAL = join(SCRIPTS_DIR, 'portal', 'post.js');

describe('.env credentials migration', () => {
  describe('portal/post.js should not contain hardcoded secrets', () => {
    it('should not contain JWT token string literals (50+ chars per segment)', () => {
      const content = fs.readFileSync(POST_TO_PORTAL, 'utf-8');
      // JWT pattern: three base64 segments separated by dots, each 50+ chars
      const jwtPattern = /"[A-Za-z0-9+/_=-]{50,}\.[A-Za-z0-9+/_=-]{50,}\.[A-Za-z0-9+/_=-]{50,}"/;
      assert.equal(jwtPattern.test(content), false,
        'portal/post.js should not contain hardcoded JWT token');
    });

    it('should not use const TOKEN = pattern', () => {
      const content = fs.readFileSync(POST_TO_PORTAL, 'utf-8');
      // Check for hardcoded token assignment
      assert.equal(
        /const\s+TOKEN\s*=/.test(content),
        false,
        'portal/post.js should not use const TOKEN = for hardcoded credentials'
      );
    });

    it('should reference portal config from shared/env.js', () => {
      const content = fs.readFileSync(POST_TO_PORTAL, 'utf-8');
      const hasPortalConfig = content.includes('getPortalConfig') || content.includes('PORTAL_TOKEN') || content.includes('PORTAL_JWT');
      assert.ok(hasPortalConfig,
        'portal/post.js should import getPortalConfig or reference PORTAL_TOKEN/PORTAL_JWT from shared/env.js');
    });

    it('should not have hardcoded groupId hardcoded as a numeric string', () => {
      const content = fs.readFileSync(POST_TO_PORTAL, 'utf-8');
      // After refactoring, groupId should come from env var PORTAL_GROUP_ID
      const hardcodedGroupPattern = /groupId:\s*'(70011431|70011)'/;
      assert.equal(hardcodedGroupPattern.test(content), false,
        'portal/post.js should use PORTAL_GROUP_ID env var instead of hardcoded groupId');
    });
  });

  describe('extract.js fallback defaults should be empty or safe', () => {
    it('should not have hardcoded ES_PASSWORD fallback', () => {
      const scriptPath = join(SCRIPTS_DIR, 'es-tool', 'extract.js');
      const content = fs.readFileSync(scriptPath, 'utf-8');
      // The line: let ES_PASSWORD = getEnv('ES_PASSWORD', '') — empty string fallback is OK
      // But anything like getEnv('ES_PASSWORD', 'actual_secret') is bad
      const passwordLines = content.split('\n').filter(l => l.includes('ES_PASSWORD') && l.includes('getEnv'));
      for (const line of passwordLines) {
        const fallbackMatch = line.match(/getEnv\([^,]+,\s*'([^']+)'\)/);
        if (fallbackMatch) {
          const fallback = fallbackMatch[1];
          assert.equal(fallback, '',
            'ES_PASSWORD fallback should be empty string, not a hardcoded secret: ' + fallback);
        }
      }
    });
  });
});
