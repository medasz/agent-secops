import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { isFeatureEnabled, getEnv } from '../../skills/secops-alert-analysis/scripts/shared/env.js';

describe('isFeatureEnabled', () => {
  afterEach(() => {
    delete process.env.ENABLE_THREATBOOK;
    delete process.env.ENABLE_NONEXISTENT;
  });

  it('returns false when env var is not set (default)', () => {
    delete process.env.ENABLE_THREATBOOK;
    assert.equal(isFeatureEnabled('THREATBOOK'), false);
  });

  it('returns true when env var is "true"', () => {
    process.env.ENABLE_THREATBOOK = 'true';
    assert.equal(isFeatureEnabled('THREATBOOK'), true);
  });

  it('returns false when env var is "false"', () => {
    process.env.ENABLE_THREATBOOK = 'false';
    assert.equal(isFeatureEnabled('THREATBOOK'), false);
  });

  it('returns false for a feature that has no env var', () => {
    assert.equal(isFeatureEnabled('NONEXISTENT'), false);
  });

  it('is case-insensitive for feature name', () => {
    process.env.ENABLE_THREATBOOK = 'true';
    assert.equal(isFeatureEnabled('threatbook'), true);
    assert.equal(isFeatureEnabled('ThreatBook'), true);
  });

  it('returns false for empty string value', () => {
    process.env.ENABLE_THREATBOOK = '';
    assert.equal(isFeatureEnabled('THREATBOOK'), false);
  });

  it('returns false for non-"true" string values', () => {
    process.env.ENABLE_THREATBOOK = '1';
    assert.equal(isFeatureEnabled('THREATBOOK'), false);

    process.env.ENABLE_THREATBOOK = 'yes';
    assert.equal(isFeatureEnabled('THREATBOOK'), false);
  });
});
