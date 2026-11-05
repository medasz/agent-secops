/**
 * Quota Management Middleware
 * @module middleware/quota
 */

import { getConfig } from '../config/loader.js';
import logger from '../lib/logger.js';

/**
 * In-memory quota tracker store
 */
class QuotaStore {
    constructor() {
        this.quotas = new Map();
    }

    /**
     * Get or create quota state for a provider
     * @param {string} providerId - Provider identifier
     * @returns {Object} Quota state
     */
    get(providerId) {
        if (!this.quotas.has(providerId)) {
            const config = getConfig();
            const dailyLimit = config.quota?.dailyLimit || 10000;

            this.quotas.set(providerId, {
                dailyLimit,
                dailyUsed: 0,
                lastReset: new Date().toDateString(),
                totalUsed: 0
            });
        }

        const state = this.quotas.get(providerId);

        // Reset daily if date changed
        const today = new Date().toDateString();
        if (state.lastReset !== today) {
            state.dailyUsed = 0;
            state.lastReset = today;
        }

        return state;
    }

    /**
     * Check if provider has remaining quota
     * @param {string} providerId - Provider identifier
     * @returns {Object} Check result
     */
    check(providerId) {
        const state = this.get(providerId);

        const remaining = Math.max(0, state.dailyLimit - state.dailyUsed);
        const resetDate = this.getNextResetDate();

        return {
            allowed: state.dailyUsed < state.dailyLimit,
            remaining,
            limit: state.dailyLimit,
            used: state.dailyUsed,
            resetDate
        };
    }

    /**
     * Increment usage for a provider
     * @param {string} providerId - Provider identifier
     * @param {number} tokens - Token count to add
     */
    increment(providerId, tokens = 1) {
        const state = this.get(providerId);
        state.dailyUsed += tokens;
        state.totalUsed += tokens;
    }

    /**
     * Get next reset date (midnight)
     * @returns {Date} Next reset date
     */
    getNextResetDate() {
        const now = new Date();
        const tomorrow = new Date(now);
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);
        return tomorrow;
    }

    /**
     * Reset quota for a provider
     * @param {string} providerId - Provider identifier
     */
    reset(providerId) {
        const state = this.get(providerId);
        state.dailyUsed = 0;
        state.lastReset = new Date().toDateString();
    }

    /**
     * Get all quota statuses
     * @returns {Array} All quota statuses
     */
    getAll() {
        const result = [];
        for (const [providerId, state] of this.quotas) {
            result.push({
                providerId,
                ...this.check(providerId)
            });
        }
        return result;
    }
}

// Singleton store
const store = new QuotaStore();

/**
 * Quota middleware factory
 * @param {Object} options - Middleware options
 * @param {string} [options.providerId] - Provider ID to track (defaults to active provider)
 * @returns {Function} Middleware function
 */
export function createQuotaMiddleware(options = {}) {
    return async (req, res, next) => {
        // Get provider from request or use default
        const providerId = options.providerId || 'default';

        const result = store.check(providerId);

        // Set quota headers
        res.setHeader('X-Quota-Limit', result.limit);
        res.setHeader('X-Quota-Remaining', result.remaining);

        if (!result.allowed) {
            logger.warn(`Quota exceeded for provider: ${providerId}`);

            // Import here to avoid circular dependency
            const { rateLimitHandler } = await import('../api/middleware/error.js');
            rateLimitHandler(res, `Daily quota exceeded. Reset at ${result.resetDate.toISOString()}`);
            return;
        }

        // Attach increment function to request for later use
        req.quotaStore = {
            increment: (tokens) => store.increment(providerId, tokens)
        };

        next();
    };
}

/**
 * Get quota status for a provider
 * @param {string} providerId - Provider identifier
 * @returns {Object} Quota status
 */
export function getQuotaStatus(providerId) {
    return store.check(providerId);
}

/**
 * Increment quota usage
 * @param {string} providerId - Provider identifier
 * @param {number} tokens - Token count
 */
export function incrementQuota(providerId, tokens) {
    store.increment(providerId, tokens);
}

/**
 * Reset quota for a provider
 * @param {string} providerId - Provider identifier
 */
export function resetQuota(providerId) {
    store.reset(providerId);
}

export default {
    createQuotaMiddleware,
    getQuotaStatus,
    incrementQuota,
    resetQuota,
    store
};