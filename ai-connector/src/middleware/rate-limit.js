/**
 * Rate Limiting Middleware
 * @module middleware/rate-limit
 */

import { getConfig } from '../config/loader.js';
import logger from '../lib/logger.js';

/**
 * In-memory rate limit store
 */
class RateLimitStore {
    constructor() {
        this.clients = new Map();
    }

    /**
     * Get or create rate limit state for a client
     * @param {string} key - Client identifier
     * @returns {Object} Rate limit state
     */
    get(key) {
        if (!this.clients.has(key)) {
            const config = getConfig();
            const windowMs = config.rateLimit?.windowMs || 60000;
            const maxRequests = config.rateLimit?.maxRequests || 60;

            this.clients.set(key, {
                requests: 0,
                windowMs,
                maxRequests,
                resetTime: Date.now() + windowMs
            });
        }
        return this.clients.get(key);
    }

    /**
     * Check if client is within rate limit
     * @param {string} key - Client identifier
     * @returns {Object} Check result
     */
    check(key) {
        const state = this.get(key);
        const now = Date.now();

        // Reset if window expired
        if (now >= state.resetTime) {
            state.requests = 0;
            state.resetTime = now + state.windowMs;
        }

        const remaining = Math.max(0, state.maxRequests - state.requests);
        const resetSeconds = Math.ceil((state.resetTime - now) / 1000);

        return {
            allowed: state.requests < state.maxRequests,
            remaining,
            reset: state.resetTime,
            resetSeconds,
            limit: state.maxRequests
        };
    }

    /**
     * Increment request count for client
     * @param {string} key - Client identifier
     */
    increment(key) {
        const state = this.get(key);
        state.requests++;
    }

    /**
     * Reset rate limit for a client
     * @param {string} key - Client identifier
     */
    reset(key) {
        this.clients.delete(key);
    }

    /**
     * Clean up expired entries
     */
    cleanup() {
        const now = Date.now();
        for (const [key, state] of this.clients) {
            if (now > state.resetTime + state.windowMs) {
                this.clients.delete(key);
            }
        }
    }
}

// Singleton store
const store = new RateLimitStore();

// Cleanup every 5 minutes
setInterval(() => store.cleanup(), 5 * 60 * 1000);

/**
 * Extract client key from request
 * @param {Object} req - Request object
 * @returns {string} Client identifier
 */
function getClientKey(req) {
    // Use API key from auth header, or IP address
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return `api:${authHeader.slice(7, 15)}`; // Use first 8 chars of key
    }

    // Fall back to IP
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.socket?.remoteAddress
        || 'unknown';
    return `ip:${ip}`;
}

/**
 * Rate limiting middleware factory
 * @param {Object} options - Middleware options
 * @returns {Function} Middleware function
 */
export function createRateLimiter(options = {}) {
    return async (req, res, next) => {
        const key = getClientKey(req);
        const result = store.check(key);

        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', result.limit);
        res.setHeader('X-RateLimit-Remaining', result.remaining);
        res.setHeader('X-RateLimit-Reset', result.reset);

        if (!result.allowed) {
            logger.warn(`Rate limit exceeded for: ${key}`);

            // Import here to avoid circular dependency
            const { rateLimitHandler } = await import('../api/middleware/error.js');
            rateLimitHandler(res, `Rate limit exceeded. Try again in ${result.resetSeconds} seconds.`);
            return;
        }

        store.increment(key);
        next();
    };
}

/**
 * Get current rate limit status for a client
 * @param {Object} req - Request object
 * @returns {Object} Rate limit status
 */
export function getRateLimitStatus(req) {
    const key = getClientKey(req);
    return store.check(key);
}

/**
 * Reset rate limit for a client
 * @param {Object} req - Request object
 */
export function resetRateLimit(req) {
    const key = getClientKey(req);
    store.reset(key);
}

export default {
    createRateLimiter,
    getRateLimitStatus,
    resetRateLimit,
    store
};