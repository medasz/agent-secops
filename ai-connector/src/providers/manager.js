/**
 * Provider Manager - manages AI providers with failover
 * @module providers/manager
 */

import { getAllProviders } from '../config/loader.js';
import logger from '../lib/logger.js';
import OpenAIProvider from './openai.js';
import AnthropicProvider from './anthropic.js';
import OllamaProvider from './ollama.js';

/**
 * Provider type mapping
 */
const PROVIDER_CLASSES = {
    openai: OpenAIProvider,
    anthropic: AnthropicProvider,
    ollama: OllamaProvider
};

class ProviderManager {
    constructor() {
        this.providers = new Map();
        this.activeProvider = null;
        this.currentProviderIndex = 0;
    }

    /**
     * Initialize all providers from config
     */
    initialize() {
        const configs = getAllProviders();

        for (const config of configs) {
            const ProviderClass = PROVIDER_CLASSES[config.type];
            if (!ProviderClass) {
                logger.warn(`Unknown provider type: ${config.type}, skipping`);
                continue;
            }

            const provider = new ProviderClass(config);
            this.providers.set(config.id, provider);
            logger.info(`Initialized provider: ${config.id} (${config.type})`);
        }

        // Set first provider as active
        const sortedProviders = Array.from(this.providers.values())
            .sort((a, b) => a.priority - b.priority);

        if (sortedProviders.length > 0) {
            this.activeProvider = sortedProviders[0];
            this.currentProviderIndex = 0;
            logger.info(`Active provider: ${this.activeProvider.id}`);
        } else {
            throw new Error('No providers configured');
        }
    }

    /**
     * Get provider by ID
     * @param {string} id - Provider ID
     * @returns {Object|undefined} Provider instance
     */
    getProvider(id) {
        return this.providers.get(id);
    }

    /**
     * Get all providers sorted by priority
     * @returns {Array} Sorted providers
     */
    getAllProviders() {
        return Array.from(this.providers.values())
            .sort((a, b) => a.priority - b.priority);
    }

    /**
     * Find provider that supports a model
     * @param {string} model - Model name
     * @returns {Object|undefined} Provider or undefined
     */
    findProviderForModel(model) {
        for (const provider of this.getAllProviders()) {
            if (provider.supportsModel(model) && provider.isEnabled()) {
                return provider;
            }
        }
        return undefined;
    }

    /**
     * Get active provider
     * @returns {Object} Active provider
     */
    getActiveProvider() {
        return this.activeProvider;
    }

    /**
     * Set active provider
     * @param {string} providerId - Provider ID to set as active
     */
    setActiveProvider(providerId) {
        const provider = this.providers.get(providerId);
        if (!provider) {
            throw new Error(`Provider not found: ${providerId}`);
        }

        this.activeProvider = provider;
        const providers = this.getAllProviders();
        this.currentProviderIndex = providers.findIndex(p => p.id === providerId);
        logger.info(`Active provider changed to: ${providerId}`);
    }

    /**
     * Execute chat completion with automatic failover
     * @param {Object} params - Chat completion parameters
     * @returns {Promise<Object>} Chat completion response
     */
    async chatComplete(params) {
        const { model } = params;

        // Find provider for the model
        let provider = this.findProviderForModel(model);

        // If no specific provider found, try active provider
        if (!provider) {
            provider = this.activeProvider;
        }

        if (!provider) {
            throw new Error('No available provider');
        }

        // Try providers in priority order with failover
        const providers = this.getAllProviders();
        let lastError;

        for (let i = 0; i < providers.length; i++) {
            const p = providers[i];

            if (!p.isEnabled()) {
                continue;
            }

            // Skip if doesn't support the model (unless it's the active one for fallback)
            if (model && !p.supportsModel(model) && p.id !== this.activeProvider?.id) {
                continue;
            }

            try {
                logger.info(`Using provider: ${p.id} for model: ${model}`);
                this.activeProvider = p;
                this.currentProviderIndex = i;

                const response = await p.chatComplete(params);
                return response;
            } catch (error) {
                logger.warn(`Provider ${p.id} failed:`, error.message);
                lastError = error;

                // Disable failed provider
                if (this.shouldDisableProvider(error)) {
                    p.disable();
                }
            }
        }

        throw lastError || new Error('All providers failed');
    }

    /**
     * Determine if provider should be disabled based on error
     * @param {Error} error - Error object
     * @returns {boolean} True if should disable
     */
    shouldDisableProvider(error) {
        // Disable on authentication errors
        if (error.statusCode === 401 || error.statusCode === 403) {
            return true;
        }

        // Disable on repeated timeouts
        if (error.code === 'timeout') {
            return true;
        }

        return false;
    }

    /**
     * Re-enable a previously disabled provider
     * @param {string} providerId - Provider ID
     */
    enableProvider(providerId) {
        const provider = this.providers.get(providerId);
        if (provider) {
            provider.enable();
            logger.info(`Provider ${providerId} enabled`);
        }
    }

    /**
     * Test all providers
     * @returns {Promise<Object>} Test results
     */
    async testAllProviders() {
        const results = {};

        for (const [id, provider] of this.providers) {
            try {
                const connected = await provider.testConnection();
                results[id] = {
                    status: connected ? 'connected' : 'failed',
                    type: provider.type
                };
            } catch (error) {
                results[id] = {
                    status: 'error',
                    error: error.message,
                    type: provider.type
                };
            }
        }

        return results;
    }

    /**
     * Get provider status
     * @returns {Array} Provider status list
     */
    getProviderStatus() {
        return this.getAllProviders().map((provider, index) => ({
            id: provider.id,
            name: provider.name,
            type: provider.type,
            status: provider.isEnabled() ? (index === 0 ? 'active' : 'backup') : 'disabled',
            models: provider.models,
            priority: provider.priority
        }));
    }
}

// Singleton instance
let instance = null;

/**
 * Get provider manager instance
 * @returns {ProviderManager} Provider manager
 */
export function getProviderManager() {
    if (!instance) {
        instance = new ProviderManager();
    }
    return instance;
}

/**
 * Initialize and get provider manager
 * @returns {Promise<ProviderManager>} Initialized provider manager
 */
export async function initializeProviders() {
    const manager = getProviderManager();
    manager.initialize();
    return manager;
}

/**
 * Reset provider manager (for testing)
 */
export function resetProviderManager() {
    instance = null;
}

export default {
    getProviderManager,
    initializeProviders,
    resetProviderManager
};