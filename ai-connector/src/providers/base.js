/**
 * Base AI Provider class
 * @module providers/base
 */

import logger from '../lib/logger.js';

/**
 * Abstract base class for AI providers
 */
export class AIProvider {
    /**
     * @param {Object} config - Provider configuration
     */
    constructor(config) {
        this.id = config.id;
        this.name = config.name;
        this.type = config.type;
        this.endpoint = config.endpoint;
        this.apiKey = config.apiKey;
        this.models = config.models;
        this.defaultModel = config.defaultModel;
        this.priority = config.priority;
        this.timeout = config.timeout || 30000;
        this.retry = config.retry || { maxAttempts: 3, initialDelayMs: 1000 };
        this.enabled = true;
    }

    /**
     * Check if provider supports a given model
     * @param {string} model - Model name
     * @returns {boolean} True if supported
     */
    supportsModel(model) {
        return this.models.includes(model);
    }

    /**
     * Get the default model for this provider
     * @returns {string} Default model name
     */
    getDefaultModel() {
        return this.defaultModel;
    }

    /**
     * Create chat completion request (to be implemented by subclasses)
     * @param {Object} params - Request parameters
     * @param {string} params.model - Model name
     * @param {Array} params.messages - Messages array
     * @param {Object} params.options - Additional options
     * @returns {Promise<Object>} Chat completion response
     */
    async chatComplete(params) {
        throw new Error('chatComplete must be implemented by subclass');
    }

    /**
     * List available models (to be implemented by subclasses)
     * @returns {Promise<Array>} List of available models
     */
    async listModels() {
        throw new Error('listModels must be implemented by subclass');
    }

    /**
     * Test provider connectivity
     * @returns {Promise<boolean>} True if provider is reachable
     */
    async testConnection() {
        try {
            await this.listModels();
            return true;
        } catch (error) {
            logger.warn(`Provider ${this.id} connection test failed:`, error.message);
            return false;
        }
    }

    /**
     * Execute with retry logic
     * @param {Function} fn - Function to execute
     * @returns {Promise<*>} Result of function
     */
    async withRetry(fn) {
        let lastError;
        const { maxAttempts, initialDelayMs } = this.retry;

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return await fn();
            } catch (error) {
                lastError = error;
                logger.warn(`Provider ${this.id} attempt ${attempt}/${maxAttempts} failed:`, error.message);

                if (attempt < maxAttempts) {
                    const delay = initialDelayMs * Math.pow(2, attempt - 1);
                    await this.sleep(delay);
                }
            }
        }

        throw lastError;
    }

    /**
     * Sleep for specified milliseconds
     * @param {number} ms - Milliseconds to sleep
     * @returns {Promise<void>}
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Enable this provider
     */
    enable() {
        this.enabled = true;
        logger.info(`Provider ${this.id} enabled`);
    }

    /**
     * Disable this provider
     */
    disable() {
        this.enabled = false;
        logger.info(`Provider ${this.id} disabled`);
    }

    /**
     * Check if provider is enabled
     * @returns {boolean} True if enabled
     */
    isEnabled() {
        return this.enabled;
    }
}

/**
 * Provider factory - create provider instance from config
 * @param {Object} config - Provider configuration
 * @returns {AIProvider} Provider instance
 */
export function createProvider(config) {
    switch (config.type) {
        case 'openai':
            return new OpenAIProvider(config);
        case 'anthropic':
            return new AnthropicProvider(config);
        case 'ollama':
            return new OllamaProvider(config);
        case 'lmstudio':
            return new LMStudioProvider(config);
        default:
            throw new Error(`Unknown provider type: ${config.type}`);
    }
}

// Placeholder imports - will be implemented in subsequent tasks
class OpenAIProvider extends AIProvider {
    async chatComplete(params) {
        throw new Error('Not implemented - see T012');
    }
    async listModels() {
        return this.models;
    }
}

class AnthropicProvider extends AIProvider {
    async chatComplete(params) {
        throw new Error('Not implemented - see T013');
    }
    async listModels() {
        return this.models;
    }
}

class OllamaProvider extends AIProvider {
    async chatComplete(params) {
        throw new Error('Not implemented - see T014');
    }
    async listModels() {
        return this.models;
    }
}

class LMStudioProvider extends AIProvider {
    async chatComplete(params) {
        throw new Error('Not implemented - see T014');
    }
    async listModels() {
        return this.models;
    }
}

export default AIProvider;