/**
 * Unified Configuration loader
 * @module config/loader
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { resolveEnvInObject, getEnv, loadEnv } from './env.js';
import logger from '../lib/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load .env file on module initialization (system env takes precedence)
loadEnv();

let config = null;

/**
 * Get the default config path
 * @returns {string} Default config file path
 */
function getDefaultConfigPath() {
    const projectRoot = resolve(__dirname, '../../');
    return join(projectRoot, 'config', 'config.json');
}

/**
 * Load and parse JSON config file
 * @param {string} configPath - Path to config file
 * @returns {Object} Parsed configuration
 */
function loadConfigFile(configPath) {
    try {
        const content = readFileSync(configPath, 'utf-8');
        return JSON.parse(content);
    } catch (error) {
        logger.error(`Failed to load config file: ${configPath}`, error.message);
        throw error;
    }
}

/**
 * Validate provider configuration
 * @param {Object} provider - Provider configuration
 * @throws {Error} If validation fails
 */
function validateProvider(provider) {
    if (!provider.id || typeof provider.id !== 'string') {
        throw new Error(`Provider missing valid id`);
    }
    if (!provider.name || typeof provider.name !== 'string') {
        throw new Error(`Provider ${provider.id} missing valid name`);
    }
    if (!provider.type || !['openai', 'anthropic', 'ollama', 'lmstudio'].includes(provider.type)) {
        throw new Error(`Provider ${provider.id} has invalid type: ${provider.type}`);
    }
    if (!provider.endpoint || typeof provider.endpoint !== 'string') {
        throw new Error(`Provider ${provider.id} missing valid endpoint`);
    }
    if (!provider.models || !Array.isArray(provider.models) || provider.models.length === 0) {
        throw new Error(`Provider ${provider.id} must have at least one model`);
    }
    if (!provider.defaultModel || typeof provider.defaultModel !== 'string') {
        throw new Error(`Provider ${provider.id} missing defaultModel`);
    }
    if (provider.priority === undefined || typeof provider.priority !== 'number') {
        throw new Error(`Provider ${provider.id} missing valid priority`);
    }
}

/**
 * Validate provider API key
 * @param {Object} provider - Provider configuration
 * @throws {Error} If validation fails
 */
function validateProviderApiKey(provider) {
    if (provider.type === 'ollama') {
        return;
    }

    if (!provider.apiKey) {
        throw new Error(`Provider ${provider.id} missing apiKey - set ${provider.type.toUpperCase()}_API_KEY in .env file`);
    }

    if (provider.apiKey.startsWith('${') && provider.apiKey.endsWith('}')) {
        const envVar = provider.apiKey.slice(2, -1);
        const value = process.env[envVar];
        if (!value) {
            throw new Error(`Provider ${provider.id} apiKey references ${envVar} which is not set - set ${envVar} in .env file`);
        }
    }
}

/**
 * Apply .env overrides to config
 * .env values take precedence over config.json values
 * @param {Object} config - Base configuration from config.json
 * @returns {Object} Configuration with .env overrides applied
 */
function applyEnvOverrides(config) {
    const overrides = {};

    // AI Provider overrides
    if (getEnv('AI_PROVIDER_ID')) overrides.id = getEnv('AI_PROVIDER_ID');
    if (getEnv('AI_PROVIDER_NAME')) overrides.name = getEnv('AI_PROVIDER_NAME');
    if (getEnv('AI_PROVIDER_TYPE')) overrides.type = getEnv('AI_PROVIDER_TYPE');
    if (getEnv('AI_ENDPOINT')) overrides.endpoint = getEnv('AI_ENDPOINT');
    if (getEnv('DEFAULT_MODEL')) {
        overrides.defaultModel = getEnv('DEFAULT_MODEL');
        overrides.models = [getEnv('DEFAULT_MODEL')];
    }
    if (getEnv('AI_TIMEOUT')) overrides.timeout = parseInt(getEnv('AI_TIMEOUT'), 10);

    // Apply provider overrides if any AI env vars are set
    if (config.providers && config.providers.length > 0 && Object.keys(overrides).length > 0) {
        const provider = config.providers[0];
        Object.assign(provider, overrides);

        // Apply retry overrides
        if (getEnv('AI_RETRY_MAX_ATTEMPTS')) {
            provider.retry = provider.retry || {};
            provider.retry.maxAttempts = parseInt(getEnv('AI_RETRY_MAX_ATTEMPTS'), 10);
        }
        if (getEnv('AI_RETRY_INITIAL_DELAY_MS')) {
            provider.retry = provider.retry || {};
            provider.retry.initialDelayMs = parseInt(getEnv('AI_RETRY_INITIAL_DELAY_MS'), 10);
        }

        // Log overrides
        logger.debug('Applied .env overrides to provider config:', overrides);
    }

    // Rate limit overrides
    if (getEnv('RATE_LIMIT_WINDOW_MS')) {
        config.rateLimit = config.rateLimit || {};
        config.rateLimit.windowMs = parseInt(getEnv('RATE_LIMIT_WINDOW_MS'), 10);
    }
    if (getEnv('RATE_LIMIT_MAX_REQUESTS')) {
        config.rateLimit = config.rateLimit || {};
        config.rateLimit.maxRequests = parseInt(getEnv('RATE_LIMIT_MAX_REQUESTS'), 10);
    }

    // Quota overrides
    if (getEnv('QUOTA_DAILY_LIMIT')) {
        config.quota = config.quota || {};
        config.quota.dailyLimit = parseInt(getEnv('QUOTA_DAILY_LIMIT'), 10);
    }

    // Server overrides
    if (getEnv('API_HOST')) {
        config.server = config.server || {};
        config.server.host = getEnv('API_HOST');
    }
    if (getEnv('API_PORT')) {
        config.server = config.server || {};
        config.server.port = parseInt(getEnv('API_PORT'), 10);
    }

    // Logging overrides
    if (getEnv('LOG_LEVEL')) {
        config.logging = config.logging || {};
        config.logging.level = getEnv('LOG_LEVEL');
    }

    // Data source overrides
    if (config.dataSources && config.dataSources.length > 0) {
        const ds = config.dataSources[0];
        if (getEnv('ES_HOST')) ds.es.host = getEnv('ES_HOST');
        if (getEnv('ES_PORT')) ds.es.port = parseInt(getEnv('ES_PORT'), 10);
        if (getEnv('ES_INDEX_PREFIX')) ds.es.indexPrefix = getEnv('ES_INDEX_PREFIX');
        if (getEnv('ES_USERNAME')) ds.auth.username = getEnv('ES_USERNAME');
    }

    return config;
}

/**
 * Load configuration from unified config.json
 * Priority: CLI args > env vars > .env file > config.json defaults
 * @param {string} [configPath] - Path to config file, defaults to config/config.json
 * @returns {Object} Loaded and validated configuration
 */
export function loadConfig(configPath = null) {
    if (config && !configPath) {
        return config;
    }

    // Determine config path
    let resolvedPath = configPath;
    if (!resolvedPath) {
        resolvedPath = getDefaultConfigPath();
    }

    // Check if file exists, provide helpful error
    if (!existsSync(resolvedPath)) {
        const examplePath = resolvedPath.replace('.json', '.example.json');
        if (existsSync(examplePath)) {
            throw new Error(
                `Config file not found: ${resolvedPath}\n` +
                `Please copy example config:\n` +
                `  cp config/config.example.json config/config.json`
            );
        }
        throw new Error(`Config file not found: ${resolvedPath}`);
    }

    logger.info(`Loading config from: ${resolvedPath}`);

    // Load and parse config
    let rawConfig;
    try {
        rawConfig = loadConfigFile(resolvedPath);
    } catch (error) {
        throw error;
    }

    // Resolve environment variables in config
    const resolvedConfig = resolveEnvInObject(rawConfig);

    // Validate providers
    if (resolvedConfig.providers && Array.isArray(resolvedConfig.providers)) {
        for (const provider of resolvedConfig.providers) {
            validateProvider(provider);
            validateProviderApiKey(provider);
        }

        // Sort providers by priority
        resolvedConfig.providers.sort((a, b) => a.priority - b.priority);
    }

    // Apply .env overrides (env vars take precedence over config.json)
    const configWithOverrides = applyEnvOverrides(resolvedConfig);

    // Build final config object with defaults
    config = {
        providers: configWithOverrides.providers || [],
        rateLimit: configWithOverrides.rateLimit || { windowMs: 60000, maxRequests: 60 },
        quota: configWithOverrides.quota || { dailyLimit: 10000 },
        server: configWithOverrides.server || { host: '0.0.0.0', port: 3000 },
        dataSources: configWithOverrides.dataSources || [],
        logging: configWithOverrides.logging || { level: 'INFO', file: 'output/ids-patrol.log' },
        output: configWithOverrides.output || { defaultFormat: 'md', outputDir: 'output', formats: ['md'] },
        analysis: configWithOverrides.analysis || {},
        retry: configWithOverrides.retry || { maxAttempts: 3, delayMs: 1000 }
    };

    logger.info(`Loaded ${config.providers.length} providers, dataSources: ${config.dataSources.length}`);
    return config;
}

/**
 * Get current configuration (must call loadConfig first)
 * @returns {Object} Current configuration
 */
export function getConfig() {
    if (!config) {
        throw new Error('Configuration not loaded. Call loadConfig() first.');
    }
    return config;
}

/**
 * Reload configuration
 * @param {string} [configPath] - Optional new config path
 * @returns {Object} Reloaded configuration
 */
export function reloadConfig(configPath = null) {
    config = null;
    return loadConfig(configPath);
}

/**
 * Get a specific provider by ID
 * @param {string} providerId - Provider ID
 * @returns {Object|undefined} Provider configuration
 */
export function getProvider(providerId) {
    const cfg = getConfig();
    return cfg.providers.find(p => p.id === providerId);
}

/**
 * Get all providers
 * @returns {Object[]} All provider configurations
 */
export function getAllProviders() {
    const cfg = getConfig();
    return [...cfg.providers];
}

/**
 * Find provider that supports a given model
 * @param {string} model - Model name
 * @returns {Object|undefined} Provider that supports the model
 */
export function findProviderByModel(model) {
    const cfg = getConfig();
    return cfg.providers.find(p => p.models.includes(model));
}

/**
 * Get the default provider
 * @returns {Object} Default provider (lowest priority)
 */
export function getDefaultProvider() {
    const cfg = getConfig();
    return cfg.providers[0];
}

/**
 * Get data source by name
 * @param {string} name - Data source name
 * @returns {Object|undefined} Data source configuration
 */
export function getDataSource(name = 'production') {
    const cfg = getConfig();
    return cfg.dataSources.find(ds => ds.name === name);
}

export default {
    loadConfig,
    getConfig,
    reloadConfig,
    getProvider,
    getAllProviders,
    findProviderByModel,
    getDefaultProvider,
    getDataSource
};