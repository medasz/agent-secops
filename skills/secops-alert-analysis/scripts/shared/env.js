/**
 * Environment variable utility
 * @module config/env
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
let envLoaded = false;

loadEnv();

/**
 * Parse .env file content
 * @param {string} content - Raw .env file content
 * @returns {Object} Parsed key-value pairs
 */
function parseEnvContent(content) {
    const result = {};
    const lines = content.split(/\r?\n/);

    for (const line of lines) {
        // Skip empty lines and comments
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) {
            continue;
        }

        // Find the first = sign
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex === -1) {
            continue;
        }

        const key = trimmed.slice(0, eqIndex).trim();
        let value = trimmed.slice(eqIndex + 1);

        // Handle inline comments and quotes (strip " #..." from unquoted values before trim)
        const trimmedValue = value.trim();
        if (trimmedValue.startsWith('"') || trimmedValue.startsWith("'")) {
            const quote = trimmedValue[0];
            const endQuoteIdx = trimmedValue.indexOf(quote, 1);
            if (endQuoteIdx !== -1) {
                value = trimmedValue.slice(1, endQuoteIdx);
            } else if (trimmedValue.endsWith(quote)) {
                value = trimmedValue.slice(1, -1);
            } else {
                value = trimmedValue;
            }
        } else {
            const commentIdx = value.indexOf(' #');
            if (commentIdx !== -1) {
                value = value.slice(0, commentIdx);
            }
            value = value.trim();
        }

        if (key) {
            result[key] = value;
        }
    }

    return result;
}

/**
 * Load environment variables from .env file
 * Only sets variables that are not already in process.env (system env takes precedence)
 * @param {string} [envPath] - Path to .env file, defaults to project root
 * @returns {Object} Loaded environment variables
 */
export function loadEnv(envPath = null) {
    // Always reload if a specific path is provided
    if (envLoaded && !envPath) {
        return {};
    }

    // Determine .env file path
    let filePath = envPath;
    if (!filePath) {
        // Default to scripts/.env (this module is in shared/, go up 1 to scripts/)
        const scriptsDir = resolve(__dirname, '../');
        filePath = resolve(scriptsDir, '.env');
    }

    // Check if file exists
    if (!existsSync(filePath)) {
        return {};
    }

    try {
        const content = readFileSync(filePath, 'utf-8');
        const parsed = parseEnvContent(content);

        // Only set variables that don't already exist (system env takes precedence)
        let loaded = {};
        for (const [key, value] of Object.entries(parsed)) {
            if (!process.env[key]) {
                process.env[key] = value;
                loaded[key] = value;
            }
        }

        envLoaded = true;
        return loaded;
    } catch (error) {
        console.warn(`Failed to load .env file from ${filePath}: ${error.message}`);
        return {};
    }
}

/**
 * Get environment variable with optional default
 * @param {string} name - Environment variable name
 * @param {*} defaultValue - Default value if not set
 * @returns {string|*} Environment variable value or default
 */
export function getEnv(name, defaultValue = undefined) {
    return process.env[name] ?? defaultValue;
}

/**
 * Get ES connection config from environment
 * @returns {{host: string, port: number, username: string, password: string, indexPrefix: string}}
 */
export function getEsConfig() {
    return {
        host:        getEnv('ES_HOST', '203.0.113.10'),
        port:        parseInt(getEnv('ES_PORT', '9200'), 10),
        username:    getEnv('ES_USERNAME', 'sec_read'),
        password:    getEnv('ES_PASSWORD', ''),
        indexPrefix: getEnv('ES_INDEX_PREFIX', 'logfmt_746_'),
    };
}

/**
 * Get Portal config from environment
 * @returns {Object} Portal configuration
 */
export function getPortalConfig() {
    return {
        enabled:        isFeatureEnabled('POST'),
        tokenAppId:     getEnv('PORTAL_TOKEN_APPID', ''),
        tokenSecret:    getEnv('PORTAL_TOKEN_SECRET', ''),
        tokenGrantType: getEnv('PORTAL_TOKEN_GRANT_TYPE', 'sys_credential'),
        tokenUrl:       getEnv('PORTAL_TOKEN_URL', 'https://portal.example.com/oncon-service/token'),
        baseUrl:        getEnv('PORTAL_BASE_URL', 'portal.example.com'),
        apiPath:        getEnv('PORTAL_API_PATH', '/oncon-service/sys_credential/save_topic_info/v1.0'),
        groupId:        getEnv('PORTAL_GROUP_ID', ''),
        typeId:         getEnv('PORTAL_TYPE_ID', ''),
        empId:          getEnv('PORTAL_EMP_ID', ''),
        templateId:     getEnv('PORTAL_TEMPLATE_ID', '1'),
        viewRight:      getEnv('PORTAL_VIEW_RIGHT', '2'),
        replyRight:     getEnv('PORTAL_REPLY_RIGHT', '1'),
        isGmVisible:    getEnv('PORTAL_IS_GM_VISIBLE', 'false'),
        viewPriv:       getEnv('PORTAL_VIEW_PRIV', ''),
        editPriv:       getEnv('PORTAL_EDIT_PRIV', ''),
    };
}

/**
 * Get ThreatBook config from environment
 * @returns {Object} ThreatBook configuration
 */
export function getThreatBookConfig() {
    return {
        enabled:      isFeatureEnabled('THREATBOOK'),
        apiKey:       getEnv('THREATBOOK_API_KEY', ''),
        baseUrl:      getEnv('THREATBOOK_BASE_URL', 'https://api.threatbook.cn/v3'),
        lang:         getEnv('THREATBOOK_LANG', 'zh'),
        cachePath:    getEnv('THREATBOOK_CACHE_PATH', 'cache/threatbook.sqlite'),
        cacheTtl:     parseInt(getEnv('THREATBOOK_CACHE_TTL', '86400'), 10),
        rateLimit:    parseInt(getEnv('THREATBOOK_RATE_LIMIT', '10'), 10),
        timeout:      parseInt(getEnv('THREATBOOK_TIMEOUT', '10000'), 10),
        dailyQuota:   parseInt(getEnv('THREATBOOK_DAILY_QUOTA', '150'), 10),
        batchSize:    parseInt(getEnv('THREATBOOK_BATCH_SIZE', '100'), 10),
        boundIp:      getEnv('THREATBOOK_BOUND_IP', ''),
        probeIp:      getEnv('THREATBOOK_PROBE_IP', ''),
        confirmLevel: getEnv('THREATBOOK_CONFIRM_LEVEL', ''),
        labelMap:     getEnv('THREATBOOK_LABEL_MAP', ''),
    };
}

/**
 * Get Proxy config from environment
 * @returns {{enabled: boolean, host: string, port: number, tls: boolean}}
 */
export function getProxyConfig() {
    return {
        enabled: isFeatureEnabled('PROXY'),
        host:    getEnv('PROXY_HOST', '127.0.0.1'),
        port:    parseInt(getEnv('PROXY_PORT', '443'), 10),
        tls:     getEnv('PROXY_TLS', 'true') === 'true',
    };
}

/**
 * Get Log config from environment
 * @returns {{level: string}}
 */
export function getLogConfig() {
    return {
        level: getEnv('LOG_LEVEL', 'info'),
    };
}

/**
 * Check if a feature is enabled via ENABLE_{NAME} env var
 * @param {string} featureName - Feature name (e.g. 'THREATBOOK')
 * @returns {boolean} true if ENABLE_{featureName} === 'true'
 */
export function isFeatureEnabled(featureName) {
    const key = `ENABLE_${featureName.toUpperCase()}`;
    return getEnv(key) === 'true';
}

export default {
    loadEnv,
    getEnv,
    isFeatureEnabled,
    getEsConfig,
    getPortalConfig,
    getThreatBookConfig,
    getProxyConfig,
    getLogConfig,
};