/**
 * Environment variable utility
 * @module config/env
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const envCache = new Map();
let envLoaded = false;

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
        let value = trimmed.slice(eqIndex + 1).trim();

        // Remove surrounding quotes if present
        if ((value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
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
        // Default to ids-patrol/.env (config is in src/config/, go up 2 levels to ids-patrol/)
        const projectRoot = resolve(__dirname, '../../');
        filePath = resolve(projectRoot, '.env');
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
    if (envCache.has(name)) {
        return envCache.get(name);
    }

    const value = process.env[name] ?? defaultValue;
    envCache.set(name, value);
    return value;
}

/**
 * Resolve environment variable placeholders in a string
 * Supports ${VAR_NAME} and $VAR_NAME syntax
 * @param {string} value - String with potential env var placeholders
 * @returns {string} Resolved string
 */
export function resolveEnvVars(value) {
    if (typeof value !== 'string') {
        return value;
    }

    return value.replace(/\$\{(\w+)\}|\$(\w+)/g, (match, braceName, dollarName) => {
        const varName = braceName || dollarName;
        return getEnv(varName, match);
    });
}

/**
 * Resolve environment variables in an object
 * @param {Object} obj - Object with potential env var values
 * @returns {Object} Object with resolved values
 */
export function resolveEnvInObject(obj) {
    if (obj === null || obj === undefined) {
        return obj;
    }

    if (typeof obj === 'string') {
        return resolveEnvVars(obj);
    }

    if (Array.isArray(obj)) {
        return obj.map(item => resolveEnvInObject(item));
    }

    if (typeof obj === 'object') {
        const resolved = {};
        for (const [key, value] of Object.entries(obj)) {
            resolved[key] = resolveEnvInObject(value);
        }
        return resolved;
    }

    return obj;
}

/**
 * Clear environment variable cache
 */
export function clearEnvCache() {
    envCache.clear();
}

export default {
    getEnv,
    resolveEnvVars,
    resolveEnvInObject,
    clearEnvCache,
    loadEnv
};