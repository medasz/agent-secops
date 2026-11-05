/**
 * Logging utility for IDS-Patrol API
 * @module lib/logger
 */

const LOG_LEVELS = {
    error: 0,
    warn: 1,
    info: 2,
    debug: 3
};

class Logger {
    constructor(options = {}) {
        this.level = options.level || 'info';
        this.prefix = options.prefix || '';
        this.timestamp = options.timestamp !== false;
    }

    _log(level, ...args) {
        if (LOG_LEVELS[level] > LOG_LEVELS[this.level]) {
            return;
        }

        const parts = [];
        if (this.timestamp) {
            parts.push(new Date().toISOString());
        }
        parts.push(`[${level.toUpperCase()}]`);
        if (this.prefix) {
            parts.push(`[${this.prefix}]`);
        }
        parts.push(...args);

        const message = parts.join(' ');
        console[level === 'warn' ? 'warn' : 'log'](message);
    }

    error(...args) {
        this._log('error', ...args);
    }

    warn(...args) {
        this._log('warn', ...args);
    }

    info(...args) {
        this._log('info', ...args);
    }

    debug(...args) {
        this._log('debug', ...args);
    }

    /**
     * Set log level dynamically
     * @param {string} level - New log level
     */
    setLevel(level) {
        if (LOG_LEVELS.hasOwnProperty(level)) {
            this.level = level;
        }
    }
}

let defaultLogger = null;

/**
 * Create a logger instance
 * @param {Object} options - Logger options
 * @param {string} [options.level='info'] - Log level
 * @param {string} [options.prefix=''] - Log prefix
 * @param {boolean} [options.timestamp=true] - Include timestamp
 * @returns {Logger} Logger instance
 */
export function createLogger(options = {}) {
    return new Logger(options);
}

/**
 * Get or create default logger instance
 * @returns {Logger} Default logger
 */
export function getLogger() {
    if (!defaultLogger) {
        defaultLogger = new Logger({
            level: process.env.LOG_LEVEL || 'info',
            prefix: 'ids-patrol'
        });
    }
    return defaultLogger;
}

/**
 * Default logger instance
 */
export default createLogger({
    level: process.env.LOG_LEVEL || 'info',
    prefix: 'ids-patrol'
});