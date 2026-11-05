/**
 * HTTP Server - OpenAI Compatible API
 * @module api/server
 */

import { createServer } from 'http';
import { parse } from 'url';
import { loadConfig, getConfig } from '../config/loader.js';
import { getEnv } from '../config/env.js';
import { initializeProviders } from '../providers/manager.js';
import logger from '../lib/logger.js';
import { routes, matchRoute } from './routes/index.js';
import * as error from './middleware/error.js';
import { createRateLimiter } from '../middleware/rate-limit.js';

/**
 * Parse JSON body from request
 * @param {Object} req - Request object
 * @returns {Promise<Object>} Parsed body
 */
async function parseBody(req) {
    const chunks = [];
    for await (const chunk of req) {
        chunks.push(chunk);
    }
    if (chunks.length === 0) {
        return {};
    }
    return JSON.parse(Buffer.concat(chunks).toString());
}

/**
 * Handle incoming HTTP request
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 */
async function handleRequest(req, res) {
    const parsedUrl = parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const method = req.method;

    logger.debug(`${method} ${pathname}`);

    // Match route
    const route = matchRoute(method, pathname);

    if (!route) {
        error.notFoundHandler(req, res);
        return;
    }

    // Attach parsed body to request for route handlers
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
        try {
            req.body = await parseBody(req);
        } catch (err) {
            error.badRequestHandler(res, 'Invalid JSON body');
            return;
        }
    }

    // Call route handler
    try {
        await route.handler(req, res);
    } catch (err) {
        logger.error('Route handler error:', err.message);
        error.internalErrorHandler(res, err);
    }
}

/**
 * Create and start the HTTP server
 * @param {Object} options - Server options
 * @param {string} [options.host='0.0.0.0'] - Server host
 * @param {number} [options.port=3000] - Server port
 * @param {string} [options.configPath] - Path to config file
 * @returns {Object} Server instance
 */
export function createApiServer(options = {}) {
    // Load configuration
    if (options.configPath) {
        loadConfig(options.configPath);
    } else {
        loadConfig();
    }

    // Initialize providers
    initializeProviders();

    const config = getConfig();

    // Priority: CLI args > environment variables > config defaults
    const host = options.host || getEnv('API_HOST', config.server.host);
    const port = options.port || parseInt(getEnv('API_PORT', config.server.port), 10);

    // Note: LOG_LEVEL is read from environment at logger module load time

    // Create rate limiter
    const rateLimiter = createRateLimiter();

    const server = createServer(async (req, res) => {
        // Apply rate limiting
        await new Promise((resolve) => {
            rateLimiter(req, res, resolve);
        });

        // Check if rate limit blocked the request
        if (res.headersSent && res.statusCode === 429) {
            return;
        }

        await handleRequest(req, res);
    });

    // Graceful shutdown
    const shutdown = () => {
        logger.info('Shutting down server...');
        server.close(() => {
            logger.info('Server closed');
            process.exit(0);
        });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);

    server.listen(port, host, () => {
        logger.info(`API Server running at http://${host}:${port}`);
        logger.info(`Available endpoints:`);
        logger.info(`  POST /v1/chat/completions`);
        logger.info(`  GET  /v1/models`);
        logger.info(`  GET  /v1/providers`);
        logger.info(`  GET  /health`);
    });

    return server;
}

/**
 * Start server from command line
 */
function main() {
    const args = process.argv.slice(2);
    let configPath = null;
    let port = null;
    let host = null;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--config' && args[i + 1]) {
            configPath = args[i + 1];
            i++;
        } else if (args[i] === '--port' && args[i + 1]) {
            port = parseInt(args[i + 1], 10);
            i++;
        } else if (args[i] === '--host' && args[i + 1]) {
            host = args[i + 1];
            i++;
        } else if (args[i] === '--help') {
            console.log(`
Usage: node server.js [options]

Options:
  --config <path>  Path to providers config file
  --port <port>    Server port (default: 3000)
  --host <host>    Server host (default: 0.0.0.0)
  --help           Show this help message
            `);
            process.exit(0);
        }
    }

    createApiServer({ configPath, port, host });
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}

export default createApiServer;