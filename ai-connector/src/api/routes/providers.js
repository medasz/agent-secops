/**
 * Providers Routes - GET /v1/providers
 * @module api/routes/providers
 */

import { getConfig } from '../../config/loader.js';

/**
 * Handle GET /v1/providers request
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 */
export async function providersRoutes(req, res) {
    try {
        const config = getConfig();

        const providers = config.providers.map((provider, index) => ({
            id: provider.id,
            name: provider.name,
            type: provider.type,
            models: provider.models,
            defaultModel: provider.defaultModel,
            priority: provider.priority,
            status: index === 0 ? 'active' : 'backup',
            endpoint: provider.endpoint,
            timeout: provider.timeout || 30000
        }));

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            providers
        }));

    } catch (error) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            error: {
                message: error.message,
                type: 'server_error',
                rate_limit_error: 'internal_error'
            }
        }));
    }
}

export default providersRoutes;