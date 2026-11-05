/**
 * Models Routes - GET /v1/models
 * @module api/routes/models
 */

import { getConfig } from '../../config/loader.js';

/**
 * Handle GET /v1/models request
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 */
export async function modelsRoutes(req, res) {
    try {
        const config = getConfig();

        const models = [];
        for (const provider of config.providers) {
            for (const model of provider.models) {
                models.push({
                    id: model,
                    object: 'model',
                    created: 1687880000, // Approximate creation time
                    owned_by: provider.id,
                    provider: provider.type
                });
            }
        }

        // Remove duplicates
        const uniqueModels = [];
        const seen = new Set();
        for (const model of models) {
            if (!seen.has(model.id)) {
                seen.add(model.id);
                uniqueModels.push(model);
            }
        }

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            object: 'list',
            data: uniqueModels
        }));

    } catch (error) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            error: {
                message: error.message,
                type: 'server_error',
                code: 'internal_error'
            }
        }));
    }
}

export default modelsRoutes;