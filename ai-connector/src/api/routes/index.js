/**
 * API Routes
 * @module api/routes
 */

import { chatRoutes } from './chat.js';
import { modelsRoutes } from './models.js';
import { providersRoutes } from './providers.js';

/**
 * Route definitions for the API
 */
export const routes = [
    // /v1/chat/completions
    {
        method: 'POST',
        path: '/v1/chat/completions',
        handler: chatRoutes
    },
    // /v1/models
    {
        method: 'GET',
        path: '/v1/models',
        handler: modelsRoutes
    },
    // /v1/providers
    {
        method: 'GET',
        path: '/v1/providers',
        handler: providersRoutes
    },
    // Health check
    {
        method: 'GET',
        path: '/health',
        handler: (req, res) => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ status: 'ok', timestamp: Date.now() }));
        }
    }
];

/**
 * Match request to route
 * @param {string} method - HTTP method
 * @param {string} pathname - Request path
 * @returns {Object|null} Matched route or null
 */
export function matchRoute(method, pathname) {
    for (const route of routes) {
        if (route.method === method && route.path === pathname) {
            return route;
        }
    }
    return null;
}

export default {
    routes,
    matchRoute
};