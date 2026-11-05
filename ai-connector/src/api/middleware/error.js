/**
 * Error handling middleware
 * @module api/middleware/error
 */

import logger from '../../lib/logger.js';

/**
 * Create API error response in OpenAI format
 * @param {string} message - Error message
 * @param {string} type - Error type
 * @param {string} code - Error code
 * @param {string} [param] - Parameter that caused error
 * @returns {Object} Error response object
 */
export function createErrorResponse(message, type, code, param = null) {
    const error = { message, type, code };
    if (param) {
        error.param = param;
    }
    return { error };
}

/**
 * Not Found handler (404)
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 */
export function notFoundHandler(req, res) {
    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(createErrorResponse(
        'Not found',
        'invalid_request_error',
        'not_found'
    )));
}

/**
 * Method Not Allowed handler (405)
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 */
export function methodNotAllowedHandler(req, res) {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Allow', 'GET, POST');
    res.end(JSON.stringify(createErrorResponse(
        'Method not allowed',
        'invalid_request_error',
        'method_not_allowed'
    )));
}

/**
 * Bad Request handler (400)
 * @param {Object} res - Response object
 * @param {string} message - Error message
 * @param {string} [param] - Parameter that caused error
 */
export function badRequestHandler(res, message, param = null) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(createErrorResponse(
        message,
        'invalid_request_error',
        'invalid_parameters',
        param
    )));
}

/**
 * Unauthorized handler (401)
 * @param {Object} res - Response object
 * @param {string} [message] - Error message
 */
export function unauthorizedHandler(res, message = 'Invalid API key') {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(createErrorResponse(
        message,
        'authentication_error',
        'invalid_api_key'
    )));
}

/**
 * Forbidden handler (403)
 * @param {Object} res - Response object
 * @param {string} [message] - Error message
 */
export function forbiddenHandler(res, message = 'Access forbidden') {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(createErrorResponse(
        message,
        'authentication_error',
        'permission_denied'
    )));
}

/**
 * Rate Limit handler (429)
 * @param {Object} res - Response object
 * @param {string} [message] - Error message
 */
export function rateLimitHandler(res, message = 'Rate limit exceeded') {
    res.statusCode = 429;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Retry-After', '60');
    res.end(JSON.stringify(createErrorResponse(
        message,
        'rate_limit_error',
        'rate_limit_exceeded'
    )));
}

/**
 * Internal Server Error handler (500)
 * @param {Object} res - Response object
 * @param {Error} [error] - Error object
 */
export function internalErrorHandler(res, error = null) {
    logger.error('Server error:', error?.message || 'Unknown error');
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(createErrorResponse(
        'Internal server error',
        'server_error',
        'internal_error'
    )));
}

/**
 * Service Unavailable handler (503)
 * @param {Object} res - Response object
 * @param {string} [message] - Error message
 */
export function serviceUnavailableHandler(res, message = 'Service temporarily unavailable') {
    res.statusCode = 503;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(createErrorResponse(
        message,
        'server_error',
        'service_unavailable'
    )));
}

/**
 * Central error handling middleware
 * @param {Error} error - Error object
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {Function} next - Next middleware function
 */
export function errorMiddleware(error, req, res, next) {
    logger.error('Request error:', error.message);

    // Handle specific error types
    if (error.name === 'ValidationError') {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(createErrorResponse(
            error.message,
            'invalid_request_error',
            'validation_error'
        )));
        return;
    }

    if (error.statusCode === 401 || error.code === 'invalid_api_key') {
        unauthorizedHandler(res, error.message);
        return;
    }

    if (error.statusCode === 429 || error.code === 'rate_limit_exceeded') {
        rateLimitHandler(res, error.message);
        return;
    }

    // Default to 500
    internalErrorHandler(res, error);
}

export default {
    createErrorResponse,
    notFoundHandler,
    methodNotAllowedHandler,
    badRequestHandler,
    unauthorizedHandler,
    forbiddenHandler,
    rateLimitHandler,
    internalErrorHandler,
    serviceUnavailableHandler,
    errorMiddleware
};