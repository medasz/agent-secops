/**
 * OpenAI Provider Implementation
 * @module providers/openai
 */

import { AIProvider } from './base.js';
import logger from '../lib/logger.js';

/**
 * OpenAI API client
 */
export class OpenAIProvider extends AIProvider {
    /**
     * @param {Object} config - Provider configuration
     */
    constructor(config) {
        super(config);
        this.apiVersion = 'v1';
    }

    /**
     * Build the API URL for a given endpoint
     * @param {string} endpoint - API endpoint
     * @returns {string} Full URL
     */
    buildUrl(endpoint) {
        return `${this.endpoint}/${this.apiVersion}/${endpoint}`;
    }

    /**
     * Make HTTP request to OpenAI API
     * @param {string} method - HTTP method
     * @param {string} endpoint - API endpoint
     * @param {Object} [body] - Request body
     * @returns {Promise<Object>} Response JSON
     */
    async request(method, endpoint, body = null) {
        const url = this.buildUrl(endpoint);

        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.apiKey}`
            },
            timeout: this.timeout
        };

        if (body) {
            options.body = JSON.stringify(body);
        }

        return this.withRetry(async () => {
            const response = await this.httpRequest(url, options);
            return response;
        });
    }

    /**
     * Make HTTP request with timeout
     * @param {string} url - Request URL
     * @param {Object} options - Request options
     * @returns {Promise<Object>} Response
     */
    httpRequest(url, options) {
        return new Promise((resolve, reject) => {
            const isHttps = url.startsWith('https');
            const httpModule = isHttps ? import('https') : import('http');

            httpModule.then(http => {
                const urlObj = new URL(url);
                const reqOptions = {
                    hostname: urlObj.hostname,
                    port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
                    path: urlObj.pathname + urlObj.search,
                    method: options.method,
                    headers: options.headers,
                    timeout: options.timeout
                };

                const req = http.request(reqOptions, (res) => {
                    const chunks = [];
                    res.on('data', chunk => chunks.push(chunk));
                    res.on('end', () => {
                        const body = Buffer.concat(chunks).toString();

                        if (res.statusCode >= 400) {
                            let errorBody;
                            try {
                                errorBody = JSON.parse(body);
                            } catch {
                                errorBody = { error: { message: body } };
                            }
                            const error = new Error(errorBody.error?.message || `HTTP ${res.statusCode}`);
                            error.statusCode = res.statusCode;
                            error.code = errorBody.error?.code || 'api_error';
                            reject(error);
                            return;
                        }

                        try {
                            resolve(JSON.parse(body));
                        } catch {
                            resolve(body);
                        }
                    });
                });

                req.on('error', reject);
                req.on('timeout', () => {
                    req.destroy();
                    const error = new Error('Request timeout');
                    error.code = 'timeout';
                    reject(error);
                });

                if (options.body) {
                    req.write(options.body);
                }
                req.end();
            }).catch(reject);
        });
    }

    /**
     * Create chat completion
     * @param {Object} params - Completion parameters
     * @returns {Promise<Object>} Chat completion response
     */
    async chatComplete(params) {
        const { model, messages, temperature, top_p, max_tokens, stream, n, stop } = params;

        const requestBody = {
            model: model,
            messages: messages,
            temperature: temperature,
            top_p: top_p,
            max_tokens: max_tokens,
            stream: stream || false,
            n: n || 1
        };

        if (stop) {
            requestBody.stop = stop;
        }

        logger.debug(`OpenAI chat completion: ${model}`);

        const response = await this.request('POST', 'chat/completions', requestBody);

        // Transform OpenAI response to standard format
        return this.transformResponse(response);
    }

    /**
     * Transform OpenAI response to standard format
     * @param {Object} response - OpenAI response
     * @returns {Object} Standardized response
     */
    transformResponse(response) {
        return {
            id: response.id,
            object: 'chat.completion',
            created: response.created,
            model: response.model,
            choices: response.choices.map(choice => ({
                index: choice.index,
                message: choice.message,
                finish_reason: choice.finish_reason
            })),
            usage: response.usage || {
                prompt_tokens: 0,
                completion_tokens: 0,
                total_tokens: 0
            }
        };
    }

    /**
     * List available models
     * @returns {Promise<Array>} List of models
     */
    async listModels() {
        const response = await this.request('GET', 'models');
        return response.data.map(model => ({
            id: model.id,
            created: model.created,
            owned_by: model.owned_by
        }));
    }

    /**
     * Test provider connectivity
     * @returns {Promise<boolean>} True if connected
     */
    async testConnection() {
        try {
            await this.listModels();
            return true;
        } catch (error) {
            logger.warn(`OpenAI provider ${this.id} test failed:`, error.message);
            return false;
        }
    }
}

export default OpenAIProvider;