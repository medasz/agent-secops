/**
 * Ollama Provider Implementation
 * @module providers/ollama
 */

import { AIProvider } from './base.js';
import logger from '../lib/logger.js';

/**
 * Ollama API client (local models)
 */
export class OllamaProvider extends AIProvider {
    /**
     * @param {Object} config - Provider configuration
     */
    constructor(config) {
        super(config);
    }

    /**
     * Build the API URL for a given endpoint
     * @param {string} endpoint - API endpoint
     * @returns {string} Full URL
     */
    buildUrl(endpoint) {
        return `${this.endpoint}/api/${endpoint}`;
    }

    /**
     * Make HTTP request to Ollama API
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
                'Content-Type': 'application/json'
            },
            timeout: this.timeout
        };

        // Add API key if configured
        if (this.apiKey) {
            options.headers['Authorization'] = `Bearer ${this.apiKey}`;
        }

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
                            const error = new Error(errorBody.error || `HTTP ${res.statusCode}`);
                            error.statusCode = res.statusCode;
                            error.code = 'api_error';
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
        const { model, messages, temperature, top_p, max_tokens, stream, stop } = params;

        const requestBody = {
            model: model,
            messages: messages,
            stream: stream || false,
            options: {}
        };

        if (temperature !== undefined) {
            requestBody.options.temperature = temperature;
        }

        if (top_p !== undefined) {
            requestBody.options.top_p = top_p;
        }

        if (max_tokens !== undefined) {
            requestBody.options.num_predict = max_tokens;
        }

        if (stop) {
            requestBody.options.stop = Array.isArray(stop) ? stop : [stop];
        }

        logger.debug(`Ollama chat completion: ${model}`);

        const response = await this.request('POST', 'chat', requestBody);

        // Transform Ollama response to standard format
        return this.transformResponse(response, model);
    }

    /**
     * Transform Ollama response to standard format
     * @param {Object} response - Ollama response
     * @param {string} model - Model name
     * @returns {Object} Standardized response
     */
    transformResponse(response, model) {
        const message = response.message || {};

        return {
            id: `chatcmpl-${generateId()}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: model,
            choices: [
                {
                    index: 0,
                    message: {
                        role: message.role || 'assistant',
                        content: message.content || ''
                    },
                    finish_reason: response.done ? 'stop' : null
                }
            ],
            usage: {
                prompt_tokens: response.prompt_eval_count || 0,
                completion_tokens: response.eval_count || 0,
                total_tokens: (response.prompt_eval_count || 0) + (response.eval_count || 0)
            }
        };
    }

    /**
     * List available models from Ollama
     * @returns {Promise<Array>} List of models
     */
    async listModels() {
        const response = await this.request('GET', 'tags');

        return (response.models || []).map(model => ({
            id: model.name,
            created: model.modified_at ? new Date(model.modified_at).getTime() / 1000 : 1687880000,
            owned_by: 'ollama',
            size: model.size
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
            logger.warn(`Ollama provider ${this.id} test failed:`, error.message);
            return false;
        }
    }
}

/**
 * Generate random ID
 * @returns {string} Random ID
 */
function generateId() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

export default OllamaProvider;