/**
 * Anthropic Provider Implementation
 * @module providers/anthropic
 */

import { AIProvider } from './base.js';
import logger from '../lib/logger.js';

/**
 * Anthropic API client
 */
export class AnthropicProvider extends AIProvider {
    /**
     * @param {Object} config - Provider configuration
     */
    constructor(config) {
        super(config);
        this.apiVersion = '2023-06-01';
    }

    /**
     * Make HTTP request to Anthropic API
     * @param {string} method - HTTP method
     * @param {string} endpoint - API endpoint
     * @param {Object} [body] - Request body
     * @returns {Promise<Object>} Response JSON
     */
    async request(method, endpoint, body = null) {
        const url = `${this.endpoint}/${endpoint}`;

        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.apiKey,
                'anthropic-version': this.apiVersion
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
                            error.code = errorBody.error?.type || 'api_error';
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
     * Transform messages to Anthropic format
     * Anthropic uses a different message format
     * @param {Array} messages - Standard messages
     * @returns {Object} Anthropic-formatted request
     */
    transformMessages(messages) {
        // Find system message if present
        let systemMessage = null;
        const filteredMessages = [];

        for (const msg of messages) {
            if (msg.role === 'system') {
                systemMessage = msg.content;
            } else {
                filteredMessages.push({
                    role: msg.role === 'assistant' ? 'assistant' : 'user',
                    content: msg.content
                });
            }
        }

        return { systemMessage, messages: filteredMessages };
    }

    /**
     * Create chat completion
     * @param {Object} params - Completion parameters
     * @returns {Promise<Object>} Chat completion response
     */
    async chatComplete(params) {
        const { model, messages, temperature, max_tokens, stream, top_p, stop } = params;

        const { systemMessage, messages: anthropicMessages } = this.transformMessages(messages);

        const requestBody = {
            model: model,
            messages: anthropicMessages,
            max_tokens: max_tokens || 1024,
            stream: stream || false
        };

        if (temperature !== undefined) {
            requestBody.temperature = temperature;
        }

        if (top_p !== undefined) {
            requestBody.top_p = top_p;
        }

        if (stop) {
            requestBody.stop_sequences = Array.isArray(stop) ? stop : [stop];
        }

        if (systemMessage) {
            requestBody.system = systemMessage;
        }

        logger.debug(`Anthropic chat completion: ${model}`);

        const response = await this.request('POST', 'v1/messages', requestBody);

        // Transform Anthropic response to standard format
        return this.transformResponse(response, model);
    }

    /**
     * Transform Anthropic response to standard format
     * @param {Object} response - Anthropic response
     * @param {string} model - Model name
     * @returns {Object} Standardized response
     */
    transformResponse(response, model) {
        const content = response.content?.[0];
        const text = content?.type === 'text' ? content.text : '';

        return {
            id: `chatcmpl-${response.id}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: model,
            choices: [
                {
                    index: 0,
                    message: {
                        role: 'assistant',
                        content: text
                    },
                    finish_reason: response.stop_reason === 'end_turn' ? 'stop' : response.stop_reason
                }
            ],
            usage: {
                prompt_tokens: response.usage?.input_tokens || 0,
                completion_tokens: response.usage?.output_tokens || 0,
                total_tokens: (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0)
            }
        };
    }

    /**
     * List available models
     * Anthropic doesn't have a standard models endpoint, so return configured models
     * @returns {Promise<Array>} List of models
     */
    async listModels() {
        return this.models.map(id => ({
            id,
            created: 1687880000,
            owned_by: 'anthropic'
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
            logger.warn(`Anthropic provider ${this.id} test failed:`, error.message);
            return false;
        }
    }
}

export default AnthropicProvider;