/**
 * Chat Routes - /v1/chat/completions
 * @module api/routes/chat
 */

import { badRequestHandler, internalErrorHandler, rateLimitHandler } from '../middleware/error.js';
import logger from '../../lib/logger.js';
import { getProviderManager } from '../../providers/manager.js';
import { getConfig } from '../../config/loader.js';

/**
 * Handle chat completion request
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 */
export async function chatRoutes(req, res) {
    try {
        // Parse body if not already parsed
        let body;
        if (req.body) {
            body = req.body;
        } else {
            const chunks = [];
            for await (const chunk of req) {
                chunks.push(chunk);
            }
            body = JSON.parse(Buffer.concat(chunks).toString());
        }

        // Validate required fields
        if (!body.model) {
            badRequestHandler(res, 'Missing required parameter: model', 'model');
            return;
        }
        if (!body.messages || !Array.isArray(body.messages) || body.messages.length === 0) {
            badRequestHandler(res, 'Missing required parameter: messages', 'messages');
            return;
        }

        // Validate messages format
        for (let i = 0; i < body.messages.length; i++) {
            const msg = body.messages[i];
            if (!msg.role || !msg.content) {
                badRequestHandler(res, `Invalid message at index ${i}: missing role or content`, 'messages');
                return;
            }
        }

        // Validate temperature if provided
        if (body.temperature !== undefined && (body.temperature < 0 || body.temperature > 2)) {
            badRequestHandler(res, 'temperature must be between 0 and 2', 'temperature');
            return;
        }

        // Validate top_p if provided
        if (body.top_p !== undefined && (body.top_p < 0 || body.top_p > 1)) {
            badRequestHandler(res, 'top_p must be between 0 and 1', 'top_p');
            return;
        }

        // Validate n if provided
        if (body.n !== undefined && body.n < 1) {
            badRequestHandler(res, 'n must be at least 1', 'n');
            return;
        }

        // Validate stream
        const stream = body.stream === true;

        // Handle streaming vs non-streaming
        if (stream) {
            await handleStreamRequest(req, res, body);
        } else {
            const result = await handleChatRequest(body);

            // Send response
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(result));
        }

    } catch (error) {
        logger.error('Chat completion error:', error.message);
        if (res.headersSent) {
            return;
        }
        internalErrorHandler(res, error);
    }
}

/**
 * Handle chat completion request using provider manager
 * @param {Object} body - Request body
 * @returns {Promise<Object>} Chat completion response
 */
async function handleChatRequest(body) {
    const { model, messages, temperature = 0.7, max_tokens = 1000, stream = false, top_p, n, stop } = body;

    // Get provider manager
    const providerManager = getProviderManager();

    // Prepare request params
    const params = {
        model,
        messages,
        temperature,
        max_tokens,
        stream,
        top_p,
        n,
        stop
    };

    logger.info(`Chat completion request: model=${model}, stream=${stream}`);

    try {
        const result = await providerManager.chatComplete(params);
        return result;
    } catch (error) {
        logger.error('Provider error:', error.message);

        // Check if rate limited
        if (error.statusCode === 429) {
            const err = new Error('Rate limit exceeded');
            err.statusCode = 429;
            err.code = 'rate_limit_exceeded';
            throw err;
        }

        throw error;
    }
}

/**
 * Handle streaming chat completion request
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {Object} body - Request body
 */
async function handleStreamRequest(req, res, body) {
    const { model, messages, temperature = 0.7, max_tokens = 1000, top_p, n, stop } = body;

    // Set SSE headers
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    const completionId = `chatcmpl-${generateId()}`;
    const created = Math.floor(Date.now() / 1000);

    // Send first chunk with role
    sendStreamChunk(res, {
        id: completionId,
        object: 'chat.completion.chunk',
        created,
        model,
        choices: [
            {
                index: 0,
                delta: { role: 'assistant', content: '' },
                finish_reason: null
            }
        ]
    });

    try {
        // Get provider manager
        const providerManager = getProviderManager();

        // For streaming, we make a non-streaming request first
        // and then split the response into chunks
        const params = {
            model,
            messages,
            temperature,
            max_tokens,
            stream: false, // Providers don't support true streaming yet
            top_p,
            n,
            stop
        };

        const result = await providerManager.chatComplete(params);
        const content = result.choices[0]?.message?.content || '';

        // Stream the content word by word or in chunks
        const words = content.split(/(?=[ \n])/);

        for (let i = 0; i < words.length; i++) {
            const isLast = i === words.length - 1;
            sendStreamChunk(res, {
                id: completionId,
                object: 'chat.completion.chunk',
                created,
                model,
                choices: [
                    {
                        index: 0,
                        delta: { content: words[i] },
                        finish_reason: isLast ? 'stop' : null
                    }
                ]
            });

            // Small delay between chunks for effect
            if (!isLast) {
                await new Promise(r => setTimeout(r, 20));
            }
        }

        // Send usage info as final message
        sendStreamChunk(res, {
            id: completionId,
            object: 'chat.completion.chunk',
            created,
            model,
            choices: [
                {
                    index: 0,
                    delta: {},
                    finish_reason: 'stop'
                }
            ],
            usage: result.usage
        });

    } catch (error) {
        logger.error('Stream error:', error.message);
        // Send error as comment
        res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
    }

    // Signal end of stream
    res.write('data: [DONE]\n\n');
    res.end();
}

/**
 * Send a stream chunk to the response
 * @param {Object} res - Response object
 * @param {Object} chunk - Chunk data
 */
function sendStreamChunk(res, chunk) {
    res.write(`data: ${JSON.stringify(chunk)}\n\n`);
}

/**
 * Generate a random ID
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

/**
 * Simple token counter (approximate)
 * @param {string} text - Text to count tokens for
 * @returns {number} Approximate token count
 */
function countTokens(text) {
    // Rough approximation: 1 token ≈ 4 characters for English
    return Math.ceil(text.length / 4);
}

export default chatRoutes;