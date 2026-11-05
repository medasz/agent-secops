/**
 * API Types - Request/Response type definitions
 * @module api/types
 */

/**
 * Message object for chat completion
 * @typedef {Object} Message
 * @property {string} role - Role: 'system', 'user', or 'assistant'
 * @property {string} content - Message content
 */

/**
 * Chat completion request parameters
 * @typedef {Object} ChatCompletionParams
 * @property {string} model - Model identifier
 * @property {Message[]} messages - Array of messages
 * @property {number} [temperature] - Sampling temperature (0-2)
 * @property {number} [top_p] - Nucleus sampling parameter
 * @property {number} [max_tokens] - Maximum tokens to generate
 * @property {boolean} [stream] - Whether to stream responses
 * @property {number} [n] - Number of completions to generate
 * @property {string|string[]} [stop] - Stop sequences
 * @property {number} [presence_penalty] - Presence penalty
 * @property {number} [frequency_penalty] - Frequency penalty
 * @property {Object} [user] - User identifier for tracking
 */

/**
 * Choice in chat completion response
 * @typedef {Object} Choice
 * @property {number} index - Choice index
 * @property {Message} message - Generated message
 * @property {string} finish_reason - Reason for completion: 'stop', 'length', 'content_filter'
 */

/**
 * Usage statistics
 * @typedef {Object} Usage
 * @property {number} prompt_tokens - Tokens in prompt
 * @property {number} completion_tokens - Tokens in completion
 * @property {number} total_tokens - Total tokens used
 */

/**
 * Chat completion response
 * @typedef {Object} ChatCompletionResponse
 * @property {string} id - Unique completion ID
 * @property {string} object - Object type: 'chat.completion'
 * @property {number} created - Unix timestamp
 * @property {string} model - Model used
 * @property {Choice[]} choices - Array of choices
 * @property {Usage} usage - Usage statistics
 */

/**
 * Delta for streaming response
 * @typedef {Object} StreamDelta
 * @property {string} [role] - Role (only in first chunk)
 * @property {string} [content] - Content delta
 */

/**
 * Stream choice
 * @typedef {Object} StreamChoice
 * @property {number} index - Choice index
 * @property {StreamDelta} delta - Content delta
 * @property {string} [finish_reason] - Finish reason
 */

/**
 * Streaming chat completion chunk
 * @typedef {Object} ChatCompletionChunk
 * @property {string} id - Chunk ID
 * @property {string} object - Object type: 'chat.completion.chunk'
 * @property {number} created - Unix timestamp
 * @property {string} model - Model used
 * @property {StreamChoice[]} choices - Array of stream choices
 */

/**
 * Model object
 * @typedef {Object} Model
 * @property {string} id - Model ID
 * @property {string} object - Object type: 'model'
 * @property {number} created - Creation timestamp
 * @property {string} owned_by - Owner organization
 */

/**
 * Provider info
 * @typedef {Object} ProviderInfo
 * @property {string} id - Provider ID
 * @property {string} name - Provider name
 * @property {string} type - Provider type
 * @property {string[]} models - Available models
 * @property {string} status - Status: 'active' or 'backup'
 */

/**
 * Error response
 * @typedef {Object} ErrorResponse
 * @property {Object} error - Error object
 * @property {string} error.message - Error message
 * @property {string} error.type - Error type
 * @property {string} error.code - Error code
 * @property {string} [error.param] - Parameter that caused error
 */

/**
 * Create a chat completion request from raw params
 * @param {Object} params - Raw parameters
 * @returns {ChatCompletionParams} Validated request params
 */
export function createChatRequest(params) {
    return {
        model: params.model,
        messages: params.messages,
        temperature: params.temperature ?? 0.7,
        top_p: params.top_p ?? 1,
        max_tokens: params.max_tokens ?? 1000,
        stream: params.stream ?? false,
        n: params.n ?? 1,
        stop: params.stop ?? null,
        presence_penalty: params.presence_penalty ?? 0,
        frequency_penalty: params.frequency_penalty ?? 0,
        user: params.user ?? null
    };
}

/**
 * Create a standard OpenAI-format response
 * @param {Object} options - Response options
 * @returns {ChatCompletionResponse} OpenAI-format response
 */
export function createChatResponse(options) {
    const { model, messages, choices, usage, id, created } = options;

    return {
        id: id || `chatcmpl-${generateId()}`,
        object: 'chat.completion',
        created: created || Math.floor(Date.now() / 1000),
        model: model,
        choices: choices || [
            {
                index: 0,
                message: {
                    role: 'assistant',
                    content: ''
                },
                finish_reason: 'stop'
            }
        ],
        usage: usage || {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0
        }
    };
}

/**
 * Create a streaming chunk
 * @param {Object} options - Chunk options
 * @returns {ChatCompletionChunk} Streaming chunk
 */
export function createStreamChunk(options) {
    const { id, model, choices, created } = options;

    return {
        id: id || `chatcmpl-${generateId()}`,
        object: 'chat.completion.chunk',
        created: created || Math.floor(Date.now() / 1000),
        model: model,
        choices: choices || [
            {
                index: 0,
                delta: {},
                finish_reason: null
            }
        ]
    };
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

/**
 * Format provider for API response
 * @param {Object} provider - Provider configuration
 * @param {number} index - Provider index
 * @returns {ProviderInfo} Formatted provider info
 */
export function formatProvider(provider, index) {
    return {
        id: provider.id,
        name: provider.name,
        type: provider.type,
        models: provider.models,
        defaultModel: provider.defaultModel,
        priority: provider.priority,
        status: index === 0 ? 'active' : 'backup',
        endpoint: provider.endpoint,
        timeout: provider.timeout || 30000
    };
}

export default {
    createChatRequest,
    createChatResponse,
    createStreamChunk,
    formatProvider
};