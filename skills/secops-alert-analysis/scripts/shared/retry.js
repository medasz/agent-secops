/**
 * Retry utility with exponential backoff
 * @module lib/retry
 */

/**
 * Sleep for specified milliseconds
 * @param {number} ms - Milliseconds to sleep
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry a function with exponential backoff
 * @param {Function} fn - Async function to retry
 * @param {Object} options - Retry options
 * @param {number} options.maxAttempts - Maximum number of attempts (default: 3)
 * @param {number} options.delayMs - Initial delay in milliseconds (default: 1000)
 * @param {number} options.maxDelayMs - Maximum delay in milliseconds (default: 30000)
 * @param {Function} [options.onRetry] - Callback called on each retry
 * @returns {Promise<any>} Result of the function
 */
export async function retry(fn, options = {}) {
  const {
    maxAttempts = 3,
    delayMs = 1000,
    maxDelayMs = 30000,
    onRetry = null
  } = options;

  let lastError;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      if (attempt < maxAttempts) {
        const delay = Math.min(delayMs * Math.pow(2, attempt - 1), maxDelayMs);
        if (onRetry) {
          onRetry(error, attempt, delay);
        }
        await sleep(delay);
      }
    }
  }

  throw lastError;
}

export default { retry, sleep };