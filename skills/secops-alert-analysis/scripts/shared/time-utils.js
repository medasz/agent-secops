/**
 * time-utils.js - Time bucketing and timezone helpers
 *
 * All time operations use Asia/Shanghai (UTC+8) timezone.
 * Reuses the logic from es-tool/paginate.js toShanghaiTimeString().
 */
const SHANGHAI_OFFSET_MS = 8 * 60 * 60 * 1000;

/**
 * Convert ISO timestamp or epoch ms to Shanghai time Date
 * @param {string|number} input - ISO string or epoch milliseconds
 * @returns {Date} Date object adjusted to Shanghai timezone display
 */
export function toShanghaiTime(input) {
  let ms;
  if (typeof input === 'number') {
    ms = input;
  } else if (typeof input === 'string') {
    // Parse ISO string to epoch ms
    ms = new Date(input).getTime();
  } else {
    return new Date(NaN);
  }
  if (isNaN(ms)) return new Date(NaN);
  // Shift to Shanghai timezone for display
  return new Date(ms + SHANGHAI_OFFSET_MS);
}

/**
 * Extract hour (0-23) in Shanghai timezone
 * @param {string|number} input - ISO string or epoch milliseconds
 * @returns {number} Hour 0-23
 */
export function getHour(input) {
  const d = toShanghaiTime(input);
  if (isNaN(d.getTime())) return -1;
  return d.getUTCHours();
}

/**
 * Format a date to a pattern string
 * @param {Date|string|number} input - Date, ISO string, or epoch ms
 * @param {string} pattern - "YYYYMMDD" or "YYYY-MM-DD"
 * @returns {string} Formatted date string
 */
export function formatDate(input, pattern = 'YYYYMMDD') {
  let d;
  if (input instanceof Date) {
    d = input;
  } else {
    d = toShanghaiTime(input);
  }
  if (isNaN(d.getTime())) return '';

  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');

  if (pattern === 'YYYY-MM-DD') {
    return `${year}-${month}-${day}`;
  }
  return `${year}${month}${day}`;
}

/**
 * Build ES date range filter for a given YYYYMMDD date string
 * @param {string} dateYYYYMMDD - Date in YYYYMMDD format
 * @returns {{gte: string, lt: string}} ES range filter values
 */
export function buildDateRangeFilter(dateYYYYMMDD) {
  const year = dateYYYYMMDD.slice(0, 4);
  const month = dateYYYYMMDD.slice(4, 6);
  const day = dateYYYYMMDD.slice(6, 8);

  return {
    gte: `${year}-${month}-${day}T00:00:00+08:00`,
    lt: `${year}-${month}-${day}T23:59:59+08:00`,
  };
}
