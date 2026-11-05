/**
 * whitelist.js - Shared IP whitelist module
 *
 * Parses references/ipWhite.md and provides IP classification.
 * Supports 4 formats: CIDR, short range, full range, single IP.
 */
import fs from 'fs';

/**
 * Convert IPv4 dotted decimal to 32-bit integer
 * @param {string} ip - IPv4 address (e.g., "192.0.2.60")
 * @returns {number} 32-bit unsigned integer
 */
export function ip2long(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return -1;
  let result = 0;
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(parts[i], 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return -1;
    result = (result << 8) | octet;
  }
  // Convert to unsigned 32-bit
  return result >>> 0;
}

/**
 * Parse a whitelist line into a structured entry
 * @param {string} line - Raw line from ipWhite.md
 * @returns {object|null} Parsed entry or null if invalid
 */
function parseLine(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('|') || trimmed.startsWith('-')) {
    return null;
  }

  // CIDR: x.x.x.x/n
  const cidrMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (cidrMatch) {
    const ip = cidrMatch[1];
    const maskBits = parseInt(cidrMatch[2], 10);
    if (maskBits < 0 || maskBits > 32) return null;
    const long = ip2long(ip);
    if (long === -1) return null;
    return {
      raw: trimmed,
      format: 'cidr',
      baseIp: ip,
      maskBits,
      baseLong: long,
      maskLong: maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0,
    };
  }

  // Full range: x.x.x.A-x.x.x.B
  const fullRangeMatch = trimmed.match(
    /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/
  );
  if (fullRangeMatch) {
    const startIp = fullRangeMatch[1];
    const endIp = fullRangeMatch[2];
    const startLong = ip2long(startIp);
    const endLong = ip2long(endIp);
    if (startLong === -1 || endLong === -1 || endLong < startLong) return null;
    return {
      raw: trimmed,
      format: 'range-full',
      baseIp: startIp,
      maskBits: null,
      endIp,
      startLong,
      endLong,
    };
  }

  // Short range: x.x.x.A-B (last octet range)
  const shortRangeMatch = trimmed.match(
    /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$/
  );
  if (shortRangeMatch) {
    const prefix = shortRangeMatch[1];
    const startOctet = parseInt(shortRangeMatch[2], 10);
    const endOctet = parseInt(shortRangeMatch[3], 10);
    if (startOctet > 255 || endOctet > 255 || endOctet < startOctet) return null;
    const baseIp = prefix + startOctet;
    const endIp = prefix + endOctet;
    return {
      raw: trimmed,
      format: 'range-short',
      baseIp,
      maskBits: null,
      endIp,
      endOctet,
      startLong: ip2long(baseIp),
      endLong: ip2long(endIp),
    };
  }

  // Single IP: x.x.x.x
  const singleMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (singleMatch) {
    const ip = singleMatch[1];
    const long = ip2long(ip);
    if (long === -1) return null;
    return {
      raw: trimmed,
      format: 'single',
      baseIp: ip,
      maskBits: null,
      ipLong: long,
    };
  }

  return null;
}

/**
 * Load whitelist from a file
 * @param {string} path - Path to ipWhite.md
 * @returns {object[]} Array of WhitelistEntry objects
 */
export function loadWhitelist(path) {
  if (!fs.existsSync(path)) {
    console.warn(`[WARN] Whitelist file not found: ${path}. Treating all non-private IPs as external.`);
    return [];
  }

  const content = fs.readFileSync(path, 'utf-8');
  const lines = content.split('\n');
  const entries = [];

  for (const line of lines) {
    const entry = parseLine(line);
    if (entry) {
      entries.push(entry);
    }
  }

  if (entries.length === 0) {
    console.warn(`[WARN] No valid entries found in whitelist file: ${path}`);
  }

  return entries;
}

/**
 * Check if an IP is external (not in whitelist)
 * @param {string} ip - IPv4 address to check
 * @param {object[]} entries - Whitelist entries from loadWhitelist()
 * @returns {{external: boolean, matched: object|null}}
 */
export function isExternal(ip, entries) {
  if (!ip || typeof ip !== 'string') {
    return { external: true, matched: null };
  }

  // Reject IPv6
  if (ip.includes(':')) {
    return { external: true, matched: null };
  }

  const ipLong = ip2long(ip);
  if (ipLong === -1) {
    return { external: true, matched: null };
  }

  for (const entry of entries) {
    if (matchesEntry(ipLong, entry)) {
      return { external: false, matched: entry };
    }
  }

  return { external: true, matched: null };
}

/**
 * Check if an IP (as long) matches a whitelist entry
 * @param {number} ipLong - IP as 32-bit unsigned integer
 * @param {object} entry - Whitelist entry
 * @returns {boolean}
 */
export function matchesEntry(ipLong, entry) {
  switch (entry.format) {
    case 'cidr':
      return (ipLong & entry.maskLong) === (entry.baseLong & entry.maskLong);

    case 'range-full':
    case 'range-short':
      return ipLong >= entry.startLong && ipLong <= entry.endLong;

    case 'single':
      return ipLong === entry.ipLong;

    default:
      return false;
  }
}
