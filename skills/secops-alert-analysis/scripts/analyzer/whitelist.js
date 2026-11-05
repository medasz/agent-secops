#!/usr/bin/env node
/**
 * whitelist.js - CLI whitelist checker
 *
 * Classifies IPs as whitelisted or external using the IP whitelist.
 * Supports: --whitelist, --ips, --input, --format, --output
 */
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { loadWhitelist, isExternal } from '../shared/whitelist.js';
import { parseArgs, showHelp, validateRequired } from '../shared/cli-args.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  whitelist: { alias: 'w', type: 'string', default: join(__dirname, '..', '..', 'references', 'ipWhite.md'), description: 'Path to whitelist file' },
  ips: { alias: null, type: 'string', description: 'Comma-separated IPs to check' },
  input: { alias: 'i', type: 'string', description: 'File with one IP per line' },
  format: { alias: 'f', type: 'string', default: 'json', description: 'Output format: json or markdown' },
  output: { alias: 'o', type: 'string', description: 'Output file path (default: stdout)' },
};

const { positional, flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/analyzer/whitelist.js', '[--whitelist <path>] [--ips <ip1,ip2,...>] [--input <file>] [--format json|markdown] [--output <path>]', SCHEMA);
}

// Collect IPs from --ips, --input, or stdin
async function collectAndRun() {
  let ips = [];

  if (flags.ips) {
    ips = flags.ips.split(',').map(s => s.trim()).filter(Boolean);
  } else if (flags.input) {
    if (!fs.existsSync(flags.input)) {
      console.error(`[ERROR] Input file not found: ${flags.input}`);
      process.exit(1);
    }
    const content = fs.readFileSync(flags.input, 'utf-8');
    ips = content.split('\n').map(s => s.trim()).filter(Boolean);
  } else if (positional.length > 0) {
    ips = positional;
  } else {
    // Try reading from stdin if it's being piped
    if (!process.stdin.isTTY) {
      const content = await readStdin();
      ips = content.split('\n').map(s => s.trim()).filter(Boolean);
      run(ips, flags);
      return;
    } else {
      console.error('[ERROR] No IPs provided. Use --ips, --input, positional args, or pipe via stdin.');
      process.exit(1);
    }
  }

  run(ips, flags);
}

/**
 * Read all of stdin as a UTF-8 string (Promise wrapper around stream events).
 */
function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(chunks.join('')));
    process.stdin.on('error', reject);
  });
}

collectAndRun();

function run(ips, opts) {
  // Load whitelist
  const entries = loadWhitelist(opts.whitelist);

  const external = [];
  const whitelisted = [];

  for (const ip of ips) {
    const result = isExternal(ip, entries);
    if (result.external) {
      external.push(ip);
    } else {
      whitelisted.push(ip);
    }
  }

  const data = {
    external,
    whitelisted,
    stats: {
      total: ips.length,
      external: external.length,
      whitelisted: whitelisted.length,
    },
  };

  let output;
  if (opts.format === 'markdown') {
    output = formatMarkdown(data);
  } else {
    output = JSON.stringify(data, null, 2);
  }

  if (opts.output) {
    fs.writeFileSync(opts.output, output, 'utf-8');
    console.error(`[INFO] Output written to ${opts.output}`);
  } else {
    console.log(output);
  }

  process.exit(0);
}

function formatMarkdown(data) {
  const lines = [];
  lines.push('# Whitelist Filter Results\n');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total IPs | ${data.stats.total} |`);
  lines.push(`| External | ${data.stats.external} |`);
  lines.push(`| Whitelisted | ${data.stats.whitelisted} |`);
  lines.push('');

  if (data.external.length > 0) {
    lines.push(`## External IPs (${data.external.length})\n`);
    lines.push('| IP |');
    lines.push('|-----|');
    for (const ip of data.external) {
      lines.push(`| ${ip} |`);
    }
    lines.push('');
  }

  if (data.whitelisted.length > 0) {
    lines.push(`## Whitelisted IPs (${data.whitelisted.length})\n`);
    lines.push('| IP |');
    lines.push('|-----|');
    for (const ip of data.whitelisted) {
      lines.push(`| ${ip} |`);
    }
  }

  return lines.join('\n');
}
