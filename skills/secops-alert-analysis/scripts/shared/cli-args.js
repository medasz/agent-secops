/**
 * cli-args.js - CLI argument parsing utility
 *
 * Shared by all scripts to avoid duplicated argument parsing.
 * Supports: positional args, --flag value, --flag=value, short aliases.
 */

/**
 * Parse process.argv against a schema
 * @param {string[]} argv - process.argv (or subset starting from args)
 * @param {object} schema - Option definitions
 *   Format: { 'option-name': { alias: 'o', type: 'string|boolean|number', default: value, required: boolean, description: '...' } }
 * @returns {{ positional: string[], flags: object }}
 */
export function parseArgs(argv, schema = {}) {
  const args = argv.slice(2); // Skip node and script path
  const flags = {};
  const positional = [];

  // Build alias map
  const aliasMap = {};
  for (const [name, def] of Object.entries(schema)) {
    if (def.alias) {
      aliasMap[def.alias] = name;
    }
  }

  // Set defaults
  for (const [name, def] of Object.entries(schema)) {
    if (def.default !== undefined) {
      flags[name] = def.default;
    }
  }

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      flags.help = true;
      i++;
      continue;
    }

    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx !== -1) {
        // --flag=value
        const key = arg.slice(2, eqIdx);
        const value = arg.slice(eqIdx + 1);
        setFlag(flags, key, value, schema);
      } else {
        // --flag value
        const key = arg.slice(2);
        const def = schema[key];
        if (def && def.type === 'boolean') {
          flags[key] = true;
        } else if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
          setFlag(flags, key, args[i + 1], schema);
          i++;
        } else {
          flags[key] = true;
        }
      }
    } else if (arg.startsWith('-') && arg.length === 2) {
      const alias = arg.slice(1);
      const key = aliasMap[alias];
      if (key) {
        const def = schema[key];
        if (def && def.type === 'boolean') {
          flags[key] = true;
        } else if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
          setFlag(flags, key, args[i + 1], schema);
          i++;
        }
      }
    } else {
      positional.push(arg);
    }

    i++;
  }

  return { positional, flags };
}

/**
 * Set a flag value with type coercion
 */
function setFlag(flags, key, value, schema) {
  const def = schema[key];
  if (def && def.type === 'number') {
    flags[key] = parseInt(value, 10);
  } else {
    flags[key] = value;
  }
}

/**
 * Print usage information and exit
 * @param {string} scriptName - Script name for display
 * @param {string} usage - Usage string
 * @param {object} schema - Option definitions
 */
export function showHelp(scriptName, usage, schema = {}) {
  console.log(`Usage: node ${scriptName} ${usage}`);
  console.log('');

  const entries = Object.entries(schema);
  if (entries.length > 0) {
    console.log('Options:');
    for (const [name, def] of entries) {
      const aliasStr = def.alias ? `-${def.alias}, ` : '    ';
      const typeStr = def.type === 'boolean' ? '' : ` <${def.type || 'string'}>`;
      const defaultStr = def.default !== undefined ? ` (default: ${def.default})` : '';
      const requiredStr = def.required ? ' [required]' : '';
      console.log(`  ${aliasStr}--${name}${typeStr}  ${def.description || ''}${defaultStr}${requiredStr}`);
    }
  }

  console.log('');
  process.exit(0);
}

/**
 * Validate required flags are present
 * @param {object} flags - Parsed flags
 * @param {object} schema - Option definitions
 * @returns {string[]} Array of missing required option names
 */
export function validateRequired(flags, schema) {
  const missing = [];
  for (const [name, def] of Object.entries(schema)) {
    if (def.required && (flags[name] === undefined || flags[name] === null || flags[name] === '')) {
      missing.push(name);
    }
  }
  return missing;
}
