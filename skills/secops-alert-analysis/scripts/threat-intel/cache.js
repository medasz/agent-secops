import { getThreatBookConfig } from '../shared/env.js';
import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let db = null;

function getDb() {
  if (db) return db;
  const cachePath = getThreatBookConfig().cachePath;
  const resolved = path.isAbsolute(cachePath)
    ? cachePath
    : path.resolve(__dirname, '..', cachePath);
  const dir = path.dirname(resolved);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  db = new DatabaseSync(resolved);
  db.exec(`
    CREATE TABLE IF NOT EXISTS threat_intel_cache (
      source      TEXT,
      entry_type  TEXT,
      entry_value TEXT,
      data        TEXT,
      cached_at   INTEGER,
      PRIMARY KEY (source, entry_type, entry_value)
    )
  `);
  return db;
}

function getTtl() {
  return getThreatBookConfig().cacheTtl;
}

export function getCache(source, entryType, entryValue) {
  const d = getDb();
  const ttl = getTtl();
  const now = Math.floor(Date.now() / 1000);
  const row = d.prepare(
    'SELECT data FROM threat_intel_cache WHERE source = ? AND entry_type = ? AND entry_value = ? AND cached_at + ? > ?'
  ).get(source, entryType, entryValue, ttl, now);
  if (!row) return null;
  try {
    return JSON.parse(row.data);
  } catch {
    return null;
  }
}

export function setCache(source, entryType, entryValue, data) {
  const d = getDb();
  const now = Math.floor(Date.now() / 1000);
  const json = JSON.stringify(data);
  d.prepare(
    'INSERT OR REPLACE INTO threat_intel_cache (source, entry_type, entry_value, data, cached_at) VALUES (?, ?, ?, ?, ?)'
  ).run(source, entryType, entryValue, json, now);
  cleanup();
}

export function cleanup() {
  const d = getDb();
  const ttl = getTtl();
  const now = Math.floor(Date.now() / 1000);
  d.prepare(
    'DELETE FROM threat_intel_cache WHERE cached_at + ? <= ?'
  ).run(ttl, now);
}

export function closeCache() {
  if (db) {
    db.close();
    db = null;
  }
}

export function resetCache() {
  const d = getDb();
  d.exec('DELETE FROM threat_intel_cache');
}

export default {
  getCache,
  setCache,
  cleanup,
  closeCache,
  resetCache
};
