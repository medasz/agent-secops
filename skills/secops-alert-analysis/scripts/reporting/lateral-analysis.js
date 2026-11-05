#!/usr/bin/env node
/**
 * lateral-analysis.js - Generate lateral movement analysis MD section
 *
 * Input:  parsed-internal-{date}.json (from parse-mcp.js --internal or extract.js --internal --parsed-output)
 * Output: lateral-analysis-{date}.md (MD fragment for gen-md-report.js --lateral injection)
 *
 */
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { parseArgs, showHelp } from '../shared/cli-args.js';
import { renderMarkdownTable } from '../shared/report-renderer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  input: { alias: 'i', type: 'string', required: true, description: 'Internal parsed JSON file (parsed-internal-{date}.json)' },
  date: { alias: 'd', type: 'string', description: 'Report date (YYYYMMDD)' },
  output: { alias: 'o', type: 'string', description: 'Output MD file (default: stdout)' },
};

const { flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/reporting/lateral-analysis.js', '--input <parsed-internal.json> [--date <YYYYMMDD>] [--output <md>]', SCHEMA);
}

const missing = [];
if (!flags.input) missing.push('--input');
if (missing.length > 0) {
  console.error(`[ERROR] Missing required options: ${missing.join(', ')}`);
  process.exit(1);
}

if (!fs.existsSync(flags.input)) {
  console.error(`[ERROR] Input file not found: ${flags.input}`);
  process.exit(1);
}

const parsedData = JSON.parse(fs.readFileSync(flags.input, 'utf-8'));
const stats = parsedData.stats || {};
const lateral = parsedData.lateral;

// --- Generate MD section ---

function formatAttackTypes(types) {
  if (!types || types.length === 0) return 'N/A';
  return types.map(t => `${t.type}(${t.count})`).join(', ');
}

function pct(count, total) {
  if (total <= 0) return '0%';
  return ((count / total) * 100).toFixed(1) + '%';
}

const lines = [];

// 空数据处理
if (!lateral || (!lateral.sources && !lateral.targets)) {
  lines.push('### 6.1 内部攻击统计\n');
  lines.push('| 指标 | 数值 |');
  lines.push('|------|------|');
  lines.push(`| 内部攻击告警总数 | ${stats.total_alerts ?? 0} |`);
  lines.push(`| 横向移动告警数 | ${stats.lateral_alerts ?? 0} |`);
  lines.push('\n> 未检测到横向移动行为\n');
} else {
  const lateralTotal = stats.lateral_alerts ?? 0;
  const sourceCount = lateral.sources?.length ?? 0;
  const targetCount = lateral.targets?.length ?? 0;

  // 6.1 内部攻击统计
  lines.push('### 6.1 内部攻击统计\n');
  lines.push('| 指标 | 数值 |');
  lines.push('|------|------|');
  lines.push(`| 内部攻击告警总数 | ${stats.total_alerts ?? 0} |`);
  lines.push(`| 横向移动告警数 | ${lateralTotal} |`);
  lines.push(`| 横向移动源IP数 | ${sourceCount} |`);
  lines.push(`| 横向移动目标IP数 | ${targetCount} |`);

  // 6.2 内部攻击趋势-按类型分布
  lines.push('\n### 6.2 内部攻击-按类型分布\n');
  const attackTypes = stats.attack_types || [];
  if (attackTypes.length > 0) {
    lines.push(renderMarkdownTable(
      ['攻击类型', '攻击次数', '占比'],
      attackTypes.map(t => [t.type, String(t.count), pct(t.count, stats.total_alerts ?? 0)])
    ));
  } else {
    lines.push('> 无类型分布数据\n');
  }

  // 6.3 横向移动源IP Top10
  lines.push('\n### 6.3 横向移动源IP Top10\n');
  const topSources = (lateral.sources || []).slice(0, 10);
  if (topSources.length > 0) {
    const rows = topSources.map((s, i) => [
      String(i + 1), s.ip, String(s.count),
      formatAttackTypes(s.attack_types), s.max_timestamp || 'N/A'
    ]);
    lines.push(renderMarkdownTable(
      ['序号', '源IP', '告警次数', '攻击类型', '最近告警时间'],
      rows
    ));
  } else {
    lines.push('> 无横向移动源IP数据\n');
  }

  // 6.4 横向移动目标IP Top10
  lines.push('\n### 6.4 横向移动目标IP Top10\n');
  const topTargets = (lateral.targets || []).slice(0, 10);
  if (topTargets.length > 0) {
    const rows = topTargets.map((t, i) => [
      String(i + 1), t.ip, String(t.count),
      formatAttackTypes(t.attack_types), t.max_timestamp || 'N/A'
    ]);
    lines.push(renderMarkdownTable(
      ['序号', '目标IP', '告警次数', '攻击类型', '最近告警时间'],
      rows
    ));
  } else {
    lines.push('> 无横向移动目标IP数据\n');
  }

  // 6.5 横向移动趋势-按时间分布
  lines.push('\n### 6.5 横向移动趋势-按时间分布\n');
  const hourlyDist = lateral.hourly_distribution || [];
  if (hourlyDist.length > 0) {
    lines.push(renderMarkdownTable(
      ['时段', '告警次数'],
      hourlyDist.map(h => [String(h.hour), String(h.count)])
    ));
  } else {
    lines.push('> 无时间分布数据\n');
  }
}

const output = lines.join('\n');

if (flags.output) {
  const outputDir = dirname(flags.output);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  fs.writeFileSync(flags.output, output, 'utf-8');
  console.error(`[INFO] Lateral analysis written to ${flags.output}`);
} else {
  console.log(output);
}
