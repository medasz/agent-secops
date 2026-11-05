#!/usr/bin/env node
/**
 * gen-html-report.js - Convert MD report to HTML using template
 *
 * Usage: node scripts/reporting/gen-html-report.js --input <report.md> --template <template.html> --output <report.html>
 *        [--title <标题>] [--date-range <范围>] [--report-time <时间>] [--analyst <分析员>] [--whitelist <path>]
 *
 * MD elements converted: h1-h4, bold, italic, tables, ul/ol, inline code, code blocks, links, blockquote
 * Template placeholders: {{title}}, {{date_range}}, {{report_time}}, {{analyst}}, {{content}}
 * "外部攻击IP完整列表" section is collapsed by default (no open attribute on <details>)
 * Whitelist filtering uses shared/whitelist.js isExternal()
 */
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { parseArgs, showHelp } from '../shared/cli-args.js';
import { loadWhitelist, isExternal } from '../shared/whitelist.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  input: { alias: 'i', type: 'string', required: true, description: 'Input MD report file' },
  template: { alias: 't', type: 'string', default: join(__dirname, '..', '..', 'templates', 'alert-report-template-v1.html'), description: 'HTML template file' },
  output: { alias: 'o', type: 'string', description: 'Output HTML file (default: stdout)' },
  title: { type: 'string', description: 'Override report title' },
  'date-range': { type: 'string', description: 'Override date range' },
  'report-time': { type: 'string', description: 'Override report time' },
  analyst: { type: 'string', description: 'Override analyst name' },
  whitelist: { alias: 'w', type: 'string', default: join(__dirname, '..', '..', 'references', 'ipWhite.md'), description: 'Whitelist file for IP filtering' },
};

const { flags } = parseArgs(process.argv, SCHEMA);

function main() {
  if (flags.help) {
    showHelp('scripts/reporting/gen-html-report.js', '--input <md> [--template <html>] [--output <html>] [--title <t>] [--whitelist <path>]', SCHEMA);
  }

  if (!flags.input) {
    console.error('[ERROR] --input is required');
    process.exit(1);
  }

  if (!fs.existsSync(flags.input)) {
    console.error(`[ERROR] Input file not found: ${flags.input}`);
    process.exit(1);
  }

  if (!fs.existsSync(flags.template)) {
    console.error(`[ERROR] Template file not found: ${flags.template}`);
    process.exit(1);
  }

  const mdContent = fs.readFileSync(flags.input, 'utf-8');
  const template = fs.readFileSync(flags.template, 'utf-8');

  const metadata = extractMetadata(mdContent, flags);

  let htmlContent = mdToHtml(mdContent);

  if (flags.whitelist && fs.existsSync(flags.whitelist)) {
    const whitelistEntries = loadWhitelist(flags.whitelist);
    htmlContent = filterWhitelistIps(htmlContent, whitelistEntries);
  }

  htmlContent = collapseIpListSection(htmlContent);

  let result = template;
  result = result.replaceAll('{{title}}', metadata.title);
  result = result.replaceAll('{{date_range}}', metadata.dateRange);
  result = result.replaceAll('{{report_time}}', metadata.reportTime);
  result = result.replaceAll('{{analyst}}', metadata.analyst);
  result = result.replaceAll('{{content}}', htmlContent);

  if (flags.output) {
    fs.writeFileSync(flags.output, result, 'utf-8');
    console.error(`[INFO] HTML report written to ${flags.output}`);
  } else {
    console.log(result);
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main();
}

// --- helpers ---

function extractMetadata(md, flags) {
  const lines = md.split('\n');

  let title = flags.title || '';
  let reportTime = flags['report-time'] || '';
  let dateRange = flags['date-range'] || '';
  let analyst = flags.analyst || '';

  for (const line of lines) {
    if (!title) {
      const h1Match = line.match(/^#\s+(.+)$/);
      if (h1Match) title = h1Match[1].trim();
    }
    if (!reportTime) {
      const m = line.match(/\*\*报告生成时间\*\*[：:]\s*(.+)/);
      if (m) reportTime = m[1].trim();
    }
    if (!dateRange) {
      // Fix D（Bug-05）：报告真实字段为「研判时间范围」；保留旧标签「分析时间范围」作为 fallback 以兼容历史产物
      const m = line.match(/\*\*研判时间范围\*\*[：:]\s*(.+)/) || line.match(/\*\*分析时间范围\*\*[：:]\s*(.+)/);
      if (m) dateRange = m[1].trim();
    }
    if (!analyst) {
      // 报告真实字段为「研判人员」；保留旧标签「安全运营告警分析研判 Agent」作为 fallback
      const m = line.match(/\*\*研判人员\*\*[：:]\s*(.+)/) || line.match(/\*\*安全运营告警分析研判 Agent\*\*[：:]\s*(.+)/);
      if (m) analyst = m[1].trim();
    }
  }

  return { title, reportTime, dateRange, analyst };
}

export { extractMetadata };

function mdToHtml(md) {
  const lines = md.split('\n');
  const html = [];
  let i = 0;
  let inList = false;
  let listType = null;
  let inCodeBlock = false;
  let codeLines = [];
  let inBlockquote = false;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim().startsWith('```')) {
      if (inCodeBlock) {
        html.push(`<pre><code>${escapeHtml(codeLines.join('\n'))}</code></pre>`);
        codeLines = [];
        inCodeBlock = false;
      } else {
        if (inList) { html.push(`</${listType}>`); inList = false; }
        if (inBlockquote) { html.push('</blockquote>'); inBlockquote = false; }
        inCodeBlock = true;
      }
      i++;
      continue;
    }
    if (inCodeBlock) {
      codeLines.push(line);
      i++;
      continue;
    }

    if (line.includes('|') && i + 1 < lines.length && lines[i + 1].includes('---')) {
      if (inList) { html.push(`</${listType}>`); inList = false; }
      if (inBlockquote) { html.push('</blockquote>'); inBlockquote = false; }
      const headers = parseTableRow(line);
      const tableRows = [];
      i++;
      while (i + 1 < lines.length && lines[i + 1].includes('|') && !lines[i + 1].match(/^#+\s/)) {
        i++;
        if (lines[i].trim() === '' || !lines[i].includes('|')) break;
        tableRows.push(parseTableRow(lines[i]));
      }
      html.push(renderHtmlTable(headers, tableRows));
      i++;
      continue;
    }

    const hMatch = line.match(/^(#{1,4})\s+(.+)$/);
    if (hMatch) {
      if (inList) { html.push(`</${listType}>`); inList = false; }
      if (inBlockquote) { html.push('</blockquote>'); inBlockquote = false; }
      const level = hMatch[1].length;
      html.push(`<h${level}>${inlineFormat(hMatch[2].trim())}</h${level}>`);
      i++;
      continue;
    }

    if (line.trim().startsWith('>')) {
      if (inList) { html.push(`</${listType}>`); inList = false; }
      if (!inBlockquote) {
        html.push('<blockquote>');
        inBlockquote = true;
      }
      html.push(inlineFormat(line.trim().slice(1).trim()));
      i++;
      continue;
    } else if (inBlockquote) {
      html.push('</blockquote>');
      inBlockquote = false;
    }

    if (line.match(/^\s*[-*]\s+/)) {
      if (inList && listType !== 'ul') { html.push(`</${listType}>`); inList = false; }
      if (!inList) { html.push('<ul>'); inList = true; listType = 'ul'; }
      html.push(`<li>${inlineFormat(line.replace(/^\s*[-*]\s+/, ''))}</li>`);
      i++;
      continue;
    }

    if (line.match(/^\s*\d+\.\s+/)) {
      if (inList && listType !== 'ol') { html.push(`</${listType}>`); inList = false; }
      if (!inList) { html.push('<ol>'); inList = true; listType = 'ol'; }
      html.push(`<li>${inlineFormat(line.replace(/^\s*\d+\.\s+/, ''))}</li>`);
      i++;
      continue;
    }

    if (inList && line.trim() !== '' && !line.match(/^\s*[-*]\s+/) && !line.match(/^\s*\d+\.\s+/)) {
      html.push(`</${listType}>`);
      inList = false;
    }

    if (line.trim() === '---' || line.trim() === '***') {
      if (inList) { html.push(`</${listType}>`); inList = false; }
      html.push('<hr>');
      i++;
      continue;
    }

    if (line.trim() === '') {
      i++;
      continue;
    }

    html.push(`<p>${inlineFormat(line.trim())}</p>`);
    i++;
  }

  if (inList) html.push(`</${listType}>`);
  if (inBlockquote) html.push('</blockquote>');
  if (inCodeBlock) html.push(`<pre><code>${escapeHtml(codeLines.join('\n'))}</code></pre>`);

  return html.join('\n');
}

function parseTableRow(line) {
  return line.split('|').map(c => c.trim()).filter((_, idx, arr) => idx !== 0 && idx !== arr.length - 1);
}

function renderHtmlTable(headers, rows) {
  const thead = '<thead><tr>' + headers.map(h => `<th>${inlineFormat(h)}</th>`).join('') + '</tr></thead>';
  const tbody = '<tbody>' + rows.map(r => '<tr>' + r.map(c => `<td>${inlineFormat(c)}</td>`).join('') + '</tr>').join('') + '</tbody>';
  return `<table>${thead}${tbody}</table>`;
}

function inlineFormat(text) {
  let result = text;
  result = result.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  result = result.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  result = result.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  result = result.replace(/`([^`]+)`/g, '<code>$1</code>');
  return result;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function filterWhitelistIps(html, whitelistEntries) {
  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const ipsToRemove = new Set();
  html.replace(ipRegex, (match, ip) => {
    const { external } = isExternal(ip, whitelistEntries);
    if (!external) ipsToRemove.add(ip);
    return match;
  });

  if (ipsToRemove.size === 0) return html;

  const marker = '外部攻击IP完整列表';
  const idx = html.indexOf(marker);
  if (idx === -1) return html;

  const sectionStart = html.lastIndexOf('<h3>', idx);
  if (sectionStart === -1) return html;

  let sectionEnd = html.indexOf('<h2>', idx);
  if (sectionEnd === -1) sectionEnd = html.indexOf('<h1>', idx);
  if (sectionEnd === -1) sectionEnd = html.length;

  const before = html.slice(0, sectionStart);
  let section = html.slice(sectionStart, sectionEnd);
  const after = html.slice(sectionEnd);

  section = section.replace(/<tr>.*?<\/tr>/g, (tr) => {
    for (const ip of ipsToRemove) {
      if (tr.includes(ip)) return '';
    }
    return tr;
  });

  return before + section + after;
}

function collapseIpListSection(html) {
  const marker = '外部攻击IP完整列表';
  const idx = html.indexOf(marker);
  if (idx === -1) return html;

  const h3Start = html.lastIndexOf('<h3>', idx);
  if (h3Start === -1) return html;

  const h3End = html.indexOf('</h3>', idx) + 5;
  const headingHtml = html.slice(h3Start, h3End);

  const tableStart = html.indexOf('<table', h3End);
  let tableEnd = html.indexOf('</table>', tableStart);
  if (tableEnd === -1) return html;
  tableEnd += 8;

  const afterSection = html.slice(tableEnd);
  const nextH2 = afterSection.indexOf('<h2>');
  const tableHtml = tableStart !== -1 ? html.slice(tableStart, tableEnd) : '';

  const collapsed = `<details>\n<summary>外部攻击IP完整列表<默认折叠></summary>\n${tableHtml}\n</details>`;

  return html.slice(0, h3Start) + headingHtml + '\n' + collapsed + afterSection.slice(nextH2 !== -1 ? nextH2 : 0);
}
