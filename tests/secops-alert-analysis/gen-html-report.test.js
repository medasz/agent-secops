import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { execFileSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCRIPT = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'scripts', 'reporting', 'gen-html-report.js');
const TEMPLATE = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'templates', 'alert-report-template-v1.html');
const FIXTURE_DIR = join(__dirname, 'fixtures');
const TMP_DIR = join(FIXTURE_DIR, 'tmp-gen-html');

describe('reporting/gen-html-report.js', () => {
  let sampleMd;
  let tmpOut;

  before(() => {
    sampleMd = join(FIXTURE_DIR, 'sample-report.md');
    if (!fs.existsSync(TMP_DIR)) fs.mkdirSync(TMP_DIR, { recursive: true });
    tmpOut = join(TMP_DIR, 'output.html');
  });

  after(() => {
    if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut);
    if (fs.existsSync(TMP_DIR)) fs.rmdirSync(TMP_DIR);
  });

  // ============================================================
  // US1: Basic generation + template placeholder replacement
  // ============================================================
  describe('US1 - Basic generation', () => {
    it('should produce non-empty HTML file', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.length > 0, 'Output HTML should be non-empty');
    });

    it('should replace all template placeholders with no {{ residue', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(!html.includes('{{title}}'), 'Should replace {{title}}');
      assert.ok(!html.includes('{{date_range}}'), 'Should replace {{date_range}}');
      assert.ok(!html.includes('{{report_time}}'), 'Should replace {{report_time}}');
      assert.ok(!html.includes('{{analyst}}'), 'Should replace {{analyst}}');
      assert.ok(!html.includes('{{content}}'), 'Should replace {{content}}');
      assert.ok(!html.includes('{{'), 'No {{ residue should remain');
    });

    it('should extract metadata from MD content', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.includes('安全运营告警分析研判报告'), 'Should have title from MD h1');
      assert.ok(html.includes('2026-07-13 14:30:00'), 'Should have report_time from MD');
      assert.ok(html.includes('TestAnalyst'), 'Should have analyst from MD');
      assert.ok(html.includes('2026-07-13 00:00:00 至 2026-07-13 23:59:59'), 'Should have date_range from MD');
    });
  });

  // ============================================================
  // US2: MD element conversion
  // ============================================================
  describe('US2 - MD element conversion', () => {
    it('should convert h1/h2/h3 to HTML tags', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.includes('<h1>'), 'Should convert # to <h1>');
      assert.ok(html.includes('<h2>'), 'Should convert ## to <h2>');
      assert.ok(html.includes('<h3>'), 'Should convert ### to <h3>');
    });

    it('should convert bold to <strong>', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.includes('<strong>'), 'Should convert ** to <strong>');
    });

    it('should convert tables to <table>', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.includes('<table>'), 'Should convert MD table to <table>');
      assert.ok(html.includes('<th>'), 'Should have <th> headers');
      assert.ok(html.includes('<td>'), 'Should have <td> cells');
    });

    it('should convert lists to <ul>/<li>', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.includes('<ul>'), 'Should convert - to <ul>');
      assert.ok(html.includes('<li>'), 'Should have <li> items');
    });

    it('should convert inline code to <code>', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.includes('<code>代码执行</code>'), 'Should convert `code` to <code>');
    });

    it('should convert blockquote to <blockquote>', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.includes('<blockquote>'), 'Should convert > to <blockquote>');
    });
  });

  // ============================================================
  // US3: IP list collapse (H5 optimization)
  // ============================================================
  describe('US3 - IP list collapse', () => {
    it('should collapse "外部攻击IP完整列表" section (no open attribute)', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.includes('外部攻击IP完整列表'), 'Should contain the section title');
      const detailsMatch = html.match(/<details[^>]*>[\s\S]*?外部攻击IP完整列表[\s\S]*?<\/details>/);
      assert.ok(detailsMatch, 'Should wrap section in <details>');
      assert.ok(!detailsMatch[0].includes(' open'), 'Should NOT have open attribute');
    });
  });

  // ============================================================
  // US4: Whitelist filtering via isExternal()
  // ============================================================
  describe('US4 - Whitelist filtering', () => {
    it('should filter whitelist IPs from IP list', () => {
      const whitelistPath = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'references', 'ipWhite.md');
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', TEMPLATE, '--output', tmpOut, '--whitelist', whitelistPath], { encoding: 'utf-8' });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(!html.includes('192.0.2.60'), 'Whitelist IP should be filtered out');
      assert.ok(html.includes('185.206.149.182'), 'External IP should remain');
      assert.ok(html.includes('5.61.209.92'), 'External IP should remain');
    });
  });

  // ============================================================
  // US5: Edge cases
  // ============================================================
  describe('US5 - Edge cases', () => {
    it('should default template when --template not provided', () => {
      execFileSync('node', [SCRIPT, '--input', sampleMd, '--output', tmpOut], { encoding: 'utf-8', cwd: join(__dirname, '..', '..', 'skills', 'secops-alert-analysis') });
      const html = fs.readFileSync(tmpOut, 'utf-8');
      assert.ok(html.length > 0, 'Should produce output with default template');
    });

    it('should exit with code 1 when template file not found', () => {
      try {
        execFileSync('node', [SCRIPT, '--input', sampleMd, '--template', '/nonexistent/template.html', '--output', tmpOut], {
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        assert.fail('Should have exited with error');
      } catch (e) {
        assert.equal(e.status, 1);
      }
    });

    it('should handle empty MD file', () => {
      const emptyMd = join(TMP_DIR, 'empty.md');
      fs.writeFileSync(emptyMd, '', 'utf-8');
      try {
        execFileSync('node', [SCRIPT, '--input', emptyMd, '--template', TEMPLATE, '--output', tmpOut], { encoding: 'utf-8' });
        const html = fs.readFileSync(tmpOut, 'utf-8');
        assert.ok(html.length > 0, 'Should produce template shell');
        assert.ok(!html.includes('{{'), 'No placeholder residue');
      } finally {
        if (fs.existsSync(emptyMd)) fs.unlinkSync(emptyMd);
      }
    });
  });
});
