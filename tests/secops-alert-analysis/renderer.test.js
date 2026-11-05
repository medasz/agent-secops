import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  renderCollapsibleSection,
  calculateExactTotal,
  renderMarkdownTable,
  getCollapsibleStyles,
} from '../../skills/secops-alert-analysis/scripts/shared/report-renderer.js';

describe('report-renderer module', () => {
  describe('renderCollapsibleSection', () => {
    it('should collapse when rows > 20 (no open attribute)', () => {
      const html = renderCollapsibleSection('External IPs', 30, '<table>...</table>');
      assert.ok(html.includes('<details>'), 'Should have <details> tag');
      assert.ok(!html.includes('<details open>'), 'Should NOT have open attribute for >20 rows');
      assert.ok(html.includes('External IPs（共 30 条）'), 'Summary should show row count');
    });

    it('should expand when rows <= 20 (has open attribute)', () => {
      const html = renderCollapsibleSection('Internal IPs', 10, '<table>...</table>');
      assert.ok(html.includes('<details open>'), 'Should have open attribute for <=20 rows');
      assert.ok(html.includes('Internal IPs（共 10 条）'), 'Summary should show row count');
    });

    it('should collapse at exactly 21 rows', () => {
      const html = renderCollapsibleSection('Test', 21, '<p>content</p>');
      assert.ok(!html.includes('open'), 'Should collapse at 21 rows');
    });

    it('should expand at exactly 20 rows', () => {
      const html = renderCollapsibleSection('Test', 20, '<p>content</p>');
      assert.ok(html.includes('<details open>'), 'Should expand at 20 rows');
    });

    it('should include the content inside the details block', () => {
      const content = '<table><tr><td>Data</td></tr></table>';
      const html = renderCollapsibleSection('Test', 5, content);
      assert.ok(html.includes(content), 'Should include the inner content');
    });
  });

  describe('calculateExactTotal', () => {
    it('should return bucketSum + sumOtherDocCount', () => {
      assert.equal(calculateExactTotal(316, 64), 380);
    });

    it('should return bucketSum when sumOtherDocCount is 0', () => {
      assert.equal(calculateExactTotal(316, 0), 316);
    });

    it('should handle zero bucketSum', () => {
      assert.equal(calculateExactTotal(0, 100), 100);
    });

    it('should handle both zero', () => {
      assert.equal(calculateExactTotal(0, 0), 0);
    });
  });

  describe('renderMarkdownTable', () => {
    it('should produce valid markdown table', () => {
      const headers = ['Name', 'Count'];
      const rows = [['Alice', '10'], ['Bob', '20']];
      const table = renderMarkdownTable(headers, rows);

      assert.ok(table.includes('| Name'), 'Should have header');
      assert.ok(table.includes('| Count'), 'Should have second header');
      assert.ok(table.includes('| Alice'), 'Should have first row');
      assert.ok(table.includes('| Bob'), 'Should have second row');
      assert.ok(table.includes('---'), 'Should have separator');
    });

    it('should handle empty rows', () => {
      const table = renderMarkdownTable(['A', 'B'], []);
      assert.ok(table.includes('| A'));
      assert.ok(table.includes('| B'));
      // Separator row uses at least one hyphen per column
      assert.ok(table.includes('-'));
    });

    it('should pad columns correctly', () => {
      const headers = ['IP', 'Count'];
      const rows = [['1.2.3.4', '100'], ['10.0.0.1', '5']];
      const table = renderMarkdownTable(headers, rows);
      const lines = table.split('\n');
      // All lines should have same width
      const widths = lines.map(l => l.length);
      assert.ok(new Set(widths).size === 1 || Math.max(...widths) - Math.min(...widths) <= 1,
        'Columns should be aligned');
    });
  });

  describe('getCollapsibleStyles', () => {
    it('should return CSS string with details styling', () => {
      const styles = getCollapsibleStyles();
      assert.ok(styles.includes('details'), 'Should style details element');
      assert.ok(styles.includes('summary'), 'Should style summary element');
      assert.ok(styles.includes('@media print'), 'Should include print CSS');
      assert.ok(styles.includes('@media (max-width: 768px)'), 'Should include mobile CSS');
    });
  });
});
