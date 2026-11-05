/**
 * report-renderer.js - HTML/Markdown rendering with collapsible sections
 *
 * Generates collapsible HTML sections using <details>/<summary>.
 * Threshold: >20 rows → collapsed by default; ≤20 rows → expanded.
 */

/**
 * Generate a collapsible HTML section
 * @param {string} title - Section title (shown in summary)
 * @param {number} rows - Number of data rows
 * @param {string} content - Inner HTML content
 * @returns {string} HTML <details>/<summary> block
 */
export function renderCollapsibleSection(title, rows, content) {
  const openAttr = rows > 20 ? '' : ' open';
  const summaryText = `${title}（共 ${rows} 条）`;
  return `<details${openAttr}>\n<summary>${summaryText}</summary>\n${content}\n</details>`;
}

/**
 * Calculate exact total from ES aggregation bucket sum + sum_other_doc_count
 * @param {number} bucketSum - Sum of doc_count from all buckets
 * @param {number} sumOtherDocCount - sum_other_doc_count from ES aggregation
 * @returns {number} Exact total
 */
export function calculateExactTotal(bucketSum, sumOtherDocCount) {
  return bucketSum + sumOtherDocCount;
}

/**
 * Render a markdown table
 * @param {string[]} headers - Column headers
 * @param {string[][]} rows - Data rows (each row is array of cell values)
 * @returns {string} Formatted markdown table
 */
export function renderMarkdownTable(headers, rows) {
  const colWidths = headers.map((h, i) => {
    const maxDataWidth = rows.reduce((max, row) => Math.max(max, (row[i] || '').length), 0);
    return Math.max(h.length, maxDataWidth);
  });

  const padCell = (text, width) => (text || '').padEnd(width, ' ');

  const headerLine = '| ' + headers.map((h, i) => padCell(h, colWidths[i])).join(' | ') + ' |';
  const separatorLine = '| ' + colWidths.map((w) => '-'.repeat(w)).join(' | ') + ' |';
  const dataLines = rows.map(
    (row) => '| ' + row.map((cell, i) => padCell(cell, colWidths[i])).join(' | ') + ' |'
  );

  return [headerLine, separatorLine, ...dataLines].join('\n');
}

/**
 * Generate collapsible CSS and print CSS for HTML templates
 * @returns {string} CSS styles for collapsible sections
 */
export function getCollapsibleStyles() {
  return `
    /* Collapsible sections */
    details {
      margin-bottom: 1rem;
      border: 1px solid var(--border, #e8e6dc);
      border-radius: 6px;
      overflow: hidden;
    }

    details > summary {
      font-family: 'Poppins', sans-serif;
      padding: 0.75rem 1rem;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      background: var(--bg, #faf9f5);
      border-bottom: 1px solid var(--border, #e8e6dc);
      user-select: none;
      list-style: none;
    }

    details > summary::before {
      content: '\\25B6';
      display: inline-block;
      margin-right: 0.5rem;
      font-size: 0.75rem;
      transition: transform 0.2s;
    }

    details[open] > summary::before {
      transform: rotate(90deg);
    }

    details > summary::-webkit-details-marker {
      display: none;
    }

    details > :not(summary) {
      padding: 0 1rem;
    }

    details > table {
      margin: 0;
    }

    /* Mobile responsive */
    @media (max-width: 768px) {
      details > summary {
        font-size: 0.8125rem;
        padding: 0.5rem 0.75rem;
      }
    }

    /* Print: force all details open */
    @media print {
      details {
        display: block !important;
        break-inside: avoid;
      }
      details > summary ~ * {
        display: block !important;
      }
      details:not([open]) {
        /* Force open by making all children visible */
      }
      details > summary {
        display: block;
      }
    }
  `;
}

/**
 * Render template: replace {{var}} placeholders with actual values
 * @param {string} templateStr - Template string with {{var}} placeholders
 * @param {Object} vars - Variable key-value pairs { varName: value }
 * @returns {string} Rendered string
 */
export function renderTemplate(templateStr, vars) {
  let result = templateStr;
  for (const [key, value] of Object.entries(vars)) {
    const placeholder = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
    result = result.replace(placeholder, String(value ?? ''));
  }
  const leftover = result.match(/\{\{[^}]+\}\}/g);
  if (leftover) {
    process.stderr.write(`[WARN] gen-md-report: 未替换的占位符: ${leftover.join(', ')}\n`);
  }
  return result;
}
