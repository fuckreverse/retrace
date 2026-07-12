import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const docsRoot = new URL('../src/content/docs', import.meta.url).pathname;
const localeRoot = (locale: 'en' | 'zh-CN') => join(docsRoot, locale, 'docs');

function markdownFiles(root: string): string[] {
  return readdirSync(root).flatMap((name) => {
    const path = join(root, name);
    return statSync(path).isDirectory() ? markdownFiles(path) : path.endsWith('.md') ? [path] : [];
  });
}

const expectedPages = [
  // Getting Started
  'getting-started/index.md',
  'getting-started/install.md',
  'getting-started/record-and-open.md',
  'getting-started/core-concepts.md',
  'getting-started/open-a-trace.md',
  // Explore
  'explore/index.md',
  'explore/desktop.md',
  'explore/tui.md',
  'explore/navigation.md',
  // Analyze
  'analyze/index.md',
  'analyze/structure.md',
  'analyze/taint.md',
  'analyze/memory.md',
  'analyze/algorithms.md',
  'analyze/platform.md',
  'analyze/trace-tools.md',
  'analyze/vmp.md',
  // Automate
  'automate/index.md',
  'automate/cli.md',
  'automate/rpc.md',
  'automate/mcp.md',
  'automate/websocket.md',
  // Reference
  'reference/index.md',
  'reference/pass-catalog.md',
  'reference/compatibility.md',
];

const catalogPasses = [
  'function', 'xref', 'cfg', 'cfg_layout', 'call_graph', 'loop',
  'taint', 'backward_taint', 'taint_source_annotation',
  'pattern', 'loop_semantics', 'algorithm_summary', 'objc_crypto',
  'strings', 'memory_strings', 'memory_snapshot', 'mem_search', 'entropy', 'yara_mem_scan',
  'objc', 'syscall_intercept',
  'trace_fold', 'reg_timeline', 'call_context', 'window_stats', 'trace_diff', 'dataflow_graph',
  'thread', 'thread_filter', 'vm_abstract',
];

describe('Tenet public documentation structure', () => {
  it('publishes every approved page in both locales', () => {
    for (const locale of ['en', 'zh-CN'] as const) {
      for (const page of expectedPages) {
        expect(existsSync(join(localeRoot(locale), page)), `${locale}/${page}`).toBe(true);
      }
    }
  });

  it('keeps English and Chinese markdown routes in lockstep', () => {
    const routes = (locale: 'en' | 'zh-CN') =>
      markdownFiles(localeRoot(locale)).map((file) => relative(localeRoot(locale), file)).sort();
    expect(routes('zh-CN')).toEqual(routes('en'));
  });

  it('documents all catalog passes in the pass catalog', () => {
    for (const locale of ['en', 'zh-CN'] as const) {
      const catalog = readFileSync(join(localeRoot(locale), 'reference/pass-catalog.md'), 'utf8');
      for (const pass of catalogPasses) {
        expect(catalog, `${locale}: ${pass}`).toContain(`\`${pass}\``);
      }
    }
  });

  it('documents merged and deprecated pass names in the catalog', () => {
    for (const locale of ['en', 'zh-CN'] as const) {
      const catalog = readFileSync(join(localeRoot(locale), 'reference/pass-catalog.md'), 'utf8');
      // constant_materialization was merged into pattern
      expect(catalog).toMatch(/constant_materialization|merged into.*pattern/i);
      // literal_search is a deprecated alias for mem_search
      expect(catalog).toMatch(/literal_search|deprecated alias/i);
    }
  });

  it('publishes compatibility boundaries', () => {
    for (const locale of ['en', 'zh-CN'] as const) {
      const compatibility = readFileSync(join(localeRoot(locale), 'reference/compatibility.md'), 'utf8');
      expect(compatibility).toContain('HF_HAS_CODE');
      expect(compatibility).toContain('vm_abstract');
    }
  });

  it('does not mention open-source or repository hosts', () => {
    const forbidden = ['github.com', 'githubusercontent', 'open.source', 'opensource'];
    for (const locale of ['en', 'zh-CN'] as const) {
      for (const file of markdownFiles(localeRoot(locale))) {
        const content = readFileSync(file, 'utf8').toLowerCase();
        for (const term of forbidden) {
          expect(content, `${relative(localeRoot(locale), file)}: ${term}`).not.toContain(term);
        }
      }
    }
  });
});
