import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function sourceFiles(root: string): string[] {
  return readdirSync(root).flatMap((name) => {
    const path = join(root, name);
    return statSync(path).isDirectory() ? sourceFiles(path) : /\.(astro|md|mdx)$/.test(path) ? [path] : [];
  });
}

describe('closed-source product language', () => {
  it('does not advertise source hosting or contributions', () => {
    const files = sourceFiles(new URL('../src', import.meta.url).pathname);
    const forbidden = /github|open[ -]?source|开源|贡献者|\bcontribute\b|\bcontributors?\b|\bcontributing\s+(?:code|guide|workflow)\b/i;
    for (const file of files) {
      expect(readFileSync(file, 'utf8'), file).not.toMatch(forbidden);
    }
  });
});

describe('Tenet homepage positioning', () => {
  const home = readFileSync(new URL('../src/pages/[locale]/index.astro', import.meta.url), 'utf8');
  const homepageCopy = readFileSync(new URL('../src/lib/copy.ts', import.meta.url), 'utf8');
  const homepageSources = `${home}\n${homepageCopy}`;

  it('describes trace indexing and state reconstruction in engineering terms', () => {
    for (const token of [
      'Instruction trace analysis',
      'Point-in-time state reconstruction',
      'Executed control-flow recovery',
      'Register and memory provenance',
      '大规模指令 Trace 分析',
      '指定指令点状态重建',
      '实际执行控制流恢复',
    ]) {
      expect(homepageSources).toContain(token);
    }
  });

  it('presents automation as an interface rather than the product narrative', () => {
    expect(home).toContain('GUI / TUI');
    expect(home).toContain('CLI / RPC');
    expect(home).toContain('MCP / WebSocket');
    expect(home).toContain('LLM clients');
    expect(home).toContain('LLM 客户端');
  });

  it('does not use the previous slogan-heavy positioning', () => {
    for (const slogan of [
      'execution truth',
      'EXECUTION EVIDENCE FOR HUMAN + AI',
      'Evidence, not narration',
      'Give every investigation a factual foundation',
      '不要把 Trace 当日志读',
      '把执行过程变成可查询证据',
      '证据，而不是叙述',
      '为每次调查建立事实基础',
    ]) {
      expect(homepageSources).not.toContain(slogan);
    }
  });

  it('publishes a four-stage workflow and concrete investigation scenarios', () => {
    for (const token of ['01 / CAPTURE', '02 / INDEX', '03 / ANALYZE', '04 / EXPORT']) {
      expect(home).toContain(token);
    }
    for (const token of ['Signature and encryption routines', 'Source-to-sink tracing', 'VM protection analysis', 'Trace comparison']) {
      expect(home).toContain(token);
    }
  });

  it('presents performance as the condition for billion-scale trace usability', () => {
    for (const token of [
      'PERFORMANCE / BILLION-INSTRUCTION TRACES',
      'BILLION-INSTRUCTION TRACE',
      'Memory-mapped IO',
      'Block compression',
      'Persistent index',
      'Scan Fusion',
      '十亿级指令',
      '内存映射',
      '分块压缩',
    ]) {
      expect(home).toContain(token);
    }
  });

  it('routes top-level product navigation to the richer homepage sections', () => {
    const header = readFileSync(new URL('../src/components/SiteHeader.astro', import.meta.url), 'utf8');
    expect(header).toContain("`${localizedPath(locale)}#product`");
    expect(header).toContain("`${localizedPath(locale)}#workflow`");
    expect(header).toContain("`${localizedPath(locale)}#use-cases`");
  });
});

describe('capture contract language', () => {
  const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');

  it('presents QBDITrace as the official capture implementation, not a requirement', () => {
    const home = source('../src/pages/[locale]/index.astro');
    const captureEn = source('../src/content/docs/en/docs/capture/index.md');
    const captureZh = source('../src/content/docs/zh-CN/docs/capture/index.md');

    expect(home).toContain('official QBDITrace');
    expect(home).toContain('compatible collector');
    expect(captureEn).toContain('Frida Stalker');
    expect(captureZh).toContain('Frida Stalker');
  });

  it('publishes the compatibility tiers and core binary contract in both locales', () => {
    for (const path of [
      '../src/content/docs/en/docs/reference/index.md',
      '../src/content/docs/zh-CN/docs/reference/index.md',
    ]) {
      const reference = source(path);
      expect(reference).toContain('0x51424454');
      expect(reference).toContain('536');
      expect(reference).toContain('REC_INST');
      expect(reference).toContain('REC_ANCHOR');
      expect(reference).toContain('REC_CODE');
      expect(reference).toContain('HF_BLOCK_COMPRESSED');
      expect(reference).toContain('Frida Stalker');
    }
  });
});
