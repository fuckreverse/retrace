import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');
const page = read('../src/pages/[locale]/third-party-notices.astro');
const footer = read('../src/components/SiteFooter.astro');
const download = read('../src/pages/[locale]/download.astro');

describe('third-party software notices', () => {
  it('publishes matching English and Chinese disclosures', () => {
    for (const phrase of [
      'Third-Party Software',
      '第三方软件声明',
      'do not grant rights to Tenet’s proprietary code',
      '不适用于 Tenet 的专有代码',
      'included with every Tenet distribution',
      '每份 Tenet 发布包',
    ]) expect(page).toContain(phrase);
  });

  it('lists the major shipped components without claiming GraphGridLayout is resolved', () => {
    for (const component of ['QBDI', 'LLVM', 'Triton', 'Z3', 'YARA', 'RocksDB', 'Capstone']) {
      expect(page).toContain(component);
    }
    expect(page).not.toContain('GraphGridLayout');
  });

  it('links the disclosure from the footer and download page', () => {
    expect(footer).toContain("'/third-party-notices/'");
    expect(download).toContain("'/third-party-notices/'");
  });
});
