import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const terms = readFileSync(new URL('../src/pages/[locale]/terms.astro', import.meta.url), 'utf8');

const requiredEnglish = [
  'Tenet Developer',
  'legal@tenet.dev',
  'Responsible use',
  'reverse engineer',
  'RMB 100',
  'People’s Republic of China',
  'downloaded that version',
];

const requiredChinese = [
  'Tenet 开发者',
  '负责任使用',
  '反编译',
  '人民币 100 元',
  '中华人民共和国法律',
  '下载该版本',
];

describe('terms of use coverage', () => {
  it('contains the approved English legal terms', () => {
    for (const phrase of requiredEnglish) expect(terms).toContain(phrase);
  });

  it('contains the approved Chinese legal terms', () => {
    for (const phrase of requiredChinese) expect(terms).toContain(phrase);
  });

  it('covers all numbered sections in both languages', () => {
    expect(terms.match(/number: '\d{2}'/g)).toHaveLength(30);
  });
});
