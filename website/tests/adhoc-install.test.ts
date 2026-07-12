import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');
const download = read('../src/pages/[locale]/download.astro');
const installEn = read('../src/content/docs/en/docs/getting-started/install.md');
const installZh = read('../src/content/docs/zh-CN/docs/getting-started/install.md');

describe('ad-hoc signed macOS distribution guidance', () => {
  it('warns on the localized download page before installation', () => {
    for (const phrase of [
      'ad-hoc signed',
      '未经 Apple 公证',
      'Gatekeeper',
      'com.apple.quarantine',
      '/Applications/Tenet.app',
    ]) expect(download).toContain(phrase);
  });

  it('documents the complete English Gatekeeper recovery flow', () => {
    for (const phrase of [
      'ad-hoc signature',
      'not notarized by Apple',
      'xattr -dr com.apple.quarantine /Applications/Tenet.app',
      'open /Applications/Tenet.app',
      'sudo spctl --master-disable',
      'Apple Silicon',
    ]) expect(installEn).toContain(phrase);
  });

  it('documents the complete Chinese Gatekeeper recovery flow', () => {
    for (const phrase of [
      'ad-hoc 签名',
      '未经 Apple 公证',
      'xattr -dr com.apple.quarantine /Applications/Tenet.app',
      'open /Applications/Tenet.app',
      'sudo spctl --master-disable',
      'Apple Silicon',
    ]) expect(installZh).toContain(phrase);
  });
});
