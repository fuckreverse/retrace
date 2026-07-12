import { describe, expect, it } from 'vitest';
import { alternateLocalePath, detectLocale, localizedPath } from '../src/lib/i18n';

describe('locale routes', () => {
  it('detects Chinese browser preferences', () => {
    expect(detectLocale('zh-CN,zh;q=0.9,en;q=0.8')).toBe('zh-CN');
    expect(detectLocale('en-US,en;q=0.9')).toBe('en');
  });

  it('creates prefixed paths and preserves the corresponding page', () => {
    expect(localizedPath('en', '/download/')).toBe('/en/download/');
    expect(alternateLocalePath('/en/product/capture/')).toBe('/zh-CN/product/capture/');
    expect(alternateLocalePath('/zh-CN/docs/getting-started/')).toBe('/en/docs/getting-started/');
  });
});
