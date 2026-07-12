import { describe, expect, it } from 'vitest';
import { parseReleaseManifest } from '../src/lib/releases';

const validManifest = {
  version: '0.1.0-preview.1',
  publishedAt: '2026-07-11',
  platform: 'macos',
  arch: 'arm64',
  minOs: '14.0',
  fileName: 'Tenet-0.1.0-preview.1-arm64.dmg',
  sizeBytes: 104857600,
  sha256: 'a'.repeat(64),
  objectKey: 'releases/tenet/0.1.0-preview.1/macos-arm64/Tenet-0.1.0-preview.1-arm64.dmg',
  releaseNotesUrl: '/en/releases/',
  channel: 'preview',
};

describe('parseReleaseManifest', () => {
  it('builds an immutable HTTPS download URL', () => {
    const release = parseReleaseManifest(validManifest, 'https://downloads.tenet.dev');
    expect(release.downloadUrl).toBe(`https://downloads.tenet.dev/${validManifest.objectKey}`);
  });

  it.each([
    ['platform', 'windows'],
    ['arch', 'x64'],
    ['sha256', 'abc'],
    ['sizeBytes', 0],
    ['objectKey', '../Tenet.dmg'],
  ])('rejects invalid %s', (field, value) => {
    expect(() => parseReleaseManifest({ ...validManifest, [field]: value }, 'https://downloads.tenet.dev')).toThrow();
  });

  it('rejects a non-HTTPS download origin', () => {
    expect(() => parseReleaseManifest(validManifest, 'http://downloads.tenet.dev')).toThrow(/HTTPS/);
  });
});
