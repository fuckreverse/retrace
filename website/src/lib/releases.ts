export interface ReleaseManifest {
  version: string;
  publishedAt: string;
  platform: 'macos';
  arch: 'arm64';
  minOs: string;
  fileName: string;
  sizeBytes: number;
  sha256: string;
  objectKey: string;
  releaseNotesUrl: string;
  channel: 'preview' | 'stable';
}

export interface Release extends ReleaseManifest {
  downloadUrl: string;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0) throw new Error(`Invalid release field: ${key}`);
  return value;
}

export function parseReleaseManifest(input: unknown, downloadOrigin: string): Release {
  if (!input || typeof input !== 'object') throw new Error('Release manifest must be an object');
  const record = input as Record<string, unknown>;
  const origin = new URL(downloadOrigin);
  if (origin.protocol !== 'https:') throw new Error('Download origin must use HTTPS');

  const platform = requireString(record, 'platform');
  const arch = requireString(record, 'arch');
  const sha256 = requireString(record, 'sha256');
  const objectKey = requireString(record, 'objectKey');
  const sizeBytes = record.sizeBytes;

  if (platform !== 'macos') throw new Error('Only macOS releases are supported');
  if (arch !== 'arm64') throw new Error('Only arm64 releases are supported');
  if (!/^[a-f0-9]{64}$/i.test(sha256)) throw new Error('Invalid SHA-256');
  if (typeof sizeBytes !== 'number' || !Number.isSafeInteger(sizeBytes) || sizeBytes <= 0) throw new Error('Invalid release size');
  if (objectKey.startsWith('/') || objectKey.includes('..') || !objectKey.endsWith('.dmg')) throw new Error('Invalid immutable object key');

  const manifest: ReleaseManifest = {
    version: requireString(record, 'version'),
    publishedAt: requireString(record, 'publishedAt'),
    platform: 'macos',
    arch: 'arm64',
    minOs: requireString(record, 'minOs'),
    fileName: requireString(record, 'fileName'),
    sizeBytes,
    sha256,
    objectKey,
    releaseNotesUrl: requireString(record, 'releaseNotesUrl'),
    channel: record.channel === 'stable' ? 'stable' : 'preview',
  };
  return { ...manifest, downloadUrl: new URL(objectKey, `${origin.href.replace(/\/$/, '')}/`).href };
}

export function formatBytes(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
