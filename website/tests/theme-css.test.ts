import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const css = readFileSync(new URL('../src/styles/starlight.css', import.meta.url), 'utf8');

describe('Starlight theme contract', () => {
  it('defines a complete light palette', () => {
    expect(css).toMatch(/:root\[data-theme=['"]light['"]\]/);
    expect(css).toContain('--sl-color-bg:');
    expect(css).toContain('--sl-color-bg-nav:');
    expect(css).toContain('--sl-color-bg-sidebar:');
    expect(css).toContain('--sl-color-text:');
  });

  it('uses semantic theme variables for custom surfaces', () => {
    expect(css).toMatch(/background:\s*var\(--sl-color-bg-nav\)/);
    expect(css).toMatch(/background:\s*var\(--sl-color-bg-inline-code\)/);
    expect(css).not.toMatch(/header\.header[^}]*#070b10/i);
    expect(css).not.toMatch(/\.sl-markdown-content code[^}]*#0b1218/i);
  });
});
