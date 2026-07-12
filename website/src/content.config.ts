import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

function preserveLocaleCase({ entry }: { entry: string }): string {
  return entry
    .replace(/\\/g, '/')
    .replace(/\.(?:md|mdx|markdown|mdown|mkdn|mkd|mdwn)$/, '')
    .replace(/\/index$/, '');
}

export const collections = {
  docs: defineCollection({ loader: docsLoader({ generateId: preserveLocaleCase }), schema: docsSchema() }),
};
