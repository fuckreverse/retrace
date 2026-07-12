import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';

const site = process.env.SITE_URL ?? 'https://tenet.dev';

export default defineConfig({
  site,
  output: 'static',
  integrations: [
    sitemap(),
    starlight({
      title: 'Tenet Documentation',
      description: 'Record execution truth with QBDITrace, then explain it with Tenet.',
      customCss: ['./src/styles/starlight.css'],
      defaultLocale: 'en',
      locales: {
        en: { label: 'English', lang: 'en' },
        'zh-CN': { label: '简体中文', lang: 'zh-CN' },
      },
      social: [],
      sidebar: [
        { label: 'Getting Started', items: [
          { autogenerate: { directory: 'docs/getting-started' } },
        ] },
        { label: 'Capture', items: [{ autogenerate: { directory: 'docs/capture' } }] },
        { label: 'Explore', items: [{ autogenerate: { directory: 'docs/explore' } }] },
        { label: 'Analyze', items: [{ autogenerate: { directory: 'docs/analyze' } }] },
        { label: 'Automate', items: [{ autogenerate: { directory: 'docs/automate' } }] },
        { label: 'Reference', items: [{ autogenerate: { directory: 'docs/reference' } }] },
      ],
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#070b10' } },
      ],
    }),
  ],
  vite: { envPrefix: ['PUBLIC_', 'SITE_'] },
});
