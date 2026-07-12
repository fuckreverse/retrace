export const locales = ['en', 'zh-CN'] as const;
export type Locale = (typeof locales)[number];

export function detectLocale(acceptLanguage = ''): Locale {
  return acceptLanguage.toLowerCase().includes('zh') ? 'zh-CN' : 'en';
}

export function localizedPath(locale: Locale, path = '/'): string {
  const normalized = path === '/' ? '' : `/${path.replace(/^\/+|\/+$/g, '')}`;
  return `/${locale}${normalized}/`;
}

export function alternateLocalePath(pathname: string): string {
  if (pathname === '/en' || pathname.startsWith('/en/')) return pathname.replace(/^\/en(?=\/|$)/, '/zh-CN');
  if (pathname === '/zh-CN' || pathname.startsWith('/zh-CN/')) return pathname.replace(/^\/zh-CN(?=\/|$)/, '/en');
  return '/en/';
}

export function isLocale(value: string | undefined): value is Locale {
  return value === 'en' || value === 'zh-CN';
}
