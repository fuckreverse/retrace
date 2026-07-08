/**
 * UI 设置状态 —— 管理所有用户可配置的外观项。
 * 持久化策略：浏览器走 localStorage；Tauri 走 invoke('load_config'/'save_config')。
 * 修改设置后自动将 CSS 自定义属性注入到 <html> 的 style 中，
 * 全局样式无需额外订阅即可响应。
 *
 * 参考 IDA Pro 的 Options → General / Colors / Font 设置：
 *   - 页面缩放（整页 DPI 类似）
 *   - 字体族 & 大小（UI 字体 / 反汇编字体分别设置）
 *   - UI 密度（行高/间距）
 *   - 主题色方案（多套预设 + 自定义）
 *   - 强调色可覆盖
 */
import { create } from 'zustand';
import { isTauri } from '@/lib/env';

// Tauri invoke 只在运行时动态导入，避免非 Tauri 环境打包报错
async function tauriInvoke(cmd: string, args?: Record<string, unknown>): Promise<unknown> {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke(cmd, args);
}

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

/** 页面缩放 (0.6 ~ 2.0)，对应 CSS zoom / transform:scale */
export type ZoomLevel = number;

/** UI 密度预设 —— 影响行高、间距、组件尺寸 */
export type UIDensity = 'compact' | 'default' | 'comfortable';

/** 主题色方案 —— 每种对应 tokens.css 里的一套完整色板 */
export type ColorScheme =
  | 'dark'
  | 'light'
  | 'one-dark'
  | 'dracula'
  | 'solarized-dark'
  | 'nord'
  | 'github-light';

/** 滚动条宽度 */
export type ScrollbarWidth = 'thin' | 'default' | 'wide';

export interface SettingsState {
  // ─── 缩放 ──────────────────────────────────────────
  zoom: ZoomLevel;

  // ─── 字体 ──────────────────────────────────────────
  /** UI 字体族 */
  fontSans: string;
  /** 等宽字体族（反汇编/寄存器/地址） */
  fontMono: string;
  /** UI 基准字号 (px)，所有 fs-* 按比例缩放 */
  fsBase: number;
  /** 等宽字体缩放系数（相对 UI 字号） */
  fsMonoScale: number;

  // ─── UI 密度 ────────────────────────────────────────
  density: UIDensity;

  // ─── 主题色 ─────────────────────────────────────────
  colorScheme: ColorScheme;
  /** 自定义强调色（HSL hue 0~360），null 则使用方案默认 */
  accentHue: number | null;

  // ─── 滚动条 ─────────────────────────────────────────
  scrollbarWidth: ScrollbarWidth;

  // ─── actions ────────────────────────────────────────
  setZoom: (z: ZoomLevel) => void;
  setFontSans: (f: string) => void;
  setFontMono: (f: string) => void;
  setFsBase: (s: number) => void;
  setFsMonoScale: (s: number) => void;
  setDensity: (d: UIDensity) => void;
  setColorScheme: (s: ColorScheme) => void;
  setAccentHue: (h: number | null) => void;
  setScrollbarWidth: (w: ScrollbarWidth) => void;
  resetToDefaults: () => void;
}

/* ------------------------------------------------------------------ */
/*  Defaults                                                           */
/* ------------------------------------------------------------------ */

const DEFAULTS: Omit<SettingsState, keyof SettingsActions> = {
  zoom: 1.0,
  fontSans: 'system',
  fontMono: 'system-mono',
  fsBase: 13,
  fsMonoScale: 1.0,
  density: 'default',
  colorScheme: 'dark',
  accentHue: null,
  scrollbarWidth: 'default',
};

type SettingsActions = Pick<SettingsState,
  | 'setZoom' | 'setFontSans' | 'setFontMono' | 'setFsBase' | 'setFsMonoScale'
  | 'setDensity' | 'setColorScheme' | 'setAccentHue' | 'setScrollbarWidth'
  | 'resetToDefaults'
>;

/* ------------------------------------------------------------------ */
/*  Persistence                                                        */
/* ------------------------------------------------------------------ */

const STORAGE_KEY = 'tenet-settings';

/** 从持久化存储读取已保存设置 */
function loadPersisted(): Partial<typeof DEFAULTS> {
  // 同步读取：启动时 Tauri invoke 是异步的，先从 localStorage 读取保证首帧可用
  // Tauri 环境下后续会通过 initFromTauri() 异步覆盖
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore corrupt */ }
  return {};
}

/** Tauri 环境下异步加载配置文件（覆盖 localStorage 的值） */
export async function initFromTauri() {
  if (!isTauri()) return;
  try {
    const raw = (await tauriInvoke('load_config')) as string;
    const config = JSON.parse(raw);
    // 合并到 store
    const store = useSettingsStore.getState();
    const merged = { ...DEFAULTS, ...config };
    store.setZoom(merged.zoom);
    store.setFontSans(merged.fontSans);
    store.setFontMono(merged.fontMono);
    store.setFsBase(merged.fsBase);
    store.setFsMonoScale(merged.fsMonoScale);
    store.setDensity(merged.density);
    store.setColorScheme(merged.colorScheme);
    store.setAccentHue(merged.accentHue);
    store.setScrollbarWidth(merged.scrollbarWidth);
  } catch { /* ignore */ }
}

/** 持久化当前设置 */
function persist(state: Partial<typeof DEFAULTS>) {
  const json = JSON.stringify(state);
  // 始终写 localStorage 作为备份
  try { localStorage.setItem(STORAGE_KEY, json); } catch { /* quota */ }
  // Tauri 环境额外写文件
  if (isTauri()) {
    tauriInvoke('save_config', { config: json }).catch(() => { /* ignore */ });
  }
}

/* ------------------------------------------------------------------ */
/*  CSS Token Injection                                                */
/* ------------------------------------------------------------------ */

/** 密度 → 尺寸 token 映射 */
const DENSITY_TOKENS: Record<UIDensity, Record<string, string>> = {
  compact: {
    '--titlebar-h': '30px',
    '--toolbar-h': '30px',
    '--statusbar-h': '22px',
    '--timeline-h': '26px',
    '--tab-h': '26px',
    '--row-h': '20px',
    '--panel-header-h': '26px',
    '--icon-btn-size': '24px',
    '--icon-btn-svg': '14px',
    '--btn-sm-h': '22px',
    '--btn-md-h': '26px',
  },
  default: {
    '--titlebar-h': '34px',
    '--toolbar-h': '34px',
    '--statusbar-h': '24px',
    '--timeline-h': '30px',
    '--tab-h': '28px',
    '--row-h': '22px',
    '--panel-header-h': '28px',
    '--icon-btn-size': '28px',
    '--icon-btn-svg': '16px',
    '--btn-sm-h': '24px',
    '--btn-md-h': '28px',
  },
  comfortable: {
    '--titlebar-h': '40px',
    '--toolbar-h': '40px',
    '--statusbar-h': '28px',
    '--timeline-h': '36px',
    '--tab-h': '34px',
    '--row-h': '26px',
    '--panel-header-h': '34px',
    '--icon-btn-size': '32px',
    '--icon-btn-svg': '18px',
    '--btn-sm-h': '28px',
    '--btn-md-h': '32px',
  },
};

/** 基准字号 → fs-* 派生表 */
function deriveFontSizes(base: number): Record<string, string> {
  return {
    '--fs-xs': `${Math.round(base * 0.846)}px`,   // ~11
    '--fs-sm': `${Math.round(base * 0.923)}px`,   // ~12
    '--fs-md': `${base}px`,                         // 13
    '--fs-lg': `${Math.round(base * 1.077)}px`,   // ~14
    '--fs-xl': `${Math.round(base * 1.23)}px`,    // ~16
    '--fs-2xl': `${Math.round(base * 1.538)}px`,  // ~20
  };
}

/** 字体族名称 → CSS font-family 值 */
const FONT_SANS_MAP: Record<string, string> = {
  'system': "-apple-system, BlinkMacSystemFont, 'PingFang SC', 'Segoe UI', 'Microsoft YaHei', system-ui, sans-serif",
  'inter': "'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif",
  'helvetica': "'Helvetica Neue', Helvetica, Arial, sans-serif",
};

const FONT_MONO_MAP: Record<string, string> = {
  'system-mono': "'SF Mono', 'JetBrains Mono', 'Fira Code', 'Menlo', 'Consolas', ui-monospace, monospace",
  'jetbrains': "'JetBrains Mono', 'Fira Code', 'Menlo', Consolas, ui-monospace, monospace",
  'fira': "'Fira Code', 'JetBrains Mono', 'Menlo', Consolas, ui-monospace, monospace",
  'menlo': "Menlo, Consolas, 'DejaVu Sans Mono', ui-monospace, monospace",
  'source-code': "'Source Code Pro', 'JetBrains Mono', Menlo, Consolas, ui-monospace, monospace",
  'iosevka': "Iosevka, 'JetBrains Mono', 'Fira Code', ui-monospace, monospace",
};

/** 滚动条宽度 → CSS 值 */
const SCROLLBAR_MAP: Record<ScrollbarWidth, string> = {
  thin: '6px',
  default: '10px',
  wide: '14px',
};

/** 主题色方案 → data-color-scheme 属性值（tokens.css 中按属性选择器匹配） */
function applyColorScheme(scheme: ColorScheme) {
  if (typeof document === 'undefined') return;
  // dark/light 走 data-theme 属性（已有 CSS 规则）
  // 其余方案走 data-color-scheme 属性
  const el = document.documentElement;
  if (scheme === 'dark' || scheme === 'light') {
    el.setAttribute('data-theme', scheme);
    el.removeAttribute('data-color-scheme');
    el.style.colorScheme = scheme;
  } else {
    // 非 dark/light 方案：设置 data-theme 为方案名（用于通用深/浅选择器），
    // 同时设置 data-color-scheme 用于精确匹配
    const isLight = scheme === 'github-light';
    el.setAttribute('data-theme', isLight ? 'light' : 'dark');
    el.setAttribute('data-color-scheme', scheme);
    el.style.colorScheme = isLight ? 'light' : 'dark';
  }
}

/** 将所有设置项注入到 <html> 的 style 中（覆盖 tokens.css 默认值） */
function injectCSS(state: Partial<typeof DEFAULTS>) {
  if (typeof document === 'undefined') return;
  const el = document.documentElement;
  const s = el.style;

  // 1) 缩放
  if (state.zoom !== undefined) {
    s.setProperty('--app-zoom', String(state.zoom));
  }

  // 2) 字体
  if (state.fontSans !== undefined) {
    s.setProperty('--font-sans', FONT_SANS_MAP[state.fontSans] ?? FONT_SANS_MAP['system']);
  }
  if (state.fontMono !== undefined) {
    const family = FONT_MONO_MAP[state.fontMono] ?? FONT_MONO_MAP['system-mono'];
    s.setProperty('--font-mono', family);
  }
  if (state.fsBase !== undefined) {
    const sizes = deriveFontSizes(state.fsBase);
    for (const [k, v] of Object.entries(sizes)) {
      s.setProperty(k, v);
    }
  }
  if (state.fsMonoScale !== undefined) {
    s.setProperty('--fs-mono-scale', String(state.fsMonoScale));
  }

  // 3) 密度
  if (state.density !== undefined) {
    const tokens = DENSITY_TOKENS[state.density];
    for (const [k, v] of Object.entries(tokens)) {
      s.setProperty(k, v);
    }
  }

  // 4) 主题色方案
  if (state.colorScheme !== undefined) {
    applyColorScheme(state.colorScheme);
  }

  // 5) 强调色覆盖
  if (state.accentHue !== undefined) {
    if (state.accentHue === null) {
      s.removeProperty('--accent-hue');
    } else {
      s.setProperty('--accent-hue', String(state.accentHue));
    }
  }

  // 6) 滚动条宽度
  if (state.scrollbarWidth !== undefined) {
    s.setProperty('--scrollbar-w', SCROLLBAR_MAP[state.scrollbarWidth] ?? SCROLLBAR_MAP['default']);
  }
}

/* ------------------------------------------------------------------ */
/*  Store                                                              */
/* ------------------------------------------------------------------ */

const persisted = loadPersisted();
const initial = { ...DEFAULTS, ...persisted };

// 启动时立即注入 CSS（保证首帧即生效）
injectCSS(initial);
// 首帧也要应用色板
applyColorScheme(initial.colorScheme);

export const useSettingsStore = create<SettingsState>((set, get) => ({
  ...initial,

  setZoom(z) { set({ zoom: z }); injectCSS({ zoom: z }); persist(get()); },
  setFontSans(f) { set({ fontSans: f }); injectCSS({ fontSans: f }); persist(get()); },
  setFontMono(f) { set({ fontMono: f }); injectCSS({ fontMono: f }); persist(get()); },
  setFsBase(s) { set({ fsBase: s }); injectCSS({ fsBase: s }); persist(get()); },
  setFsMonoScale(s) { set({ fsMonoScale: s }); injectCSS({ fsMonoScale: s }); persist(get()); },
  setDensity(d) { set({ density: d }); injectCSS({ density: d }); persist(get()); },
  setColorScheme(s) { set({ colorScheme: s }); injectCSS({ colorScheme: s }); persist(get()); },
  setAccentHue(h) { set({ accentHue: h }); injectCSS({ accentHue: h }); persist(get()); },
  setScrollbarWidth(w) { set({ scrollbarWidth: w }); injectCSS({ scrollbarWidth: w }); persist(get()); },

  resetToDefaults() {
    set(DEFAULTS);
    injectCSS(DEFAULTS);
    applyColorScheme(DEFAULTS.colorScheme);
    persist(DEFAULTS);
  },
}));
