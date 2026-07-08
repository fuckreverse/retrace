/**
 * 主题状态 —— 亮/暗切换的便捷接口。
 * 内部代理 settingsStore.colorScheme，保持向后兼容。
 * 新代码请直接使用 useSettingsStore。
 */
import { create } from 'zustand';
import { useSettingsStore, type ColorScheme } from './settingsStore';

export type Theme = 'dark' | 'light';

function schemeToTheme(s: ColorScheme): Theme {
  return s === 'light' || s === 'github-light' ? 'light' : 'dark';
}

interface ThemeState {
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggle: () => void;
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  theme: schemeToTheme(useSettingsStore.getState().colorScheme),
  setTheme(t) {
    // 切换主题时保留深色/浅色偏好，选择对应的色板
    const scheme: ColorScheme = t === 'light' ? 'light' : 'dark';
    useSettingsStore.getState().setColorScheme(scheme);
    set({ theme: t });
  },
  toggle() {
    get().setTheme(get().theme === 'dark' ? 'light' : 'dark');
  },
}));

// 监听 settingsStore 的色板变更，同步 theme
useSettingsStore.subscribe((state) => {
  const newTheme = schemeToTheme(state.colorScheme);
  const current = useThemeStore.getState().theme;
  if (newTheme !== current) {
    useThemeStore.setState({ theme: newTheme });
  }
});
