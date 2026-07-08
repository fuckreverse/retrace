/**
 * 运行环境判定工具。
 * isTauri(): 判断当前是否运行在 Tauri webview 内。
 * 用于让前端在浏览器 / Tauri 两种环境下走不同分支（endpoint、菜单呈现等）。
 */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

/**
 * Mock 调试模式：URL 带 `?mock=1`（或 `?mock=true`）时开启。
 * 用于纯前端 UI 联调——跳过 Welcome 打开流程与真实 WS 后端探测，
 * 直接进入分析主界面并使用 `src/mock/data.ts` 的假数据。
 * 见 `pnpm dev:mock`（vite.config.ts 未做特殊处理，只是自动带上该 query 打开浏览器）。
 */
export function isMockMode(): boolean {
  if (typeof window === 'undefined') return false;
  const v = new URLSearchParams(window.location.search).get('mock');
  return v === '1' || v === 'true';
}
