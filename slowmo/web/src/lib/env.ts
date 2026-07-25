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

/**
 * 是否运行在 macOS 上（浏览器 / Tauri 均适用）。
 * 用于展示层的平台自适应——例如快捷键提示文案（Cmd vs Ctrl）、
 * 是否渲染 macOS 风格的 App 菜单等。不依赖 Tauri API，浏览器环境
 * 也能正确判断（用于纯浏览器调试 / 未来 Web 版本）。
 *
 * `navigator.userAgentData.platform` 是更新的标准 API，但 Safari/Firefox
 * 尚未实现，因此优先回退到 `navigator.platform`（已废弃但兼容性更好）
 * 和 `navigator.userAgent` 字符串匹配。
 */
export function isMacPlatform(): boolean {
  if (typeof navigator === 'undefined') return false;
  const uaData = (navigator as unknown as { userAgentData?: { platform?: string } }).userAgentData;
  // Prefer the first *non-empty* source rather than plain `??`: an empty
  // string is falsy-for-our-purposes but not nullish, so `?? ''` would
  // silently keep an empty `userAgentData.platform` instead of falling
  // back to `navigator.platform`.
  const platform = uaData?.platform || navigator.platform || '';
  if (/mac/i.test(platform)) return true;
  return /mac/i.test(navigator.userAgent || '');
}

/** 展示用的"主修饰键"名称：macOS 上是 "Cmd"，其余平台是 "Ctrl"。 */
export function modKeyLabel(): string {
  return isMacPlatform() ? 'Cmd' : 'Ctrl';
}

/**
 * 把菜单定义里以 "Cmd+" 书写的快捷键提示转换为当前平台的展示文案。
 * 仅用于 UI 展示（HTML 菜单 tooltip / 原生菜单在非 macOS 平台的等价
 * 呈现），不影响实际按键绑定——真正的加速键由 Tauri 侧
 * `.accelerator("CmdOrCtrl+...")` 处理，Tauri/OS 自身已按平台正确解释。
 */
export function displayShortcut(shortcut: string): string {
  return isMacPlatform() ? shortcut : shortcut.replace(/Cmd/g, 'Ctrl');
}
