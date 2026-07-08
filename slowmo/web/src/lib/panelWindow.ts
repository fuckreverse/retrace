/**
 * 单面板窗口路由 —— 通过 URL 查询参数 `?panel=<id>` 决定：
 *   - 无 panel 参数：正常渲染完整 Shell（主窗口）。
 *   - 有 panel 参数：只渲染该面板（弹出的独立窗口，与主窗口通过 windowSync 联动）。
 *
 * 面板 id 与 CenterArea/Sidebar 的 tab value 对齐；此处维护「可弹出」的白名单。
 */

/** 当前支持弹出到独立窗口的面板 id → 展示标题 */
export const POPOUT_PANELS: Record<string, string> = {
  vm: 'VM Workspace',
};

/** 读取当前 URL 的 panel 参数（无 / 非法则返回 null） */
export function getPanelParam(): string | null {
  if (typeof window === 'undefined') return null;
  const p = new URLSearchParams(window.location.search).get('panel');
  return p && p in POPOUT_PANELS ? p : null;
}

/** 当前是否为「单面板」子窗口 */
export function isPanelWindow(): boolean {
  return getPanelParam() !== null;
}

/** 构造弹出窗口的 URL（保留当前 origin + path，替换 query） */
export function panelWindowUrl(panelId: string): string {
  const base = `${window.location.origin}${window.location.pathname}`;
  return `${base}?panel=${encodeURIComponent(panelId)}`;
}
