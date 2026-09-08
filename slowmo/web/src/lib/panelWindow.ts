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

/**
 * 读取 URL 中的后端 WS 端口参数（`&ws=<port>`）。
 * 弹出面板子窗口用它连到正确的后端实例——子窗口不共享主窗口的
 * dynamicWsPort（独立 JS 上下文），缺省会错误连到 9090。
 * 缺失/非法时返回 null（回退默认 9090，浏览器 proxy 模式不受影响）。
 */
export function getPanelWsPort(): number | null {
  if (typeof window === 'undefined') return null;
  const raw = new URLSearchParams(window.location.search).get('ws');
  const port = raw ? Number(raw) : NaN;
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : null;
}

/** 当前是否为「单面板」子窗口 */
export function isPanelWindow(): boolean {
  return getPanelParam() !== null;
}

/**
 * 构造弹出窗口的 URL（保留当前 origin + path，替换 query）。
 * wsPort 非空时附加 `&ws=<port>`，让子窗口直连正确的后端实例。
 */
export function panelWindowUrl(panelId: string, wsPort?: number | null): string {
  const base = `${window.location.origin}${window.location.pathname}`;
  const portSuffix = wsPort != null ? `&ws=${wsPort}` : '';
  return `${base}?panel=${encodeURIComponent(panelId)}${portSuffix}`;
}
