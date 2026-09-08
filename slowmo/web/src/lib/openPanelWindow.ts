/**
 * 把某个面板弹出到独立窗口。环境自适应：
 *   - Tauri：创建原生 WebviewWindow（真正的独立 OS 窗口，可拖到另一显示器）。
 *   - 浏览器：window.open 开新窗口。
 *
 * 两者都加载同源的 `?panel=<id>` URL，由 App 路由到 PanelWindow，
 * 并通过 windowSync（BroadcastChannel）与主窗口实时联动。
 */
import { isTauri } from './env';
import { getWsPort } from '@/api/ws';
import { panelWindowUrl, POPOUT_PANELS } from './panelWindow';

/** 已打开的浏览器子窗口引用（避免重复开、便于聚焦） */
const browserWindows = new Map<string, Window>();

export async function openPanelWindow(panelId: string): Promise<void> {
  if (!(panelId in POPOUT_PANELS)) return;
  const title = POPOUT_PANELS[panelId];

  if (isTauri()) {
    // 动态导入，保持浏览器主包干净
    try {
      const { WebviewWindow } = await import('@tauri-apps/api/webviewWindow');
      const label = `panel-${panelId}`;
      const existing = await WebviewWindow.getByLabel(label);
      if (existing) {
        await existing.setFocus();
        return;
      }
      const win = new WebviewWindow(label, {
        // 附加当前后端 WS 端口：子窗口是独立 JS 上下文，不共享主窗口的
        // dynamicWsPort，必须通过 URL 传递才能连到正确的后端实例
        //（多 trace 并行时端口是 9090+n）。
        url: `index.html?panel=${encodeURIComponent(panelId)}${getWsPort() != null ? `&ws=${getWsPort()}` : ''}`,
        title: `Tenet · ${title}`,
        width: 900,
        height: 640,
        resizable: true,
      });
      win.once('tauri://error', (e) => {
        // eslint-disable-next-line no-console
        console.error('[openPanelWindow] failed to create webview window', e);
      });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[openPanelWindow] tauri webview import failed', err);
    }
    return;
  }

  // 浏览器：复用已开窗口或新开
  const prev = browserWindows.get(panelId);
  if (prev && !prev.closed) {
    prev.focus();
    return;
  }
  const w = window.open(
    panelWindowUrl(panelId, getWsPort()),
    `tenet-panel-${panelId}`,
    'width=900,height=640,menubar=no,toolbar=no',
  );
  if (w) browserWindows.set(panelId, w);
}
