/**
 * 面板 tab 分组路由 —— 让菜单项能定向切换到任意分组容器里的 tab。
 *
 * 4 个分组：
 *   - 'left'          → SidebarLeft   (functions / strings)
 *   - 'right'         → SidebarRight  (hexdump / memory)
 *   - 'center-top'    → CenterArea 上栏 (instructions / cfg / strings / regtl / dataflow)
 *   - 'center-bottom' → CenterArea 下栏 (analysis / callstack / patterns / … / settings)
 *
 * 通过 window CustomEvent 广播，各分组容器只响应自己组的事件（避免 tab 值跨组冲突）。
 * 浏览器与 Tauri 共用同一机制。
 */
import type { TabGroup } from './menu';

export const SELECT_TAB_EVENT = 'tenet:select-tab';

export interface SelectTabDetail {
  group: TabGroup;
  tab: string;
}

/** 请求把某个分组切换到指定 tab */
export function selectTab(group: TabGroup, tab: string): void {
  window.dispatchEvent(
    new CustomEvent<SelectTabDetail>(SELECT_TAB_EVENT, { detail: { group, tab } }),
  );
}
