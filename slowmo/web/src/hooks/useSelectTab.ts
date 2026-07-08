/**
 * 分组容器订阅菜单的 tab 切换请求。
 * 每个 Tabs 宿主（SidebarLeft/Right、CenterArea 上下栏）用自己的 group 调用本 hook，
 * 仅当事件 group 与自身一致、且目标 tab 属于本组时才切换。
 */
import { useEffect } from 'react';
import { SELECT_TAB_EVENT, type SelectTabDetail } from '@/lib/tabRouting';
import type { TabGroup } from '@/lib/menu';

export function useSelectTab(
  group: TabGroup,
  setTab: (tab: string) => void,
  validTabs: readonly string[],
): void {
  useEffect(() => {
    const onSelect = (e: Event) => {
      const detail = (e as CustomEvent<SelectTabDetail>).detail;
      if (!detail || detail.group !== group) return;
      if (!validTabs.includes(detail.tab)) return;
      setTab(detail.tab);
    };
    window.addEventListener(SELECT_TAB_EVENT, onSelect);
    return () => window.removeEventListener(SELECT_TAB_EVENT, onSelect);
    // validTabs 为稳定常量数组，setTab 为稳定 setter
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [group]);
}
