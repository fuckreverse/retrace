/**
 * Hex Dump 跨面板联动入口 —— 补齐"跳到 Hex Dump"的最后一公里。
 *
 * 以前 Mem Access 点地址 / Registers 右键 Open Value / Instructions 右键
 * Open PC 只更新 hexAddr（store 数据联动），但 Hex Dump tab 不会自动切换、
 * 折叠的右栏也不会展开——用户停在别的 tab 时点完完全无反馈。
 *
 * 本助手统一"数据 + 视图"三件事：
 *   1. setHexAddr(addr)        —— Hex Dump 面板定位到该地址
 *   2. 展开右栏（若已折叠）     —— 折叠状态下切 tab 不可见
 *   3. selectTab('right','hexdump') —— 切到 Hex Dump tab（含分组路由事件）
 *
 * 所有"Open in Hex Dump"类动作都应走这里，不要再直接调 setHexAddr。
 */
import { useTraceStore } from '@/store/traceStore';
import { useSettingsStore } from '@/store/settingsStore';
import { selectTab } from './tabRouting';

export function openInHexDump(addr: string): void {
  useTraceStore.getState().setHexAddr(addr);
  const settings = useSettingsStore.getState();
  if (settings.sidebarRightCollapsed) {
    settings.toggleSidebarRightCollapsed();
  }
  selectTab('right', 'hexdump');
}
