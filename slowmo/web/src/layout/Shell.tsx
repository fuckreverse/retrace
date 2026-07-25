/**
 * 应用外壳布局 —— 复刻 GUI 主窗口：
 * 标题栏 / 工具栏 / (左栏 · 中央上下 · 右栏上下) / 时间线 / 状态栏
 */
import { useEffect } from 'react';
import * as Tooltip from '@radix-ui/react-tooltip';
import { useTraceStore } from '@/store/traceStore';
import { useNativeMenu } from '@/hooks/useNativeMenu';
import { initWindowSync } from '@/lib/windowSync';
import { TitleBar } from './TitleBar';
import { Toolbar } from './Toolbar';
import { Timeline } from './Timeline';
import { StatusBar } from './StatusBar';
import { CenterArea } from './CenterArea';
import { SidebarLeft } from './SidebarLeft';
import { SidebarRight } from './SidebarRight';
import { GotoDialog, SearchDialog } from './GotoSearchDialog';
import './shell.css';

export function Shell() {
  const init = useTraceStore((s) => s.init);
  const loading = useTraceStore((s) => s.loading);
  const navBack = useTraceStore((s) => s.navBack);
  const navForward = useTraceStore((s) => s.navForward);
  const step = useTraceStore((s) => s.step);
  const openGotoDialog = useTraceStore((s) => s.openGotoDialog);
  const openSearchDialog = useTraceStore((s) => s.openSearchDialog);
  const toggleBookmark = useTraceStore((s) => s.toggleBookmark);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const currentInst = useTraceStore((s) => s.currentInst);
  const totalInst = useTraceStore((s) => s.totalInst);

  // 原生菜单事件桥接（仅 Tauri 生效，浏览器 no-op）
  useNativeMenu();

  useEffect(() => {
    init();
  }, [init]);

  // 主窗口：广播 store 状态给弹出的面板窗口（跨窗口实时联动）
  useEffect(() => initWindowSync(), []);

  // 全局快捷键
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      // 排除任何"主修饰键"（macOS: Cmd/metaKey；Windows/Linux: Ctrl/ctrlKey）
      // 组合，避免和菜单快捷键 / 浏览器或系统快捷键（如 Ctrl+↓ 的桌面切换、
      // Cmd/Ctrl+G 的浏览器"查找下一个"、Cmd/Ctrl+B 的书签栏切换）冲突。
      // 这些单键绑定都是无修饰键的裸键快捷键，一旦按下 Cmd/Ctrl 就必须放行
      // 给浏览器/系统/原生菜单处理，而不是仍按 e.key 命中触发。
      const modPressed = e.metaKey || e.ctrlKey;
      if (e.altKey && e.key === 'ArrowLeft') { navBack(); e.preventDefault(); }
      else if (e.altKey && e.key === 'ArrowRight') { navForward(); e.preventDefault(); }
      else if (modPressed) { /* 交给浏览器/系统/原生菜单处理，不拦截 */ }
      else if (e.key === 'ArrowDown') { step(1); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { step(-1); e.preventDefault(); }
      else if (e.key === 'g' || e.key === 'G') { openGotoDialog(); e.preventDefault(); }
      else if (e.key === '/') { openSearchDialog(); e.preventDefault(); }
      else if (e.key === 'b' || e.key === 'B') { toggleBookmark(currentInst); e.preventDefault(); }
      else if (e.key === 'Home') { navigateTo(0); e.preventDefault(); }
      else if (e.key === 'End') { navigateTo(Math.max(0, totalInst - 1)); e.preventDefault(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navBack, navForward, step, openGotoDialog, openSearchDialog, toggleBookmark, currentInst, navigateTo, totalInst]);

  if (loading) {
    return (
      <div className="boot-screen">
        <div className="boot-logo">tenet</div>
        <div className="boot-spinner" />
        <div className="boot-hint">正在加载 trace…</div>
      </div>
    );
  }

  return (
    <Tooltip.Provider delayDuration={400}>
      <div className="shell">
        <TitleBar />
        <Toolbar />
        <div className="shell-main">
          <SidebarLeft />
          <CenterArea />
          <SidebarRight />
        </div>
        <Timeline />
        <StatusBar />
        <GotoDialog />
        <SearchDialog />
      </div>
    </Tooltip.Provider>
  );
}
