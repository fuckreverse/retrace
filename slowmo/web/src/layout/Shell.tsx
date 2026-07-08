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
import './shell.css';

export function Shell() {
  const init = useTraceStore((s) => s.init);
  const loading = useTraceStore((s) => s.loading);
  const navBack = useTraceStore((s) => s.navBack);
  const navForward = useTraceStore((s) => s.navForward);
  const step = useTraceStore((s) => s.step);

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
      if (e.altKey && e.key === 'ArrowLeft') { navBack(); e.preventDefault(); }
      else if (e.altKey && e.key === 'ArrowRight') { navForward(); e.preventDefault(); }
      else if (e.key === 'ArrowDown' && !e.metaKey) { step(1); e.preventDefault(); }
      else if (e.key === 'ArrowUp' && !e.metaKey) { step(-1); e.preventDefault(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navBack, navForward, step]);

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
      </div>
    </Tooltip.Provider>
  );
}
