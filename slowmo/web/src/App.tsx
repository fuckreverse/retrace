import { useEffect } from 'react';
import { Shell } from './layout/Shell';
import { PanelWindow } from './layout/PanelWindow';
import { WelcomePage } from './layout/WelcomePage';
import { isPanelWindow } from './lib/panelWindow';
import { useAppStore } from './store/appStore';
import { initFromTauri } from './store/settingsStore';
import { startBackendLogCapture } from './lib/backendLog';

// 尽早启动 tenet 后端（sidecar）日志采集：模块加载时立即执行，而非等某个
// 组件挂载，这样 open_trace 阶段（index 构建等）的日志也不会被漏掉。
// 浏览器环境下 isTauri() 为 false，内部 no-op。
startBackendLogCapture();

/** Boot / loading screen — reuses existing boot-screen styling from shell.css */
function LoadingPage() {
  return (
    <div className="boot-screen">
      <div className="boot-logo">tenet</div>
      <div className="boot-spinner" />
      <div className="boot-hint">Starting backend…</div>
    </div>
  );
}

export default function App() {
  const view = useAppStore((s) => s.view);

  // Tauri 环境下异步加载配置文件
  useEffect(() => { initFromTauri(); }, []);

  // ?panel=<id> → 单面板独立窗口；不走 welcome 路由
  if (isPanelWindow()) return <PanelWindow />;

  switch (view) {
    case 'welcome':
      return <WelcomePage />;
    case 'loading':
      return <LoadingPage />;
    case 'analysis':
      return <Shell />;
  }
}
