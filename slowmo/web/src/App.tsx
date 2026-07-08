import { useEffect } from 'react';
import { Shell } from './layout/Shell';
import { PanelWindow } from './layout/PanelWindow';
import { WelcomePage } from './layout/WelcomePage';
import { isPanelWindow } from './lib/panelWindow';
import { useAppStore } from './store/appStore';
import { initFromTauri } from './store/settingsStore';

/** Boot / loading screen — reuses existing boot-screen styling from shell.css */
function LoadingPage() {
  return (
    <div className="boot-screen">
      <div className="boot-logo">tenet</div>
      <div className="boot-spinner" />
      <div className="boot-hint">Starting backend\u2026</div>
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
