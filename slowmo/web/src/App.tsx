import { useEffect } from 'react';
import { Shell } from './layout/Shell';
import { PanelWindow } from './layout/PanelWindow';
import { WelcomePage } from './layout/WelcomePage';
import { isPanelWindow, getPanelWsPort } from './lib/panelWindow';
import { useAppStore, type BackendProgress } from './store/appStore';
import { initFromTauri } from './store/settingsStore';
import { startBackendLogCapture } from './lib/backendLog';
import { setWsPort } from './api/ws';

// 尽早启动 tenet 后端（sidecar）日志采集：模块加载时立即执行，而非等某个
// 组件挂载，这样 open_trace 阶段（index 构建等）的日志也不会被漏掉。
// 浏览器环境下 isTauri() 为 false，内部 no-op。
startBackendLogCapture();

// 面板子窗口（?panel=<id>&ws=<port>）：从 URL 恢复后端 WS 端口。
// 必须在任何 WS 请求发起前执行（transport 单例创建时固化 URL），
// 否则多 trace 并行时子窗口会错误地连到默认 9090 后端。
if (isPanelWindow()) {
  const panelWsPort = getPanelWsPort();
  if (panelWsPort) setWsPort(panelWsPort);
}

/** Boot / loading screen — reuses existing boot-screen styling from shell.css */
function LoadingPage() {
  const progress = useAppStore((s) => s.loadingProgress);
  return (
    <div className="boot-screen">
      <div className="boot-logo">tenet</div>
      {progress ? (
        <BackendProgressBar progress={progress} />
      ) : (
        <>
          <div className="boot-spinner" />
          <div className="boot-hint">Starting backend…</div>
        </>
      )}
    </div>
  );
}

/**
 * 真实后端进度（索引构建等）——由 Rust 侧 `backend-progress` 事件驱动
 * （sidecar 的 TENET-PROGRESS 行）。progress ∈ [0,1]；百分比行直接展示
 * 后端的 message（含速度信息，如 "Indexing 42.3% [180 MB/s]"）。
 */
function BackendProgressBar({ progress }: { progress: BackendProgress }) {
  const pct = Math.max(0, Math.min(100, Math.round(progress.progress * 100)));
  const failed = progress.state === 'failed';
  const message = failed
    ? progress.error || progress.message || 'Failed'
    : progress.message || progress.phase || progress.kind;
  return (
    <div className="boot-progress">
      <div className={failed ? 'boot-progress-bar boot-progress-failed' : 'boot-progress-bar'}>
        <div className="boot-progress-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="boot-hint mono">{failed ? '\u2715 ' : ''}{message}</div>
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
