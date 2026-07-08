import { useTraceStore } from '@/store/traceStore';
import { isTauri } from '@/lib/env';
import { MenuBar } from './MenuBar';

// Tauri 环境下菜单由 macOS 原生菜单栏承载，隐藏窗内 HTML 菜单；浏览器渲染 HTML 下拉菜单。
const useNativeMenuBar = isTauri();

export function TitleBar() {
  const info = useTraceStore((s) => s.info);
  const source = useTraceStore((s) => s.dataSource);

  return (
    <div className="titlebar">
      <div className="titlebar-brand">
        <span className="titlebar-logo">T</span>
        <span>Tenet</span>
      </div>
      {!useNativeMenuBar && <MenuBar />}
      <div className="titlebar-meta">
        {info && <span className="mono">{info.module_name}</span>}
        <span className={`source-tag ${source === 'live' ? 'live' : 'mock'}`}>
          <span className="dot" />
          {source === 'live' ? 'Live · TenetService' : 'Mock 数据'}
        </span>
      </div>
    </div>
  );
}
