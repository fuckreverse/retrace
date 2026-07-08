/**
 * 单面板独立窗口外壳 —— 弹出窗口（?panel=<id>）加载此组件，
 * 只渲染目标面板 + 极简标题栏，并与主窗口通过 windowSync 实时联动。
 */
import { useEffect, type ReactNode } from 'react';
import * as Tooltip from '@radix-ui/react-tooltip';
import { useTraceStore } from '@/store/traceStore';
import { getPanelParam, POPOUT_PANELS } from '@/lib/panelWindow';
import { initWindowSync } from '@/lib/windowSync';
import { VmWorkspacePanel } from '@/panels/AuxPanels';
import './shell.css';

/** 可弹出面板 id → 渲染内容 */
const PANEL_CONTENT: Record<string, ReactNode> = {
  vm: <VmWorkspacePanel />,
};

export function PanelWindow() {
  const panelId = getPanelParam()!; // 调用方保证非空
  const init = useTraceStore((s) => s.init);
  const loading = useTraceStore((s) => s.loading);
  const currentInst = useTraceStore((s) => s.currentInst);
  const totalInst = useTraceStore((s) => s.totalInst);
  const title = POPOUT_PANELS[panelId] ?? panelId;

  // 独立窗口自行拉取 trace 元数据（totalInst 等），游标状态随后由 windowSync 覆盖
  useEffect(() => {
    init();
  }, [init]);

  // 开启跨窗口联动（子窗口：监听主窗口广播）
  useEffect(() => initWindowSync(), []);

  if (loading) {
    return (
      <div className="boot-screen">
        <div className="boot-logo">tenet</div>
        <div className="boot-spinner" />
        <div className="boot-hint">正在加载 {title}…</div>
      </div>
    );
  }

  return (
    <Tooltip.Provider delayDuration={400}>
      <div className="shell panel-window-shell">
        <div className="titlebar">
          <div className="titlebar-brand">
            <span className="titlebar-logo">T</span>
            <span>{title}</span>
          </div>
          <div className="titlebar-meta">
            <span className="mono">inst {currentInst}/{totalInst > 0 ? totalInst - 1 : 0}</span>
            <span className="source-tag live">
              <span className="dot" />
              联动主窗口
            </span>
          </div>
        </div>
        <div className="panel-window-body">{PANEL_CONTENT[panelId] ?? null}</div>
      </div>
    </Tooltip.Provider>
  );
}
