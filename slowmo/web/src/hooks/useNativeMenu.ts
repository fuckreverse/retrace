/**
 * 菜单动作分发中枢（浏览器 HTML 菜单 与 Tauri 原生菜单共用）。
 *
 * - runMenuAction(id): 按菜单叶子 id 执行动作，映射到 store actions 或 tab 跳转。
 * - useNativeMenu():   仅 Tauri 环境生效，监听 Rust emit 的 `menu://<id>` 事件并转交 runMenuAction。
 *
 * 菜单结构见 src/lib/menu.ts（对照 GUI 移植）。浏览器环境下 isTauri() 为 false，
 * useNativeMenu 直接 no-op、不加载任何 Tauri API —— 浏览器路径零影响。
 */
import { useEffect } from 'react';
import { isTauri } from '@/lib/env';
import { ALL_MENU_IDS, type TabGroup } from '@/lib/menu';
import { selectTab } from '@/lib/tabRouting';
import { openPanelWindow } from '@/lib/openPanelWindow';
import {
  backwardTaintToDot,
  blocksToDot,
  callGraphToDot,
  dataflowToDot,
  downloadTextFile,
} from '@/lib/dotExport';
import { api } from '@/api/service';
import { useTraceStore } from '@/store/traceStore';
import { useThemeStore } from '@/store/themeStore';
import { useAppStore } from '@/store/appStore';

/** id → (分组, tab)：点击后切换到对应分组容器里的面板 */
const TAB_TARGETS: Record<string, { group: TabGroup; tab: string }> = {
  // View · Core Panels
  view_memory: { group: 'right', tab: 'memory' },
  view_hexdump: { group: 'right', tab: 'hexdump' },
  view_callstack: { group: 'center-bottom', tab: 'callstack' },
  view_functions: { group: 'left', tab: 'functions' },
  view_strings: { group: 'left', tab: 'strings' },
  view_analysis: { group: 'center-bottom', tab: 'analysis' },
  // View · Visualization
  view_cfg: { group: 'center-top', tab: 'cfg' },
  view_callgraph: { group: 'center-bottom', tab: 'callgraph' },
  view_regtimeline: { group: 'center-top', tab: 'regtl' },
  view_dataflow: { group: 'center-top', tab: 'dataflow' },
  // View · Analysis Results
  view_patterns: { group: 'center-bottom', tab: 'patterns' },
  view_constants: { group: 'center-bottom', tab: 'constants' },
  view_loops: { group: 'center-bottom', tab: 'loops' },
  view_algorithms: { group: 'center-bottom', tab: 'algorithms' },
  view_objc: { group: 'center-bottom', tab: 'objc' },
  view_objccrypto: { group: 'center-bottom', tab: 'objccrypto' },
  view_api: { group: 'center-bottom', tab: 'api' },
  view_memstrings: { group: 'center-bottom', tab: 'memstrings' },
  // View · Profiling & Diff
  view_tracefold: { group: 'center-bottom', tab: 'tracefold' },
  view_winstats: { group: 'center-bottom', tab: 'winstats' },
  view_dataflow2: { group: 'center-top', tab: 'dataflow' },
  view_regtimeline2: { group: 'center-top', tab: 'regtl' },
  view_tracediff: { group: 'center-bottom', tab: 'tracediff' },
  view_dwarf: { group: 'center-bottom', tab: 'dwarf' },
  // View · bottom
  view_log: { group: 'center-bottom', tab: 'log' },
  view_cache: { group: 'center-bottom', tab: 'cache' },
  view_settings: { group: 'center-bottom', tab: 'settings' },

  // Analysis · Data Flow
  an_taint_fwd: { group: 'center-bottom', tab: 'taintsrc' },
  an_taint_back: { group: 'center-bottom', tab: 'backtaint' },
  an_regtimeline: { group: 'center-top', tab: 'regtl' },
  an_dataflow_graph: { group: 'center-top', tab: 'dataflow' },
  // Analysis · Structure
  an_functions: { group: 'left', tab: 'functions' },
  an_strings: { group: 'left', tab: 'strings' },
  an_callgraph: { group: 'center-bottom', tab: 'callgraph' },
  an_loops: { group: 'center-bottom', tab: 'loops' },
  an_cfg: { group: 'center-top', tab: 'cfg' },
  // Analysis · Crypto & Pattern
  an_patterns: { group: 'center-bottom', tab: 'patterns' },
  an_constants: { group: 'center-bottom', tab: 'constants' },
  an_algorithms: { group: 'center-bottom', tab: 'algorithms' },
  an_objccrypto: { group: 'center-bottom', tab: 'objccrypto' },
  // Analysis · ObjC / API
  an_objc: { group: 'center-bottom', tab: 'objc' },
  an_api: { group: 'center-bottom', tab: 'api' },
  // Analysis · Profiling
  an_tracefold: { group: 'center-bottom', tab: 'tracefold' },
  an_winstats: { group: 'center-bottom', tab: 'winstats' },
  an_tracediff: { group: 'center-bottom', tab: 'tracediff' },
  an_memstrings: { group: 'center-bottom', tab: 'memstrings' },
  // Tools
  tools_entropy: { group: 'center-bottom', tab: 'entropy' },
  tools_snapshot: { group: 'center-bottom', tab: 'snapshots' },
  tools_memsearch: { group: 'center-bottom', tab: 'memsearch' },
  tools_yara: { group: 'center-bottom', tab: 'yara' },
  tools_memhistory: { group: 'right', tab: 'memory' },
  tools_dataflow_cursor: { group: 'center-top', tab: 'dataflow' },
};

const EXPORT_IDS = ['export_cfg', 'export_callgraph', 'export_backtaint', 'export_dataflow'] as const;
type ExportId = (typeof EXPORT_IDS)[number];

function isExportId(id: string): id is ExportId {
  return EXPORT_IDS.some((exportId) => exportId === id);
}

function exportFilename(prefix: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `${prefix}-export-${timestamp}.dot`;
}

/** 获取最新分析数据并导出 DOT；反向污点明确使用当前指令与默认 x0。 */
async function exportDot(id: ExportId, currentInst: number): Promise<void> {
  try {
    switch (id) {
      case 'export_cfg':
        downloadTextFile(exportFilename('cfg'), blocksToDot(await api.cfg()));
        return;
      case 'export_callgraph':
        downloadTextFile(exportFilename('callgraph'), callGraphToDot(await api.callGraph()));
        return;
      case 'export_dataflow':
        downloadTextFile(exportFilename('dataflow'), dataflowToDot(await api.dataflowGraph()));
        return;
      case 'export_backtaint': {
        const reg = 'x0';
        const steps = await api.backwardTaint(currentInst, reg);
        downloadTextFile(
          exportFilename('backward-taint'),
          backwardTaintToDot(steps, currentInst, reg),
        );
        return;
      }
    }
  } catch (error) {
    console.error(`Failed to export ${id} as DOT`, error);
    window.alert('DOT export failed. Please check the backend connection and try again.');
  }
}

/** 执行一个菜单叶子动作 */
export function runMenuAction(id: string): void {
  const trace = useTraceStore.getState();
  const theme = useThemeStore.getState();
  const app = useAppStore.getState();

  // 0) File menu — Open Trace / Open Recent
  if (id === 'file_open') {
    // Trigger file picker via WelcomePage's open flow
    // If already in analysis view, switch to welcome first
    if (app.view !== 'welcome') {
      app.setView('welcome');
    }
    // The welcome page handles the file dialog
    // Programmatically trigger the open dialog
    void (async () => {
      if (!isTauri()) return;
      try {
        const { open } = await import('@tauri-apps/plugin-dialog');
        const result = await open({
          title: 'Open Trace File',
          filters: [{ name: 'Trace Files', extensions: ['bin'] }],
          multiple: false,
        });
        if (result) {
          app.requestOpenTrace(result);
        }
      } catch { /* dialog cancelled or error */ }
    })();
    return;
  }
  if (id.startsWith('file_recent:')) {
    const path = id.slice('file_recent:'.length);
    app.requestOpenTrace(path);
    return;
  }

  // Export menu — 获取数据后直接下载 DOT，不再跳转面板
  if (isExportId(id)) {
    void exportDot(id, trace.currentInst);
    return;
  }

  // 1) 纯 store 动作类
  switch (id) {
    case 'file_quit':
      // Tauri 原生菜单已用系统 Quit；浏览器无法关闭窗口，尝试 close 兜底
      if (isTauri()) return; // 交给系统预定义项处理（此分支一般不会触发）
      window.close();
      return;
    case 'nav_goto':
      trace.openGotoDialog();
      return;
    case 'nav_search':
      trace.openSearchDialog();
      return;
    case 'nav_back':
      trace.navBack();
      return;
    case 'nav_forward':
      trace.navForward();
      return;
    case 'nav_first':
      trace.navigateTo(0);
      return;
    case 'nav_last':
      trace.navigateTo(Math.max(0, trace.totalInst - 1));
      return;
    case 'nav_bookmark':
      trace.toggleBookmark(trace.currentInst);
      return;
    case 'view_theme_toggle':
      theme.toggle();
      return;
    case 'an_clear':
      trace.clearHighlights();
      return;
    case 'popout_vm':
      void openPanelWindow('vm');
      return;
  }

  // 2) tab 跳转类
  const target = TAB_TARGETS[id];
  if (target) {
    selectTab(target.group, target.tab);
    return;
  }

  // 3) 其余（disabled / 尚未接入的项）忽略
}

export function useNativeMenu() {
  useEffect(() => {
    if (!isTauri()) return;

    let unlisteners: (() => void)[] = [];
    let cancelled = false;

    import('@tauri-apps/api/event')
      .then(({ listen }) => {
        const promises: Promise<() => void>[] = [];

        // 1) Static menu IDs (from menu.ts catalog)
        for (const id of ALL_MENU_IDS) {
          promises.push(listen(`menu://${id}`, () => runMenuAction(id)));
        }

        // 2) Dynamic menu: "Open Recent" items.
        // Rust lib.rs emits a single `menu://file_recent` event with the
        // trace path as string payload (avoids needing to register one
        // listener per recent-file entry).
        promises.push(
          listen<string>('menu://file_recent', (event) => {
            const path = event.payload;
            if (path) {
              runMenuAction(`file_recent:${path}`);
            }
          }),
        );

        return Promise.all(promises);
      })
      .then((fns) => {
        if (cancelled) {
          fns.forEach((u) => u());
          return;
        }
        unlisteners = fns;
      })
      .catch(() => {
        /* 事件 API 加载失败则静默忽略 */
      });

    return () => {
      cancelled = true;
      unlisteners.forEach((u) => u());
    };
  }, []);
}
