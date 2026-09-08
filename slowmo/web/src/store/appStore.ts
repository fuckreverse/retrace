/**
 * App-level state — 管理应用视图路由(welcome/loading/analysis)、
 * 最近文件列表、Pass 预设选择、后端连接信息。
 * 与 traceStore（trace 数据/游标）正交：appStore 管"打开哪个 trace"，
 * traceStore 管"trace 打开后的分析状态"。
 */
import { create } from 'zustand';
import { isTauri, isMockMode } from '@/lib/env';
import { api } from '@/api/service';
import { setWsPort, resetWsTransport, probeWs } from '@/api/ws';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

/** App-level view states */
export type AppView = 'welcome' | 'loading' | 'analysis';

/** Pass preset levels */
export type PassPreset = 'minimal' | 'standard' | 'full' | 'custom';

export interface RecentEntry {
  path: string;
  module_name: string;
  inst_count: number;
  last_opened: number; // epoch ms
}

export interface BackendPorts {
  ws_port: number;
  mcp_port: number;
  trace_path: string;
}

/**
 * 后端实时进度事件载荷（Rust 侧 `backend-progress`，由 sidecar 的
 * `TENET-PROGRESS` 行解析而来，见 src-tauri/src/lib.rs 与
 * tools/tenet/src/main.cpp 的 --progress-json）。仅在 loading 阶段消费：
 * WS 服务要到索引建完才启动，这段窗口期的进度只能靠这条侧信道。
 */
export interface BackendProgress {
  trace_path: string;
  /** "index" | "pass" | "streaming" | ... */
  kind: string;
  /** 子阶段："scan" / "compact" / ... */
  phase: string;
  /** "running" / "completed" / "failed" / ... */
  state: string;
  /** 0..1，state === 'running' 时有意义 */
  progress: number;
  completed: number;
  total: number;
  /** 人类可读进度行，如 "Indexing 42.3% [180 MB/s]" */
  message: string;
  error: string;
}

/* ------------------------------------------------------------------ */
/*  Pass catalog (mirrors C++ pass_registry.cpp)                       */
/* ------------------------------------------------------------------ */

export interface PassCatalogEntry {
  name: string;
  display: string;
  category: string;
  defaultOn: boolean;
}

export const PASS_CATEGORIES = [
  'Structure',
  'Taint',
  'Crypto',
  'Memory',
  'Platform API',
  'Profile',
  'Misc',
] as const;

export const PASS_CATALOG: PassCatalogEntry[] = [
  { name: 'function',                display: 'Functions',      category: 'Structure',     defaultOn: true  },
  { name: 'xref',                    display: 'XRefs',          category: 'Structure',     defaultOn: true  },
  { name: 'cfg',                     display: 'CFG',            category: 'Structure',     defaultOn: true  },
  { name: 'cfg_layout',             display: 'CFG Layout',     category: 'Structure',     defaultOn: false },
  { name: 'call_graph',             display: 'Call Graph',     category: 'Structure',     defaultOn: true  },
  { name: 'loop',                    display: 'Loops',          category: 'Structure',     defaultOn: true  },
  { name: 'taint',                   display: 'Taint',          category: 'Taint',         defaultOn: false },
  { name: 'backward_taint',         display: 'Back Taint',     category: 'Taint',         defaultOn: false },
  { name: 'taint_source_annotation', display: 'Taint Sources',  category: 'Taint',         defaultOn: false },
  { name: 'pattern',                display: 'Patterns',       category: 'Crypto',        defaultOn: true  },
  { name: 'loop_semantics',         display: 'Loop Semantics', category: 'Crypto',        defaultOn: true  },
  { name: 'algorithm_summary',      display: 'Algorithm',      category: 'Crypto',        defaultOn: true  },
  { name: 'objc_crypto',            display: 'ObjC\u00d7Crypto', category: 'Crypto',      defaultOn: false },
  { name: 'strings',                display: 'Strings',        category: 'Memory',        defaultOn: true  },
  { name: 'memory_strings',         display: 'Mem Strings',    category: 'Memory',        defaultOn: false },
  { name: 'memory_snapshot',        display: 'Mem Snapshot',   category: 'Memory',        defaultOn: false },
  { name: 'mem_search',             display: 'Mem Search',     category: 'Memory',        defaultOn: false },
  { name: 'entropy',                display: 'Entropy',        category: 'Memory',        defaultOn: false },
  { name: 'yara_mem_scan',          display: 'YARA Scan',      category: 'Memory',        defaultOn: false },
  { name: 'objc',                   display: 'ObjC',           category: 'Platform API',  defaultOn: false },
  { name: 'syscall_intercept',      display: 'Syscalls',       category: 'Platform API',  defaultOn: false },
  { name: 'trace_fold',             display: 'Trace Fold',     category: 'Profile',       defaultOn: false },
  { name: 'reg_timeline',           display: 'Reg Timeline',   category: 'Profile',       defaultOn: false },
  { name: 'call_context',           display: 'Call Context',   category: 'Profile',       defaultOn: false },
  { name: 'window_stats',           display: 'Window Stats',   category: 'Profile',       defaultOn: false },
  { name: 'trace_diff',             display: 'Trace Diff',     category: 'Profile',       defaultOn: false },
  { name: 'dataflow_graph',         display: 'Dataflow',       category: 'Profile',       defaultOn: false },
  { name: 'thread',                 display: 'Threads',        category: 'Misc',          defaultOn: true  },
  { name: 'thread_filter',          display: 'Thread Filter',  category: 'Misc',          defaultOn: false },
  { name: 'vm_abstract',            display: 'VM Abstract',    category: 'Misc',          defaultOn: false },
];

/** Derive pass name lists from the catalog for each preset */
export function getPassesForPreset(preset: PassPreset, customPasses: string[]): string[] {
  switch (preset) {
    case 'minimal':
      return ['xref', 'cfg'];
    case 'standard':
      return PASS_CATALOG.filter((p) => p.defaultOn).map((p) => p.name);
    case 'full':
      return PASS_CATALOG.map((p) => p.name);
    case 'custom':
      return customPasses;
  }
}

/* ------------------------------------------------------------------ */
/*  Tauri invoke helper (lazy import, no-op in browser)                */
/* ------------------------------------------------------------------ */

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<T>(cmd, args);
}

/* ------------------------------------------------------------------ */
/*  Store                                                              */
/* ------------------------------------------------------------------ */

interface AppState {
  view: AppView;
  recentFiles: RecentEntry[];
  openTraces: Set<string>;
  passPreset: PassPreset;
  customPasses: string[];
  backendPorts: BackendPorts | null;
  error: string | null;

  /** The path pending to be opened (set before pass preset dialog) */
  pendingTracePath: string | null;
  /** Whether the pass preset dialog is shown */
  showPassPresetDialog: boolean;
  /** loading 阶段的后端实时进度（null = 尚未收到任何进度事件） */
  loadingProgress: BackendProgress | null;

  // actions
  setView: (view: AppView) => void;
  loadRecentFiles: () => Promise<void>;
  requestOpenTrace: (path: string) => void;
  openTrace: (path: string) => Promise<void>;
  cancelOpen: () => void;
  setPassPreset: (preset: PassPreset) => void;
  setCustomPasses: (passes: string[]) => void;
  confirmAndOpen: () => Promise<void>;
  setError: (error: string | null) => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  // Mock 调试模式（?mock=1）直接跳过 Welcome，进入分析主界面（数据来自 mock/data.ts）
  view: isMockMode() ? 'analysis' : 'welcome',
  recentFiles: [],
  openTraces: new Set(),
  passPreset: 'standard',
  customPasses: PASS_CATALOG.filter((p) => p.defaultOn).map((p) => p.name),
  backendPorts: null,
  error: null,
  pendingTracePath: null,
  showPassPresetDialog: false,
  loadingProgress: null,

  setView(view) {
    set({ view });
  },

  async loadRecentFiles() {
    if (!isTauri()) {
      // Browser mode: no recent files
      set({ recentFiles: [] });
      return;
    }
    try {
      const files = await tauriInvoke<RecentEntry[]>('get_recent_files');
      set({ recentFiles: files });
    } catch {
      // Tauri command not implemented yet — fallback to empty
      set({ recentFiles: [] });
    }
  },

  requestOpenTrace(path) {
    const { openTraces } = get();
    if (openTraces.has(path)) return; // already open, ignore
    set({ pendingTracePath: path, showPassPresetDialog: true });
  },

  async openTrace(path) {
    set({ view: 'loading', error: null, showPassPresetDialog: false, loadingProgress: null });

    // Pass 预设：连接就绪后自动触发所选 pass（后端串行排队执行）。
    // 以前预设只被传给 Rust 侧 open_trace 的一个死参数，从未生效；
    // 现在改为前端在 WS 握手成功后逐个调 RunPass，自定义预设同样适用。
    const runPresetPasses = () => {
      const { passPreset, customPasses } = get();
      for (const name of getPassesForPreset(passPreset, customPasses)) {
        void api.runPass(name);
      }
    };

    if (!isTauri()) {
      // Browser mode: directly go to analysis (backend must already be running)
      set({ view: 'analysis' });
      runPresetPasses();
      return;
    }

    try {
      // Check if already open
      const isOpen = await tauriInvoke<boolean>('is_trace_open', { path });
      if (isOpen) {
        const traces = new Set(get().openTraces);
        traces.add(path);
        set({ openTraces: traces, view: 'welcome', error: 'This trace is already open in another window' });
        return;
      }

      // Open the trace via Tauri backend (Rust spawns the sidecar with
      // --progress-json so we get structured progress during index build)
      const ports = await tauriInvoke<BackendPorts>('open_trace', { path });

      // Configure WS connection to use the allocated port.
      // 注：ports.mcp_port 仍由后端分配（供 AI agent 的 MCP 服务使用），
      // 但前端不再连接 MCP，只用 WS。
      setWsPort(ports.ws_port);
      resetWsTransport();

      // Listen for an early "backend-crashed" signal from the Rust side
      // (emitted when the sidecar process exits with a non-zero code before
      // we ever see it come up) so we can fail fast instead of always
      // waiting out the full poll timeout below. Rust also cleans up its
      // own OpenTraces/BackendProcesses bookkeeping when this fires, so a
      // retry of the same path won't be rejected as "already open".
      let crashed = false;
      let unlistenCrash: (() => void) | null = null;
      if (isTauri()) {
        try {
          const { listen } = await import('@tauri-apps/api/event');
          unlistenCrash = await listen<string>('backend-crashed', (event) => {
            if (event.payload === path) crashed = true;
          });
        } catch {
          /* event API unavailable — fall back to timeout-only detection */
        }
      }

      // Subscribe to structured backend progress (index build, etc.) —
      // Rust parses the sidecar's TENET-PROGRESS stderr lines and emits
      // `backend-progress`. This drives the loading screen's progress bar
      // and also feeds the liveness timeout below (as long as the backend
      // keeps reporting progress, we keep waiting).
      let lastProgressAt = Date.now();
      let unlistenProgress: (() => void) | null = null;
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlistenProgress = await listen<BackendProgress>('backend-progress', (event) => {
          if (event.payload.trace_path !== path) return;
          lastProgressAt = Date.now();
          set({ loadingProgress: event.payload });
        });
      } catch {
        /* progress display is best-effort — fall back to a plain spinner */
      }

      // Wait for the C++ backend to become ready (WS handshake).
      // Timeout model: absolute cap of 10 minutes, plus a 90s no-progress
      // window — a large first-time index build can legitimately take
      // minutes, but only while progress events keep flowing. Backends
      // without --progress-json support degrade to the 90s fixed wait.
      const absoluteMaxWait = 600_000;
      const noProgressTimeout = 90_000;
      const pollInterval = 500;
      const start = Date.now();
      let ready = false;
      while (Date.now() - start < absoluteMaxWait && Date.now() - lastProgressAt < noProgressTimeout) {
        if (crashed) break;
        ready = await probeWs();
        if (ready) break;
        await new Promise((r) => setTimeout(r, pollInterval));
      }
      unlistenProgress?.();
      unlistenCrash?.();
      if (crashed) {
        set({ view: 'welcome', loadingProgress: null, error: 'Backend exited unexpectedly. Check the app logs for details.' });
        return;
      }
      if (!ready) {
        set({ view: 'welcome', loadingProgress: null, error: 'Backend did not start in time. Check the trace file.' });
        return;
      }

      const traces = new Set(get().openTraces);
      traces.add(path);
      set({ backendPorts: ports, openTraces: traces, view: 'analysis', loadingProgress: null });
      // 预设 pass 自动运行（不阻塞视图切换，进度由 AnalysisPanel 展示）
      runPresetPasses();
    } catch (e) {
      set({ view: 'welcome', loadingProgress: null, error: String(e) });
    }
  },

  cancelOpen() {
    set({ pendingTracePath: null, showPassPresetDialog: false });
  },

  setPassPreset(preset) {
    set({ passPreset: preset });
  },

  setCustomPasses(passes) {
    set({ customPasses: passes });
  },

  async confirmAndOpen() {
    const { pendingTracePath } = get();
    if (!pendingTracePath) return;
    set({ pendingTracePath: null });
    await get().openTrace(pendingTracePath);
  },

  setError(error) {
    set({ error });
  },
}));
