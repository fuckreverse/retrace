/**
 * 统一数据服务：全部能力走 WebSocket（TenetWSService），失败降级到 mock。
 *
 * 设计要点：
 *   - 热路径（trace_info / disasm / regs / memread / functions / callstack / pass）
 *     走 ws-api.ts 里的强类型二进制通道。
 *   - 其余分析能力统一走 ws.wsRunAnalysis(toolName, params)——一条"万能"请求，
 *     把后端已注册的 MCP 工具名 + JSON 参数透传给后端进程内的 TenetMcpService，
 *     返回结果与旧 MCP over HTTP 的 content[0].text 结构完全一致。
 *   - 前端不再依赖 MCP HTTP 通道（MCP 现仅供 AI agent 使用）。
 *   - 后端不可用（WS 连不上）时，所有能力回退到 mock 数据。
 *
 * ⚠️ toolName 使用后端实际注册名（见 src/io/mcp/*.cpp register_tool），
 *    与前端能力名可能不同（如 constants→constants_scan、entropy→entropy_analysis）。
 */
import { wsTransport } from './ws';
import * as ws from './ws-api';
import * as mock from '@/mock/data';
import { isMockMode } from '@/lib/env';
import type {
  AlgorithmEntry,
  ApiCallEntry,
  BackwardTaintStep,
  CacheEntry,
  CallFrame,
  CallGraphResult,
  CfgResult,
  ConstantEntry,
  DataflowGraph,
  DiffEntry,
  DisasmResult,
  DwarfEntry,
  EntropyBlock,
  FoldEntry,
  FunctionEntry,
  LogEntry,
  LoopEntry,
  MemReadResult,
  MemSearchHit,
  MemStringEntry,
  ObjcCryptoLink,
  ObjcMessage,
  PassInfo,
  PatternMatch,
  RegsResult,
  RegTimeline,
  SnapshotEntry,
  StringEntry,
  TaintSource,
  TaintStep,
  TraceInfo,
  VmHandler,
  WindowStat,
  XrefResult,
  YaraMatch,
} from '@/types/tenet';

export type DataSource = 'live' | 'mock' | 'unknown';

let dataSource: DataSource = 'unknown';

export function getDataSource(): DataSource {
  return dataSource;
}

/**
 * WS 是否已被判定不可用。仅在"确实尝试连接且从未握手成功"后置 true，
 * 之后同一会话内所有能力直接走 mock，避免每次调用都超时等待。
 *
 * Mock 调试模式（?mock=1）下直接初始化为 true：跳过真实 WS 连接尝试，
 * 所有请求立即走 mock 数据，避免逐个等待 15s 请求超时。
 */
let wsUnavailable = isMockMode();

/**
 * 统一路由：优先走 WS（wsFn），失败回退到 mock（fallback）。
 *
 * - WS 请求成功 → 标记数据源为 live。
 * - WS 请求失败：若 transport 从未握手成功，判定后端不可用（wsUnavailable=true），
 *   本次及之后均走 mock；否则视为单次请求错误，本次回退 mock 但下次仍尝试 WS。
 */
async function route<T>(wsFn: () => Promise<T>, fallback: () => T): Promise<T> {
  if (wsUnavailable) {
    dataSource = 'mock';
    return fallback();
  }
  try {
    const res = await wsFn();
    dataSource = 'live';
    return res;
  } catch {
    if (!wsTransport().isEverConnected()) {
      wsUnavailable = true;
    }
    dataSource = 'mock';
    return fallback();
  }
}

/**
 * 通用分析路由：走 wsRunAnalysis(toolName, params)，
 * 用 pick 从返回 JSON 里取字段（贴合各能力的返回形状），失败回退 mock。
 */
async function analysis<T>(
  toolName: string,
  params: Record<string, unknown>,
  pick: (raw: unknown) => T,
  fallback: () => T,
): Promise<T> {
  return route(async () => {
    const raw = await ws.wsRunAnalysis(toolName, params);
    return pick(raw);
  }, fallback);
}

/** 从 { key: T[] } 形状里取数组；raw 为 null/缺失时回退 [] */
function arr<T>(raw: unknown, key: string): T[] {
  if (raw && typeof raw === 'object' && Array.isArray((raw as Record<string, unknown>)[key])) {
    return (raw as Record<string, T[]>)[key];
  }
  return [];
}

export const api = {
  // ─── 热路径：强类型二进制通道 ───────────────────────────────────────────
  async traceInfo(): Promise<TraceInfo> {
    return route(() => ws.wsTraceInfo(), () => mock.mockTraceInfo());
  },

  async disasm(startInstId: number, count: number): Promise<DisasmResult> {
    return route(
      () => ws.wsFetchRows(startInstId, count),
      () => mock.mockDisasm(startInstId, count),
    );
  },

  async regs(instId: number): Promise<RegsResult> {
    return route(() => ws.wsGetRegs(instId, 'before'), () => mock.mockRegs(instId));
  },

  async memRead(addr: string, size: number, instId: number): Promise<MemReadResult> {
    return route(
      () => ws.wsReadMemory(addr, size, instId),
      () => mock.mockMemRead(addr, size, instId),
    );
  },

  async functions(): Promise<FunctionEntry[]> {
    return route(() => ws.wsFunctions(), () => mock.mockFunctions());
  },

  async callStack(instId: number): Promise<CallFrame[]> {
    return route(() => ws.wsCallStack(instId), () => mock.mockCallStack(instId));
  },

  async passes(): Promise<PassInfo[]> {
    return route(() => ws.wsGetPassCatalog(), () => mock.mockPasses());
  },

  /**
   * 通知后端导航到指定指令（用于跨客户端 / 与 GUI 状态同步）。
   * 仅在 WS 可用时生效；失败静默忽略（前端本地状态已更新）。
   */
  async navigate(instId: number): Promise<void> {
    if (wsUnavailable) return;
    try {
      await ws.wsNavigate(instId);
    } catch {
      /* best-effort：本地状态已推进，忽略后端同步失败 */
    }
  },

  /** 订阅服务端导航推送；返回取消订阅函数（WS 不可用时为 no-op） */
  onServerNavigation(cb: (instId: number) => void): () => void {
    if (wsUnavailable) return () => {};
    return ws.onServerNavigation(cb);
  },

  // ─── 通用分析通道：wsRunAnalysis(后端工具名, 参数) ──────────────────────

  async xref(pc: string): Promise<XrefResult> {
    return analysis<XrefResult>(
      'search_pc',
      { pc, limit: 1000 },
      (raw) => raw as XrefResult,
      () => mock.mockXref(pc),
    );
  },

  async callGraph(): Promise<CallGraphResult> {
    return analysis<CallGraphResult>(
      'call_graph',
      { format: 'json' },
      (raw) => raw as CallGraphResult,
      () => mock.mockCallGraph(),
    );
  },

  async cfg(): Promise<CfgResult> {
    return analysis<CfgResult>(
      'cfg_export',
      { format: 'json' },
      (raw) => raw as CfgResult,
      () => mock.mockCfg(),
    );
  },

  async patterns(): Promise<PatternMatch[]> {
    return analysis<PatternMatch[]>(
      'pattern_scan',
      {},
      (raw) => arr<PatternMatch>(raw, 'matches'),
      () => mock.mockPatterns(),
    );
  },

  async strings(): Promise<StringEntry[]> {
    return analysis<StringEntry[]>(
      'strings_scan',
      { limit: 500 },
      (raw) => arr<StringEntry>(raw, 'strings'),
      () => mock.mockStrings(),
    );
  },

  async objcMessages(): Promise<ObjcMessage[]> {
    return analysis<ObjcMessage[]>(
      'objc_messages',
      {},
      (raw) => arr<ObjcMessage>(raw, 'messages'),
      () => mock.mockObjcMessages(),
    );
  },

  async taintForward(regIndex: number, instId: number): Promise<TaintStep[]> {
    return analysis<TaintStep[]>(
      'taint_forward',
      { reg_index: regIndex, inst_id: instId },
      (raw) => arr<TaintStep>(raw, 'steps'),
      () => mock.mockTaintForward(regIndex, instId).steps,
    );
  },

  async constants(): Promise<ConstantEntry[]> {
    return analysis<ConstantEntry[]>(
      'constants_scan',
      {},
      (raw) => arr<ConstantEntry>(raw, 'constants'),
      () => mock.mockConstants(),
    );
  },

  async algorithms(): Promise<AlgorithmEntry[]> {
    return analysis<AlgorithmEntry[]>(
      'algorithm_summary',
      {},
      (raw) => arr<AlgorithmEntry>(raw, 'algorithms'),
      () => mock.mockAlgorithms(),
    );
  },

  async apiIntercepts(): Promise<ApiCallEntry[]> {
    return analysis<ApiCallEntry[]>(
      'syscall_intercept',
      {},
      (raw) => arr<ApiCallEntry>(raw, 'calls'),
      () => mock.mockApiIntercepts(),
    );
  },

  async loops(): Promise<LoopEntry[]> {
    return analysis<LoopEntry[]>(
      'loop_semantics',
      {},
      (raw) => arr<LoopEntry>(raw, 'loops'),
      () => mock.mockLoops(),
    );
  },

  async regTimeline(reg: string): Promise<RegTimeline> {
    // 后端 reg_timeline 参数名是 reg_index（可传寄存器名字符串，如 'x0'）
    return analysis<RegTimeline>(
      'reg_timeline',
      { reg_index: reg },
      (raw) => raw as RegTimeline,
      () => mock.mockRegTimeline(reg),
    );
  },

  async memSearch(query: string): Promise<MemSearchHit[]> {
    return analysis<MemSearchHit[]>(
      'mem_search',
      { query },
      (raw) => arr<MemSearchHit>(raw, 'hits'),
      () => mock.mockMemSearch(query),
    );
  },

  async memStrings(): Promise<MemStringEntry[]> {
    return analysis<MemStringEntry[]>(
      'memory_strings',
      {},
      (raw) => arr<MemStringEntry>(raw, 'strings'),
      () => mock.mockMemStrings(),
    );
  },

  async entropy(): Promise<EntropyBlock[]> {
    return analysis<EntropyBlock[]>(
      'entropy_analysis',
      {},
      (raw) => arr<EntropyBlock>(raw, 'blocks'),
      () => mock.mockEntropy(),
    );
  },

  async yara(): Promise<YaraMatch[]> {
    return analysis<YaraMatch[]>(
      'yara_mem_scan',
      {},
      (raw) => arr<YaraMatch>(raw, 'matches'),
      () => mock.mockYara(),
    );
  },

  async windowStats(): Promise<WindowStat[]> {
    return analysis<WindowStat[]>(
      'window_stats',
      {},
      (raw) => arr<WindowStat>(raw, 'windows'),
      () => mock.mockWindowStats(),
    );
  },

  async traceFold(): Promise<FoldEntry[]> {
    return analysis<FoldEntry[]>(
      'trace_fold',
      {},
      (raw) => arr<FoldEntry>(raw, 'folds'),
      () => mock.mockTraceFold(),
    );
  },

  async traceDiff(): Promise<DiffEntry[]> {
    return analysis<DiffEntry[]>(
      'trace_diff',
      {},
      (raw) => arr<DiffEntry>(raw, 'diffs'),
      () => mock.mockTraceDiff(),
    );
  },

  async dataflowGraph(): Promise<DataflowGraph> {
    return analysis<DataflowGraph>(
      'dataflow_graph',
      { format: 'json' },
      (raw) => raw as DataflowGraph,
      () => mock.mockDataflowGraph(),
    );
  },

  async backwardTaint(instId: number, reg: string): Promise<BackwardTaintStep[]> {
    return analysis<BackwardTaintStep[]>(
      'taint_backward',
      { inst_id: instId, reg },
      (raw) => arr<BackwardTaintStep>(raw, 'steps'),
      () => mock.mockBackwardTaint(instId, reg),
    );
  },

  async objcCrypto(): Promise<ObjcCryptoLink[]> {
    return analysis<ObjcCryptoLink[]>(
      'objc_crypto',
      {},
      (raw) => arr<ObjcCryptoLink>(raw, 'links'),
      () => mock.mockObjcCrypto(),
    );
  },

  async snapshots(): Promise<SnapshotEntry[]> {
    return analysis<SnapshotEntry[]>(
      'memory_snapshot',
      {},
      (raw) => arr<SnapshotEntry>(raw, 'snapshots'),
      () => mock.mockSnapshots(),
    );
  },

  async vmHandlers(): Promise<VmHandler[]> {
    return analysis<VmHandler[]>(
      'vm_abstract',
      {},
      (raw) => arr<VmHandler>(raw, 'handlers'),
      () => mock.mockVmHandlers(),
    );
  },

  // ─── 无对应后端工具：仅 mock ────────────────────────────────────────────

  async taintSources(): Promise<TaintSource[]> {
    // 后端未注册 taint_sources 工具，直接用 mock
    return mock.mockTaintSources();
  },

  async dwarf(): Promise<DwarfEntry[]> {
    // 后端未注册 dwarf 工具，直接用 mock
    return mock.mockDwarf();
  },

  async cache(): Promise<CacheEntry[]> {
    // 后端未注册 cache_manager 工具，直接用 mock
    return mock.mockCache();
  },

  async log(): Promise<LogEntry[]> {
    // 引擎日志由前端本地聚合，直接用 mock
    return mock.mockLog();
  },
};
