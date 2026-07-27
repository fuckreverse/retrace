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
import { isMockMode, isTauri } from '@/lib/env';
import { getBackendLogSnapshot } from '@/lib/backendLog';
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

  async progress(): Promise<ws.ProgressTask[]> {
    if (wsUnavailable) return [];
    return ws.wsGetProgress();
  },

  /** 触发后端异步运行一个 pass；状态与百分比统一由 progress() 查询。 */
  async runPass(name: string): Promise<{ ok: boolean; message: string }> {
    if (wsUnavailable) return mock.mockRunPass(name);
    try {
      const res = await ws.wsRunPass(name);
      dataSource = 'live';
      return res;
    } catch (e) {
      if (!wsTransport().isEverConnected()) wsUnavailable = true;
      return { ok: false, message: e instanceof Error ? e.message : String(e) };
    }
  },

  /** 清空全部分析结果（对齐 GUI "Clear All Analysis"），失败静默忽略 */
  async clearAnalysis(): Promise<void> {
    if (wsUnavailable) return;
    try {
      await ws.wsClearAnalysis();
    } catch {
      /* best-effort */
    }
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

  /**
   * 正向线性搜索反汇编文本（对齐 GUI Search 弹窗：子串匹配 mnemonic+operands）。
   * 服务端从 fromInst 开始扫描，同步阻塞直到扫完（后端限流，见 TenetService::search_forward）。
   */
  async searchForward(query: string, fromInst: number): Promise<number[]> {
    return route(() => ws.wsSearchForward(query, fromInst), () => mock.mockSearchForward(query, fromInst));
  },

  /** 服务端持久书签：跨客户端/GUI 同步，而非纯前端本地 Set */
  async toggleBookmark(instId: number): Promise<number[]> {
    return route(() => ws.wsToggleBookmark(instId), () => mock.mockToggleBookmark(instId));
  },

  async getBookmarks(): Promise<number[]> {
    return route(() => ws.wsGetBookmarks(), () => mock.mockGetBookmarks());
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

  /**
   * 导出控制流图（对齐后端 cfg_export，见 mcp_tools_core.cpp register_graph_tools）。
   * 传 entryPc 或 instId 时为函数作用域（disasm 全量、含 polyline 边路由）；
   * 不传为全图模式（>500 blocks 时后端跳过 disasm 预览以控制 payload 体积）。
   */
  async cfg(opts?: { entryPc?: string; instId?: number }): Promise<CfgResult> {
    const params: Record<string, unknown> = { format: 'json' };
    if (opts?.entryPc != null) params.entry_pc = opts.entryPc;
    if (opts?.instId != null) params.inst_id = opts.instId;
    return analysis<CfgResult>(
      'cfg_export',
      params,
      (raw) => {
        const r = raw as Record<string, unknown>;
        const blocks = arr<Record<string, unknown>>(r, 'blocks').map((b) => ({
          pc: String(b.pc ?? ''),
          x: Number(b.x ?? 0),
          y: Number(b.y ?? 0),
          width: Number(b.width ?? 0),
          height: Number(b.height ?? 0),
          end_pc: b.end_pc != null ? String(b.end_pc) : undefined,
          executions: b.executions != null ? Number(b.executions) : undefined,
          terminator: typeof b.terminator === 'string'
            ? b.terminator as NonNullable<CfgResult['blocks'][number]['terminator']>
            : undefined,
          disasm: Array.isArray(b.disasm) ? b.disasm as string[] : undefined,
        }));
        const edges = arr<Record<string, unknown>>(r, 'edges').map((e) => ({
          from: String(e.from ?? ''),
          to: String(e.to ?? ''),
          arrow: typeof e.arrow === 'string' ? e.arrow : undefined,
          kind: e.kind === 'fallthrough' ? 'fallthrough' as const : e.kind === 'branch' ? 'branch' as const : undefined,
          taken_count: e.taken_count != null ? Number(e.taken_count) : undefined,
          polyline: Array.isArray(e.polyline)
            ? e.polyline.map((p) => {
                const point = p as Record<string, unknown>;
                return { x: Number(point.x), y: Number(point.y) };
              })
            : undefined,
        }));
        const fn = r.function && typeof r.function === 'object'
          ? r.function as Record<string, unknown>
          : undefined;
        return {
          format: String(r.format ?? 'json'),
          scope: typeof r.scope === 'string' ? r.scope as NonNullable<CfgResult['scope']> : undefined,
          function: fn ? {
            entry_pc: String(fn.entry_pc ?? ''),
            name: String(fn.name ?? ''),
            total_calls: fn.total_calls != null ? Number(fn.total_calls) : undefined,
          } : undefined,
          blocks,
          edges,
          canvas_width: r.canvas_width != null ? Number(r.canvas_width) : undefined,
          canvas_height: r.canvas_height != null ? Number(r.canvas_height) : undefined,
        };
      },
      () => mock.mockCfg(),
    );
  },

  /** 获取后端预生成的权威 CFG DOT（与 CLI --export-cfg 共用 CFGLayoutResult.dot_annotated）。 */
  async cfgDot(): Promise<string> {
    return analysis<string>(
      'cfg_export',
      { format: 'dot' },
      (raw) => {
        if (!raw || typeof raw !== 'object') return '';
        const dot = (raw as Record<string, unknown>).dot;
        return typeof dot === 'string' ? dot : '';
      },
      () => '',
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

  /**
   * 内存/寄存器/立即数搜索，对齐后端 mem_search 工具真实参数（见
   * mcp_tools_analysis.cpp register_search_tools）：
   *   - mode='pattern': hex_pattern（空格分隔字节，'??' 为通配符）或 text（ASCII 子串）
   *   - mode='exact':   exact_value（十六进制或十进制标量，如 crypto IV / 指针）
   *   - searchRegisters: 同时扫描寄存器差异（search_registers）
   *   - searchImmediates: 同时扫描 MOVZ/MOVK 立即数（仅对 exact 模式生效，search_immediates）
   */
  async memSearch(opts: {
    mode: 'pattern' | 'exact';
    pattern?: string;
    isText?: boolean;
    exactValue?: string;
    searchRegisters?: boolean;
    searchImmediates?: boolean;
  }): Promise<MemSearchHit[]> {
    const params: Record<string, unknown> = {};
    if (opts.mode === 'pattern' && opts.pattern) {
      if (opts.isText) params.text = opts.pattern;
      else params.hex_pattern = opts.pattern;
    } else if (opts.mode === 'exact' && opts.exactValue) {
      params.exact_value = opts.exactValue;
    }
    if (opts.searchRegisters) params.search_registers = true;
    if (opts.searchImmediates) params.search_immediates = true;
    return analysis<MemSearchHit[]>(
      'mem_search',
      params,
      (raw) => arr<Record<string, unknown>>(raw, 'hits').map((h): MemSearchHit => ({
        addr: String(h.addr ?? ''),
        inst_id: Number(h.inst_id ?? 0),
        match_type: h.source === 'mem_write' ? 'write' : 'read',
        value: String(h.matched_value ?? h.addr ?? ''),
        context: String(h.source ?? ''),
      })),
      () => mock.mockMemSearch(opts.pattern ?? opts.exactValue ?? ''),
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

  /** 对齐后端 yara_mem_scan 可选参数（见 mcp_tools_analysis.cpp），全部留空即用默认内置规则全量扫描 */
  async yara(opts?: { rulesDir?: string; minEntropy?: number; scanCode?: boolean; minWritesPerPage?: number }): Promise<YaraMatch[]> {
    const params: Record<string, unknown> = {};
    if (opts?.rulesDir) params.rules_dir = opts.rulesDir;
    if (opts?.minEntropy != null) params.min_entropy = opts.minEntropy;
    if (opts?.scanCode != null) params.scan_code = opts.scanCode;
    if (opts?.minWritesPerPage != null) params.min_writes_per_page = opts.minWritesPerPage;
    return analysis<YaraMatch[]>(
      'yara_mem_scan',
      params,
      (raw) => arr<Record<string, unknown>>(raw, 'matches').map((m): YaraMatch => ({
        rule: String(m.rule_name ?? ''),
        namespace: String(m.category ?? ''),
        tags: Array.isArray(m.tags) ? m.tags as string[] : [],
        addr: String(m.addr ?? ''),
        inst_id: Number(m.inst_id ?? 0),
        strings_matched: Number(m.strings_matched ?? 0),
      })),
      () => mock.mockYara(),
    );
  },

  async windowStats(): Promise<WindowStat[]> {
    return analysis<WindowStat[]>(
      'window_stats',
      {},
      // 后端字段名（start/end/instruction_count/mem_read_count/...）与前端展示字段不同，需显式映射
      (raw) => arr<Record<string, unknown>>(raw, 'windows').map((w): WindowStat => {
        const topMnem = Array.isArray(w.top_mnemonics) ? w.top_mnemonics as Array<{ mnemonic?: string }> : [];
        return {
          window_start: Number(w.start ?? 0),
          window_end: Number(w.end ?? 0),
          inst_count: Number(w.instruction_count ?? 0),
          mem_reads: Number(w.mem_read_count ?? 0),
          mem_writes: Number(w.mem_write_count ?? 0),
          branch_density: Number(w.branch_density ?? 0),
          unique_pcs: Number(w.unique_pcs ?? 0),
          mnemonic_entropy: Number(w.mnemonic_entropy ?? 0),
          dominant_mnemonic: topMnem[0]?.mnemonic ?? '',
        };
      }),
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

  /**
   * 比较两段指令区间的寄存器/内存差异（对齐后端 trace_diff 必填参数）。
   * rangeA/rangeB 均为 [start, end) inst_id 区间；traceBPath 可选，指向另一份
   * trace 文件做跨文件比较，留空则在同一份 trace 内比较两段。
   */
  async traceDiff(rangeA: [number, number], rangeB: [number, number], traceBPath?: string): Promise<DiffEntry[]> {
    const params: Record<string, unknown> = {
      range_a_start: rangeA[0],
      range_a_end: rangeA[1],
      range_b_start: rangeB[0],
      range_b_end: rangeB[1],
    };
    if (traceBPath) params.trace_b_path = traceBPath;
    return analysis<DiffEntry[]>(
      'trace_diff',
      params,
      // 后端返回 segments[]（divergence 段），映射为前端 DiffEntry 展示形状
      (raw) => arr<Record<string, unknown>>(raw, 'segments').map((s): DiffEntry => ({
        inst_id: Number(s.start_inst_a ?? 0),
        kind: s.resynced ? 'changed' : 'removed',
        left: `#${s.start_inst_a} @ ${s.start_pc}`,
        right: s.resynced ? `resync #${s.resync_inst_b} @ ${s.resync_pc}` : `#${s.start_inst_b}`,
        note: String(s.detail ?? s.type ?? ''),
      })),
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

  /**
   * VM 去虚拟化（对齐后端 vm_abstract 静态分析 hint 参数，见 mcp_tools_analysis.cpp）。
   * 后端要求至少提供一个静态 hint（dispatcher_pc / indirect_branch_pc / mem_anchor_addr
   * / hints_file），否则直接报错——本工具不做无提示的自动结构发现。
   */
  async vmHandlers(hints?: {
    dispatcherPc?: string;
    indirectBranchPc?: string;
    memAnchorAddr?: string;
    dispatchType?: string;
    opcodeSize?: number;
    forceRerun?: boolean;
  }): Promise<VmHandler[]> {
    const params: Record<string, unknown> = {};
    if (hints?.dispatcherPc) params.dispatcher_pc = hints.dispatcherPc;
    if (hints?.indirectBranchPc) params.indirect_branch_pc = hints.indirectBranchPc;
    if (hints?.memAnchorAddr) params.mem_anchor_addr = hints.memAnchorAddr;
    if (hints?.dispatchType) params.dispatch_type = hints.dispatchType;
    if (hints?.opcodeSize) params.opcode_size = hints.opcodeSize;
    if (hints?.forceRerun) params.force_rerun = true;
    return analysis<VmHandler[]>(
      'vm_abstract',
      params,
      (raw) => arr<Record<string, unknown>>(raw, 'handlers').map((h, i): VmHandler => {
        const opcodes = Array.isArray(h.opcode_values) ? h.opcode_values as string[] : [];
        return {
          id: i,
          handler_pc: String(h.entry_pc ?? ''),
          opcode: opcodes[0] ?? '?',
          semantics: String(h.label ?? ''),
          hit_count: Number(h.execution_count ?? 0),
        };
      }),
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
    // Tauri 环境下返回真实的 tenet 后端（sidecar）日志缓冲区（见
    // src/lib/backendLog.ts，由 Rust 侧 `backend-log` 事件填充）。
    // 浏览器 / mock 模式下没有真实后端进程可言，退回 mock 数据。
    if (isTauri()) return getBackendLogSnapshot();
    return mock.mockLog();
  },
};
