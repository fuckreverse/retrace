/**
 * WS 消息层 —— 把 TenetWSService 的二进制协议封装成返回前端类型的函数。
 *
 * 每个函数：
 *   1. 用 flatbuffers Builder 构造请求内嵌消息；
 *   2. 通过 wsRequest 发送并等待响应；
 *   3. 校验响应 type，解析内嵌消息为前端类型（src/types/tenet.ts）。
 *
 * uint64 字段在生成绑定里是 bigint，这里统一转换为 number / hex 字符串
 * 以贴合现有前端类型（inst_id: number, pc/addr: hex string）。
 */
import * as flatbuffers from 'flatbuffers';
import { wsRequest, wsTransport, type WsResponse } from './ws';
import {
  MessageType,
  PassState as FbPassState,
  EvtNavigationMsg,
  FetchRowsRequest,
  FetchRowsResponse,
  GetRegsRequest,
  GetRegsResponse,
  ReadMemoryRequest,
  ReadMemoryResponse,
  NavigateRequest,
  NavigateResponse,
  NavBackResponse,
  NavForwardResponse,
  GetTraceInfoResponse,
  SearchForwardRequest,
  SearchForwardResponse,
  RunPassRequest,
  RunPassResponse,
  GetPassCatalogResponse,
  GetCallStackRequest,
  GetCallStackResponse,
  GetFunctionsResponse,
  RunAnalysisRequest,
  RunAnalysisResponse,
} from './ws-gen/tenet/ws';
import type {
  DisasmResult,
  InstRow,
  RegsResult,
  MemReadResult,
  TraceInfo,
  FunctionEntry,
  CallFrame,
  PassInfo,
  PassState,
} from '@/types/tenet';

// ─── 小工具 ─────────────────────────────────────────────────────────────────

/** AArch64 GPR 名称顺序，与后端 gpr[] 数组下标对齐（34 个） */
const GPR_NAMES = [
  'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9',
  'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19',
  'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28',
  'fp', 'lr', 'sp', 'nzcv', 'pc',
];

/** bigint → 0x 前缀 16 进制字符串 */
function hex(v: bigint): string {
  return `0x${v.toString(16)}`;
}

/** 校验响应类型，不符则抛错 */
function expect(resp: WsResponse, want: MessageType): flatbuffers.ByteBuffer {
  if (resp.type !== want) {
    throw new Error(`unexpected WS response type ${resp.type}, want ${want}`);
  }
  return new flatbuffers.ByteBuffer(resp.payload);
}

// ─── 热路径：指令 / 寄存器 / 内存 ────────────────────────────────────────────

export async function wsFetchRows(startId: number, count: number): Promise<DisasmResult> {
  const resp = await wsRequest(MessageType.FetchRowsReq, (b) =>
    FetchRowsRequest.createFetchRowsRequest(b, BigInt(startId), count),
  );
  const bb = expect(resp, MessageType.FetchRowsResp);
  const r = FetchRowsResponse.getRootAsFetchRowsResponse(bb);

  const rows: InstRow[] = [];
  const n = r.rowsLength();
  for (let i = 0; i < n; i++) {
    const row = r.rows(i);
    if (!row) continue;
    rows.push({
      inst_id: Number(row.instId()),
      pc: hex(row.pc()),
      mnemonic: (row.mnemonic() as string) ?? undefined,
      operands: (row.operands() as string) ?? undefined,
      // FetchRows 是轻量行，不含逐寄存器 diff/mem（按需 getRegs/readMemory）
    });
  }
  return { rows, start: startId, count };
}

export async function wsGetRegs(
  instId: number,
  when: 'before' | 'after' = 'before',
  includeFpr = false,
): Promise<RegsResult> {
  const whenCode = when === 'after' ? 1 : 0;
  const resp = await wsRequest(MessageType.GetRegsReq, (b) =>
    GetRegsRequest.createGetRegsRequest(b, BigInt(instId), whenCode, includeFpr),
  );
  const bb = expect(resp, MessageType.GetRegsResp);
  const r = GetRegsResponse.getRootAsGetRegsResponse(bb);

  const regs: Record<string, string> = {};
  const n = r.gprLength();
  for (let i = 0; i < n; i++) {
    const name = GPR_NAMES[i] ?? `r${i}`;
    const v = r.gpr(i);
    regs[name] = hex(v ?? BigInt(0));
  }
  return { inst_id: Number(r.instId()), when, regs };
}

export async function wsReadMemory(
  addr: string,
  size: number,
  instId: number,
): Promise<MemReadResult> {
  const addrBig = BigInt(addr);
  const resp = await wsRequest(MessageType.ReadMemoryReq, (b) =>
    ReadMemoryRequest.createReadMemoryRequest(b, addrBig, size, BigInt(instId)),
  );
  const bb = expect(resp, MessageType.ReadMemoryResp);
  const r = ReadMemoryResponse.getRootAsReadMemoryResponse(bb);

  const dataArr = r.dataArray();
  const knownArr = r.knownArray();
  const data = dataArr ? Array.from(dataArr) : [];
  const known = knownArr ? Array.from(knownArr, (v) => v !== 0) : [];
  const knownCount = known.reduce((acc, k) => acc + (k ? 1 : 0), 0);
  const hexStr = data.map((byte) => byte.toString(16).padStart(2, '0')).join('');

  return {
    addr: hex(r.addr()),
    size,
    inst_id: Number(r.instId()),
    known_count: knownCount,
    hex: hexStr,
    data,
    known,
  };
}

// ─── 导航 ───────────────────────────────────────────────────────────────────

export async function wsNavigate(instId: number): Promise<number> {
  const resp = await wsRequest(MessageType.NavigateReq, (b) =>
    NavigateRequest.createNavigateRequest(b, BigInt(instId)),
  );
  const bb = expect(resp, MessageType.NavigateResp);
  return Number(NavigateResponse.getRootAsNavigateResponse(bb).instId());
}

export async function wsNavBack(): Promise<{ instId: number; ok: boolean }> {
  const resp = await wsRequest(MessageType.NavBackReq, (b) => {
    // 无 payload：空表
    b.startObject(0);
    return b.endObject();
  });
  const bb = expect(resp, MessageType.NavBackResp);
  const r = NavBackResponse.getRootAsNavBackResponse(bb);
  return { instId: Number(r.instId()), ok: r.ok() };
}

export async function wsNavForward(): Promise<{ instId: number; ok: boolean }> {
  const resp = await wsRequest(MessageType.NavForwardReq, (b) => {
    b.startObject(0);
    return b.endObject();
  });
  const bb = expect(resp, MessageType.NavForwardResp);
  const r = NavForwardResponse.getRootAsNavForwardResponse(bb);
  return { instId: Number(r.instId()), ok: r.ok() };
}

// ─── Trace Info ──────────────────────────────────────────────────────────────

export async function wsTraceInfo(): Promise<TraceInfo> {
  const resp = await wsRequest(MessageType.GetTraceInfoReq, (b) => {
    b.startObject(0);
    return b.endObject();
  });
  const bb = expect(resp, MessageType.GetTraceInfoResp);
  const r = GetTraceInfoResponse.getRootAsGetTraceInfoResponse(bb);

  const base = r.moduleBase();
  const slide = r.moduleSlide();
  const numGpr = r.numGpr();
  return {
    status: 'loaded',
    arch: 'aarch64',
    gpr_count: numGpr || GPR_NAMES.length,
    module_name: r.moduleName() ?? '',
    module_base: hex(base),
    module_slide: hex(slide),
    image_base: hex(base - slide),
    address_range: { start: hex(base), end: hex(base) },
    file_size: 0,
    flags: {
      has_mem: true,
      has_nzcv: true,
      reg_diff: true,
      has_code: r.hasCode(),
      has_fpr: r.hasFpr(),
    },
    instruction_count: Number(r.totalInst()),
    anchor_count: 0,
  };
}

// ─── 搜索 ───────────────────────────────────────────────────────────────────

export async function wsSearchForward(query: string, fromInst: number): Promise<number[]> {
  const resp = await wsRequest(MessageType.SearchForwardReq, (b) => {
    const qOff = b.createString(query);
    return SearchForwardRequest.createSearchForwardRequest(b, qOff, BigInt(fromInst));
  });
  const bb = expect(resp, MessageType.SearchForwardResp);
  const r = SearchForwardResponse.getRootAsSearchForwardResponse(bb);
  const out: number[] = [];
  const n = r.resultsLength();
  for (let i = 0; i < n; i++) {
    const v = r.results(i);
    if (v != null) out.push(Number(v));
  }
  return out;
}

// ─── Pass 管理 ────────────────────────────────────────────────────────────────

function mapPassState(s: FbPassState): PassState {
  switch (s) {
    case FbPassState.Running: return 'running';
    case FbPassState.Completed: return 'completed';
    case FbPassState.Failed:
    case FbPassState.Cancelled: return 'failed';
    default: return 'not_run';
  }
}

export async function wsGetPassCatalog(): Promise<PassInfo[]> {
  const resp = await wsRequest(MessageType.GetPassCatalogReq, (b) => {
    b.startObject(0);
    return b.endObject();
  });
  const bb = expect(resp, MessageType.GetPassCatalogResp);
  const r = GetPassCatalogResponse.getRootAsGetPassCatalogResponse(bb);
  const out: PassInfo[] = [];
  const n = r.passesLength();
  for (let i = 0; i < n; i++) {
    const p = r.passes(i);
    if (!p) continue;
    out.push({
      name: p.name() ?? '',
      display_name: p.displayName() ?? p.name() ?? '',
      category: p.category() ?? '',
      state: mapPassState(p.state()),
    });
  }
  return out;
}

export async function wsRunPass(
  name: string,
  taintRegs: number[] = [],
  taintInstId = 0,
): Promise<{ ok: boolean; message: string }> {
  const resp = await wsRequest(MessageType.RunPassReq, (b) => {
    const nameOff = b.createString(name);
    const regsOff = RunPassRequest.createTaintRegsVector(b, taintRegs);
    return RunPassRequest.createRunPassRequest(b, nameOff, regsOff, BigInt(taintInstId));
  });
  const bb = expect(resp, MessageType.RunPassResp);
  const r = RunPassResponse.getRootAsRunPassResponse(bb);
  return { ok: r.ok(), message: r.message() ?? '' };
}

// ─── 调用栈 / 函数 ─────────────────────────────────────────────────────────────

export async function wsCallStack(instId: number): Promise<CallFrame[]> {
  const resp = await wsRequest(MessageType.GetCallStackReq, (b) =>
    GetCallStackRequest.createGetCallStackRequest(b, BigInt(instId)),
  );
  const bb = expect(resp, MessageType.GetCallStackResp);
  const r = GetCallStackResponse.getRootAsGetCallStackResponse(bb);
  const out: CallFrame[] = [];
  const n = r.entriesLength();
  for (let i = 0; i < n; i++) {
    const e = r.entries(i);
    if (!e) continue;
    out.push({
      func_name: e.functionName() ?? '',
      func_pc: hex(e.targetPc()),
      call_inst_id: Number(e.callInstId()),
      depth: e.depth(),
    });
  }
  return out;
}

// ─── 服务端推送事件 ─────────────────────────────────────────────────────────

/**
 * 订阅服务端导航事件（其他客户端 / GUI 触发的 navigate）。
 * 回调收到新的 inst_id。返回取消订阅函数。
 */
export function onServerNavigation(cb: (instId: number) => void): () => void {
  return wsTransport().onEvent((type, payload) => {
    if (type !== MessageType.EvtNavigation) return;
    const bb = new flatbuffers.ByteBuffer(payload);
    const evt = EvtNavigationMsg.getRootAsEvtNavigationMsg(bb);
    cb(Number(evt.instId()));
  });
}

export async function wsFunctions(): Promise<FunctionEntry[]> {
  const resp = await wsRequest(MessageType.GetFunctionsReq, (b) => {
    b.startObject(0);
    return b.endObject();
  });
  const bb = expect(resp, MessageType.GetFunctionsResp);
  const r = GetFunctionsResponse.getRootAsGetFunctionsResponse(bb);
  const out: FunctionEntry[] = [];
  const n = r.functionsLength();
  for (let i = 0; i < n; i++) {
    const f = r.functions(i);
    if (!f) continue;
    out.push({
      pc: hex(f.entryPc()),
      name: f.name() ?? '',
      calls: f.totalCalls(),
      insts: Number(f.totalInstructions()),
    });
  }
  return out;
}

// ─── 通用分析通道 ────────────────────────────────────────────────────────────
//
// RunAnalysis 是一条"万能"请求：把后端已注册的任意 MCP 工具名 + JSON 参数
// 透传给后端进程内的 TenetMcpService::call_tool()，返回的 json_data 字节
// 反序列化后，与 MCP over HTTP 的 content[0].text 结构完全一致。
// 前端所有非热路径分析能力（pattern / cfg / taint / strings ...）统一走这里，
// 从而彻底摆脱对 MCP HTTP 通道的依赖。

const _utf8Decoder = new TextDecoder('utf-8');

/**
 * 调用后端注册的分析工具。
 * @param toolName 后端 MCP 工具名（注意与前端能力名的映射，见 service.ts）
 * @param params   工具参数对象（会被序列化为 JSON）
 * @returns 解析后的工具结果 JSON（object / array / 标量）
 */
export async function wsRunAnalysis<T = unknown>(
  toolName: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  const paramsJson = JSON.stringify(params ?? {});
  const resp = await wsRequest(MessageType.RunAnalysisReq, (b) => {
    const nameOff = b.createString(toolName);
    const paramsOff = b.createString(paramsJson);
    return RunAnalysisRequest.createRunAnalysisRequest(b, nameOff, paramsOff);
  });
  const bb = expect(resp, MessageType.RunAnalysisResp);
  const r = RunAnalysisResponse.getRootAsRunAnalysisResponse(bb);

  if (!r.ok()) {
    throw new Error(`RunAnalysis(${toolName}) failed: ${r.error() ?? 'unknown error'}`);
  }

  const bytes = r.jsonDataArray();
  if (!bytes || bytes.length === 0) {
    // 空结果：视为 null（调用方按需回退到 mock / 默认值）
    return null as unknown as T;
  }
  const text = _utf8Decoder.decode(bytes);
  return JSON.parse(text) as T;
}
