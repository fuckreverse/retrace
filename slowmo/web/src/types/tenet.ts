/**
 * Tenet 数据模型 —— 对齐后端 MCP 工具返回结构。
 * 来源：tools/tenet/src/io/mcp/mcp_tools_*.cpp 与 src/common/*.h
 * 地址均为 rebase 后的展示地址(hex string)。
 */

/** trace_info */
export interface TraceInfo {
  status: string;
  arch: string;
  gpr_count: number;
  module_name: string;
  module_base: string;
  module_slide: string;
  image_base: string;
  address_range: { start: string; end: string };
  file_size: number;
  flags: {
    has_mem: boolean;
    has_nzcv: boolean;
    reg_diff: boolean;
    has_code: boolean;
    has_fpr?: boolean;
  };
  instruction_count: number;
  anchor_count: number;
}

export interface RegDiff {
  reg: string;
  value: string; // hex
}

export type MemAccessType = 'READ' | 'WRITE';

export interface MemAccess {
  type: MemAccessType;
  addr: string; // hex
  size: number;
  value: string; // hex
}

/** disasm 返回的单行指令 */
export interface InstRow {
  inst_id: number;
  pc: string; // hex
  mnemonic?: string;
  operands?: string;
  reg_diffs?: RegDiff[];
  mem_accesses?: MemAccess[];
}

export interface DisasmResult {
  rows: InstRow[];
  start: number;
  count: number;
}

/** get_regs */
export interface RegsResult {
  inst_id: number;
  when: 'before' | 'after';
  regs: Record<string, string>; // reg_name -> hex value
}

/** memread */
export interface MemReadResult {
  addr: string;
  size: number;
  inst_id: number;
  known_count: number;
  hex: string;
  data?: number[];
  known?: boolean[];
}

/** search_pc / xref */
export interface XrefResult {
  pc: string;
  exec_count: number;
  offset: number;
  returned: number;
  has_more: boolean;
  next_offset: number;
  inst_ids: number[];
}

/** call_graph (json) */
export interface CallGraphNode {
  pc: string;
  name: string;
  is_root: boolean;
  calls_made: number;
  calls_received: number;
}
export interface CallGraphEdge {
  caller: string;
  callee: string;
  call_count: number;
}
export interface CallGraphResult {
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
}

/** cfg_export (json) */
export interface CfgBlock {
  pc: string;
  x: number;
  y: number;
  width: number;
  height: number;
  end_pc?: string;
  executions?: number;
  terminator?: 'fallthrough' | 'branch' | 'conditional_branch' | 'call' | 'return' | 'indirect_branch';
  disasm?: string[];
}
export interface CfgEdge {
  from: string;
  to: string;
  arrow?: string;
  kind?: 'fallthrough' | 'branch';
  taken_count?: number;
  polyline?: { x: number; y: number }[];
}
export interface CfgResult {
  format: string;
  scope?: 'function' | 'global';
  function?: { entry_pc: string; name: string; total_calls?: number };
  blocks: CfgBlock[];
  edges: CfgEdge[];
  canvas_width?: number;
  canvas_height?: number;
}

/** functions */
export interface FunctionEntry {
  pc: string;
  name: string;
  calls: number;
  insts: number;
}

/** taint_forward step */
export interface TaintStep {
  inst_id: number;
  pc: string;
  type: string;
  triton_resolved: boolean;
  dst_reg?: string;
  dst_mem?: string;
  dst_mem_size?: number;
}
export interface TaintForwardResult {
  statistics: {
    events_count: number;
    steps_count: number;
    instructions_processed: number;
    tainted_memory_count: number;
    kill_events: number;
    call_crossings: number;
  };
  stop_reason?: string;
  tainted_regs_final: number[];
  steps: TaintStep[];
  total_steps: number;
}

/** pattern_scan */
export interface PatternMatch {
  pattern_name: string;
  category: string;
  confidence: number;
  start_inst_id: number;
  end_inst_id: number;
  anchor_pc: string;
  description: string;
}
export interface PatternScanResult {
  total: number;
  matches: PatternMatch[];
}

/** strings_scan */
export interface StringEntry {
  inst_id: number;
  addr: string;
  value: string;
  length: number;
  encoding?: string;
}

/** objc_messages */
export interface ObjcMessage {
  inst_id: number;
  cls: string;
  selector: string;
  args: string;
  ret: string;
}

/** call stack frame */
export interface CallFrame {
  func_name: string;
  func_pc: string;
  call_inst_id: number;
  depth: number;
}

/** analysis pass 状态 */
export type PassState = 'not_run' | 'running' | 'completed' | 'failed';
export interface PassInfo {
  name: string;
  display_name: string;
  category: string;
  state: PassState;
  progress?: number;
  summary?: string;
  message?: string;
}

/** constants —— 常量识别 (魔数 / 密码学常量 / 表首地址) */
export interface ConstantEntry {
  inst_id: number;
  value: string; // hex
  kind: string; // e.g. "AES S-box", "SHA-256 K", "Magic", "Immediate"
  note: string;
  confidence: number;
}

/** algorithm_summary —— 自动算法识别 */
export interface AlgorithmEntry {
  name: string; // e.g. "AES-128", "SHA-256"
  category: string; // Crypto / Hash / Encoding / Checksum
  confidence: number;
  start_inst_id: number;
  end_inst_id: number;
  evidence: string[];
  key_size?: number;
}

/** api_intercepts —— C API 拦截记录 (CommonCrypto / BoringSSL / JNI) */
export interface ApiCallEntry {
  inst_id: number;
  library: string; // CommonCrypto / BoringSSL / libc
  func: string;
  args: string;
  ret: string;
}

/** loop_semantics —— 循环语义 */
export interface LoopEntry {
  header_inst_id: number;
  header_pc: string;
  iterations: number;
  body_size: number;
  kind: string; // "memcpy-like" / "xor-loop" / "counter" / "unknown"
  induction_var?: string;
}

/** register_timeline —— 单寄存器随时间取值序列 */
export interface RegTimelinePoint {
  inst_id: number;
  value: string; // hex
}
export interface RegTimeline {
  reg: string;
  points: RegTimelinePoint[];
}

/** memory_search —— 内存值/字节序列搜索命中 */
export interface MemSearchHit {
  addr: string;
  inst_id: number;
  match_type: 'read' | 'write';
  value: string; // hex
  context: string; // 命中处上下文说明
}

/** memory_strings —— 运行时内存中出现的字符串 */
export interface MemStringEntry {
  addr: string;
  inst_id: number;
  value: string;
  length: number;
  region: string; // stack / heap / const
}

/** entropy —— 分块香农熵，用于识别加密/压缩区 */
export interface EntropyBlock {
  addr: string;
  size: number;
  entropy: number; // 0..8
  classification: string; // "high (encrypted?)" / "text" / "code" / "low"
}

/** yara —— YARA 规则命中 */
export interface YaraMatch {
  rule: string;
  namespace: string;
  tags: string[];
  addr: string;
  inst_id: number;
  strings_matched: number;
}

/** window_stats —— 指令窗口统计（字段对齐后端 mcp_tools_analysis.cpp window_stats 输出） */
export interface WindowStat {
window_start: number;
window_end: number;
inst_count: number;
mem_reads: number;
mem_writes: number;
/** 分支密度 0..1（branches / instruction_count），非计数值 */
branch_density: number;
/** 窗口内唯一 PC 数（指令多样性） */
unique_pcs: number;
/** 助记符分布的香农熵（越高越分散） */
mnemonic_entropy: number;
/** Top mnemonic（按出现次数排序，取第一个作为"主导指令"展示） */
dominant_mnemonic: string;
}

/** trace_fold —— 折叠/去重后的执行段(循环/重复块压缩) */
export interface FoldEntry {
  start_inst_id: number;
  end_inst_id: number;
  repeat_count: number;
  pattern_pc: string;
  summary: string;
}

/** trace_diff —— 两条 trace 的差异条目 */
export interface DiffEntry {
  inst_id: number;
  kind: 'added' | 'removed' | 'changed' | 'same';
  left: string;
  right: string;
  note?: string;
}

/** taint_sources —— 已登记的污点源 */
export interface TaintSource {
  id: number;
  kind: 'register' | 'memory' | 'api_return';
  location: string; // e.g. "x0 @ #4120" / "0x16d002000"
  label: string;
  active: boolean;
  propagated: number; // 影响到的指令数
}

/** dataflow_graph —— 数据流图节点/边 */
export interface DataflowNode {
  id: string;
  label: string;
  kind: 'reg' | 'mem' | 'const' | 'op';
  x: number;
  y: number;
  inst_id?: number;
}
export interface DataflowEdge {
  from: string;
  to: string;
  label?: string;
}
export interface DataflowGraph {
  nodes: DataflowNode[];
  edges: DataflowEdge[];
  canvas_width: number;
  canvas_height: number;
}

/** backward_taint —— 反向污点/producer chain 步骤 */
export interface BackwardTaintStep {
  inst_id: number;
  pc: string;
  reg: string;
  contribution: string; // 说明该指令如何贡献了目标值
}

/** objc_crypto —— ObjC × 密码学关联(消息与密钥/密文的关系) */
export interface ObjcCryptoLink {
  inst_id: number;
  selector: string;
  crypto_role: string; // key / iv / plaintext / ciphertext / digest
  data_preview: string;
  linked_api?: string;
}

/** snapshots —— 寄存器/内存快照点 */
export interface SnapshotEntry {
  id: number;
  inst_id: number;
  pc: string;
  label: string;
  reg_count: number;
  mem_bytes: number;
}

/** dwarf —— 调试符号(源码行/变量) */
export interface DwarfEntry {
  pc: string;
  inst_id: number;
  file: string;
  line: number;
  func: string;
  variables: string[];
}

/** vm_workspace —— VMP/去虚拟化工作区中的 handler/bytecode */
export interface VmHandler {
  id: number;
  handler_pc: string;
  opcode: string;
  semantics: string;
  hit_count: number;
}

/** log —— 分析引擎日志 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export interface LogEntry {
  ts: string;
  level: LogLevel;
  source: string;
  message: string;
}

/** cache_manager —— 索引/缓存条目 */
export interface CacheEntry {
  name: string;
  kind: string; // RocksDB / mmap / memoized
  size_bytes: number;
  status: 'fresh' | 'stale' | 'building';
  last_built: string;
}
