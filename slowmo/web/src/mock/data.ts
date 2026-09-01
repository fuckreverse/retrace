/**
 * Mock 数据层 —— 在后端 TenetService 未就绪时提供逼真的 AArch64 trace 数据。
 * 生成一段确定性的伪 trace，覆盖所有面板所需的数据形态。
 */
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
  InstRow,
  LogEntry,
  LoopEntry,
  MemAccess,
  MemReadResult,
  MemSearchHit,
  MemStringEntry,
  ObjcCryptoLink,
  ObjcMessage,
  PassInfo,
  PatternMatch,
  RegDiff,
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
  ThreadsResult,
  ThreadFilterResult,
  CrossThreadDataflowResult,
} from '@/types/tenet';

const GPR_NAMES = [
  'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9',
  'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19',
  'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28',
  'fp', 'lr', 'sp', 'nzcv', 'pc',
];

export const TOTAL_INST = 20000;
const IMAGE_BASE = 0x100000000n;

function hex(v: bigint | number): string {
  const b = typeof v === 'number' ? BigInt(Math.floor(v)) : v;
  return '0x' + (b & 0xffffffffffffffffn).toString(16).toUpperCase();
}

// 简单确定性 PRNG（LCG）。
// 小种子（如循环下标 0~100）直接喂给 LCG 时，首次输出的低位熵不足，
// 会导致连续种子的第一次采样高度聚集（例如 mockCallGraph 曾出现
// 全部种子首次采样都 <0.6，导致恒定生成 0 条边）。这里先用 32 位整数
// 哈希（xorshift 变体）把种子打散，避免小种子/连续种子的强相关性；
// 打散仅用于播种，不改变后续调用序列的分布性质。
function rng(seed: number): () => number {
  let s = seed >>> 0;
  s ^= s << 13; s >>>= 0;
  s ^= s >>> 17;
  s ^= s << 5; s >>>= 0;
  s = (s ^ 0x9e3779b9) >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0xffffffff;
  };
}

const MNEMONICS = [
  'mov', 'add', 'sub', 'ldr', 'str', 'ldp', 'stp', 'and', 'orr', 'eor',
  'lsl', 'lsr', 'ror', 'cmp', 'b', 'bl', 'blr', 'ret', 'cbz', 'cbnz',
  'adrp', 'movz', 'movk', 'mul', 'madd', 'bfi', 'ubfx', 'rev',
];

// 若干"函数"入口(静态地址)
const FUNCS: { pc: bigint; name: string }[] = [
  { pc: 0x100004000n, name: 'sub_100004000' },
  { pc: 0x100004120n, name: '-[CryptoManager deriveKey:]' },
  { pc: 0x1000043a0n, name: 'aes_key_expansion' },
  { pc: 0x100004610n, name: 'sha256_transform' },
  { pc: 0x100004890n, name: 'sub_100004890' },
  { pc: 0x100004a20n, name: 'CCCryptorCreate' },
  { pc: 0x100004c00n, name: 'anti_debug_check' },
  { pc: 0x100004e40n, name: 'sub_100004E40' },
];

/** 生成第 id 条指令 */
function genInst(id: number): InstRow {
  const r = rng(id + 1);
  const func = FUNCS[Math.floor(r() * FUNCS.length)];
  const pcOff = Math.floor(r() * 0x40) * 4;
  const pc = func.pc + BigInt(pcOff) - 0x100000000n + IMAGE_BASE;
  const mnemonic = MNEMONICS[Math.floor(r() * MNEMONICS.length)];

  const isMem = ['ldr', 'str', 'ldp', 'stp'].includes(mnemonic);
  const rd = Math.floor(r() * 29);
  const rn = Math.floor(r() * 29);
  let operands = '';
  const regDiffs: RegDiff[] = [];
  const memAccesses: MemAccess[] = [];

  if (isMem) {
    const addr = 0x16d000000n + BigInt(Math.floor(r() * 0x1000) * 8);
    const val = BigInt(Math.floor(r() * 0xffffffff));
    const type = mnemonic.startsWith('ld') ? 'READ' : 'WRITE';
    operands = `x${rd}, [x${rn}, #0x${(Math.floor(r() * 32) * 8).toString(16)}]`;
    memAccesses.push({ type, addr: hex(addr), size: 8, value: hex(val) });
    if (type === 'READ') regDiffs.push({ reg: `x${rd}`, value: hex(val) });
  } else if (mnemonic === 'ret') {
    operands = '';
  } else if (['b', 'bl', 'blr', 'cbz', 'cbnz'].includes(mnemonic)) {
    const target = FUNCS[Math.floor(r() * FUNCS.length)].pc - 0x100000000n + IMAGE_BASE;
    operands = mnemonic === 'blr' ? `x${rn}` : hex(target);
    if (mnemonic === 'bl' || mnemonic === 'blr') {
      regDiffs.push({ reg: 'lr', value: hex(pc + 4n) });
    }
  } else if (['movz', 'movk', 'mov'].includes(mnemonic)) {
    const imm = Math.floor(r() * 0xffff);
    operands = `x${rd}, #0x${imm.toString(16)}`;
    regDiffs.push({ reg: `x${rd}`, value: hex(BigInt(imm)) });
  } else {
    const imm = Math.floor(r() * 0xff);
    operands = `x${rd}, x${rn}, #0x${imm.toString(16)}`;
    regDiffs.push({ reg: `x${rd}`, value: hex(BigInt(Math.floor(r() * 0xffffffff))) });
  }

  // nzcv 偶尔变化
  if (mnemonic === 'cmp') regDiffs.push({ reg: 'nzcv', value: hex(BigInt(Math.floor(r() * 16) << 28)) });
  regDiffs.push({ reg: 'pc', value: hex(pc) });

  return {
    inst_id: id,
    pc: hex(pc),
    mnemonic,
    operands,
    reg_diffs: regDiffs,
    mem_accesses: memAccesses,
  };
}

// 缓存已生成指令
const instCache = new Map<number, InstRow>();
export function mockInst(id: number): InstRow {
  if (id < 0) id = 0;
  if (id >= TOTAL_INST) id = TOTAL_INST - 1;
  let row = instCache.get(id);
  if (!row) {
    row = genInst(id);
    instCache.set(id, row);
  }
  return row;
}

export function mockDisasm(start: number, count: number): DisasmResult {
  const rows: InstRow[] = [];
  const end = Math.min(start + count, TOTAL_INST);
  for (let i = start; i < end; i++) rows.push(mockInst(i));
  return { rows, start, count: end - start };
}

export function mockTraceInfo(): TraceInfo {
  return {
    status: 'loaded',
    arch: 'aarch64',
    gpr_count: 34,
    module_name: 'DemoTarget.app/DemoTarget',
    module_base: '0x104A00000',
    module_slide: '0x4A00000',
    image_base: '0x100000000',
    address_range: { start: '0x100004000', end: '0x100005000' },
    file_size: 48_237_184,
    flags: { has_mem: true, has_nzcv: true, reg_diff: true, has_code: true, has_fpr: false },
    instruction_count: TOTAL_INST,
    anchor_count: Math.floor(TOTAL_INST / 1024),
  };
}

/** 累积重建到某条指令时的完整寄存器状态 */
export function mockRegs(instId: number): RegsResult {
  const regs: Record<string, string> = {};
  const r = rng(instId * 7 + 3);
  for (const name of GPR_NAMES) {
    if (name === 'nzcv') {
      regs[name] = hex(BigInt(Math.floor(r() * 16) << 28));
    } else if (name === 'pc') {
      regs[name] = mockInst(instId).pc;
    } else if (name === 'sp') {
      regs[name] = hex(0x16d000000n - BigInt(Math.floor(r() * 0x400) * 16));
    } else {
      regs[name] = hex(BigInt(Math.floor(r() * 0xffffffffff)));
    }
  }
  return { inst_id: instId, when: 'before', regs };
}

export function mockMemRead(addr: string, size: number, instId: number): MemReadResult {
  const base = BigInt(addr);
  const r = rng(Number(base & 0xffffn) + instId);
  const data: number[] = [];
  const known: boolean[] = [];
  for (let i = 0; i < size; i++) {
    const isKnown = r() > 0.15;
    known.push(isKnown);
    data.push(isKnown ? Math.floor(r() * 256) : 0);
  }
  const hexStr = data.map((b) => b.toString(16).padStart(2, '0')).join('');
  return {
    addr,
    size,
    inst_id: instId,
    known_count: known.filter(Boolean).length,
    hex: hexStr,
    data,
    known,
  };
}

/** mock 模式下的服务端持久书签基线（模块级可变态，模拟跨客户端同步） */
const MOCK_BOOKMARKS = new Set<number>();

/** 在已生成的 mock 指令窗口内做子串匹配（贴合 GUI Search 的 mnemonic+operands 语义） */
export function mockSearchForward(query: string, fromInst: number): number[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const hits: number[] = [];
  const scanLimit = Math.min(TOTAL_INST, fromInst + 200_000);
  for (let i = fromInst; i < scanLimit && hits.length < 500; i++) {
    const row = mockInst(i);
    const text = `${row.mnemonic ?? ''} ${row.operands ?? ''}`.toLowerCase();
    if (text.includes(q)) hits.push(i);
  }
  return hits;
}

export function mockToggleBookmark(instId: number): number[] {
  if (MOCK_BOOKMARKS.has(instId)) MOCK_BOOKMARKS.delete(instId);
  else MOCK_BOOKMARKS.add(instId);
  return Array.from(MOCK_BOOKMARKS).sort((a, b) => a - b);
}

export function mockGetBookmarks(): number[] {
  return Array.from(MOCK_BOOKMARKS).sort((a, b) => a - b);
}

export function mockXref(pc: string): XrefResult {
  const r = rng(Number(BigInt(pc) & 0xffffn));
  const count = 1 + Math.floor(r() * 40);
  const ids: number[] = [];
  for (let i = 0; i < count; i++) ids.push(Math.floor(r() * TOTAL_INST));
  ids.sort((a, b) => a - b);
  return {
    pc,
    exec_count: count,
    offset: 0,
    returned: ids.length,
    has_more: false,
    next_offset: ids.length,
    inst_ids: ids,
  };
}

export function mockFunctions(): FunctionEntry[] {
  return FUNCS.map((f, i) => {
    const r = rng(i + 100);
    return {
      pc: hex(f.pc - 0x100000000n + IMAGE_BASE),
      name: f.name,
      calls: 1 + Math.floor(r() * 200),
      insts: 10 + Math.floor(r() * 500),
    };
  });
}

export function mockCallGraph(): CallGraphResult {
  const nodes = FUNCS.map((f, i) => {
    const r = rng(i + 200);
    return {
      pc: hex(f.pc - 0x100000000n + IMAGE_BASE),
      name: f.name,
      is_root: i === 0,
      calls_made: Math.floor(r() * 50),
      calls_received: Math.floor(r() * 80),
    };
  });
  const edges = [];
  for (let i = 0; i < FUNCS.length; i++) {
    for (let j = 0; j < FUNCS.length; j++) {
      if (i === j) continue;
      const r = rng(i * 10 + j);
      if (r() > 0.6) {
        edges.push({ caller: nodes[i].pc, callee: nodes[j].pc, call_count: 1 + Math.floor(r() * 30) });
      }
    }
  }
  return { nodes, edges };
}

export function mockCfg(): CfgResult {
  const r = rng(42);
  const blocks: CfgResult['blocks'] = [];
  const terminators: NonNullable<CfgResult['blocks'][number]['terminator']>[] = [
    'fallthrough', 'conditional_branch', 'call', 'fallthrough',
    'conditional_branch', 'call', 'return',
  ];
  const nBlocks = 7;
  for (let i = 0; i < nBlocks; i++) {
    const pc = FUNCS[1].pc + BigInt(i * 0x20) - 0x100000000n + IMAGE_BASE;
    blocks.push({
      pc: hex(pc),
      x: 60 + (i % 3) * 240,
      y: 40 + Math.floor(i / 3) * 150,
      width: 200,
      height: 90,
      end_pc: hex(pc + 8n),
      executions: 1 + Math.floor(r() * 500),
      terminator: terminators[i],
      disasm: [
        `${hex(pc)}  ldr  x0, [sp, #0x10]`,
        `${hex(pc + 4n)}  add  x0, x0, #0x1`,
        `${hex(pc + 8n)}  cmp  x0, #0x10`,
      ],
    });
  }
  const edges: CfgResult['edges'] = [];
  const addEdge = (fromIndex: number, toIndex: number, kind: 'fallthrough' | 'branch', takenCount: number) => {
    const from = blocks[fromIndex];
    const to = blocks[toIndex];
    const start = { x: from.x + from.width / 2, y: from.y + from.height };
    const end = { x: to.x + to.width / 2, y: to.y };
    const bendY = (start.y + end.y) / 2;
    edges.push({
      from: from.pc,
      to: to.pc,
      kind,
      taken_count: takenCount,
      polyline: [start, { x: start.x, y: bendY }, { x: end.x, y: bendY }, end],
    });
  };
  for (let i = 0; i < nBlocks - 1; i++) {
    addEdge(i, i + 1, i % 2 === 0 ? 'fallthrough' : 'branch', 1 + Math.floor(r() * 300));
  }
  // 一条回边(循环)
  addEdge(4, 2, 'branch', 120);
  return {
    format: 'json',
    scope: 'function',
    function: {
      entry_pc: hex(FUNCS[1].pc - 0x100000000n + IMAGE_BASE),
      name: FUNCS[1].name,
      total_calls: 37,
    },
    blocks,
    edges,
    canvas_width: 780,
    canvas_height: 360,
  };
}

export function mockCallStack(instId: number): CallFrame[] {
  const r = rng(instId);
  const depth = 1 + Math.floor(r() * 4);
  const frames: CallFrame[] = [];
  for (let i = 0; i < depth; i++) {
    const f = FUNCS[Math.floor(r() * FUNCS.length)];
    frames.push({
      func_name: f.name,
      func_pc: hex(f.pc - 0x100000000n + IMAGE_BASE),
      call_inst_id: Math.max(0, instId - Math.floor(r() * 2000) - i * 100),
      depth: i,
    });
  }
  return frames;
}

export function mockPatterns(): PatternMatch[] {
  return [
    { pattern_name: 'AES S-Box lookup', category: 'Crypto', confidence: 0.95, start_inst_id: 3120, end_inst_id: 3450, anchor_pc: '0x1000043A0', description: '检测到 AES 密钥扩展中的 S-Box 查表访问模式' },
    { pattern_name: 'SHA-256 round constants', category: 'Crypto', confidence: 0.88, start_inst_id: 5600, end_inst_id: 6200, anchor_pc: '0x100004610', description: 'SHA-256 轮常量序列 0x428A2F98...' },
    { pattern_name: 'ptrace anti-debug', category: 'AntiDebug', confidence: 0.72, start_inst_id: 9800, end_inst_id: 9820, anchor_pc: '0x100004C00', description: 'ptrace(PT_DENY_ATTACH) 反调试检测' },
    { pattern_name: 'XOR obfuscation loop', category: 'Other', confidence: 0.61, start_inst_id: 12400, end_inst_id: 12900, anchor_pc: '0x100004890', description: '循环 XOR 解混淆模式' },
  ];
}

export function mockStrings(): StringEntry[] {
  const samples = [
    'CryptoManager', 'deriveKey:', 'AES-256-CBC', '/private/var/mobile',
    'kSecAttrKeyType', 'Failed to allocate', '%s: invalid argument',
    'https://api.example.com/v2/auth', 'X-Signature', 'com.demo.target',
  ];
  return samples.map((s, i) => ({
    inst_id: 1000 + i * 340,
    addr: hex(0x100006000n + BigInt(i * 0x20)),
    value: s,
    length: s.length,
    encoding: 'ASCII',
  }));
}

export function mockObjcMessages(): ObjcMessage[] {
  const rows: ObjcMessage[] = [
    { inst_id: 4120, cls: 'NSString', selector: 'stringWithUTF8String:', args: '(char*)0x16d001000', ret: '0x2830a1240' },
    { inst_id: 4500, cls: 'CryptoManager', selector: 'deriveKey:', args: '(NSData*)0x2830a1280', ret: '0x2830a1300' },
    { inst_id: 5010, cls: 'NSData', selector: 'bytes', args: '', ret: '0x16d002000' },
    { inst_id: 7800, cls: 'NSMutableData', selector: 'appendBytes:length:', args: '0x16d002000, 32', ret: 'void' },
  ];
  return rows;
}

export function mockTaintForward(regIndex: number, instId: number): { steps: TaintStep[]; stats: { instructions_processed: number; tainted_memory_count: number } } {
  const r = rng(regIndex * 31 + instId);
  const steps: TaintStep[] = [];
  const n = 20 + Math.floor(r() * 60);
  let cur = instId;
  for (let i = 0; i < n; i++) {
    cur += 1 + Math.floor(r() * 50);
    if (cur >= TOTAL_INST) break;
    steps.push({
      inst_id: cur,
      pc: mockInst(cur).pc,
      type: ['RegToReg', 'RegToMem', 'MemToReg'][Math.floor(r() * 3)],
      triton_resolved: r() > 0.5,
      dst_reg: `x${Math.floor(r() * 29)}`,
    });
  }
  return { steps, stats: { instructions_processed: n * 40, tainted_memory_count: Math.floor(n / 3) } };
}

/** mock 模式下的 pass 状态基线（模块级可变态，供 mockRunPass 修改后持久生效） */
const MOCK_PASS_BASELINE: PassInfo[] = [
  { name: 'xref', display_name: 'Cross References', category: 'Structure', state: 'completed', summary: '312 unique PCs indexed' },
  { name: 'function', display_name: 'Function Discovery', category: 'Structure', state: 'completed', summary: '8 functions' },
  { name: 'cfg', display_name: 'Control Flow Graph', category: 'Structure', state: 'completed', summary: '7 blocks, 8 edges' },
  { name: 'call_graph', display_name: 'Call Graph', category: 'Structure', state: 'not_run' },
  { name: 'loop', display_name: 'Loop Detection', category: 'Structure', state: 'completed', summary: '3 loops' },
  { name: 'taint', display_name: 'Forward Taint', category: 'Taint', state: 'not_run' },
  { name: 'backward_taint', display_name: 'Backward Taint', category: 'Taint', state: 'not_run' },
  { name: 'pattern', display_name: 'Crypto/AntiDebug Patterns', category: 'Crypto-Pattern', state: 'completed', summary: '4 matches' },
  { name: 'constants', display_name: 'Constant Materialization', category: 'Crypto-Pattern', state: 'not_run' },
  { name: 'algorithm_summary', display_name: 'Algorithm Summary', category: 'Crypto-Pattern', state: 'not_run' },
  { name: 'strings', display_name: 'Static Strings', category: 'Memory-String', state: 'completed', summary: '10 strings' },
  { name: 'memory_strings', display_name: 'Runtime Memory Strings', category: 'Memory-String', state: 'not_run' },
  { name: 'objc', display_name: 'ObjC Messages', category: 'ObjC-Platform', state: 'completed', summary: '4 messages' },
  { name: 'objc_crypto', display_name: 'ObjC × Crypto', category: 'ObjC-Platform', state: 'not_run' },
  { name: 'syscall_intercept', display_name: 'API Intercepts', category: 'ObjC-Platform', state: 'not_run' },
  { name: 'window_stats', display_name: 'Window Stats', category: 'Profile-Trace', state: 'not_run' },
  { name: 'trace_fold', display_name: 'Trace Fold', category: 'Profile-Trace', state: 'not_run' },
];

export function mockPasses(): PassInfo[] {
  return MOCK_PASS_BASELINE.map((p) => ({ ...p }));
}

/** mock 模式下模拟真实运行：直接标记 completed，供 AnalysisPanel 轮询感知变化 */
export function mockRunPass(name: string): { ok: boolean; message: string } {
  const p = MOCK_PASS_BASELINE.find((x) => x.name === name);
  if (!p) return { ok: false, message: `unknown pass: ${name}` };
  p.state = 'completed';
  p.summary = p.summary ?? 'done (mock)';
  return { ok: true, message: 'completed' };
}

export function mockConstants(): ConstantEntry[] {
  return [
    { inst_id: 3120, value: '0x63636363', kind: 'AES S-box', note: 'AES SubBytes 查表首值', confidence: 0.94 },
    { inst_id: 3180, value: '0x01000000', kind: 'AES Rcon', note: '密钥扩展轮常量 Rcon[1]', confidence: 0.9 },
    { inst_id: 5600, value: '0x428A2F98', kind: 'SHA-256 K', note: 'SHA-256 初始轮常量 K[0]', confidence: 0.96 },
    { inst_id: 5604, value: '0x71374491', kind: 'SHA-256 K', note: 'SHA-256 轮常量 K[1]', confidence: 0.96 },
    { inst_id: 5608, value: '0x6A09E667', kind: 'SHA-256 IV', note: 'SHA-256 初始哈希值 H[0]', confidence: 0.93 },
    { inst_id: 12400, value: '0xDEADBEEF', kind: 'Magic', note: '疑似自定义幻数/校验标记', confidence: 0.55 },
    { inst_id: 9800, value: '0x1F', kind: 'Immediate', note: 'ptrace PT_DENY_ATTACH 请求码', confidence: 0.7 },
  ];
}

export function mockAlgorithms(): AlgorithmEntry[] {
  return [
    {
      name: 'AES-128', category: 'Crypto', confidence: 0.92, start_inst_id: 3120, end_inst_id: 3450,
      key_size: 128, evidence: ['S-box 查表模式', 'Rcon 轮常量序列', '10 轮结构 MixColumns'],
    },
    {
      name: 'SHA-256', category: 'Hash', confidence: 0.88, start_inst_id: 5600, end_inst_id: 6200,
      evidence: ['64 个 K 轮常量', '8 个 H 初始向量', 'Σ/σ 旋转移位组合'],
    },
    {
      name: 'Base64', category: 'Encoding', confidence: 0.64, start_inst_id: 14200, end_inst_id: 14400,
      evidence: ['64 字符查表', '3→4 字节分组循环'],
    },
  ];
}

export function mockApiIntercepts(): ApiCallEntry[] {
  return [
    { inst_id: 4602, library: 'CommonCrypto', func: 'CCCryptorCreate', args: 'op=kCCEncrypt, alg=kCCAlgorithmAES, key=0x2830a1300, keyLen=16', ret: 'kCCSuccess' },
    { inst_id: 4820, library: 'CommonCrypto', func: 'CCCryptorUpdate', args: 'in=0x16d002000, len=32, out=0x16d003000', ret: 'kCCSuccess' },
    { inst_id: 5900, library: 'CommonCrypto', func: 'CC_SHA256', args: 'data=0x16d002000, len=64, md=0x16d004000', ret: '0x16d004000' },
    { inst_id: 9800, library: 'libc', func: 'ptrace', args: 'request=PT_DENY_ATTACH(31), pid=0', ret: '0' },
    { inst_id: 15200, library: 'BoringSSL', func: 'EVP_DigestSign', args: 'ctx=0x2830b0000, sig=0x16d005000', ret: '1' },
  ];
}

export function mockLoops(): LoopEntry[] {
  return [
    { header_inst_id: 3200, header_pc: hex(0x1000043c0n), iterations: 176, body_size: 12, kind: 'xor-loop', induction_var: 'x8' },
    { header_inst_id: 5700, header_pc: hex(0x100004650n), iterations: 64, body_size: 28, kind: 'counter', induction_var: 'w9' },
    { header_inst_id: 12440, header_pc: hex(0x1000048c0n), iterations: 512, body_size: 6, kind: 'memcpy-like', induction_var: 'x10' },
  ];
}

export function mockRegTimeline(reg: string): RegTimeline {
  const seed = reg.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
  const r = rng(seed);
  const points = [];
  let id = 0;
  let val = BigInt(Math.floor(r() * 0xffffffff));
  for (let i = 0; i < 60; i++) {
    id += 20 + Math.floor(r() * 400);
    if (id >= TOTAL_INST) break;
    // 偶尔跳变，否则微调
    if (r() > 0.7) val = BigInt(Math.floor(r() * 0xffffffffff));
    else val = (val + BigInt(Math.floor(r() * 0x40))) & 0xffffffffffffffffn;
    points.push({ inst_id: id, value: hex(val) });
  }
  return { reg, points };
}

/* ---------- Memory-String 类 ---------- */
export function mockMemSearch(query: string): MemSearchHit[] {
  const r = rng(query.split('').reduce((a, c) => a + c.charCodeAt(0), 7));
  const n = 3 + Math.floor(r() * 8);
  const hits: MemSearchHit[] = [];
  for (let i = 0; i < n; i++) {
    const id = Math.floor(r() * TOTAL_INST);
    hits.push({
      addr: hex(0x16d000000n + BigInt(Math.floor(r() * 0x2000) * 8)),
      inst_id: id,
      match_type: r() > 0.5 ? 'read' : 'write',
      value: hex(BigInt(Math.floor(r() * 0xffffffff))),
      context: `${mockInst(id).mnemonic} @ #${id}`,
    });
  }
  return hits.sort((a, b) => a.inst_id - b.inst_id);
}

export function mockMemStrings(): MemStringEntry[] {
  const samples = [
    { v: 'user_token=eyJhbGciOi', reg: 'heap' },
    { v: '/data/data/com.demo/files', reg: 'const' },
    { v: 'AES/CBC/PKCS7Padding', reg: 'const' },
    { v: '\\x00\\x01\\x02key_material', reg: 'stack' },
    { v: 'HmacSHA256', reg: 'const' },
    { v: 'device_id:8f3a91c2', reg: 'heap' },
    { v: 'Bearer 4f9a2e...', reg: 'stack' },
  ];
  return samples.map((s, i) => ({
    addr: hex(0x16d001000n + BigInt(i * 0x40)),
    inst_id: 2000 + i * 900,
    value: s.v,
    length: s.v.length,
    region: s.reg,
  }));
}

export function mockEntropy(): EntropyBlock[] {
  const r = rng(88);
  const blocks: EntropyBlock[] = [];
  for (let i = 0; i < 24; i++) {
    const e = Math.min(8, Math.max(0, 2 + r() * 6.2));
    let cls = 'low';
    if (e > 7.2) cls = 'high (encrypted?)';
    else if (e > 5.5) cls = 'compressed';
    else if (e > 3.5) cls = 'code';
    else cls = 'text/low';
    blocks.push({
      addr: hex(0x16d000000n + BigInt(i * 0x100)),
      size: 256,
      entropy: Number(e.toFixed(2)),
      classification: cls,
    });
  }
  return blocks;
}

export function mockYara(): YaraMatch[] {
  return [
    { rule: 'AES_Constants', namespace: 'crypto', tags: ['crypto', 'aes'], addr: hex(0x1000043a0n), inst_id: 3120, strings_matched: 3 },
    { rule: 'SHA256_Init', namespace: 'crypto', tags: ['crypto', 'hash'], addr: hex(0x100004610n), inst_id: 5600, strings_matched: 2 },
    { rule: 'AntiDebug_ptrace', namespace: 'evasion', tags: ['anti-debug'], addr: hex(0x100004c00n), inst_id: 9800, strings_matched: 1 },
    { rule: 'Base64_Alphabet', namespace: 'encoding', tags: ['encoding'], addr: hex(0x100004e40n), inst_id: 14200, strings_matched: 1 },
  ];
}

/* ---------- Profile-Trace 类 ---------- */
const MOCK_MNEMONICS = ['ldr', 'str', 'add', 'sub', 'bl', 'cmp', 'b.eq', 'mov', 'mul', 'eor'];

export function mockWindowStats(): WindowStat[] {
  const r = rng(55);
  const stats: WindowStat[] = [];
  const win = 2000;
  for (let s = 0; s < TOTAL_INST; s += win) {
    const end = Math.min(s + win, TOTAL_INST);
    const count = end - s;
    stats.push({
      window_start: s,
      window_end: end,
      inst_count: count,
      mem_reads: Math.floor(count * (0.2 + r() * 0.15)),
      mem_writes: Math.floor(count * (0.08 + r() * 0.1)),
      branch_density: 0.12 + r() * 0.08,
      unique_pcs: Math.floor(count * (0.3 + r() * 0.3)),
      mnemonic_entropy: 1.5 + r() * 2.0,
      dominant_mnemonic: MOCK_MNEMONICS[Math.floor(r() * MOCK_MNEMONICS.length)],
    });
  }
  return stats;
}

export function mockTraceFold(): FoldEntry[] {
  return [
    { start_inst_id: 3200, end_inst_id: 5312, repeat_count: 176, pattern_pc: hex(0x1000043c0n), summary: 'AES 密钥扩展循环 (12 条/次 × 176)' },
    { start_inst_id: 5700, end_inst_id: 7492, repeat_count: 64, pattern_pc: hex(0x100004650n), summary: 'SHA-256 压缩轮 (28 条/次 × 64)' },
    { start_inst_id: 12440, end_inst_id: 15512, repeat_count: 512, pattern_pc: hex(0x1000048c0n), summary: 'memcpy 样式复制循环 (6 条/次 × 512)' },
    { start_inst_id: 16000, end_inst_id: 16240, repeat_count: 40, pattern_pc: hex(0x100004e40n), summary: 'Base64 编码分组 (6 条/次 × 40)' },
  ];
}

export function mockTraceDiff(): DiffEntry[] {
  const r = rng(77);
  const rows: DiffEntry[] = [];
  for (let i = 0; i < 30; i++) {
    const id = i * 60 + Math.floor(r() * 40);
    const inst = mockInst(id);
    const roll = r();
    let kind: DiffEntry['kind'] = 'same';
    if (roll > 0.85) kind = 'added';
    else if (roll > 0.7) kind = 'removed';
    else if (roll > 0.45) kind = 'changed';
    rows.push({
      inst_id: id,
      kind,
      left: `${inst.mnemonic} ${inst.operands ?? ''}`.trim(),
      right: kind === 'changed'
        ? `${inst.mnemonic} x${Math.floor(r() * 29)}, #0x${Math.floor(r() * 0xff).toString(16)}`
        : kind === 'removed' ? '—' : `${inst.mnemonic} ${inst.operands ?? ''}`.trim(),
      note: kind === 'changed' ? '操作数不同' : undefined,
    });
  }
  return rows;
}

/* ---------- Taint / Dataflow 类 ---------- */
export function mockTaintSources(): TaintSource[] {
  return [
    { id: 1, kind: 'api_return', location: 'CC_SHA256 ret @ #5900', label: 'digest buffer', active: true, propagated: 342 },
    { id: 2, kind: 'register', location: 'x0 @ #4120', label: 'deriveKey: 入参', active: true, propagated: 1287 },
    { id: 3, kind: 'memory', location: '0x16d002000', label: 'plaintext', active: false, propagated: 96 },
    { id: 4, kind: 'api_return', location: 'CCCryptorUpdate out @ #4820', label: 'ciphertext', active: true, propagated: 210 },
  ];
}

export function mockDataflowGraph(): DataflowGraph {
  const nodes: DataflowGraph['nodes'] = [
    { id: 'n1', label: 'x0 (key)', kind: 'reg', x: 60, y: 40, inst_id: 4120 },
    { id: 'n2', label: '0x16d002000', kind: 'mem', x: 60, y: 160, inst_id: 4500 },
    { id: 'n3', label: 'eor', kind: 'op', x: 280, y: 100, inst_id: 5000 },
    { id: 'n4', label: '#0x63636363', kind: 'const', x: 280, y: 220, inst_id: 3120 },
    { id: 'n5', label: 'x8 (state)', kind: 'reg', x: 500, y: 100, inst_id: 5100 },
    { id: 'n6', label: '0x16d003000', kind: 'mem', x: 500, y: 220, inst_id: 4820 },
    { id: 'n7', label: 'digest', kind: 'mem', x: 700, y: 160, inst_id: 5900 },
  ];
  const edges: DataflowGraph['edges'] = [
    { from: 'n1', to: 'n3', label: 'src' },
    { from: 'n2', to: 'n3', label: 'src' },
    { from: 'n4', to: 'n3', label: 'sbox' },
    { from: 'n3', to: 'n5' },
    { from: 'n5', to: 'n6', label: 'store' },
    { from: 'n6', to: 'n7', label: 'hash' },
  ];
  return { nodes, edges, canvas_width: 820, canvas_height: 300 };
}

export function mockBackwardTaint(instId: number, reg: string): BackwardTaintStep[] {
  const r = rng(instId + reg.length);
  const steps: BackwardTaintStep[] = [];
  let cur = instId;
  const roles = ['直接赋值', '算术合并', '内存加载', '异或混淆', 'S-box 查表'];
  for (let i = 0; i < 12; i++) {
    cur -= 1 + Math.floor(r() * 60);
    if (cur < 0) break;
    steps.push({
      inst_id: cur,
      pc: mockInst(cur).pc,
      reg: `x${Math.floor(r() * 29)}`,
      contribution: roles[Math.floor(r() * roles.length)],
    });
  }
  return steps;
}

/* ---------- ObjC × Crypto ---------- */
export function mockObjcCrypto(): ObjcCryptoLink[] {
  return [
    { inst_id: 4500, selector: 'deriveKey:', crypto_role: 'key', data_preview: '3a ed db 41 …', linked_api: 'CCCryptorCreate' },
    { inst_id: 4620, selector: 'dataUsingEncoding:', crypto_role: 'plaintext', data_preview: '"user_token=…"', linked_api: 'CCCryptorUpdate' },
    { inst_id: 5010, selector: 'bytes', crypto_role: 'iv', data_preview: '00 01 02 03 …' },
    { inst_id: 5900, selector: 'SHA256Digest', crypto_role: 'digest', data_preview: 'e2 f9 4a 5c …', linked_api: 'CC_SHA256' },
    { inst_id: 7800, selector: 'appendBytes:length:', crypto_role: 'ciphertext', data_preview: '5b cc 29 86 …' },
  ];
}

/* ---------- 辅助面板 ---------- */
export function mockSnapshots(): SnapshotEntry[] {
  return [
    { id: 1, inst_id: 0, pc: hex(0x10000417cn), label: 'trace 起点', reg_count: 34, mem_bytes: 4096 },
    { id: 2, inst_id: 4120, pc: hex(0x100004120n), label: 'deriveKey: 进入', reg_count: 34, mem_bytes: 8192 },
    { id: 3, inst_id: 5900, pc: hex(0x100004610n), label: 'SHA256 完成', reg_count: 34, mem_bytes: 2048 },
    { id: 4, inst_id: 9800, pc: hex(0x100004c00n), label: '反调试检测前', reg_count: 34, mem_bytes: 1024 },
  ];
}

export function mockDwarf(): DwarfEntry[] {
  return [
    { pc: hex(0x100004120n), inst_id: 4120, file: 'CryptoManager.m', line: 87, func: '-[CryptoManager deriveKey:]', variables: ['salt', 'iterations', 'outKey'] },
    { pc: hex(0x1000043a0n), inst_id: 3120, file: 'aes.c', line: 214, func: 'aes_key_expansion', variables: ['rk', 'i', 'temp'] },
    { pc: hex(0x100004610n), inst_id: 5600, file: 'sha256.c', line: 56, func: 'sha256_transform', variables: ['w[64]', 'a', 'b', 'c', 'd'] },
    { pc: hex(0x100004c00n), inst_id: 9800, file: 'security.c', line: 12, func: 'anti_debug_check', variables: ['ret'] },
  ];
}

export function mockVmHandlers(): VmHandler[] {
  const r = rng(123);
  const ops = ['VM_ADD', 'VM_XOR', 'VM_LOAD', 'VM_STORE', 'VM_PUSH', 'VM_POP', 'VM_JMP', 'VM_CMP', 'VM_MUL', 'VM_ROL'];
  return ops.map((op, i) => ({
    id: i,
    handler_pc: hex(0x100005000n + BigInt(i * 0x80)),
    opcode: `0x${(0x10 + i).toString(16).toUpperCase()}`,
    semantics: op,
    hit_count: 1 + Math.floor(r() * 400),
  }));
}

export function mockLog(): LogEntry[] {
  const base = Date.now() - 60000;
  const rows: [number, LogEntry['level'], string, string][] = [
    [0, 'info', 'TraceReader', 'mmap trace.bin (48.2 MiB), 20000 instructions'],
    [120, 'info', 'IndexBuilder', 'building RocksDB index…'],
    [1850, 'info', 'IndexBuilder', 'index built in 1.73s (312 unique PCs)'],
    [1900, 'info', 'PassManager', 'scheduling 17 passes across 7 categories'],
    [2100, 'debug', 'XRefPass', 'resolved 312 xref buckets'],
    [2400, 'info', 'PatternPass', '4 matches (Crypto×2, AntiDebug×1, Other×1)'],
    [2600, 'warn', 'TritonBridge', 'FPR snapshot missing for #12400, taint may be imprecise'],
    [2900, 'info', 'CfgPass', '7 blocks / 8 edges for -[CryptoManager deriveKey:]'],
    [3200, 'error', 'DwarfPass', 'no debug_line for module region 0x100006000-0x100007000'],
    [3400, 'info', 'AlgorithmPass', 'identified AES-128 (0.92), SHA-256 (0.88)'],
  ];
  return rows.map(([off, level, source, message]) => ({
    ts: new Date(base + off * 20).toISOString().substring(11, 23),
    level, source, message,
  }));
}

export function mockCache(): CacheEntry[] {
  return [
    { name: 'trace.index.rocksdb', kind: 'RocksDB', size_bytes: 12_582_912, status: 'fresh', last_built: '2s ago' },
    { name: 'pc_xref.cache', kind: 'memoized', size_bytes: 524_288, status: 'fresh', last_built: '2s ago' },
    { name: 'anchor.mmap', kind: 'mmap', size_bytes: 8_388_608, status: 'fresh', last_built: 'on load' },
    { name: 'cfg.layout.cache', kind: 'memoized', size_bytes: 131_072, status: 'stale', last_built: '5m ago' },
    { name: 'triton.semantics.cache', kind: 'memoized', size_bytes: 2_097_152, status: 'building', last_built: '—' },
  ];
}

// ─── 多线程分析 mock ─────────────────────────────────────────────────────

export function mockThreads(): ThreadsResult {
  return {
    total_threads: 2,
    total_switches: 3,
    threads: [
      { thread_id: 4711, first_seen_inst: 0, last_seen_inst: 1999, instructions: 2000, switch_in_count: 2 },
      { thread_id: 8244, first_seen_inst: 2000, last_seen_inst: 3499, instructions: 1500, switch_in_count: 1 },
    ],
    switch_events: [
      { inst_id: 2000, thread_id: 8244 },
      { inst_id: 3000, thread_id: 4711 },
      { inst_id: 3500, thread_id: 8244 },
    ],
  };
}

export function mockThreadFilter(threadIds: number[]): ThreadFilterResult {
  const t1: Array<[number, number]> = [[0, 2000], [3000, 500]];
  const t2: Array<[number, number]> = [[2000, 1000], [3500, 800]];
  const byThread = new Map<number, { instructions: number; ranges: Array<[number, number]> }>([
    [4711, { instructions: 2500, ranges: t1 }],
    [8244, { instructions: 1800, ranges: t2 }],
  ]);
  const merged: Array<[number, number]> = [];
  if (threadIds.length === 0) {
    return { thread_count: 2, is_filtered: false, threads: [...byThread].map(([thread_id, v]) => ({ thread_id, ...v })) };
  }
  const all = [...t1, ...t2].filter((_, i) => threadIds.includes(i < 2 ? 4711 : 8244));
  all.sort((a, b) => a[0] - b[0]);
  for (const r of all) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[0] + last[1]) last[1] = Math.max(last[1], r[0] + r[1] - last[0]);
    else merged.push([r[0], r[1]]);
  }
  const count = merged.reduce((s, r) => s + r[1], 0);
  return {
    thread_count: 2,
    is_filtered: true,
    filtered_count: count,
    filtered_ranges: merged,
    threads: [...byThread].map(([thread_id, v]) => ({ thread_id, ...v })),
  };
}

export function mockCrossThreadDataflow(): CrossThreadDataflowResult {
  return {
    total_hand_offs: 2,
    total_channels: 1,
    thread_pair_count: 1,
    edges: [
      { writer_inst: 1200, writer_thread: 4711, reader_inst: 2050, reader_thread: 8244, addr: '0x100006A40', size: 4 },
      { writer_inst: 3100, writer_thread: 4711, reader_inst: 3600, reader_thread: 8244, addr: '0x100006A44', size: 8 },
    ],
    edges_offset: 0,
    edges_returned: 2,
    edges_has_more: false,
    channels: [
      {
        addr: '0x100006A40',
        from_thread: 4711,
        to_thread: 8244,
        hand_offs: 2,
        edges: [
          { writer_inst: 1200, reader_inst: 2050 },
          { writer_inst: 3100, reader_inst: 3600 },
        ],
      },
    ],
  };
}
