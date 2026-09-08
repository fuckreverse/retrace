/**
 * Instructions 面板 —— 核心反汇编视图，虚拟滚动 + 游标驱动联动。
 * 列: gutter | # | Address | Mnemonic | Operands
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { clsx } from 'clsx';
import * as ContextMenu from '@radix-ui/react-context-menu';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { InstRow } from '@/types/tenet';
import { Icon } from '@/components/icons';
import { IconButton, Input, Chip } from '@/components/ui';
import { selectTab } from '@/lib/tabRouting';
import { copyText } from '@/lib/clipboard';
import { openInHexDump } from '@/lib/hexLink';
import { followCall, followReturn } from '@/lib/nav';
import { useSettingsStore } from '@/store/settingsStore';
import './instructions.css';

interface TaintReg { name: string; index: number; }

/** 无操作数寄存器时的回退污点寄存器列表 */
const DEFAULT_TAINT_REGS: TaintReg[] = [
  { name: 'x0', index: 0 },
  { name: 'x1', index: 1 },
  { name: 'x2', index: 2 },
  { name: 'x3', index: 3 },
  { name: 'x8', index: 8 },
  { name: 'x19', index: 19 },
  { name: 'x20', index: 20 },
  { name: 'x21', index: 21 },
  { name: 'lr', index: 30 },
];

// 操作数中的 AArch64 寄存器（word 边界，形如 "x0, [sp, #0x10]"；
// 立即数 #0x10 中的 "x10" 前是数字字符、不构成边界，不会误匹配）
const OPERAND_REG_RE = /\b(x[0-9]{1,2}|w[0-9]{1,2}|xzr|wzr|lr|fp|sp|nzcv)\b/g;

/** 寄存器别名归一化并映射 regIndex（wN→xN、lr→30、fp→29、sp/xzr→31）；nzcv 无独立 regIndex，不参与污点。 */
function normalizeTaintReg(raw: string): TaintReg | null {
  const lower = raw.toLowerCase();
  if (lower === 'nzcv') return null;
  if (lower === 'xzr' || lower === 'wzr') return { name: 'xzr', index: 31 };
  if (lower === 'lr') return { name: 'x30', index: 30 };
  if (lower === 'fp') return { name: 'x29', index: 29 };
  if (lower === 'sp') return { name: 'sp', index: 31 };
  const m = /^[xw]([0-9]{1,2})$/.exec(lower);
  if (m) {
    const n = parseInt(m[1], 10);
    if (n <= 30) return { name: `x${n}`, index: n };
  }
  return null;
}

/** 从操作数字符串按出现顺序提取实际出现的寄存器（去重、wN 归一化为 xN）。 */
function extractOperandRegs(operands: string | undefined): TaintReg[] {
  if (!operands) return [];
  const seen = new Set<string>();
  const out: TaintReg[] = [];
  for (const m of operands.matchAll(OPERAND_REG_RE)) {
    const reg = normalizeTaintReg(m[1]);
    if (!reg || seen.has(reg.name)) continue;
    seen.add(reg.name);
    out.push(reg);
  }
  return out;
}

/** 助记符过滤：内存访问 / 分支（前缀匹配，兼容 "b.eq" 这类条件后缀形式） */
const MNEMONIC_MEM_RE = /^(ldr|str|ldp|stp|ldurb|sturb|ldur|stur|ldrb|strb|ldrh|strh|ldrs|cas|swp)/;
const MNEMONIC_BRANCH_RE = /^(b\.|b|bl|br|blr|ret|cbz|cbnz|tbz|tbnz)/;
type InstFilter = 'all' | 'mem' | 'branch';

const ROW_H_FALLBACK = 22; // 与 tokens.css 默认 --row-h 一致，CSS 变量不可用时兜底
const OVERSCAN = 12;
const WINDOW = 400; // 每次向后端拉取的窗口

/**
 * 读取当前生效的 --row-h CSS 变量（px）。
 * 虚拟滚动的行高计算必须与 .inst-row 实际渲染高度一致，否则不同 UI 密度
 * （compact/default/comfortable，见 settingsStore 的 DENSITY_TOKENS）下会产生
 * 累积的位置偏差。依赖 density 触发重新读取，因为 injectCSS 只在 <html> 上
 * setProperty，不会触发 React 重渲染。
 */
function readRowHeightPx(): number {
  if (typeof document === 'undefined') return ROW_H_FALLBACK;
  const raw = getComputedStyle(document.documentElement).getPropertyValue('--row-h').trim();
  const n = parseFloat(raw);
  return Number.isFinite(n) && n > 0 ? n : ROW_H_FALLBACK;
}

export function InstructionsPanel() {
  const total = useTraceStore((s) => s.totalInst);
  const cur = useTraceStore((s) => s.currentInst);
  const bookmarks = useTraceStore((s) => s.bookmarks);
  const taintFwd = useTraceStore((s) => s.taintForward);
  const taintBwd = useTraceStore((s) => s.taintBackward);
  const producer = useTraceStore((s) => s.producerChain);
  const searchResults = useTraceStore((s) => s.searchResults);
  const searchCurrent = useTraceStore((s) => s.searchCurrent);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const toggleBookmark = useTraceStore((s) => s.toggleBookmark);
  const setViewport = useTraceStore((s) => s.setViewport);
  const setTaintFwd = useTraceStore((s) => s.setTaintForward);
  // setHexAddr 不再直接使用：Hex 联动统一走 lib/hexLink 的 openInHexDump
  const searchNext = useTraceStore((s) => s.searchNext);
  const searchPrev = useTraceStore((s) => s.searchPrev);
  const clearSearch = useTraceStore((s) => s.clearSearch);
  const setSearch = useTraceStore((s) => s.setSearch);

  const density = useSettingsStore((s) => s.density);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(600);
  const [rows, setRows] = useState<Map<number, InstRow>>(new Map());
  const [searchInput, setSearchInput] = useState('');
  const [taintBusy, setTaintBusy] = useState<number | null>(null);
  // 最近一次正向污点的规模反馈（工具栏展示，可手动清除高亮）
  const [lastTaint, setLastTaint] = useState<{ reg: string; count: number } | null>(null);
  // 助记符过滤 chips（与线程过滤一致：跳过渲染、不改变虚拟滚动坐标）
  const [filter, setFilter] = useState<InstFilter>('all');
  const [rowH, setRowH] = useState(ROW_H_FALLBACK);

  // density 变化时（含首帧）重新读取实际生效的行高，保持与 CSS 一致
  useEffect(() => { setRowH(readRowHeightPx()); }, [density]);

  const searchSet = new Set(searchResults);

  // 线程过滤：选中线程集合（空 = 不过滤）。
  // 过滤模式下非选中线程的指令行以零高度占位方式隐藏（保留 inst_id 与虚拟
  // 滚动坐标一致，避免全量重排）：直接跳过渲染即可。

  // 计算可见区间
  const first = Math.max(0, Math.floor(scrollTop / rowH) - OVERSCAN);
  const last = Math.min(total, Math.ceil((scrollTop + viewH) / rowH) + OVERSCAN);

  useEffect(() => {
    setViewport(first, last);
  }, [first, last, setViewport]);

  // 拉取窗口数据
  useEffect(() => {
    let cancelled = false;
    const start = Math.max(0, Math.floor(first / WINDOW) * WINDOW);
    api.disasm(start, WINDOW).then((res) => {
      if (cancelled) return;
      setRows((prev) => {
        const next = new Map(prev);
        for (const r of res.rows) next.set(r.inst_id, r);
        // 限制缓存大小
        if (next.size > 3000) {
          const keep = new Map<number, InstRow>();
          for (let i = first - WINDOW; i < last + WINDOW; i++) {
            const v = next.get(i);
            if (v) keep.set(i, v);
          }
          return keep;
        }
        return next;
      });
    });
    return () => { cancelled = true; };
  }, [first, last]);

  // 尺寸监听
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    setViewH(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  // 当前指令变化时确保可见
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const y = cur * rowH;
    if (y < el.scrollTop + 40 || y > el.scrollTop + el.clientHeight - 60) {
      el.scrollTop = Math.max(0, y - el.clientHeight / 2);
    }
  }, [cur, rowH]);

  const [searching, setSearching] = useState(false);

  const doSearch = useCallback(async () => {
    const q = searchInput.trim();
    if (!q) { clearSearch(); return; }
    setSearching(true);
    try {
      // 真实调用后端 SearchForward（对齐 GUI Search 弹窗语义：从当前游标开始
      // 正向线性扫描反汇编文本，子串匹配 mnemonic+operands）。
      const hits = await api.searchForward(q, cur);
      setSearch(q, hits);
    } finally {
      setSearching(false);
    }
  }, [searchInput, cur, clearSearch, setSearch]);

  const rowClass = (id: number) => {
    if (id === cur) return 'inst-cur';
    if (producer.has(id)) return 'inst-producer';
    if (taintBwd.has(id)) return 'inst-taint-bwd';
    if (taintFwd.has(id)) return 'inst-taint-fwd';
    if (searchSet.has(id)) return 'inst-search';
    return '';
  };

  /** 从指定指令和寄存器开始运行后端 taint_forward pass。 */
  const runTaintForward = useCallback(async (instId: number, regIndex: number, regName: string) => {
    setTaintBusy(instId);
    try {
      const steps = await api.taintForward(regIndex, instId);
      setTaintFwd(steps.map((s) => s.inst_id));
      // 污点完成后的规模反馈（执行新污点时覆盖旧值）
      setLastTaint({ reg: regName, count: steps.length });
    } finally {
      setTaintBusy(null);
    }
  }, [setTaintFwd]);

  const runTaintBackward = useCallback((instId: number) => {
    navigateTo(instId);
    selectTab('center-bottom', 'backtaint');
    // 通知 BackwardTaintPanel（跨面板契约：监听同名自定义事件）
    window.dispatchEvent(new CustomEvent('tenet:backward-taint', { detail: { instId } }));
  }, [navigateTo]);

  const threadFilterActive = useTraceStore((s) => s.threadFilterIds.length > 0);
  const threadFilterCount = useTraceStore((s) => s.threadFilterCount);
  const includesFn = useTraceStore((s) => s.threadFilterIncludes);

  const visible: number[] = [];
  for (let i = first; i < last; i++) {
    if (threadFilterActive && !includesFn(i)) continue;
    // 助记符过滤：行未加载（row 为 undefined）时不过滤，避免过滤态下大片空白
    if (filter !== 'all') {
      const row = rows.get(i);
      if (row) {
        const mnem = row.mnemonic ?? '';
        if (filter === 'mem' ? !MNEMONIC_MEM_RE.test(mnem) : !MNEMONIC_BRANCH_RE.test(mnem)) continue;
      }
    }
    visible.push(i);
  }

  return (
    <div className="inst-panel">
      <div className="inst-toolbar">
        <div className="inst-search">
          <Icon.Search className="inst-search-icon" />
          <Input
            placeholder="搜索助记符 / 操作数…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && doSearch()}
            style={{ width: 220 }}
          />
        </div>
        <div className="inst-filter">
          <Chip active={filter === 'all'} onClick={() => setFilter('all')}>全部</Chip>
          <Chip active={filter === 'mem'} onClick={() => setFilter('mem')}>内存访问</Chip>
          <Chip active={filter === 'branch'} onClick={() => setFilter('branch')}>分支</Chip>
        </div>
        {searchResults.length > 0 && (
          <div className="inst-search-nav">
            <span className="dim">{searchCurrent + 1}/{searchResults.length}</span>
            <IconButton title="上一个" onClick={searchPrev}><Icon.Prev /></IconButton>
            <IconButton title="下一个" onClick={searchNext}><Icon.Next /></IconButton>
            <IconButton title="清除" onClick={() => { clearSearch(); setSearchInput(''); }}>
              <Icon.Trash />
            </IconButton>
          </div>
        )}
        <span className="inst-bm dim">★ {bookmarks.size}</span>
        {threadFilterActive && (
          <span className="mono dim" style={{ marginLeft: 8 }}>
            [thread filter: {threadFilterCount} insts]
          </span>
        )}
        {searching && <span className="dim mono" style={{ marginLeft: 8 }}>搜索中…</span>}
        {taintBusy != null && <span className="dim mono" style={{ marginLeft: 8 }}>污点分析中…</span>}
        {lastTaint && (
          <>
            <span className="mono dim" style={{ marginLeft: 8 }}>
              污点 {lastTaint.reg}: {lastTaint.count} 条
            </span>
            <IconButton title="清除污点高亮" onClick={() => { setTaintFwd([]); setLastTaint(null); }}>
              <Icon.Trash />
            </IconButton>
          </>
        )}
      </div>

      <div
        className="inst-scroll"
        ref={scrollRef}
        onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
      >
        <div style={{ height: total * rowH, position: 'relative' }}>
          {visible.map((id) => {
            const row = rows.get(id);
            return (
              <InstRowView
                key={id}
                id={id}
                row={row}
                top={id * rowH}
                cls={rowClass(id)}
                hasBookmark={bookmarks.has(id)}
                onClick={() => navigateTo(id)}
                onBookmark={() => toggleBookmark(id)}
                onHex={() => row && openInHexDump(row.pc)}
                onTaint={(regIndex, regName) => runTaintForward(id, regIndex, regName)}
onBackwardTaint={() => runTaintBackward(id)}
onFollowCall={row && /^bl\b/.test(row.mnemonic ?? '') ? () => void followCall(id) : undefined}
onFollowReturn={row && /^ret\b/.test(row.mnemonic ?? '') ? () => void followReturn(id) : undefined}
/>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function InstRowView({
id, row, top, cls, hasBookmark, onClick, onBookmark, onHex, onTaint, onBackwardTaint, onFollowCall, onFollowReturn,
}: {
  id: number;
  row?: InstRow;
  top: number;
  cls: string;
  hasBookmark: boolean;
  onClick: () => void;
  onBookmark: () => void;
  onHex: () => void;
onTaint: (regIndex: number, regName: string) => void;
onBackwardTaint: () => void;
/** 当前指令是 bl 时提供（跳到被调函数首次执行点） */
onFollowCall?: () => void;
/** 当前指令是 ret 时提供（跳回调用点下一条指令） */
onFollowReturn?: () => void;
}) {
// 污点子菜单寄存器：优先取该行操作数中实际出现的寄存器，为空则回退默认列表
  const extracted = extractOperandRegs(row?.operands);
  const taintRegs = extracted.length > 0 ? extracted : DEFAULT_TAINT_REGS;
  return (
    <ContextMenu.Root>
      <ContextMenu.Trigger asChild>
        <div
          className={clsx('inst-row', cls)}
          style={{ top }}
          onClick={onClick}
        >
          <span className="inst-gutter">
            {cls === 'inst-cur' ? '▶' : hasBookmark ? '★' : ''}
          </span>
          <span className="inst-id mono">{id}</span>
          <span className="inst-addr mono">{row?.pc ?? '········'}</span>
          <span className="inst-mnem mono">{row?.mnemonic ?? '···'}</span>
          <span className="inst-ops mono">{row?.operands ?? ''}</span>
        </div>
      </ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content className="ctx-menu">
          <ContextMenu.Item className="ctx-item" onSelect={onClick}>跳转到此处</ContextMenu.Item>
{onFollowCall && <ContextMenu.Item className="ctx-item" onSelect={onFollowCall}>跳转到被调函数</ContextMenu.Item>}
{onFollowReturn && <ContextMenu.Item className="ctx-item" onSelect={onFollowReturn}>返回调用点</ContextMenu.Item>}
          <ContextMenu.Item className="ctx-item" onSelect={onBookmark}>
            {hasBookmark ? '移除书签' : '添加书签'}
          </ContextMenu.Item>
          <ContextMenu.Separator className="ctx-sep" />
          <ContextMenu.Sub>
            <ContextMenu.SubTrigger className="ctx-item">正向污点：从此寄存器…</ContextMenu.SubTrigger>
            <ContextMenu.Portal>
              <ContextMenu.SubContent className="ctx-menu">
                {taintRegs.map((reg) => (
                  <ContextMenu.Item
                    key={reg.name}
                    className="ctx-item"
                    onSelect={() => onTaint(reg.index, reg.name)}
                  >
                    {reg.name}
                  </ContextMenu.Item>
                ))}
              </ContextMenu.SubContent>
            </ContextMenu.Portal>
          </ContextMenu.Sub>
          <ContextMenu.Item className="ctx-item" onSelect={onBackwardTaint}>从此处反向污点</ContextMenu.Item>
          <ContextMenu.Item className="ctx-item" onSelect={onHex}>在 Hex Dump 打开 PC</ContextMenu.Item>
          <ContextMenu.Separator className="ctx-sep" />
          <ContextMenu.Item className="ctx-item" onSelect={() => row && void copyText(row.pc, '地址')}>
            复制地址
          </ContextMenu.Item>
          <ContextMenu.Item className="ctx-item" onSelect={() => row && void copyText(`${row.mnemonic} ${row.operands}`, '反汇编')}>
            复制反汇编
          </ContextMenu.Item>
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );
}
