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
import { IconButton, Input } from '@/components/ui';
import { selectTab } from '@/lib/tabRouting';
import { useSettingsStore } from '@/store/settingsStore';
import './instructions.css';

const TAINT_FORWARD_REGS = [
  { name: 'x0', index: 0 },
  { name: 'x1', index: 1 },
  { name: 'x2', index: 2 },
  { name: 'x3', index: 3 },
  { name: 'x8', index: 8 },
  { name: 'x19', index: 19 },
  { name: 'x20', index: 20 },
  { name: 'x21', index: 21 },
  { name: 'lr', index: 30 },
] as const;

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
  const setHexAddr = useTraceStore((s) => s.setHexAddr);
  const setTaintFwd = useTraceStore((s) => s.setTaintForward);
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
  const [rowH, setRowH] = useState(ROW_H_FALLBACK);

  // density 变化时（含首帧）重新读取实际生效的行高，保持与 CSS 一致
  useEffect(() => { setRowH(readRowHeightPx()); }, [density]);

  const searchSet = new Set(searchResults);

  // 计算可见区间
  const first = Math.max(0, Math.floor(scrollTop / rowH) - OVERSCAN);
  const last = Math.min(total, Math.ceil((scrollTop + viewH) / rowH) + OVERSCAN);

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
      const hits = await api.searchForward(q, 0);
      setSearch(q, hits);
    } finally {
      setSearching(false);
    }
  }, [searchInput, clearSearch, setSearch]);

  const rowClass = (id: number) => {
    if (id === cur) return 'inst-cur';
    if (producer.has(id)) return 'inst-producer';
    if (taintBwd.has(id)) return 'inst-taint-bwd';
    if (taintFwd.has(id)) return 'inst-taint-fwd';
    if (searchSet.has(id)) return 'inst-search';
    return '';
  };

  /** 从指定指令和寄存器开始运行后端 taint_forward pass。 */
  const runTaintForward = useCallback(async (instId: number, regIndex: number) => {
    setTaintBusy(instId);
    try {
      const steps = await api.taintForward(regIndex, instId);
      setTaintFwd(steps.map((s) => s.inst_id));
    } finally {
      setTaintBusy(null);
    }
  }, [setTaintFwd]);

  const runTaintBackward = useCallback((instId: number) => {
    navigateTo(instId);
    selectTab('center-bottom', 'backtaint');
  }, [navigateTo]);

  const visible: number[] = [];
  for (let i = first; i < last; i++) visible.push(i);

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
        {searching && <span className="dim mono" style={{ marginLeft: 8 }}>搜索中…</span>}
        {taintBusy != null && <span className="dim mono" style={{ marginLeft: 8 }}>污点分析中…</span>}
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
                onHex={() => row && setHexAddr(row.pc)}
                onTaint={(regIndex) => runTaintForward(id, regIndex)}
                onBackwardTaint={() => runTaintBackward(id)}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}

function InstRowView({
  id, row, top, cls, hasBookmark, onClick, onBookmark, onHex, onTaint, onBackwardTaint,
}: {
  id: number;
  row?: InstRow;
  top: number;
  cls: string;
  hasBookmark: boolean;
  onClick: () => void;
  onBookmark: () => void;
  onHex: () => void;
  onTaint: (regIndex: number) => void;
  onBackwardTaint: () => void;
}) {
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
          <ContextMenu.Item className="ctx-item" onSelect={onClick}>Navigate Here</ContextMenu.Item>
          <ContextMenu.Item className="ctx-item" onSelect={onBookmark}>
            {hasBookmark ? 'Remove Bookmark' : 'Add Bookmark'}
          </ContextMenu.Item>
          <ContextMenu.Separator className="ctx-sep" />
          <ContextMenu.Sub>
            <ContextMenu.SubTrigger className="ctx-item">Taint Forward From…</ContextMenu.SubTrigger>
            <ContextMenu.Portal>
              <ContextMenu.SubContent className="ctx-menu">
                {TAINT_FORWARD_REGS.map((reg) => (
                  <ContextMenu.Item
                    key={reg.name}
                    className="ctx-item"
                    onSelect={() => onTaint(reg.index)}
                  >
                    {reg.name}
                  </ContextMenu.Item>
                ))}
              </ContextMenu.SubContent>
            </ContextMenu.Portal>
          </ContextMenu.Sub>
          <ContextMenu.Item className="ctx-item" onSelect={onBackwardTaint}>Backward Taint from Here</ContextMenu.Item>
          <ContextMenu.Item className="ctx-item" onSelect={onHex}>Open PC in Hex Dump</ContextMenu.Item>
          <ContextMenu.Separator className="ctx-sep" />
          <ContextMenu.Item className="ctx-item" onSelect={() => row && navigator.clipboard?.writeText(row.pc)}>
            Copy Address
          </ContextMenu.Item>
          <ContextMenu.Item className="ctx-item" onSelect={() => row && navigator.clipboard?.writeText(`${row.mnemonic} ${row.operands}`)}>
            Copy Disassembly
          </ContextMenu.Item>
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );
}
