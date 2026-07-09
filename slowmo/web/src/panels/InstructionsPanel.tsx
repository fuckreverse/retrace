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
import './instructions.css';

const ROW_H = 24;
const OVERSCAN = 12;
const WINDOW = 400; // 每次向后端拉取的窗口

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

  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(600);
  const [rows, setRows] = useState<Map<number, InstRow>>(new Map());
  const [searchInput, setSearchInput] = useState('');
  const [taintBusy, setTaintBusy] = useState<number | null>(null);

  const searchSet = new Set(searchResults);

  // 计算可见区间
  const first = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const last = Math.min(total, Math.ceil((scrollTop + viewH) / ROW_H) + OVERSCAN);

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
    const y = cur * ROW_H;
    if (y < el.scrollTop + 40 || y > el.scrollTop + el.clientHeight - 60) {
      el.scrollTop = Math.max(0, y - el.clientHeight / 2);
    }
  }, [cur]);

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

  /** 右键 "Taint Forward (x0)"：真实调用后端 taint_forward pass，从该指令处 x0 寄存器开始正向污点传播 */
  const runTaintForward = useCallback(async (instId: number) => {
    setTaintBusy(instId);
    try {
      const steps = await api.taintForward(0 /* x0 */, instId);
      setTaintFwd(steps.map((s) => s.inst_id));
    } finally {
      setTaintBusy(null);
    }
  }, [setTaintFwd]);

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
        <div style={{ height: total * ROW_H, position: 'relative' }}>
          {visible.map((id) => {
            const row = rows.get(id);
            return (
              <InstRowView
                key={id}
                id={id}
                row={row}
                top={id * ROW_H}
                cls={rowClass(id)}
                hasBookmark={bookmarks.has(id)}
                onClick={() => navigateTo(id)}
                onBookmark={() => toggleBookmark(id)}
                onHex={() => row && setHexAddr(row.pc)}
                onTaint={() => runTaintForward(id)}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}

function InstRowView({
  id, row, top, cls, hasBookmark, onClick, onBookmark, onHex, onTaint,
}: {
  id: number;
  row?: InstRow;
  top: number;
  cls: string;
  hasBookmark: boolean;
  onClick: () => void;
  onBookmark: () => void;
  onHex: () => void;
  onTaint: () => void;
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
          <ContextMenu.Item className="ctx-item" onSelect={onTaint}>Taint Forward (x0)</ContextMenu.Item>
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
