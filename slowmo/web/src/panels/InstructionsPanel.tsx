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

  const doSearch = useCallback(() => {
    const q = searchInput.trim().toLowerCase();
    if (!q) { clearSearch(); return; }
    // mock: 简单在已加载的行里找 mnemonic/operands 匹配, 并散布若干命中
    const hits: number[] = [];
    for (const [id, r] of rows) {
      if (`${r.mnemonic} ${r.operands}`.toLowerCase().includes(q)) hits.push(id);
    }
    // 兜底: 若无命中，按 hash 散布
    if (hits.length === 0) {
      for (let i = 0; i < total; i += Math.max(1, Math.floor(total / 60))) hits.push(i);
    }
    hits.sort((a, b) => a - b);
    setSearch(q, hits.slice(0, 200));
  }, [searchInput, rows, total, clearSearch, setSearch]);

  const rowClass = (id: number) => {
    if (id === cur) return 'inst-cur';
    if (producer.has(id)) return 'inst-producer';
    if (taintBwd.has(id)) return 'inst-taint-bwd';
    if (taintFwd.has(id)) return 'inst-taint-fwd';
    if (searchSet.has(id)) return 'inst-search';
    return '';
  };

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
                onTaint={() => setTaintFwd(mockTaintIds(id, total))}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}

function mockTaintIds(start: number, total: number): number[] {
  const ids: number[] = [];
  let c = start;
  for (let i = 0; i < 40; i++) {
    c += 1 + Math.floor(Math.random() * 40);
    if (c >= total) break;
    ids.push(c);
  }
  return ids;
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
