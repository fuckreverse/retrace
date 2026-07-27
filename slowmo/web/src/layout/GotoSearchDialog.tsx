/**
 * Goto 弹窗（G）与 Search 弹窗（/）—— 对齐 GUI popups.cpp 的
 * render_goto_popup() / render_search_popup() 语义：
 *
 *  - Goto: "0x<hex 静态地址>" | 纯十进制 inst_id | 函数名（精确 → 前缀 → 包含）
 *    地址解析通过 xref 索引（api.xref）查找该 PC 首次执行的 inst_id。
 *  - Search: 从当前游标正向线性扫描反汇编文本子串匹配（真实调用 api.searchForward）。
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import { Icon } from '@/components/icons';
import { IconButton } from '@/components/ui';
import type { FunctionEntry } from '@/types/tenet';
import './goto-search.css';

const GOTO_HISTORY_KEY = 'tenet-goto-history';
const SEARCH_HISTORY_KEY = 'tenet-search-history';
const HISTORY_LIMIT = 10;

function loadHistory(key: string): string[] {
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(key) ?? '[]');
    if (Array.isArray(raw)) {
      return raw.filter((item): item is string => typeof item === 'string').slice(0, HISTORY_LIMIT);
    }
  } catch { /* ignore unavailable or corrupt storage */ }
  return [];
}

function addHistoryItem(key: string, history: string[], value: string): string[] {
  const next = [value, ...history.filter((item) => item !== value)].slice(0, HISTORY_LIMIT);
  try { localStorage.setItem(key, JSON.stringify(next)); } catch { /* ignore unavailable or full storage */ }
  return next;
}

/** 判断字符串是否可解析为 inst_id（纯十进制数字） */
function parseInstId(s: string): number | null {
  if (!/^[0-9]+$/.test(s)) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

/** 判断字符串是否可解析为十六进制地址（"0x..." 或裸十六进制且含 a-f） */
function parseHexAddr(s: string): bigint | null {
  if (/^0[xX][0-9a-fA-F]+$/.test(s)) {
    try { return BigInt(s); } catch { return null; }
  }
  if (s.length >= 4 && /^[0-9a-fA-F]+$/.test(s) && /[a-fA-F]/.test(s)) {
    try { return BigInt(`0x${s}`); } catch { return null; }
  }
  return null;
}

export function GotoDialog() {
  const open = useTraceStore((s) => s.showGotoDialog);
  const close = useTraceStore((s) => s.closeGotoDialog);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const totalInst = useTraceStore((s) => s.totalInst);

  const [query, setQuery] = useState('');
  const [history, setHistory] = useState<string[]>(() => loadHistory(GOTO_HISTORY_KEY));
  const [funcs, setFuncs] = useState<FunctionEntry[]>([]);
  const [selected, setSelected] = useState(-1);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setHistory(loadHistory(GOTO_HISTORY_KEY));
    setSelected(-1);
    api.functions().then(setFuncs);
    // Radix Dialog 打开动画期间聚焦，稍作延迟保证元素已挂载
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  const candidates = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return funcs.slice(0, 12);
    const prefix = funcs.filter((f) => f.name.toLowerCase().startsWith(q));
    const contains = funcs.filter((f) => !f.name.toLowerCase().startsWith(q) && f.name.toLowerCase().includes(q));
    return [...prefix, ...contains].slice(0, 12);
  }, [funcs, query]);

  const showRecent = query.trim().length === 0 && history.length > 0;
  const selectableTargets = showRecent
    ? [...history, ...candidates.map((candidate) => candidate.name)]
    : candidates.map((candidate) => candidate.name);

  const commit = async (text: string) => {
    const s = text.trim();
    if (!s) return;
    setBusy(true);
    try {
      let destination: number | null = null;
      const instId = parseInstId(s);
      if (instId != null) {
        if (instId < totalInst) destination = instId;
      } else {
        const addr = parseHexAddr(s);
        if (addr != null) {
          const pc = `0x${addr.toString(16)}`;
          const xref = await api.xref(pc);
          destination = xref.inst_ids[0] ?? null;
        } else {
          // 函数名：精确 → 前缀 → 包含。首次打开时函数列表可能仍在加载，按需等待。
          const availableFuncs = funcs.length > 0 ? funcs : await api.functions();
          if (funcs.length === 0) setFuncs(availableFuncs);
          const ql = s.toLowerCase();
          const exact = availableFuncs.find((f) => f.name.toLowerCase() === ql);
          const prefix = availableFuncs.find((f) => f.name.toLowerCase().startsWith(ql));
          const contains = availableFuncs.find((f) => f.name.toLowerCase().includes(ql));
          const target = exact ?? prefix ?? contains;
          if (target) {
            const xref = await api.xref(target.pc);
            destination = xref.inst_ids[0] ?? null;
          }
        }
      }
      if (destination != null) {
        navigateTo(destination);
        setHistory((current) => addHistoryItem(GOTO_HISTORY_KEY, current, s));
      }
      close();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={(v) => { if (!v) close(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="gs-overlay" />
        <Dialog.Content className="gs-dialog" aria-describedby={undefined}>
          <div className="gs-card">
            <Dialog.Title className="gs-title">Go to…</Dialog.Title>
            <div className="gs-hint">0x&lt;static addr&gt;（IDA 地址）、指令编号 #id、或函数名</div>
            <input
              ref={inputRef}
              className="gs-input"
              value={query}
              onChange={(e) => { setQuery(e.target.value); setSelected(-1); }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  void commit(selected >= 0 ? selectableTargets[selected] : query);
                } else if (e.key === 'ArrowDown') {
                  e.preventDefault();
                  setSelected((i) => Math.min(selectableTargets.length - 1, i + 1));
                } else if (e.key === 'ArrowUp') {
                  e.preventDefault();
                  setSelected((i) => Math.max(0, i - 1));
                } else if (e.key === 'Escape') {
                  close();
                }
              }}
              placeholder="0x100004a10, 4210, or -[CryptoManager deriveKey:]"
              disabled={busy}
            />
            {(showRecent || candidates.length > 0) && (
              <div className="gs-list">
                {showRecent && (
                  <div className="gs-list-group">
                    <div className="gs-list-heading">Recent</div>
                    {history.map((item, i) => (
                      <div
                        key={item}
                        className={clsx('gs-list-item', 'gs-recent-item', i === selected && 'selected')}
                        onMouseEnter={() => setSelected(i)}
                        onClick={() => void commit(item)}
                      >
                        <span className="mono gs-list-name">{item}</span>
                      </div>
                    ))}
                  </div>
                )}
                {candidates.length > 0 && (
                  <div className="gs-list-group">
                    {showRecent && <div className="gs-list-heading">Functions</div>}
                    {candidates.map((f, i) => {
                      const itemIndex = (showRecent ? history.length : 0) + i;
                      return (
                        <div
                          key={f.pc}
                          className={clsx('gs-list-item', itemIndex === selected && 'selected')}
                          onMouseEnter={() => setSelected(itemIndex)}
                          onClick={() => void commit(f.name)}
                        >
                          <span className="mono gs-list-name">{f.name}</span>
                          <span className="mono dim gs-list-pc">{f.pc}</span>
                          <span className="dim gs-list-calls">{f.calls} calls</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
            <div className="gs-footer">
              <button className="gs-btn" onClick={close} type="button">Cancel</button>
              <button className="gs-btn gs-btn-primary" onClick={() => void commit(query)} type="button" disabled={busy}>
                {busy ? 'Going…' : 'Go'}
              </button>
              <span className="gs-key-hint">Enter=go  ↑↓=select  Esc=cancel</span>
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function SearchDialog() {
  const open = useTraceStore((s) => s.showSearchDialog);
  const close = useTraceStore((s) => s.closeSearchDialog);
  const cur = useTraceStore((s) => s.currentInst);
  const setSearch = useTraceStore((s) => s.setSearch);
  const searchResults = useTraceStore((s) => s.searchResults);
  const searchNext = useTraceStore((s) => s.searchNext);
  const searchPrev = useTraceStore((s) => s.searchPrev);

  const [query, setQuery] = useState('');
  const [history, setHistory] = useState<string[]>(() => loadHistory(SEARCH_HISTORY_KEY));
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setHistory(loadHistory(SEARCH_HISTORY_KEY));
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  const run = async (text = query) => {
    const q = text.trim();
    if (!q) return;
    setBusy(true);
    try {
      const hits = await api.searchForward(q, cur);
      setQuery(q);
      setSearch(q, hits);
      setHistory((current) => addHistoryItem(SEARCH_HISTORY_KEY, current, q));
    } finally {
      setBusy(false);
    }
  };

  const navigateSearch = (direction: 'prev' | 'next') => {
    if (direction === 'prev') searchPrev();
    else searchNext();
    close();
  };

  return (
    <Dialog.Root open={open} onOpenChange={(v) => { if (!v) close(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="gs-overlay" />
        <Dialog.Content className="gs-dialog" aria-describedby={undefined}>
          <div className="gs-card">
            <Dialog.Title className="gs-title">Search disassembly</Dialog.Title>
            <div className="gs-hint">从当前指令 #{cur} 起正向扫描助记符 / 操作数子串</div>
            <input
              ref={inputRef}
              className="gs-input"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void run();
                else if (e.key === 'Escape') close();
              }}
              placeholder="e.g. bl, ldr x0, str"
              disabled={busy}
            />
            {query.trim().length === 0 && history.length > 0 && (
              <div className="gs-list gs-history-list">
                <div className="gs-list-heading">Recent</div>
                {history.map((item) => (
                  <div
                    key={item}
                    className="gs-list-item gs-recent-item"
                    onClick={() => void run(item)}
                  >
                    <span className="mono gs-list-name">{item}</span>
                  </div>
                ))}
              </div>
            )}
            <div className="gs-footer">
              <button className="gs-btn" onClick={close} type="button">Cancel</button>
              <button className="gs-btn gs-btn-primary" onClick={() => void run()} type="button" disabled={busy}>
                {busy ? 'Searching…' : 'Find'}
              </button>
              {searchResults.length > 0 && (
                <>
                  <span className="gs-key-hint">命中 {searchResults.length} 处</span>
                  <div className="gs-search-nav">
                    <IconButton title="上一个" type="button" onClick={() => navigateSearch('prev')}><Icon.Prev /></IconButton>
                    <IconButton title="下一个" type="button" onClick={() => navigateSearch('next')}><Icon.Next /></IconButton>
                  </div>
                </>
              )}
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
