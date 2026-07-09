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
import type { FunctionEntry } from '@/types/tenet';
import './goto-search.css';

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
  const [funcs, setFuncs] = useState<FunctionEntry[]>([]);
  const [selected, setSelected] = useState(-1);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setQuery('');
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

  const commit = async (text: string) => {
    const s = text.trim();
    if (!s) return;
    setBusy(true);
    try {
      const instId = parseInstId(s);
      if (instId != null) {
        if (instId < totalInst) navigateTo(instId);
        close();
        return;
      }
      const addr = parseHexAddr(s);
      if (addr != null) {
        const pc = `0x${addr.toString(16)}`;
        const xref = await api.xref(pc);
        if (xref.inst_ids.length > 0) navigateTo(xref.inst_ids[0]);
        close();
        return;
      }
      // 函数名：精确 → 前缀 → 包含
      const ql = s.toLowerCase();
      const exact = funcs.find((f) => f.name.toLowerCase() === ql);
      const target = exact ?? candidates[0];
      if (target) {
        const xref = await api.xref(target.pc);
        if (xref.inst_ids.length > 0) navigateTo(xref.inst_ids[0]);
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
                  void commit(selected >= 0 ? candidates[selected].name : query);
                } else if (e.key === 'ArrowDown') {
                  e.preventDefault();
                  setSelected((i) => Math.min(candidates.length - 1, i + 1));
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
            {candidates.length > 0 && (
              <div className="gs-list">
                {candidates.map((f, i) => (
                  <div
                    key={f.pc}
                    className={clsx('gs-list-item', i === selected && 'selected')}
                    onMouseEnter={() => setSelected(i)}
                    onClick={() => void commit(f.name)}
                  >
                    <span className="mono gs-list-name">{f.name}</span>
                    <span className="mono dim gs-list-pc">{f.pc}</span>
                    <span className="dim gs-list-calls">{f.calls} calls</span>
                  </div>
                ))}
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

  const [query, setQuery] = useState('');
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  const run = async () => {
    const q = query.trim();
    if (!q) return;
    setBusy(true);
    try {
      const hits = await api.searchForward(q, cur);
      setSearch(q, hits);
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
            <div className="gs-footer">
              <button className="gs-btn" onClick={close} type="button">Cancel</button>
              <button className="gs-btn gs-btn-primary" onClick={() => void run()} type="button" disabled={busy}>
                {busy ? 'Searching…' : 'Find'}
              </button>
              {searchResults.length > 0 && (
                <span className="gs-key-hint">上次命中 {searchResults.length} 处</span>
              )}
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
