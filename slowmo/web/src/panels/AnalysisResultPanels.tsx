/**
 * 分析结果类面板集合 —— Patterns / Strings / ObjC / CallGraph。
 * 均为"表格 + 过滤 + 点击 inst_id 跳转"的统一交互范式。
 */
import { useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { CallGraphResult, ObjcMessage, PatternMatch, StringEntry } from '@/types/tenet';
import { Chip, ConfidenceBar, Input } from '@/components/ui';
import './lists.css';

function categoryTone(cat: string): 'accent' | 'danger' | 'warning' | 'default' {
  if (cat === 'Crypto') return 'accent';
  if (cat === 'AntiDebug') return 'danger';
  if (cat === 'Other') return 'warning';
  return 'default';
}

/* ---------- Patterns ---------- */
export function PatternsPanel() {
  const [rows, setRows] = useState<PatternMatch[]>([]);
  const [cat, setCat] = useState('All');
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.patterns().then(setRows); }, []);

  const filtered = rows.filter((r) => cat === 'All' || r.category === cat);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        {['All', 'Crypto', 'AntiDebug', 'Other'].map((c) => (
          <Chip key={c} active={cat === c} onClick={() => setCat(c)}>{c}</Chip>
        ))}
        <span className="list-count" style={{ marginLeft: 'auto' }}>{filtered.length} matches</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead>
            <tr><th style={{ width: 90 }}>Category</th><th>Name</th><th style={{ width: 100 }}>Confidence</th><th>Description</th><th style={{ width: 60 }}>Inst</th></tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i} onClick={() => navigateTo(r.start_inst_id)}>
                <td><span className={clsx('cat-tag', `cat-${categoryTone(r.category)}`)}>{r.category}</span></td>
                <td className="mono">{r.pattern_name}</td>
                <td><ConfidenceBar value={r.confidence} /></td>
                <td className="dim wrap">{r.description}</td>
                <td className="mono link">#{r.start_inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Strings ---------- */
export function StringsPanel() {
  const [rows, setRows] = useState<StringEntry[]>([]);
  const [filter, setFilter] = useState('');
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.strings().then(setRows); }, []);
  const filtered = useMemo(
    () => rows.filter((r) => r.value.toLowerCase().includes(filter.toLowerCase())),
    [rows, filter],
  );

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <Input placeholder="Filter strings…" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 200 }} />
        <span className="list-count" style={{ marginLeft: 'auto' }}>{filtered.length} strings</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 120 }}>Address</th><th>String</th><th style={{ width: 60 }}>Len</th><th style={{ width: 70 }}>Enc</th><th style={{ width: 60 }}>Inst</th></tr></thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i} onClick={() => navigateTo(r.inst_id)}>
                <td className="mono dim">{r.addr}</td>
                <td className="mono str-val">"{r.value}"</td>
                <td className="mono num dim">{r.length}</td>
                <td className="dim">{r.encoding}</td>
                <td className="mono link">#{r.inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- ObjC Messages ---------- */
export function ObjcPanel() {
  const [rows, setRows] = useState<ObjcMessage[]>([]);
  const [filter, setFilter] = useState('');
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.objcMessages().then(setRows); }, []);
  const filtered = rows.filter((r) =>
    `${r.cls} ${r.selector}`.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <Input placeholder="Filter class/selector…" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 200 }} />
        <span className="list-count" style={{ marginLeft: 'auto' }}>{filtered.length} messages</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 150 }}>Class</th><th>Selector</th><th>Args</th><th style={{ width: 100 }}>Return</th><th style={{ width: 60 }}>Inst</th></tr></thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i} onClick={() => navigateTo(r.inst_id)}>
                <td className="mono objc-name">{r.cls}</td>
                <td className="mono str-val">{r.selector}</td>
                <td className="mono dim wrap">{r.args}</td>
                <td className="mono dim">{r.ret}</td>
                <td className="mono link">#{r.inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Call Graph ---------- */
export function CallGraphPanel() {
  const [data, setData] = useState<CallGraphResult | null>(null);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.callGraph().then(setData); }, []);
  if (!data) return null;

  const nameOf = (pc: string) => data.nodes.find((n) => n.pc === pc)?.name ?? pc;
  const hot = [...data.nodes].sort((a, b) => b.calls_received - a.calls_received).slice(0, 50);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">Hot Callees · {data.nodes.length} nodes / {data.edges.length} edges</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th>Function</th><th style={{ width: 90 }}>Received</th><th style={{ width: 80 }}>Made</th></tr></thead>
          <tbody>
            {hot.map((n) => (
              <tr key={n.pc} onClick={() => navigateTo(0)}>
                <td className={clsx('mono', n.name.startsWith('-[') && 'objc-name')}>
                  {n.is_root && <span className="cat-tag cat-accent" style={{ marginRight: 6 }}>root</span>}
                  {nameOf(n.pc)}
                </td>
                <td className="mono num">{n.calls_received}</td>
                <td className="mono num dim">{n.calls_made}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
