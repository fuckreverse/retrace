/**
 * 分析结果类面板集合 —— Patterns / Strings / ObjC / CallGraph。
 * 均为"表格 + 过滤 + 点击 inst_id 跳转"的统一交互范式。
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { CallGraphResult, ObjcMessage, PatternMatch, StringEntry } from '@/types/tenet';
import { Button, Chip, ConfidenceBar, IconButton, Input } from '@/components/ui';
import { Icon } from '@/components/icons';
import './lists.css';
import './cfg.css';

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
const CG_NODE_W = 150;
const CG_NODE_H = 36;
const CG_COL_GAP = 80;
const CG_ROW_GAP = 16;

interface CgLayoutNode {
  pc: string;
  name: string;
  is_root: boolean;
  calls_made: number;
  calls_received: number;
  x: number;
  y: number;
}

/** 简单分层布局：从 root 节点 BFS 分层，未被 root 触达的节点归入末层。列=深度，行=同层顺序 */
function layoutCallGraph(data: CallGraphResult): { nodes: CgLayoutNode[]; width: number; height: number } {
  const outAdj = new Map<string, string[]>();
  for (const e of data.edges) {
    if (!outAdj.has(e.caller)) outAdj.set(e.caller, []);
    outAdj.get(e.caller)!.push(e.callee);
  }
  const depth = new Map<string, number>();
  const roots = data.nodes.filter((n) => n.is_root);
  const queue: string[] = [];
  for (const r of roots) { depth.set(r.pc, 0); queue.push(r.pc); }
  if (queue.length === 0 && data.nodes.length > 0) {
    // 没有显式 root：退化为最高 calls_received 作为根，避免全部落在同一层
    const fallback = [...data.nodes].sort((a, b) => b.calls_received - a.calls_received)[0];
    depth.set(fallback.pc, 0);
    queue.push(fallback.pc);
  }
  let qi = 0;
  while (qi < queue.length) {
    const cur = queue[qi++];
    const d = depth.get(cur)!;
    for (const next of outAdj.get(cur) ?? []) {
      if (!depth.has(next)) { depth.set(next, d + 1); queue.push(next); }
    }
  }
  const maxKnownDepth = Math.max(0, ...Array.from(depth.values()));
  const byDepth = new Map<number, CallGraphResult['nodes']>();
  for (const n of data.nodes) {
    const d = depth.get(n.pc) ?? maxKnownDepth + 1; // 未触达节点统一放最后一列
    if (!byDepth.has(d)) byDepth.set(d, []);
    byDepth.get(d)!.push(n);
  }
  const nodes: CgLayoutNode[] = [];
  let maxRows = 0;
  const depths = Array.from(byDepth.keys()).sort((a, b) => a - b);
  for (const d of depths) {
    const col = byDepth.get(d)!.sort((a, b) => b.calls_received - a.calls_received);
    maxRows = Math.max(maxRows, col.length);
    col.forEach((n, row) => {
      nodes.push({
        ...n,
        x: 20 + d * (CG_NODE_W + CG_COL_GAP),
        y: 20 + row * (CG_NODE_H + CG_ROW_GAP),
      });
    });
  }
  const width = 40 + (depths.length || 1) * (CG_NODE_W + CG_COL_GAP);
  const height = 40 + maxRows * (CG_NODE_H + CG_ROW_GAP);
  return { nodes, width, height };
}

type CgView = 'graph' | 'table';

export function CallGraphPanel() {
  const [data, setData] = useState<CallGraphResult | null>(null);
  const [view, setView] = useState<CgView>('graph');
  const [selected, setSelected] = useState<string | null>(null);
  const [currentPc, setCurrentPc] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 20, y: 10 });
  const canvasRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ x: number; y: number } | null>(null);
  const cur = useTraceStore((s) => s.currentInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { void api.callGraph().then(setData); }, []);

  const layout = useMemo(() => (data ? layoutCallGraph(data) : null), [data]);
  const nodeByPc = useMemo(() => new Map(layout?.nodes.map((n) => [n.pc, n])), [layout]);
  const matches = useMemo(() => {
    const query = search.trim().toLowerCase();
    return query && layout ? layout.nodes.filter((n) => n.name.toLowerCase().includes(query)) : [];
  }, [layout, search]);
  const matchingPcs = useMemo(() => new Set(matches.map((n) => n.pc)), [matches]);

  const centerNode = (node: CgLayoutNode, targetZoom = zoom) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    setZoom(targetZoom);
    setPan({
      x: canvas.clientWidth / 2 - (node.x + CG_NODE_W / 2) * targetZoom,
      y: canvas.clientHeight / 2 - (node.y + CG_NODE_H / 2) * targetZoom,
    });
  };

  useEffect(() => {
    let cancelled = false;
    void api.callStack(cur).then((frames) => {
      if (cancelled) return;
      const top = frames[frames.length - 1];
      const node = top ? nodeByPc.get(top.func_pc) ?? layout?.nodes.find((n) => n.name === top.func_name) : undefined;
      setCurrentPc(node?.pc ?? null);
      const canvas = canvasRef.current;
      if (node && canvas) {
        const left = pan.x + node.x * zoom, topY = pan.y + node.y * zoom;
        const visible = left >= 0 && topY >= 0 && left + CG_NODE_W * zoom <= canvas.clientWidth && topY + CG_NODE_H * zoom <= canvas.clientHeight;
        if (!visible) centerNode(node);
      }
    });
    return () => { cancelled = true; };
    // pan/zoom intentionally omitted: user navigation should not retrigger following.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cur, layout, nodeByPc]);

  useEffect(() => {
    const query = search.trim().toLowerCase();
    const exact = matches.find((node) => node.name.toLowerCase() === query);
    if (exact) centerNode(exact, Math.min(4, Math.max(1.2, zoom)));
    // Only a newly entered exact query should trigger automatic location.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, matches]);

  if (!data || !layout) return <div className="empty-state">正在加载调用图…</div>;

  const nameOf = (pc: string) => data.nodes.find((n) => n.pc === pc)?.name ?? pc;
  const hot = [...data.nodes].sort((a, b) => b.calls_received - a.calls_received).slice(0, 50);
  const maxCalls = Math.max(1, ...data.nodes.map((n) => n.calls_received));
  const gotoFunc = async (pc: string) => { const xref = await api.xref(pc); if (xref.inst_ids.length > 0) navigateTo(xref.inst_ids[0]); };

  const fitToScreen = () => {
    const canvas = canvasRef.current;
    if (!canvas || layout.nodes.length === 0) return;
    const minX = Math.min(...layout.nodes.map((n) => n.x)), minY = Math.min(...layout.nodes.map((n) => n.y));
    const maxX = Math.max(...layout.nodes.map((n) => n.x + CG_NODE_W)), maxY = Math.max(...layout.nodes.map((n) => n.y + CG_NODE_H));
    const width = Math.max(1, maxX - minX), height = Math.max(1, maxY - minY);
    const nextZoom = Math.min(4, Math.max(0.15, Math.min((canvas.clientWidth - 80) / width, (canvas.clientHeight - 80) / height)));
    setZoom(nextZoom);
    setPan({ x: (canvas.clientWidth - width * nextZoom) / 2 - minX * nextZoom, y: (canvas.clientHeight - height * nextZoom) / 2 - minY * nextZoom });
  };
  const locateSearch = () => { if (matches[0]) centerNode(matches[0], Math.min(4, Math.max(1.2, zoom))); };
  const onWheel = (e: React.WheelEvent) => { e.preventDefault(); setZoom((z) => Math.min(4, Math.max(0.15, z - e.deltaY * 0.001))); };
  const onDown = (e: React.MouseEvent) => { dragRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMove = (e: React.MouseEvent) => { if (dragRef.current) setPan({ x: e.clientX - dragRef.current.x, y: e.clientY - dragRef.current.y }); };
  const onUp = () => { dragRef.current = null; };

  return (
    <div className="cfg-panel">
      <div className="cfg-toolbar">
        <Chip active={view === 'graph'} onClick={() => setView('graph')}>Graph</Chip>
        <Chip active={view === 'table'} onClick={() => setView('table')}>Table</Chip>
        {view === 'graph' && <>
          <Input aria-label="搜索函数" placeholder="Search function…" value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') locateSearch(); }} style={{ width: 160 }} />
          <div className="toolbar-sep" />
          <IconButton title="放大" onClick={() => setZoom((z) => Math.min(4, z + 0.2))}><Icon.Forward /></IconButton>
          <span className="dim" style={{ width: 46, textAlign: 'center' }}>{(zoom * 100).toFixed(0)}%</span>
          <IconButton title="缩小" onClick={() => setZoom((z) => Math.max(0.15, z - 0.2))}><Icon.Back /></IconButton>
          <IconButton title="Fit to Screen" onClick={fitToScreen}><Icon.Box /></IconButton>
          <Button size="sm" variant="ghost" onClick={() => { setZoom(1); setPan({ x: 20, y: 10 }); }}>Reset View</Button>
        </>}
        <span className="dim" style={{ marginLeft: 'auto' }}>{data.nodes.length} nodes · {data.edges.length} edges</span>
      </div>
      {view === 'table' ? <div className="list-scroll"><table className="data-table">
        <thead><tr><th>Function</th><th style={{ width: 90 }}>Received</th><th style={{ width: 80 }}>Made</th></tr></thead>
        <tbody>{hot.map((n) => <tr key={n.pc} onClick={() => void gotoFunc(n.pc)}><td className={clsx('mono', n.name.startsWith('-[') && 'objc-name')}>{n.is_root && <span className="cat-tag cat-accent" style={{ marginRight: 6 }}>root</span>}{nameOf(n.pc)}</td><td className="mono num">{n.calls_received}</td><td className="mono num dim">{n.calls_made}</td></tr>)}</tbody>
      </table></div> : (
        <div ref={canvasRef} className="cfg-canvas" onWheel={onWheel} onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}>
          <svg width="100%" height="100%"><g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            <defs><marker id="cg-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0L8 4L0 8z" fill="var(--border-strong)" /></marker></defs>
            {data.edges.map((e, i) => {
              const a = nodeByPc.get(e.caller), b = nodeByPc.get(e.callee);
              if (!a || !b) return null;
              const x1 = a.x + CG_NODE_W, y1 = a.y + CG_NODE_H / 2, x2 = b.x, y2 = b.y + CG_NODE_H / 2, mx = (x1 + x2) / 2;
              const highlighted = selected === e.caller || selected === e.callee;
              return <path key={i} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke={highlighted ? 'var(--accent)' : 'var(--border-strong)'} strokeWidth={highlighted ? 2 : Math.min(3, 1 + (e.call_count ?? 1) / 200)} opacity={highlighted ? 0.9 : 0.5} markerEnd="url(#cg-arrow)" />;
            })}
            {layout.nodes.map((n) => {
              const heat = n.calls_received / maxCalls, isSel = selected === n.pc, isCurrent = currentPc === n.pc, isMatch = matchingPcs.has(n.pc);
              const stroke = isCurrent ? 'var(--success)' : isMatch ? 'var(--warning)' : isSel ? 'var(--accent)' : n.is_root ? 'var(--success)' : 'var(--border-strong)';
              return <g key={n.pc} className={`df-node${isCurrent ? ' cg-node-current' : ''}${isMatch ? ' cg-node-match' : ''}`} transform={`translate(${n.x},${n.y})`} onClick={(ev) => { ev.stopPropagation(); setSelected(n.pc); void gotoFunc(n.pc); }}>
                <rect width={CG_NODE_W} height={CG_NODE_H} rx={8} fill="var(--bg-elevated)" stroke={stroke} strokeWidth={isCurrent ? 3 : isSel || isMatch || n.is_root ? 2 : 1} />
                <rect width={Math.max(2, CG_NODE_W * heat)} height={3} y={CG_NODE_H - 3} fill="var(--accent)" opacity={0.6} />
                <text x={8} y={16} className={clsx('df-node-label', n.name.startsWith('-[') && 'objc-name')}>{n.name.length > 20 ? `${n.name.slice(0, 20)}…` : n.name}</text>
                <text x={8} y={30} className="df-node-inst" textAnchor="start">recv {n.calls_received} · made {n.calls_made}</text>
              </g>;
            })}
          </g></svg>
        </div>
      )}
    </div>
  );
}
