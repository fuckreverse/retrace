/**
 * Taint / Dataflow / ObjC-Crypto 面板集合。
 * TaintSourcesPanel / DataflowGraphPanel(SVG) / BackwardTaintPanel / ObjcCryptoPanel。
 */
import { useEffect, useRef, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type {
  BackwardTaintStep,
  DataflowGraph,
  DataflowNode,
  ObjcCryptoLink,
  TaintSource,
} from '@/types/tenet';
import { Button, Chip, IconButton } from '@/components/ui';
import { Icon } from '@/components/icons';
import './lists.css';
import './cfg.css';

/* ---------- Taint Sources ---------- */
export function TaintSourcesPanel() {
  const [rows, setRows] = useState<TaintSource[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const setTaintFwd = useTraceStore((s) => s.setTaintForward);

  useEffect(() => { api.taintSources().then(setRows); }, []);

  const kindTone = (k: TaintSource['kind']) =>
    k === 'api_return' ? 'cat-accent' : k === 'register' ? 'cat-warning' : 'cat-default';

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} taint sources · {rows.filter((r) => r.active).length} active</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 50 }}>#</th><th style={{ width: 100 }}>Kind</th><th style={{ width: 60 }}>Active</th><th>Location</th><th>Label</th><th style={{ width: 110 }}>Propagated</th></tr></thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id} onClick={() => {
                const m = s.location.match(/#(\d+)/);
                if (m) navigateTo(Number(m[1]));
                // 简单联动：模拟污点扩散高亮
                if (m) setTaintFwd(Array.from({ length: 30 }, (_, i) => Number(m[1]) + i * 7));
              }}>
                <td className="mono dim">{s.id}</td>
                <td><span className={clsx('cat-tag', kindTone(s.kind))}>{s.kind}</span></td>
                <td>{s.active ? <span className="dot-on" /> : <span className="dot-off" />}</td>
                <td className="mono">{s.location}</td>
                <td className="str-val">{s.label}</td>
                <td className="mono num dim">{s.propagated.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Dataflow Graph (SVG) ---------- */
const NODE_W = 130;
const NODE_H = 40;
function nodeFill(kind: DataflowNode['kind']): string {
  switch (kind) {
    case 'reg': return 'var(--hl-reg)';
    case 'mem': return 'var(--hl-addr)';
    case 'const': return 'var(--hl-imm)';
    default: return 'var(--accent)';
  }
}
export function DataflowGraphPanel() {
  const [data, setData] = useState<DataflowGraph | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 20, y: 10 });
  const cur = useTraceStore((s) => s.currentInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const wrapRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => { void api.dataflowGraph().then(setData); }, []);

  const centerNode = (node: DataflowNode, targetZoom = zoom) => {
    const canvas = wrapRef.current;
    if (!canvas) return;
    setZoom(targetZoom);
    setPan({
      x: canvas.clientWidth / 2 - (node.x + NODE_W / 2) * targetZoom,
      y: canvas.clientHeight / 2 - (node.y + NODE_H / 2) * targetZoom,
    });
  };

  useEffect(() => {
    const node = data?.nodes.find((n) => n.inst_id === cur);
    const canvas = wrapRef.current;
    if (!node || !canvas) return;
    const left = pan.x + node.x * zoom, top = pan.y + node.y * zoom;
    const visible = left >= 0 && top >= 0 && left + NODE_W * zoom <= canvas.clientWidth && top + NODE_H * zoom <= canvas.clientHeight;
    if (!visible) centerNode(node);
    // pan/zoom intentionally omitted: only cursor/data changes trigger following.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cur, data]);

  if (!data) return null;
  const nodeById = (id: string) => data.nodes.find((n) => n.id === id);
  const fitToScreen = () => {
    const canvas = wrapRef.current;
    if (!canvas || data.nodes.length === 0) return;
    const minX = Math.min(...data.nodes.map((n) => n.x)), minY = Math.min(...data.nodes.map((n) => n.y));
    const maxX = Math.max(...data.nodes.map((n) => n.x + NODE_W)), maxY = Math.max(...data.nodes.map((n) => n.y + NODE_H));
    const width = Math.max(1, maxX - minX), height = Math.max(1, maxY - minY);
    const nextZoom = Math.min(4, Math.max(0.2, Math.min((canvas.clientWidth - 80) / width, (canvas.clientHeight - 80) / height)));
    setZoom(nextZoom);
    setPan({ x: (canvas.clientWidth - width * nextZoom) / 2 - minX * nextZoom, y: (canvas.clientHeight - height * nextZoom) / 2 - minY * nextZoom });
  };
  const onWheel = (e: React.WheelEvent) => { e.preventDefault(); setZoom((z) => Math.min(4, Math.max(0.2, z - e.deltaY * 0.001))); };
  const onDown = (e: React.MouseEvent) => { dragRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMove = (e: React.MouseEvent) => { if (dragRef.current) setPan({ x: e.clientX - dragRef.current.x, y: e.clientY - dragRef.current.y }); };
  const onUp = () => { dragRef.current = null; };

  return (
    <div className="cfg-panel">
      <div className="cfg-toolbar">
        <span className="list-count">{data.nodes.length} nodes / {data.edges.length} edges · def-use 数据流</span>
        <IconButton title="放大" onClick={() => setZoom((z) => Math.min(4, z + 0.2))}><Icon.Forward /></IconButton>
        <span className="dim" style={{ width: 46, textAlign: 'center' }}>{(zoom * 100).toFixed(0)}%</span>
        <IconButton title="缩小" onClick={() => setZoom((z) => Math.max(0.2, z - 0.2))}><Icon.Back /></IconButton>
        <IconButton title="Fit to Screen" onClick={fitToScreen}><Icon.Box /></IconButton>
        <Button size="sm" variant="ghost" onClick={() => { setZoom(1); setPan({ x: 20, y: 10 }); }}>Reset View</Button>
        <div className="cfg-legend" style={{ marginLeft: 'auto' }}>
          <span><i style={{ background: 'var(--hl-reg)' }} />reg</span><span><i style={{ background: 'var(--hl-addr)' }} />mem</span>
          <span><i style={{ background: 'var(--hl-imm)' }} />const</span><span><i style={{ background: 'var(--accent)' }} />op</span>
        </div>
      </div>
      <div className="cfg-canvas" ref={wrapRef} onWheel={onWheel} onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}>
        <svg width="100%" height="100%" className="cfg-svg"><g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
          <defs><marker id="df-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0L8 4L0 8z" fill="var(--border-strong)" /></marker></defs>
          {data.edges.map((e, i) => {
            const a = nodeById(e.from), b = nodeById(e.to);
            if (!a || !b) return null;
            const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2, mx = (x1 + x2) / 2;
            return <g key={i}><path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke="var(--border-strong)" strokeWidth={1.5} markerEnd="url(#df-arrow)" />{e.label && <text x={mx} y={(y1 + y2) / 2 - 4} className="df-edge-label">{e.label}</text>}</g>;
          })}
          {data.nodes.map((n) => {
            const isCurrent = n.inst_id === cur;
            return <g key={n.id} className={`df-node${isCurrent ? ' df-node-current' : ''}`} onClick={(event) => { event.stopPropagation(); if (n.inst_id != null) navigateTo(n.inst_id); }}>
              <rect x={n.x} y={n.y} width={NODE_W} height={NODE_H} rx={8} fill="var(--bg-elevated)" stroke={isCurrent ? 'var(--success)' : nodeFill(n.kind)} strokeWidth={isCurrent ? 3 : 1.5} />
              <circle cx={n.x + 12} cy={n.y + NODE_H / 2} r={4} fill={nodeFill(n.kind)} />
              <text x={n.x + 24} y={n.y + NODE_H / 2 + 4} className="df-node-label">{n.label}</text>
              {n.inst_id != null && <text x={n.x + NODE_W - 6} y={n.y + 13} className="df-node-inst">#{n.inst_id}</text>}
            </g>;
          })}
        </g></svg>
      </div>
    </div>
  );
}

/* ---------- Backward Taint ---------- */
const BT_REGS = ['x0', 'x1', 'x8', 'x19', 'x20', 'lr'];
/** InstructionsPanel.runTaintBackward 派发的跨面板契约事件名。 */
const BACKWARD_TAINT_EVENT = 'tenet:backward-taint';

export function BackwardTaintPanel() {
  const cur = useTraceStore((s) => s.currentInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const setProducer = useTraceStore((s) => s.setProducerChain);
  const [reg, setReg] = useState('x0');
  const [steps, setSteps] = useState<BackwardTaintStep[]>([]);
  // 起点固定模型：start = null 表示尚未指定（惰性用挂载时的 cur 初始化），
  // 一旦指定（右键事件）便固定不变，游标移动不再覆盖分析结果。
  const [start, setStart] = useState<number | null>(() => useTraceStore.getState().currentInst);
  // follow = true 时起点随游标移动（effectiveStart = cur），默认关闭。
  const [follow, setFollow] = useState(false);

  // 记录上次已请求的 (起点, 寄存器) 组合：follow 关闭时游标移动虽然会
  // 重跑 effect，但 key 不变则直接跳过，避免每步一个网络请求。
  const lastKeyRef = useRef('');

  const fetchBackward = (instId: number, register: string) => {
    lastKeyRef.current = `${instId}:${register}`;
    void api.backwardTaint(instId, register).then((s) => {
      setSteps(s);
      setProducer(s.map((x) => x.inst_id));
    });
  };

  // 数据获取：起点/寄存器变化时重算；follow 开启时才随游标重算。
  useEffect(() => {
    const effectiveStart = follow ? cur : (start ?? cur);
    const key = `${effectiveStart}:${reg}`;
    if (key === lastKeyRef.current) return; // follow 关闭时游标移动：跳过
    fetchBackward(effectiveStart, reg);
    // fetchBackward/setProducer 引用不稳定，刻意不入依赖。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [start, reg, follow, cur]);

  // 监听契约事件：右键“反向污点”指定新的固定起点，并立即重算一次。
  // 显式指定起点意味着固定，因此同时关闭 follow。
  useEffect(() => {
    const handler = (event: Event) => {
      const instId = (event as CustomEvent<{ instId: number }>).detail?.instId;
      if (typeof instId !== 'number') return;
      setFollow(false);
      setStart(instId);
      fetchBackward(instId, reg); // 直接重算；effect 内靠 lastKeyRef 去重避免双请求
    };
    window.addEventListener(BACKWARD_TAINT_EVENT, handler);
    return () => window.removeEventListener(BACKWARD_TAINT_EVENT, handler);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reg]);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="dim">起点 #{follow ? cur : (start ?? cur)}</span>
        <Chip active={follow} onClick={() => setFollow((v) => !v)}>跟随游标</Chip>
        <span className="dim">{follow ? '起点随游标移动' : '起点已固定；右键指令可重新指定，开启“跟随游标”可恢复旧有行为'}</span>
        {BT_REGS.map((r) => <Chip key={r} active={reg === r} onClick={() => setReg(r)}>{r}</Chip>)}
        <span className="list-count" style={{ marginLeft: 'auto' }}>{steps.length} 个生产者</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 60 }}>Inst</th><th style={{ width: 130 }}>PC</th><th style={{ width: 70 }}>Reg</th><th>Contribution</th></tr></thead>
          <tbody>
            {steps.map((s, i) => (
              <tr key={i} onClick={() => navigateTo(s.inst_id)}>
                <td className="mono link">#{s.inst_id}</td>
                <td className="mono dim">{s.pc}</td>
                <td className="mono" style={{ color: 'var(--hl-reg)' }}>{s.reg}</td>
                <td className="dim">{s.contribution}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- ObjC × Crypto ---------- */
function roleTone(role: string): string {
  if (role === 'key' || role === 'iv') return 'cat-danger';
  if (role === 'digest') return 'cat-accent';
  if (role === 'ciphertext') return 'cat-warning';
  return 'cat-default';
}
export function ObjcCryptoPanel() {
  const [rows, setRows] = useState<ObjcCryptoLink[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.objcCrypto().then(setRows); }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} ObjC × Crypto 关联</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 180 }}>Selector</th><th style={{ width: 110 }}>Role</th><th>Data</th><th style={{ width: 150 }}>Linked API</th><th style={{ width: 60 }}>Inst</th></tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} onClick={() => navigateTo(r.inst_id)}>
                <td className="mono str-val">{r.selector}</td>
                <td><span className={clsx('cat-tag', roleTone(r.crypto_role))}>{r.crypto_role}</span></td>
                <td className="mono dim">{r.data_preview}</td>
                <td className="mono objc-name">{r.linked_api ?? '—'}</td>
                <td className="mono link">#{r.inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
