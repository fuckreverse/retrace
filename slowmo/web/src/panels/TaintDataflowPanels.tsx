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
import { Chip } from '@/components/ui';
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
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => { api.dataflowGraph().then(setData); }, []);
  if (!data) return null;

  const nodeById = (id: string) => data.nodes.find((n) => n.id === id)!;

  return (
    <div className="cfg-panel">
      <div className="cfg-toolbar">
        <span className="list-count">{data.nodes.length} nodes / {data.edges.length} edges · def-use 数据流</span>
        <div className="cfg-legend" style={{ marginLeft: 'auto' }}>
          <span><i style={{ background: 'var(--hl-reg)' }} />reg</span>
          <span><i style={{ background: 'var(--hl-addr)' }} />mem</span>
          <span><i style={{ background: 'var(--hl-imm)' }} />const</span>
          <span><i style={{ background: 'var(--accent)' }} />op</span>
        </div>
      </div>
      <div className="cfg-canvas-wrap" ref={wrapRef}>
        <svg width={data.canvas_width} height={data.canvas_height} className="cfg-svg">
          <defs>
            <marker id="df-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0 0L8 4L0 8z" fill="var(--border-strong)" />
            </marker>
          </defs>
          {data.edges.map((e, i) => {
            const a = nodeById(e.from), b = nodeById(e.to);
            const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2;
            const x2 = b.x, y2 = b.y + NODE_H / 2;
            const mx = (x1 + x2) / 2;
            return (
              <g key={i}>
                <path
                  d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                  fill="none" stroke="var(--border-strong)" strokeWidth={1.5} markerEnd="url(#df-arrow)"
                />
                {e.label && <text x={mx} y={(y1 + y2) / 2 - 4} className="df-edge-label">{e.label}</text>}
              </g>
            );
          })}
          {data.nodes.map((n) => (
            <g key={n.id} className="df-node" onClick={() => n.inst_id != null && navigateTo(n.inst_id)}>
              <rect x={n.x} y={n.y} width={NODE_W} height={NODE_H} rx={8}
                fill="var(--bg-elevated)" stroke={nodeFill(n.kind)} strokeWidth={1.5} />
              <circle cx={n.x + 12} cy={n.y + NODE_H / 2} r={4} fill={nodeFill(n.kind)} />
              <text x={n.x + 24} y={n.y + NODE_H / 2 + 4} className="df-node-label">{n.label}</text>
              {n.inst_id != null && <text x={n.x + NODE_W - 6} y={n.y + 13} className="df-node-inst">#{n.inst_id}</text>}
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}

/* ---------- Backward Taint ---------- */
const BT_REGS = ['x0', 'x1', 'x8', 'x19', 'x20', 'lr'];
export function BackwardTaintPanel() {
  const cur = useTraceStore((s) => s.currentInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const setProducer = useTraceStore((s) => s.setProducerChain);
  const [reg, setReg] = useState('x0');
  const [steps, setSteps] = useState<BackwardTaintStep[]>([]);

  useEffect(() => {
    api.backwardTaint(cur, reg).then((s) => {
      setSteps(s);
      setProducer(s.map((x) => x.inst_id));
    });
  }, [cur, reg, setProducer]);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="dim">从 #{cur} 反向追溯</span>
        {BT_REGS.map((r) => <Chip key={r} active={reg === r} onClick={() => setReg(r)}>{r}</Chip>)}
        <span className="list-count" style={{ marginLeft: 'auto' }}>{steps.length} producers</span>
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
