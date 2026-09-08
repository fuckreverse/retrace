/**
 * 扩展分析面板集合 —— Constants / Algorithm Summary / API Intercepts / Loops / Register Timeline。
 * 复用 lists.css 的表格范式，点击行 → navigateTo(inst_id) 联动主视图。
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type {
  AlgorithmEntry,
  ApiCallEntry,
  ConstantEntry,
  LoopEntry,
  RegTimeline,
} from '@/types/tenet';
import { Button, Chip, ConfidenceBar, Input } from '@/components/ui';
import './lists.css';

/* ---------- Constants ---------- */
export function ConstantsPanel() {
  const [rows, setRows] = useState<ConstantEntry[]>([]);
  const [filter, setFilter] = useState('');
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.constants().then(setRows); }, []);
  const filtered = useMemo(
    () => rows.filter((r) => `${r.kind} ${r.value} ${r.note}`.toLowerCase().includes(filter.toLowerCase())),
    [rows, filter],
  );

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <Input placeholder="过滤常量…" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 200 }} />
        <span className="list-count" style={{ marginLeft: 'auto' }}>{filtered.length} 个常量</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 130 }}>Value</th><th style={{ width: 120 }}>Kind</th><th>Note</th><th style={{ width: 100 }}>Confidence</th><th style={{ width: 60 }}>Inst</th></tr></thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i} onClick={() => navigateTo(r.inst_id)}>
                <td className="mono str-val">{r.value}</td>
                <td className="mono objc-name">{r.kind}</td>
                <td className="dim wrap">{r.note}</td>
                <td><ConfidenceBar value={r.confidence} /></td>
                <td className="mono link">#{r.inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Algorithm Summary ---------- */
export function AlgorithmPanel() {
  const [rows, setRows] = useState<AlgorithmEntry[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.algorithms().then(setRows); }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} algorithms identified</span>
      </div>
      <div className="list-scroll">
        <div className="algo-cards">
          {rows.map((a, i) => (
            <div key={i} className="algo-card" onClick={() => navigateTo(a.start_inst_id)}>
              <div className="algo-head">
                <span className="algo-name mono">{a.name}</span>
                <span className={clsx('cat-tag', a.category === 'Crypto' ? 'cat-accent' : a.category === 'Hash' ? 'cat-warning' : 'cat-default')}>
                  {a.category}
                </span>
                {a.key_size && <span className="dim algo-key">{a.key_size}-bit</span>}
                <div style={{ marginLeft: 'auto', width: 110 }}><ConfidenceBar value={a.confidence} /></div>
              </div>
              <div className="algo-evidence">
                {a.evidence.map((e, j) => <span key={j} className="algo-chip">{e}</span>)}
              </div>
              <div className="algo-range dim mono">#{a.start_inst_id} – #{a.end_inst_id}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ---------- API Intercepts ---------- */
export function ApiInterceptsPanel() {
  const [rows, setRows] = useState<ApiCallEntry[]>([]);
  const [lib, setLib] = useState('All');
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.apiIntercepts().then(setRows); }, []);
  const libs = useMemo(() => ['All', ...Array.from(new Set(rows.map((r) => r.library)))], [rows]);
  const filtered = rows.filter((r) => lib === 'All' || r.library === lib);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        {libs.map((l) => <Chip key={l} active={lib === l} onClick={() => setLib(l)}>{l}</Chip>)}
        <span className="list-count" style={{ marginLeft: 'auto' }}>{filtered.length} calls</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 110 }}>Library</th><th style={{ width: 160 }}>Function</th><th>Arguments</th><th style={{ width: 110 }}>Return</th><th style={{ width: 60 }}>Inst</th></tr></thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i} onClick={() => navigateTo(r.inst_id)}>
                <td><span className="cat-tag cat-accent">{r.library}</span></td>
                <td className="mono str-val">{r.func}</td>
                <td className="mono dim wrap">{r.args}</td>
                <td className="mono">{r.ret}</td>
                <td className="mono link">#{r.inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Loop Semantics ---------- */
export function LoopsPanel() {
  const [rows, setRows] = useState<LoopEntry[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.loops().then(setRows); }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} loops</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 120 }}>Header</th><th style={{ width: 120 }}>Kind</th><th style={{ width: 90 }}>Iterations</th><th style={{ width: 90 }}>Body</th><th style={{ width: 80 }}>IndVar</th><th style={{ width: 60 }}>Inst</th></tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} onClick={() => navigateTo(r.header_inst_id)}>
                <td className="mono dim">{r.header_pc}</td>
                <td className="mono objc-name">{r.kind}</td>
                <td className="mono num">{r.iterations}</td>
                <td className="mono num dim">{r.body_size} insts</td>
                <td className="mono">{r.induction_var ?? '—'}</td>
                <td className="mono link">#{r.header_inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Register Timeline ---------- */
const TIMELINE_REGS = ['x0', 'x1', 'x8', 'x19', 'x20', 'x21', 'lr', 'sp'];

export function RegTimelinePanel() {
  const [reg, setReg] = useState('x0');
  const [data, setData] = useState<RegTimeline | null>(null);
  const total = useTraceStore((s) => s.totalInst);
  const cur = useTraceStore((s) => s.currentInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => { api.regTimeline(reg).then(setData); }, [reg]);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv || !data) return;
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth, h = cv.clientHeight;
    cv.width = w * dpr; cv.height = h * dpr;
    const ctx = cv.getContext('2d')!;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    if (data.points.length === 0) return;

    const style = getComputedStyle(document.documentElement);
    const accent = style.getPropertyValue('--accent').trim() || '#4c8dff';
    const grid = style.getPropertyValue('--border').trim() || '#30363d';

    // 归一化数值到 [0,1]
    const vals = data.points.map((p) => Number(BigInt(p.value) & 0xffffffffn));
    const min = Math.min(...vals), max = Math.max(...vals);
    const span = max - min || 1;
    const pad = 8;
    const plotW = w - pad * 2, plotH = h - pad * 2;

    // 网格
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = pad + (plotH * i) / 4;
      ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke();
    }

    // 折线(阶梯)
    ctx.strokeStyle = accent;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    data.points.forEach((p, i) => {
      const x = pad + (plotW * p.inst_id) / Math.max(1, total);
      const y = pad + plotH - (plotH * (vals[i] - min)) / span;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // 数据点
    ctx.fillStyle = accent;
    data.points.forEach((p, i) => {
      const x = pad + (plotW * p.inst_id) / Math.max(1, total);
      const y = pad + plotH - (plotH * (vals[i] - min)) / span;
      ctx.beginPath(); ctx.arc(x, y, 2, 0, Math.PI * 2); ctx.fill();
    });

    // 当前游标
    const cx = pad + (plotW * cur) / Math.max(1, total);
    ctx.strokeStyle = '#ffa657';
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(cx, pad); ctx.lineTo(cx, h - pad); ctx.stroke();
  }, [data, total, cur]);

  const onCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const cv = canvasRef.current;
    if (!cv) return;
    const rect = cv.getBoundingClientRect();
    const frac = (e.clientX - rect.left - 8) / (rect.width - 16);
    navigateTo(Math.max(0, Math.min(total - 1, Math.round(frac * total))));
  };

  const [customReg, setCustomReg] = useState('');
  const commitCustomReg = () => {
    const v = customReg.trim().toLowerCase();
    if (v) setReg(v);
  };

  return (
    <div className="list-panel">
      <div className="list-toolbar" style={{ flexWrap: 'wrap', rowGap: 6 }}>
        {TIMELINE_REGS.map((rn) => <Chip key={rn} active={reg === rn} onClick={() => setReg(rn)}>{rn}</Chip>)}
        <input
          className="input mono"
          style={{ width: 90 }}
          value={customReg}
          onChange={(e) => setCustomReg(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && commitCustomReg()}
          placeholder="自定义 (如 x21/v0)"
        />
        <Button variant="default" size="sm" onClick={commitCustomReg} disabled={!customReg.trim()}>Go</Button>
        <span className="dim">当前：<span className="mono">{reg}</span></span>
        <span className="list-count" style={{ marginLeft: 'auto' }}>{data?.points.length ?? 0} samples</span>
      </div>
      <div className="regtl-canvas-wrap">
        <canvas ref={canvasRef} className="regtl-canvas" onClick={onCanvasClick} />
      </div>
      <div className="list-scroll regtl-list">
        <table className="data-table">
          <thead><tr><th style={{ width: 60 }}>Inst</th><th>Value</th></tr></thead>
          <tbody>
            {(data?.points ?? []).map((p, i) => (
              <tr key={i} onClick={() => navigateTo(p.inst_id)}>
                <td className="mono link">#{p.inst_id}</td>
                <td className="mono str-val">{p.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
