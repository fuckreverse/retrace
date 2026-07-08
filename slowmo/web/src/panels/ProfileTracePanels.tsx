/**
 * Profile-Trace 类面板 —— Window Stats / Trace Fold / Trace Diff。
 */
import { useEffect, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { DiffEntry, FoldEntry, WindowStat } from '@/types/tenet';
import './lists.css';

/* ---------- Window Stats ---------- */
export function WindowStatsPanel() {
  const [rows, setRows] = useState<WindowStat[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.windowStats().then(setRows); }, []);
  const maxCount = Math.max(1, ...rows.map((r) => r.inst_count));

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} windows · 2000 insts/window</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 140 }}>Window</th><th style={{ width: 130 }}>Density</th>
              <th style={{ width: 80 }}>Reads</th><th style={{ width: 80 }}>Writes</th>
              <th style={{ width: 80 }}>Branch</th><th style={{ width: 70 }}>Calls</th><th>Dominant Fn</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((w, i) => (
              <tr key={i} onClick={() => navigateTo(w.window_start)}>
                <td className="mono link">#{w.window_start}–#{w.window_end}</td>
                <td>
                  <div className="ent-bar">
                    <div className="ent-fill" style={{ width: `${(w.inst_count / maxCount) * 100}%`, background: 'var(--accent)' }} />
                    <span className="ent-label mono">{w.inst_count}</span>
                  </div>
                </td>
                <td className="mono num dim">{w.mem_reads}</td>
                <td className="mono num dim">{w.mem_writes}</td>
                <td className="mono num dim">{w.branches}</td>
                <td className="mono num dim">{w.calls}</td>
                <td className="mono objc-name">{w.dominant_func}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Trace Fold ---------- */
export function TraceFoldPanel() {
  const [rows, setRows] = useState<FoldEntry[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.traceFold().then(setRows); }, []);
  const savedTotal = rows.reduce((a, r) => a + (r.end_inst_id - r.start_inst_id), 0);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} folded regions · ~{savedTotal.toLocaleString()} insts collapsed</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 150 }}>Range</th><th style={{ width: 130 }}>Pattern PC</th><th style={{ width: 90 }}>×Repeat</th><th>Summary</th></tr></thead>
          <tbody>
            {rows.map((f, i) => (
              <tr key={i} onClick={() => navigateTo(f.start_inst_id)}>
                <td className="mono link">#{f.start_inst_id}–#{f.end_inst_id}</td>
                <td className="mono dim">{f.pattern_pc}</td>
                <td className="mono num"><span className="cat-tag cat-warning">×{f.repeat_count}</span></td>
                <td className="dim wrap">{f.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Trace Diff ---------- */
function diffTone(kind: DiffEntry['kind']): string {
  if (kind === 'added') return 'diff-added';
  if (kind === 'removed') return 'diff-removed';
  if (kind === 'changed') return 'diff-changed';
  return '';
}
export function TraceDiffPanel() {
  const [rows, setRows] = useState<DiffEntry[]>([]);
  const [showSame, setShowSame] = useState(false);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.traceDiff().then(setRows); }, []);
  const filtered = rows.filter((r) => showSame || r.kind !== 'same');
  const counts = {
    added: rows.filter((r) => r.kind === 'added').length,
    removed: rows.filter((r) => r.kind === 'removed').length,
    changed: rows.filter((r) => r.kind === 'changed').length,
  };

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="cat-tag cat-accent">+{counts.added}</span>
        <span className="cat-tag cat-danger">-{counts.removed}</span>
        <span className="cat-tag cat-warning">~{counts.changed}</span>
        <label className="diff-toggle">
          <input type="checkbox" checked={showSame} onChange={(e) => setShowSame(e.target.checked)} /> 显示相同
        </label>
        <span className="list-count" style={{ marginLeft: 'auto' }}>trace A ↔ trace B</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 60 }}>Inst</th><th style={{ width: 40 }}></th><th>Trace A (left)</th><th>Trace B (right)</th><th style={{ width: 100 }}>Note</th></tr></thead>
          <tbody>
            {filtered.map((d, i) => (
              <tr key={i} className={diffTone(d.kind)} onClick={() => navigateTo(d.inst_id)}>
                <td className="mono link">#{d.inst_id}</td>
                <td className="mono diff-sign">{d.kind === 'added' ? '+' : d.kind === 'removed' ? '−' : d.kind === 'changed' ? '~' : '='}</td>
                <td className="mono">{d.left}</td>
                <td className="mono">{d.right}</td>
                <td className="dim">{d.note ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
