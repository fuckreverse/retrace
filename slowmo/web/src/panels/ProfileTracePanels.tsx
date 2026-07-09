/**
 * Profile-Trace 类面板 —— Window Stats / Trace Fold / Trace Diff。
 */
import { useEffect, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { DiffEntry, FoldEntry, WindowStat } from '@/types/tenet';
import { Button } from '@/components/ui';
import './lists.css';

/* ---------- Window Stats ---------- */
export function WindowStatsPanel() {
  const [rows, setRows] = useState<WindowStat[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.windowStats().then(setRows); }, []);
  const maxCount = Math.max(1, ...rows.map((r) => r.inst_count));
  const windowSize = rows[0] ? rows[0].window_end - rows[0].window_start : 0;

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} windows{windowSize ? ` · ~${windowSize} insts/window` : ''}</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 140 }}>Window</th><th style={{ width: 130 }}>Density</th>
              <th style={{ width: 80 }}>Reads</th><th style={{ width: 80 }}>Writes</th>
              <th style={{ width: 90 }}>Branch %</th><th style={{ width: 80 }}>Uniq PCs</th>
              <th style={{ width: 80 }}>Entropy</th><th>Dominant Insn</th>
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
                <td className="mono num dim">{(w.branch_density * 100).toFixed(1)}%</td>
                <td className="mono num dim">{w.unique_pcs}</td>
                <td className="mono num dim">{w.mnemonic_entropy.toFixed(2)}</td>
                <td className="mono objc-name">{w.dominant_mnemonic}</td>
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
  const [rows, setRows] = useState<DiffEntry[] | null>(null);
  const [showSame, setShowSame] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cur = useTraceStore((s) => s.currentInst);
  const total = useTraceStore((s) => s.totalInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  // 默认给出一组合理初值：以当前指令为 A 区间起点，B 区间紧随其后，方便快速试用
  const [aStart, setAStart] = useState('0');
  const [aEnd, setAEnd] = useState('100');
  const [bStart, setBStart] = useState('100');
  const [bEnd, setBEnd] = useState('200');
  const [traceBPath, setTraceBPath] = useState('');

  useEffect(() => {
    if (total <= 0) return;
    setAStart(String(cur));
    setAEnd(String(Math.min(total - 1, cur + 100)));
    setBStart(String(Math.min(total - 1, cur + 100)));
    setBEnd(String(Math.min(total - 1, cur + 200)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [total]);

  const run = async () => {
    const a0 = Number(aStart), a1 = Number(aEnd), b0 = Number(bStart), b1 = Number(bEnd);
    if (![a0, a1, b0, b1].every(Number.isFinite) || a1 <= a0 || b1 <= b0) {
      setError('区间必须为合法数字，且 end 必须大于 start');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await api.traceDiff([a0, a1], [b0, b1], traceBPath.trim() || undefined);
      setRows(result);
    } catch {
      setError('比较失败（后端 trace_diff 调用出错）');
      setRows(null);
    } finally {
      setBusy(false);
    }
  };

  const filtered = (rows ?? []).filter((r) => showSame || r.kind !== 'same');
  const counts = {
    added: (rows ?? []).filter((r) => r.kind === 'added').length,
    removed: (rows ?? []).filter((r) => r.kind === 'removed').length,
    changed: (rows ?? []).filter((r) => r.kind === 'changed').length,
  };

  return (
    <div className="list-panel">
      <div className="list-toolbar" style={{ flexWrap: 'wrap', rowGap: 6 }}>
        <span className="diff-range-label">A</span>
        <input className="input mono diff-range-input" value={aStart} onChange={(e) => setAStart(e.target.value)} placeholder="start" />
        <span className="dim">–</span>
        <input className="input mono diff-range-input" value={aEnd} onChange={(e) => setAEnd(e.target.value)} placeholder="end" />
        <span className="diff-range-label">B</span>
        <input className="input mono diff-range-input" value={bStart} onChange={(e) => setBStart(e.target.value)} placeholder="start" />
        <span className="dim">–</span>
        <input className="input mono diff-range-input" value={bEnd} onChange={(e) => setBEnd(e.target.value)} placeholder="end" />
        <input
          className="input mono"
          style={{ width: 160 }}
          value={traceBPath}
          onChange={(e) => setTraceBPath(e.target.value)}
          placeholder="trace B 路径（可选，跨文件）"
        />
        <Button variant="primary" size="sm" onClick={() => void run()} disabled={busy}>
          {busy ? '比较中…' : '比较'}
        </Button>
        {rows && (
          <>
            <span className="cat-tag cat-accent">+{counts.added}</span>
            <span className="cat-tag cat-danger">-{counts.removed}</span>
            <span className="cat-tag cat-warning">~{counts.changed}</span>
            <label className="diff-toggle">
              <input type="checkbox" checked={showSame} onChange={(e) => setShowSame(e.target.checked)} /> 显示相同
            </label>
          </>
        )}
      </div>
      <div className="list-scroll">
        {error ? (
          <div className="empty-state">{error}</div>
        ) : !rows ? (
          <div className="empty-state">输入 Region A / Region B 的指令区间 [start, end)，点击"比较"对比两段执行的寄存器/内存差异</div>
        ) : (
          <table className="data-table">
            <thead><tr><th style={{ width: 60 }}>Inst</th><th style={{ width: 40 }}></th><th>Trace A (left)</th><th>Trace B (right)</th><th style={{ width: 160 }}>Note</th></tr></thead>
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
        )}
      </div>
    </div>
  );
}
