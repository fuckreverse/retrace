/**
 * Threads 面板 —— 多线程 trace 的线程概要与指令视图过滤。
 *
 * - 每行一个线程：id、首末指令、指令数、切换次数。
 * - 勾选/点击行 → 调用 thread_filter MCP 工具（后端 Roaring bitmap →
 *   游程编码区间并集）→ traceStore.threadFilterRanges → Instructions
 *   面板据此隐藏非选中线程的指令行。
 * - 顶部 Chip 显示过滤状态；"All" 恢复全量视图。
 */
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { ThreadSummary } from '@/types/tenet';
import { Button } from '@/components/ui';
import './lists.css';

export function ThreadsPanel() {
  const [threads, setThreads] = useState<ThreadSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const setThreadFilter = useTraceStore((s) => s.setThreadFilter);
  const clearThreadFilter = useTraceStore((s) => s.clearThreadFilter);
  const filterIds = useTraceStore((s) => s.threadFilterIds);
  const filterCount = useTraceStore((s) => s.threadFilterCount);

  useEffect(() => {
    api.threads().then((r) => setThreads(r.threads));
  }, []);

  const toggle = async (tid: number) => {
    const next = filterIds.includes(tid)
      ? filterIds.filter((t) => t !== tid)
      : [...filterIds, tid];
    if (next.length === 0) {
      clearThreadFilter();
      return;
    }
    setBusy(true);
    try {
      const r = await api.threadFilter(next);
      const ranges = r.is_filtered && r.filtered_ranges ? r.filtered_ranges : [];
      const count = r.filtered_count ?? 0;
      setThreadFilter(next, ranges, count);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">
          {threads.length} threads
          {filterIds.length > 0 && ` · filtered ${filterCount} insts`}
        </span>
        {filterIds.length > 0 && (
          <Button size="sm" variant="ghost" onClick={() => clearThreadFilter()} style={{ marginLeft: 'auto' }}>
            显示全部
          </Button>
        )}
        {busy && <span className="dim mono" style={{ marginLeft: 'auto' }}>过滤中…</span>}
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 28 }}>✓</th>
              <th style={{ width: 90 }}>Thread</th>
              <th style={{ width: 70, textAlign: 'right' }}>First</th>
              <th style={{ width: 70, textAlign: 'right' }}>Last</th>
              <th style={{ width: 80, textAlign: 'right' }}>Insts</th>
              <th style={{ width: 70, textAlign: 'right' }}>Switches</th>
            </tr>
          </thead>
          <tbody>
            {threads.map((t) => {
              const selected = filterIds.includes(t.thread_id);
              return (
                <tr
                  key={t.thread_id}
                  className={clsx(selected && 'row-selected')}
                  onClick={() => void toggle(t.thread_id)}
                >
                  <td className="mono">{selected ? '●' : '○'}</td>
                  <td className="mono link">#{t.thread_id}</td>
                  <td className="mono num dim" onClick={(e) => { e.stopPropagation(); navigateTo(t.first_seen_inst); }}>#{t.first_seen_inst}</td>
                  <td className="mono num dim" onClick={(e) => { e.stopPropagation(); navigateTo(t.last_seen_inst); }}>#{t.last_seen_inst}</td>
                  <td className="mono num">{t.instructions}</td>
                  <td className="mono num dim">{t.switch_in_count}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Cross-Thread Dataflow ---------- */

/**
 * XThread Dataflow 面板 —— 共享内存跨线程交接检测。
 * 通道按地址聚合（hand-off 次数降序）；点击 reader_inst 跳转。
 */
export function XThreadDataflowPanel() {
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.crossThreadDataflow>> | null>(null);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => {
    api.crossThreadDataflow().then(setResult);
  }, []);

  if (!result) {
    return (
      <div className="list-panel">
        <div className="list-toolbar"><span className="list-count">computing…</span></div>
      </div>
    );
  }

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">
          {result.total_hand_offs} hand-offs · {result.total_channels} channels · {result.thread_pair_count} pairs
        </span>
      </div>
      <div className="list-scroll">
        {result.channels.length === 0 && (
          <div className="empty-hint" style={{ padding: 12 }}>no cross-thread hand-offs detected</div>
        )}
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 130 }}>Addr</th>
              <th style={{ width: 90 }}>Producer</th>
              <th style={{ width: 90 }}>Consumer</th>
              <th style={{ width: 70, textAlign: 'right' }}>Hand-offs</th>
              <th>Edges (writer → reader)</th>
            </tr>
          </thead>
          <tbody>
            {result.channels.map((c, i) => (
              <tr key={`${c.addr}-${i}`}>
                <td className="mono dim">{c.addr}</td>
                <td className="mono num dim">#{c.from_thread}</td>
                <td className="mono num dim">#{c.to_thread}</td>
                <td className="mono num">{c.hand_offs}</td>
                <td>
                  {c.edges.map((e, k) => (
                    <span key={k}>
                      {k > 0 && ', '}
                      <span className="mono link" onClick={() => navigateTo(e.writer_inst)}>#{e.writer_inst}</span>
                      <span className="dim"> → </span>
                      <span className="mono link" onClick={() => navigateTo(e.reader_inst)}>#{e.reader_inst}</span>
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
