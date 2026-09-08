import { useEffect, useMemo, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { useTaskStore, selectRunningTasks } from '@/store/taskStore';
import { subscribeDataSource, type DataSource } from '@/api/service';
import { selectTab } from '@/lib/tabRouting';

/** 后台任务运行指示器：spinner + 数量 + 聚合进度条，点击跳转 Analysis 面板。 */
function TaskIndicator() {
  const tasks = useTaskStore((s) => s.tasks);
  const running = useMemo(() => selectRunningTasks(tasks), [tasks]);
  const failed = useMemo(() => tasks.filter((t) => t.state === 'failed'), [tasks]);

  if (running.length === 0 && failed.length === 0) return null;

  // 聚合进度：各运行中任务 progress 的平均值（不确定进度的任务按 0 计入，
  // 有总量的后端任务会逐渐拉开差距，显示为整体逼近 100%）。
  const avg = running.length > 0
    ? running.reduce((acc, t) => acc + t.progress, 0) / running.length
    : 0;
  const topTask = running[0];
  const label = running.length > 0
    ? topTask.label || topTask.id
    : '';

  return (
    <button
      className="sb-item sb-tasks"
      title={running.length > 0
        ? `运行中：${running.map((t) => t.label || t.id).join(', ')}（点击查看 Analysis 面板）`
        : '有失败的后台任务（点击查看 Analysis 面板）'}
      onClick={() => selectTab('center-bottom', 'analysis')}
    >
      {running.length > 0 && <span className="sb-spinner" />}
      <span>
        后台任务 <b>{running.length}</b>
        {running.length > 0 && label ? ` · ${label}` : ''}
      </span>
      {running.length > 0 && (
        <span className="sb-task-bar"><span style={{ width: `${Math.round(avg * 100)}%` }} /></span>
      )}
      {failed.length > 0 && (
        <span className="sb-task-failed">✕ {failed.length}</span>
      )}
    </button>
  );
}

export function StatusBar() {
  const cur = useTraceStore((s) => s.currentInst);
  const total = useTraceStore((s) => s.totalInst);
  const info = useTraceStore((s) => s.info);
  const [source, setSource] = useState<DataSource>(useTraceStore.getState().dataSource);
  const bookmarks = useTraceStore((s) => s.bookmarks);
  const searchResults = useTraceStore((s) => s.searchResults);

  // 数据源变化实时联动（live ↔ mock）：降级到 mock 不再静默，
  // 避免用户把 mock 假数据当成真实分析结果。
  useEffect(() => subscribeDataSource(setSource), []);

  return (
    <div className="statusbar">
      <span className="sb-item">arch <b className="mono">{info?.arch ?? '—'}</b></span>
      <span className="sb-item">inst <b className="mono">#{cur}</b> / {total.toLocaleString()}</span>
      <span className="sb-item">书签 <b>{bookmarks.size}</b></span>
      {searchResults.length > 0 && (
        <span className="sb-item">搜索命中 <b>{searchResults.length}</b></span>
      )}
      <TaskIndicator />
      <span className="sb-spacer" />
      <span className="sb-item">
        anchors <b className="mono">{info?.anchor_count ?? 0}</b>
      </span>
      <span className="sb-item">
        {source === 'live' ? '已连接 TenetService' : source === 'mock'
          ? '\u26a0 Mock 数据（后端未连接，展示的不是真实分析结果）'
          : '后端连接中…'}
      </span>
    </div>
  );
}
