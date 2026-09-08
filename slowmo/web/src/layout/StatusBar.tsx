import { useEffect, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { subscribeDataSource, type DataSource } from '@/api/service';

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
