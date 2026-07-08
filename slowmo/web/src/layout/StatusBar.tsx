import { useTraceStore } from '@/store/traceStore';

export function StatusBar() {
  const cur = useTraceStore((s) => s.currentInst);
  const total = useTraceStore((s) => s.totalInst);
  const info = useTraceStore((s) => s.info);
  const source = useTraceStore((s) => s.dataSource);
  const bookmarks = useTraceStore((s) => s.bookmarks);
  const searchResults = useTraceStore((s) => s.searchResults);

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
        {source === 'live' ? '● 已连接 TenetService' : '● 使用 Mock 数据(后端未连接)'}
      </span>
    </div>
  );
}
