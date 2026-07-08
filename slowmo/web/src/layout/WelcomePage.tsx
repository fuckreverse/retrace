/**
 * Welcome / Startup 页面 — 应用启动且无 trace 加载时显示。
 * 左侧拖放区可点击打开文件或直接拖入 .bin，右侧显示最近打开的 trace 列表。
 */
import { useCallback, useEffect, useState, type DragEvent } from 'react';
import { useAppStore, type RecentEntry } from '@/store/appStore';
import { isTauri } from '@/lib/env';
import { PassPresetDialog } from './PassPresetDialog';
import './welcome.css';

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Format instruction count: 1234567 -> "1.23M" */
function fmtCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

/** Format epoch ms -> relative time string */
function fmtTime(epoch: number): string {
  const diff = Date.now() - epoch;
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(epoch).toLocaleDateString();
}

/** Truncate a file path from the left to keep the filename visible */
function truncatePath(path: string, maxLen = 40): string {
  if (path.length <= maxLen) return path;
  const parts = path.split('/');
  // Keep filename and walk backwards
  let result = parts[parts.length - 1];
  for (let i = parts.length - 2; i >= 0; i--) {
    const candidate = parts[i] + '/' + result;
    if (candidate.length > maxLen - 4) {
      return '\u2026/' + result;
    }
    result = candidate;
  }
  return result;
}

/* ------------------------------------------------------------------ */
/*  Inline SVG icons                                                   */
/* ------------------------------------------------------------------ */

function FolderOpenIcon() {
  return (
    <svg className="welcome-drop-icon" viewBox="0 0 48 48" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 38V14a2 2 0 0 1 2-2h10l4 4h18a2 2 0 0 1 2 2v4" />
      <path d="M6 38l4-16h34l-4 16H6z" />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg className="welcome-trace-lock" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="7" width="10" height="7" rx="1.5" />
      <path d="M5 7V5a3 3 0 0 1 6 0v2" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export function WelcomePage() {
  const recentFiles = useAppStore((s) => s.recentFiles);
  const openTraces = useAppStore((s) => s.openTraces);
  const error = useAppStore((s) => s.error);
  const loadRecentFiles = useAppStore((s) => s.loadRecentFiles);
  const requestOpenTrace = useAppStore((s) => s.requestOpenTrace);
  const setError = useAppStore((s) => s.setError);

  const [dragging, setDragging] = useState(false);

  // Load recent files on mount
  useEffect(() => {
    loadRecentFiles();
  }, [loadRecentFiles]);

  // ---- Drag & Drop ----
  const onDragOver = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(true);
  }, []);

  const onDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(false);
  }, []);

  const onDrop = useCallback(
    async (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragging(false);

      // In Tauri: files come from the data transfer
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        const file = files[0];
        if (file.name.endsWith('.bin')) {
          // In Tauri, the file path is available via webkitRelativePath or name
          // For Tauri drag-drop, we get the path from the file
          const path = (file as File & { path?: string }).path ?? file.name;
          requestOpenTrace(path);
        } else {
          setError('Please drop a .bin trace file');
        }
      }
    },
    [requestOpenTrace, setError],
  );

  // ---- Open file dialog (Tauri only) ----
  const onClickOpen = useCallback(async () => {
    if (!isTauri()) {
      setError('File picker is only available in the Tauri app. Please run tenet with a trace file.');
      return;
    }
    try {
      // Use Tauri invoke to call the dialog plugin — avoids needing
      // @tauri-apps/plugin-dialog JS package as a dependency.
      const { invoke } = await import('@tauri-apps/api/core');
      const result = await invoke<string | null>('plugin:dialog|open', {
        title: 'Open Trace File',
        filters: [{ name: 'Trace Files', extensions: ['bin'] }],
        multiple: false,
      });
      if (result) {
        requestOpenTrace(result);
      }
    } catch (e) {
      setError(`Failed to open file dialog: ${e}`);
    }
  }, [requestOpenTrace, setError]);

  // ---- Click a recent trace ----
  const onClickRecent = useCallback(
    (entry: RecentEntry) => {
      if (openTraces.has(entry.path)) return;
      requestOpenTrace(entry.path);
    },
    [openTraces, requestOpenTrace],
  );

  // Sort recent files by last_opened desc
  const sortedRecent = [...recentFiles].sort((a, b) => b.last_opened - a.last_opened);

  return (
    <div className="welcome">
      {/* Drag area (also functions as titlebar for window dragging) */}
      <div className="welcome-titlebar" />

      <div className="welcome-body">
        {/* Branding */}
        <div className="welcome-brand">
          <div className="welcome-logo">tenet</div>
          <div className="welcome-subtitle">Trace Analyzer</div>
        </div>

        {/* Main content: drop zone + recent traces */}
        <div className="welcome-content">
          {/* Drop zone */}
          <div
            className={`welcome-drop-zone${dragging ? ' dragging' : ''}`}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            onClick={onClickOpen}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onClickOpen(); }}
          >
            <FolderOpenIcon />
            <button className="welcome-open-btn" type="button" tabIndex={-1}>
              Open Trace\u2026
            </button>
            <span className="welcome-drop-hint">or drag &amp; drop a .bin file here</span>
          </div>

          {/* Recent traces */}
          <div className="welcome-recent">
            <div className="welcome-recent-header">Recent Traces</div>
            <div className="welcome-recent-list">
              {sortedRecent.length === 0 ? (
                <div className="welcome-recent-empty">No recent traces</div>
              ) : (
                sortedRecent.map((entry) => {
                  const isLocked = openTraces.has(entry.path);
                  return (
                    <button
                      key={entry.path}
                      className={`welcome-trace-item${isLocked ? ' locked' : ''}`}
                      onClick={() => onClickRecent(entry)}
                      title={isLocked ? 'This trace is already open' : entry.path}
                      type="button"
                    >
                      <div className="welcome-trace-info">
                        <span className="welcome-trace-module">{entry.module_name}</span>
                        <span className="welcome-trace-path">{truncatePath(entry.path)}</span>
                      </div>
                      <div className="welcome-trace-meta">
                        <span>{fmtCount(entry.inst_count)} insts</span>
                        <span>{fmtTime(entry.last_opened)}</span>
                        {isLocked && <LockIcon />}
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="welcome-footer">v0.1.0</div>

      {/* Error toast */}
      {error && (
        <div className="welcome-error">
          <span>{error}</span>
          <button onClick={() => setError(null)} type="button">dismiss</button>
        </div>
      )}

      {/* Pass preset dialog (modal) */}
      <PassPresetDialog />
    </div>
  );
}
