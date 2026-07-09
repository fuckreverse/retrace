/**
 * tenet C++ 后端（sidecar）日志的前端聚合层。
 *
 * 背景：`tenet` 后端作为 Tauri sidecar 子进程运行（见 src-tauri/src/lib.rs
 * 的 `open_trace`），其 stdout/stderr 由 Rust 侧逐行转发为 `backend-log`
 * 事件。此前前端完全没有消费这个事件——`LogPanel` 只是展示 mock 数据，
 * 真实后端日志无从查看（打包 release 版本下 Rust 侧甚至不落盘）。
 *
 * 本模块在应用启动时（模块加载即执行，不依赖任何组件挂载）建立唯一一路
 * `backend-log` 监听，维护一个有上限的环形缓冲区，并支持简单的订阅/推送，
 * 这样：
 *   - 即使 "Output (Log)" 面板从未打开，日志也不会丢失（只要不超过缓冲上限）；
 *   - 面板打开时可以立刻拿到历史缓冲 + 后续实时追加。
 *
 * 浏览器（非 Tauri）环境下 `isTauri()` 为 false，直接 no-op，不加载任何
 * Tauri API —— 与 useNativeMenu 等模块的处理方式一致。
 */
import { isTauri } from '@/lib/env';
import type { LogEntry } from '@/types/tenet';

/** 环形缓冲区上限：超出后丢弃最旧的记录，避免长时间运行内存无限增长。 */
const MAX_LINES = 5000;

/** Rust 侧 `BackendLogLine` 的 JSON 载荷结构（见 src-tauri/src/lib.rs）。 */
interface BackendLogPayload {
  trace_path: string;
  level: string;
  message: string;
}

let buffer: LogEntry[] = [];
let started = false;
const listeners = new Set<(rows: LogEntry[]) => void>();

function notify() {
  const snapshot = buffer.slice();
  for (const fn of listeners) fn(snapshot);
}

function normalizeLevel(level: string): LogEntry['level'] {
  switch (level) {
    case 'error':
    case 'warn':
    case 'debug':
      return level;
    default:
      return 'info';
  }
}

function push(payload: BackendLogPayload) {
  const now = new Date();
  buffer.push({
    ts: now.toISOString().substring(11, 23),
    level: normalizeLevel(payload.level),
    source: 'tenet-backend',
    message: payload.message,
  });
  if (buffer.length > MAX_LINES) {
    buffer.splice(0, buffer.length - MAX_LINES);
  }
  notify();
}

/**
 * 启动全局 `backend-log` 监听。幂等——多次调用只会注册一次。
 * 应在应用入口（App.tsx）尽早调用，确保 sidecar 启动阶段（index 构建等）
 * 的日志也能被捕获，而不是等到用户打开 Log 面板才开始监听。
 */
export function startBackendLogCapture(): void {
  if (started || !isTauri()) return;
  started = true;
  import('@tauri-apps/api/event')
    .then(({ listen }) => {
      listen<BackendLogPayload>('backend-log', (event) => push(event.payload));
    })
    .catch(() => {
      // Tauri event API 不可用时静默降级——Log 面板会退回空列表。
    });
}

/** 获取当前缓冲区快照（供 LogPanel 初次渲染使用）。 */
export function getBackendLogSnapshot(): LogEntry[] {
  return buffer.slice();
}

/** 订阅后续更新；返回取消订阅函数。 */
export function subscribeBackendLog(fn: (rows: LogEntry[]) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** 清空缓冲区（例如切换 trace 时可选调用）。 */
export function clearBackendLog(): void {
  buffer = [];
  notify();
}
