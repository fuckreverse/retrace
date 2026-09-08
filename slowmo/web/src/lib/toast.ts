/**
 * 轻量全局 toast 通知 —— 补齐"事件发生时用户无感知"的缺口：
 * pass 运行失败、后端连接降级等事件以前只在对应面板内可见，
 * 用户停在别的面板时完全无感。本模块提供应用级瞬时通知：
 *   - showToast(kind, message)：任意组件/模块直接调用
 *   - subscribeToasts(fn)：ToastHost 订阅渲染（订阅时立即收到当前快照）
 *
 * 通知按 kind 自动过期（error 留存更久），点击可立即关闭。
 * 不引入第三方库：就是一个带过期语义的环形 Map + 监听器集合。
 */
export type ToastKind = 'info' | 'success' | 'error';

export interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
  createdAt: number;
}

/** 各 kind 的自动消失时长（ms） */
const TTL_MS: Record<ToastKind, number> = {
  info: 4000,
  success: 4000,
  error: 8000,
};

let nextId = 1;
const items = new Map<number, ToastItem>();
const listeners = new Set<(items: ToastItem[]) => void>();
const timers = new Map<number, number>();

function notify(): void {
  const snapshot = [...items.values()];
  for (const fn of listeners) fn(snapshot);
}

/** 弹出一条 toast；同一会话内不合并（短时效通知，重复代价可接受）。 */
export function showToast(kind: ToastKind, message: string): void {
  const id = nextId++;
  items.set(id, { id, kind, message, createdAt: Date.now() });
  // 上限保护：极端刷屏时丢弃最旧的（连同其定时器）
  if (items.size > 5) {
    const oldest = items.keys().next().value;
    if (oldest !== undefined) dismissToast(oldest);
  }
  notify();
  const timer = window.setTimeout(() => dismissToast(id), TTL_MS[kind]);
  timers.set(id, timer);
}

/** 立即关闭指定 toast（点击 / 程序调用）。 */
export function dismissToast(id: number): void {
  const timer = timers.get(id);
  if (timer !== undefined) {
    window.clearTimeout(timer);
    timers.delete(id);
  }
  if (items.delete(id)) notify();
}

/** 订阅当前 toast 列表；订阅时立即推送一次快照。返回取消订阅函数。 */
export function subscribeToasts(fn: (items: ToastItem[]) => void): () => void {
  listeners.add(fn);
  fn([...items.values()]);
  return () => listeners.delete(fn);
}
