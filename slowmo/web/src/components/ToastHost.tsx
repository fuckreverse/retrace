/**
 * 全局 toast 通知宿主 —— 挂载在 Shell（主窗口）右上角/右下角，
 * 消费 lib/toast.ts 的事件流。点击任意 toast 立即关闭。
 */
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import { dismissToast, subscribeToasts, type ToastItem } from '@/lib/toast';
import './toast.css';

export function ToastHost() {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  useEffect(() => subscribeToasts(setToasts), []);

  if (toasts.length === 0) return null;

  return (
    <div className="toast-host">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={clsx('toast', `toast-${t.kind}`)}
          onClick={() => dismissToast(t.id)}
          role="status"
        >
          <span className="toast-icon">
            {t.kind === 'error' ? '\u2715' : t.kind === 'success' ? '\u2713' : '\u2139'}
          </span>
          <span className="toast-msg">{t.message}</span>
        </div>
      ))}
    </div>
  );
}
