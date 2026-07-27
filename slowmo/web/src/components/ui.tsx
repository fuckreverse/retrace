/**
 * 通用 UI 组件库 —— 飞象风格基础件。
 */
import { clsx } from 'clsx';
import type { ReactNode, ButtonHTMLAttributes, InputHTMLAttributes } from 'react';
import * as Tooltip from '@radix-ui/react-tooltip';
import './ui.css';

/* ---------- Panel ---------- */
export function Panel({
  title,
  actions,
  children,
  noPadding,
  className,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  noPadding?: boolean;
  className?: string;
}) {
  return (
    <div className={clsx('panel', className)}>
      {title !== undefined && (
        <div className="panel-header">
          <span className="panel-title">{title}</span>
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      <div className={clsx('panel-body', noPadding && 'no-pad')}>{children}</div>
    </div>
  );
}

/* ---------- Button ---------- */
interface BtnProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'ghost' | 'primary' | 'danger';
  size?: 'sm' | 'md';
  active?: boolean;
}
export function Button({ variant = 'default', size = 'md', active, className, ...rest }: BtnProps) {
  return (
    <button
      className={clsx('btn', `btn-${variant}`, `btn-${size}`, active && 'btn-active', className)}
      {...rest}
    />
  );
}

/* ---------- IconButton ---------- */
export function IconButton({
  children,
  title,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { title?: string }) {
  const btn = (
    <button
      className={clsx('icon-btn', className)}
      title={title}
      aria-label={title}
      {...rest}
    >
      {children}
    </button>
  );
  if (!title) return btn;
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>{btn}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content className="tooltip" sideOffset={6}>
          {title}
          <Tooltip.Arrow className="tooltip-arrow" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

/* ---------- Input ---------- */
export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={clsx('input', className)} {...rest} />;
}

/* ---------- Badge ---------- */
export function Badge({
  children,
  tone = 'default',
}: {
  children: ReactNode;
  tone?: 'default' | 'accent' | 'success' | 'warning' | 'danger';
}) {
  return <span className={clsx('badge', `badge-${tone}`)}>{children}</span>;
}

/* ---------- Chip 过滤按钮 ---------- */
export function Chip({
  children,
  active,
  onClick,
}: {
  children: ReactNode;
  active?: boolean;
  onClick?: () => void;
}) {
  return (
    <button className={clsx('chip', active && 'chip-active')} onClick={onClick}>
      {children}
    </button>
  );
}

/* ---------- Empty ---------- */
export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}

/* ---------- ConfidenceBar ---------- */
export function ConfidenceBar({ value }: { value: number }) {
  const tone = value >= 0.8 ? 'success' : value >= 0.5 ? 'warning' : 'danger';
  return (
    <div className="conf-bar">
      <div className={clsx('conf-fill', `conf-${tone}`)} style={{ width: `${value * 100}%` }} />
      <span className="conf-label">{(value * 100).toFixed(0)}%</span>
    </div>
  );
}
