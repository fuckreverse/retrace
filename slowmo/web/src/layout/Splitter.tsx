/**
 * 通用可拖拽分割条。
 * - direction="vertical"：竖直分割条，左右拖拽调整宽度（用于侧栏）
 * - direction="horizontal"：水平分割条，上下拖拽调整比例（用于中央上下区域）
 * 拖拽过程中通过 rAF 节流更新，鼠标释放时才调用 onCommit 做持久化，
 * 避免拖拽期间高频写 localStorage/Tauri 配置文件。
 */
import { useCallback, useRef } from 'react';
import { clsx } from 'clsx';

interface SplitterProps {
  direction: 'vertical' | 'horizontal';
  /** 拖拽实时回调（每帧），用于更新视觉宽度/比例 */
  onDrag: (deltaPx: number) => void;
  /** 拖拽结束回调，用于持久化 */
  onCommit?: () => void;
  className?: string;
  title?: string;
}

const KEYBOARD_STEP = 10; // 方向键单次调整的像素步长

export function Splitter({ direction, onDrag, onCommit, className, title }: SplitterProps) {
  const dragging = useRef(false);
  const lastPos = useRef(0);
  const raf = useRef<number | null>(null);
  const pendingDelta = useRef(0);

  const flush = useCallback(() => {
    raf.current = null;
    if (pendingDelta.current !== 0) {
      onDrag(pendingDelta.current);
      pendingDelta.current = 0;
    }
  }, [onDrag]);

  const onPointerMove = useCallback((e: PointerEvent) => {
    if (!dragging.current) return;
    const pos = direction === 'vertical' ? e.clientX : e.clientY;
    const delta = pos - lastPos.current;
    lastPos.current = pos;
    pendingDelta.current += delta;
    if (raf.current === null) raf.current = requestAnimationFrame(flush);
  }, [direction, flush]);

  const stopDrag = useCallback(() => {
    if (!dragging.current) return;
    dragging.current = false;
    document.removeEventListener('pointermove', onPointerMove);
    document.removeEventListener('pointerup', stopDrag);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    if (raf.current !== null) { cancelAnimationFrame(raf.current); flush(); }
    onCommit?.();
  }, [onPointerMove, onCommit, flush]);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragging.current = true;
    lastPos.current = direction === 'vertical' ? e.clientX : e.clientY;
    document.addEventListener('pointermove', onPointerMove);
    document.addEventListener('pointerup', stopDrag);
    document.body.style.cursor = direction === 'vertical' ? 'col-resize' : 'row-resize';
    document.body.style.userSelect = 'none';
  }, [direction, onPointerMove, stopDrag]);

  // 键盘可达性：聚焦后用方向键调整（vertical 用左右键，horizontal 用上下键），
  // 与拖拽共用 onDrag/onCommit，每次按键即视为一次完整的调整+提交。
  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
    const isVertical = direction === 'vertical';
    const decKey = isVertical ? 'ArrowLeft' : 'ArrowUp';
    const incKey = isVertical ? 'ArrowRight' : 'ArrowDown';
    if (e.key !== decKey && e.key !== incKey) return;
    e.preventDefault();
    const delta = e.key === incKey ? KEYBOARD_STEP : -KEYBOARD_STEP;
    onDrag(delta);
    onCommit?.();
  }, [direction, onDrag, onCommit]);

  return (
    <div
      className={clsx('splitter', `splitter-${direction}`, className)}
      onPointerDown={onPointerDown}
      onKeyDown={onKeyDown}
      title={title}
      role="separator"
      aria-orientation={direction === 'vertical' ? 'vertical' : 'horizontal'}
      tabIndex={0}
    >
      <div className="splitter-handle" />
    </div>
  );
}
