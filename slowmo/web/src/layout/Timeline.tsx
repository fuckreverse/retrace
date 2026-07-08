import { useEffect, useRef } from 'react';
import { useTraceStore } from '@/store/traceStore';

/** 执行密度 + 污点覆盖 + 当前游标的时间线泳道 */
export function Timeline() {
  const ref = useRef<HTMLCanvasElement>(null);
  const total = useTraceStore((s) => s.totalInst);
  const cur = useTraceStore((s) => s.currentInst);
  const bookmarks = useTraceStore((s) => s.bookmarks);
  const taintFwd = useTraceStore((s) => s.taintForward);
  const searchResults = useTraceStore((s) => s.searchResults);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || total <= 0) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    const ctx = canvas.getContext('2d')!;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const cssVar = (n: string) =>
      getComputedStyle(document.documentElement).getPropertyValue(n).trim();

    // 执行密度热力图(伪)
    const bins = Math.min(w, 400);
    const binW = w / bins;
    for (let i = 0; i < bins; i++) {
      const t = i / bins;
      const density = 0.3 + 0.7 * Math.abs(Math.sin(t * 12) * Math.cos(t * 5));
      const alpha = 0.12 + density * 0.35;
      ctx.fillStyle = `rgba(76, 141, 255, ${alpha})`;
      ctx.fillRect(i * binW, h * 0.15, binW + 0.5, h * 0.5);
    }

    // 污点覆盖(绿色标记)
    ctx.fillStyle = cssVar('--hl-read') || '#3fb950';
    taintFwd.forEach((id) => {
      const x = (id / total) * w;
      ctx.fillRect(x, h * 0.68, 1.5, h * 0.14);
    });

    // 搜索命中(金色)
    ctx.fillStyle = cssVar('--warning') || '#d29922';
    searchResults.forEach((id) => {
      const x = (id / total) * w;
      ctx.fillRect(x, h * 0.84, 1.5, h * 0.12);
    });

    // 书签(青)
    ctx.fillStyle = cssVar('--accent') || '#4c8dff';
    bookmarks.forEach((id) => {
      const x = (id / total) * w;
      ctx.beginPath();
      ctx.moveTo(x, 2);
      ctx.lineTo(x - 3, 8);
      ctx.lineTo(x + 3, 8);
      ctx.closePath();
      ctx.fill();
    });

    // 当前游标
    const cx = (cur / total) * w;
    ctx.strokeStyle = '#fff';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(cx, 0);
    ctx.lineTo(cx, h);
    ctx.stroke();
    ctx.fillStyle = '#fff';
    ctx.beginPath();
    ctx.arc(cx, h / 2, 3, 0, Math.PI * 2);
    ctx.fill();
  }, [total, cur, bookmarks, taintFwd, searchResults]);

  const onClick = (e: React.MouseEvent) => {
    const rect = ref.current!.getBoundingClientRect();
    const t = (e.clientX - rect.left) / rect.width;
    navigateTo(Math.round(t * total));
  };

  return (
    <div className="timeline" onClick={onClick}>
      <canvas ref={ref} />
    </div>
  );
}
