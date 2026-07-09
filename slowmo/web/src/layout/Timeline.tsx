import { useEffect, useRef, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { WindowStat } from '@/types/tenet';

/** 执行密度 + 污点覆盖 + 当前游标的时间线泳道 */
export function Timeline() {
  const ref = useRef<HTMLCanvasElement>(null);
  const total = useTraceStore((s) => s.totalInst);
  const cur = useTraceStore((s) => s.currentInst);
  const bookmarks = useTraceStore((s) => s.bookmarks);
  const taintFwd = useTraceStore((s) => s.taintForward);
  const searchResults = useTraceStore((s) => s.searchResults);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const [windows, setWindows] = useState<WindowStat[]>([]);

  // 执行密度真实数据：一次性拉取 window_stats（后端 pass，trace 加载后才有意义）
  useEffect(() => {
    if (total <= 0) return;
    let cancelled = false;
    api.windowStats().then((rows) => { if (!cancelled) setWindows(rows); });
    return () => { cancelled = true; };
  }, [total]);

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

    // 执行密度热力图：按 window_stats 的 inst_count（指令密度）映射像素列，
    // 每个像素列取落在其静态区间内的窗口密度最大值（避免窄窗口被平均掉）
    if (windows.length > 0) {
      const maxCount = Math.max(1, ...windows.map((win) => win.inst_count));
      let wi = 0;
      const pixelW = Math.max(1, Math.round(w));
      for (let x = 0; x < pixelW; x++) {
        const instAtX = (x / pixelW) * total;
        while (wi < windows.length - 1 && windows[wi].window_end < instAtX) wi++;
        const win = windows[wi];
        const density = win ? win.inst_count / maxCount : 0;
        const alpha = 0.12 + density * 0.5;
        ctx.fillStyle = `rgba(76, 141, 255, ${alpha})`;
        ctx.fillRect(x, h * 0.15, 1.2, h * 0.5);
      }
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
  }, [total, cur, bookmarks, taintFwd, searchResults, windows]);

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
