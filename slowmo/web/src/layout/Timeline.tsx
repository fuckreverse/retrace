import { useCallback, useEffect, useRef, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { WindowStat } from '@/types/tenet';

interface HoverInfo {
  x: number;
  instId: number;
  instCount?: number;
  bookmark: boolean;
}

/** 执行密度 + 污点覆盖 + 当前游标的时间线泳道 */
export function Timeline() {
  const ref = useRef<HTMLCanvasElement>(null);
  const total = useTraceStore((s) => s.totalInst);
  const cur = useTraceStore((s) => s.currentInst);
  const bookmarks = useTraceStore((s) => s.bookmarks);
  const taintFwd = useTraceStore((s) => s.taintForward);
  const searchResults = useTraceStore((s) => s.searchResults);
  const viewportStart = useTraceStore((s) => s.viewportStart);
  const viewportEnd = useTraceStore((s) => s.viewportEnd);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const [windows, setWindows] = useState<WindowStat[]>([]);
  const [hover, setHover] = useState<HoverInfo | null>(null);
  const dragging = useRef(false);
  const pendingInst = useRef<number | null>(null);
  const raf = useRef<number | null>(null);
  const previousCursor = useRef('');
  const previousUserSelect = useRef('');

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
        const rawDensity = win ? win.inst_count / maxCount : 0;
        const density = Math.pow(rawDensity, 0.5);
        const alpha = 0.12 + density * 0.5;
        ctx.fillStyle = `rgba(76, 141, 255, ${alpha})`;
        ctx.fillRect(x, h * 0.15, 1.2, h * 0.5);
      }
    }

    // Instructions 面板当前可视区间
    if (viewportEnd > viewportStart && total > 0) {
      const vx1 = (viewportStart / total) * w;
      const vx2 = (viewportEnd / total) * w;
      const viewportWidth = Math.max(1, vx2 - vx1);
      ctx.fillStyle = 'rgba(255, 255, 255, 0.08)';
      ctx.fillRect(vx1, 0, viewportWidth, h);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.35)';
      ctx.lineWidth = 1;
      ctx.strokeRect(vx1 + 0.5, 0.5, viewportWidth - 1, h - 1);
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

    // Hover 游标（淡色虚线，当前游标仍绘制在它上方）
    if (hover) {
      ctx.save();
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.4)';
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(hover.x, 0);
      ctx.lineTo(hover.x, h);
      ctx.stroke();
      ctx.restore();
    }

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
  }, [total, cur, bookmarks, taintFwd, searchResults, viewportStart, viewportEnd, windows, hover]);

  const instAtClientX = useCallback((clientX: number) => {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect || rect.width <= 0 || total <= 0) return null;
    const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    return Math.round(ratio * Math.max(0, total - 1));
  }, [total]);

  const flushScrub = useCallback(() => {
    raf.current = null;
    const instId = pendingInst.current;
    pendingInst.current = null;
    if (instId !== null) navigateTo(instId, false);
  }, [navigateTo]);

  const queueScrub = useCallback((clientX: number) => {
    const instId = instAtClientX(clientX);
    if (instId === null) return;
    pendingInst.current = instId;
    if (raf.current === null) raf.current = requestAnimationFrame(flushScrub);
  }, [flushScrub, instAtClientX]);

  const stopScrub = useCallback((event?: PointerEvent) => {
    if (!dragging.current) return;
    if (event) {
      const instId = instAtClientX(event.clientX);
      if (instId !== null) pendingInst.current = instId;
    }
    dragging.current = false;
    document.body.style.cursor = previousCursor.current;
    document.body.style.userSelect = previousUserSelect.current;
    if (raf.current !== null) {
      cancelAnimationFrame(raf.current);
      raf.current = null;
    }
    const finalInst = pendingInst.current;
    pendingInst.current = null;
    // 拖动期间不污染导航历史；释放时仅提交一个最终历史节点。
    if (finalInst !== null) navigateTo(finalInst);
  }, [instAtClientX, navigateTo]);

  useEffect(() => {
    const onPointerMove = (event: PointerEvent) => {
      if (dragging.current) queueScrub(event.clientX);
    };
    const onPointerUp = (event: PointerEvent) => stopScrub(event);
    const onPointerCancel = (event: PointerEvent) => stopScrub(event);
    document.addEventListener('pointermove', onPointerMove);
    document.addEventListener('pointerup', onPointerUp);
    document.addEventListener('pointercancel', onPointerCancel);
    return () => {
      document.removeEventListener('pointermove', onPointerMove);
      document.removeEventListener('pointerup', onPointerUp);
      document.removeEventListener('pointercancel', onPointerCancel);
      stopScrub();
      if (raf.current !== null) cancelAnimationFrame(raf.current);
    };
  }, [queueScrub, stopScrub]);

  const onPointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0 || total <= 0) return;
    event.preventDefault();
    dragging.current = true;
    setHover(null);
    previousCursor.current = document.body.style.cursor;
    previousUserSelect.current = document.body.style.userSelect;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    queueScrub(event.clientX);
  };

  const onPointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    if (dragging.current || total <= 0) return;
    const canvas = ref.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const instId = instAtClientX(event.clientX);
    if (instId === null) return;
    const x = Math.max(0, Math.min(rect.width, event.clientX - rect.left));
    const windowStat = windows.find(
      (win) => instId >= win.window_start && instId <= win.window_end,
    );
    const bookmark = [...bookmarks].some(
      (id) => Math.abs((id / Math.max(1, total)) * rect.width - x) <= 3,
    );
    setHover({ x, instId, instCount: windowStat?.inst_count, bookmark });
  };

  return (
    <div
      className="timeline"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerLeave={() => { if (!dragging.current) setHover(null); }}
    >
      <canvas ref={ref} />
      {hover && (
        <div className="timeline-tooltip" style={{ left: hover.x }}>
          <span>inst_id: {hover.instId}</span>
          {hover.instCount !== undefined && <span>inst_count: {hover.instCount}</span>}
          {hover.bookmark && <span>Bookmark</span>}
        </div>
      )}
    </div>
  );
}
