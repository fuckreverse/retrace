/**
 * CFG 面板 —— 可交互控制流图(SVG)，块热力着色 + 平移缩放。
 */
import { useEffect, useRef, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { CfgResult } from '@/types/tenet';
import { Button, IconButton } from '@/components/ui';
import { Icon } from '@/components/icons';
import './cfg.css';

function heatColor(exec: number, max: number): string {
  const t = max > 0 ? Math.log(exec + 1) / Math.log(max + 1) : 0;
  // 蓝 -> 绿 -> 红
  if (t < 0.5) {
    const k = t / 0.5;
    return `rgb(${Math.round(76 + k * (63 - 76))}, ${Math.round(141 + k * (185 - 141))}, ${Math.round(255 + k * (80 - 255))})`;
  }
  const k = (t - 0.5) / 0.5;
  return `rgb(${Math.round(63 + k * (248 - 63))}, ${Math.round(185 + k * (81 - 185))}, ${Math.round(80 + k * (73 - 80))})`;
}

export function CfgPanel() {
  const [cfg, setCfg] = useState<CfgResult | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 20, y: 10 });
  const dragRef = useRef<{ x: number; y: number } | null>(null);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => {
    api.cfg().then(setCfg);
  }, []);

  const maxExec = cfg ? Math.max(1, ...cfg.blocks.map((b) => b.executions ?? 1)) : 1;
  const blockMap = new Map(cfg?.blocks.map((b) => [b.pc, b]));

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    setZoom((z) => Math.min(4, Math.max(0.2, z - e.deltaY * 0.001)));
  };
  const onDown = (e: React.MouseEvent) => { dragRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMove = (e: React.MouseEvent) => {
    if (dragRef.current) setPan({ x: e.clientX - dragRef.current.x, y: e.clientY - dragRef.current.y });
  };
  const onUp = () => { dragRef.current = null; };

  return (
    <div className="cfg-panel">
      <div className="cfg-toolbar">
        <Button size="sm" variant="ghost">Run CFG Layout</Button>
        <div className="toolbar-sep" />
        <IconButton title="放大" onClick={() => setZoom((z) => Math.min(4, z + 0.2))}><Icon.Forward /></IconButton>
        <span className="dim" style={{ width: 46, textAlign: 'center' }}>{(zoom * 100).toFixed(0)}%</span>
        <IconButton title="缩小" onClick={() => setZoom((z) => Math.max(0.2, z - 0.2))}><Icon.Back /></IconButton>
        <Button size="sm" variant="ghost" onClick={() => { setZoom(1); setPan({ x: 20, y: 10 }); }}>Reset View</Button>
        <span className="dim" style={{ marginLeft: 'auto' }}>
          {cfg ? `${cfg.blocks.length} blocks · ${cfg.edges.length} edges` : ''}
        </span>
      </div>
      <div
        className="cfg-canvas"
        onWheel={onWheel}
        onMouseDown={onDown}
        onMouseMove={onMove}
        onMouseUp={onUp}
        onMouseLeave={onUp}
      >
        <svg width="100%" height="100%">
          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {/* edges */}
            {cfg?.edges.map((e, i) => {
              const a = blockMap.get(e.from);
              const b = blockMap.get(e.to);
              if (!a || !b) return null;
              const x1 = a.x + a.width / 2;
              const y1 = a.y + a.height;
              const x2 = b.x + b.width / 2;
              const y2 = b.y;
              const isBack = b.y <= a.y;
              const midY = (y1 + y2) / 2;
              const color = e.kind === 'fallthrough' ? 'var(--hl-read)' : 'var(--hl-branch)';
              const path = isBack
                ? `M${x1},${y1} C${x1 + 120},${y1 + 40} ${x2 + 120},${y2 - 40} ${x2},${y2}`
                : `M${x1},${y1} C${x1},${midY} ${x2},${midY} ${x2},${y2}`;
              return (
                <g key={i}>
                  <path d={path} fill="none" stroke={color} strokeWidth={1 + Math.min(3, (e.taken_count ?? 1) / 100)} opacity={0.7} markerEnd="url(#arrow)" />
                </g>
              );
            })}
            <defs>
              <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill="var(--text-tertiary)" />
              </marker>
            </defs>
            {/* blocks */}
            {cfg?.blocks.map((b) => {
              const color = heatColor(b.executions ?? 1, maxExec);
              const isSel = selected === b.pc;
              return (
                <g
                  key={b.pc}
                  transform={`translate(${b.x},${b.y})`}
                  className="cfg-block"
                  onClick={(ev) => { ev.stopPropagation(); setSelected(b.pc); navigateTo(0); }}
                >
                  <rect width={b.width} height={b.height} rx={8} className="cfg-block-rect" stroke={isSel ? 'var(--accent)' : 'var(--border-strong)'} strokeWidth={isSel ? 2 : 1} />
                  <rect width={b.width} height={22} rx={8} fill={color} opacity={0.25} />
                  <rect y={16} width={b.width} height={6} fill="var(--bg-surface)" />
                  <text x={10} y={15} className="cfg-block-head mono" fill={color}>{b.pc}</text>
                  <text x={b.width - 10} y={15} textAnchor="end" className="cfg-block-exec mono">{b.executions}×</text>
                  {b.disasm?.slice(0, 3).map((line, li) => (
                    <text key={li} x={10} y={38 + li * 16} className="cfg-block-line mono">
                      {line.length > 30 ? line.slice(0, 30) + '…' : line}
                    </text>
                  ))}
                </g>
              );
            })}
          </g>
        </svg>
      </div>
    </div>
  );
}
