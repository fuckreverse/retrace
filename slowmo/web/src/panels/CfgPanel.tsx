/**
 * CFG 面板 —— 可交互控制流图(SVG)，块热力着色 + 平移缩放。
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { CfgBlock, CfgResult } from '@/types/tenet';
import { Button, IconButton, Input } from '@/components/ui';
import { Icon } from '@/components/icons';
import './cfg.css';

const MIN_ZOOM = 0.2;
const MAX_ZOOM = 4;
const VIEW_PADDING = 40;

function heatColor(exec: number, max: number): string {
  const t = max > 0 ? Math.log(exec + 1) / Math.log(max + 1) : 0;
  if (t < 0.5) {
    const k = t / 0.5;
    return `rgb(${Math.round(76 + k * (63 - 76))}, ${Math.round(141 + k * (185 - 141))}, ${Math.round(255 + k * (80 - 255))})`;
  }
  const k = (t - 0.5) / 0.5;
  return `rgb(${Math.round(63 + k * (248 - 63))}, ${Math.round(185 + k * (81 - 185))}, ${Math.round(80 + k * (73 - 80))})`;
}

function address(value: string): bigint | null {
  const match = value.match(/0x[0-9a-f]+/i);
  if (!match) return null;
  try { return BigInt(match[0]); } catch { return null; }
}

function blockForPc(blocks: CfgBlock[], pc: string): CfgBlock | null {
  const target = address(pc);
  if (target == null) return null;

  // disasm 含地址时优先做精确匹配，避免把块间空洞误认为前一个块。
  const exact = blocks.find((block) => block.disasm?.some((line) => address(line) === target));
  if (exact) return exact;

  // 大 CFG 可能省略 disasm；此时以排序后的相邻 block 起始地址作为范围边界。
  const sorted = blocks
    .map((block) => ({ block, start: address(block.pc) }))
    .filter((item): item is { block: CfgBlock; start: bigint } => item.start != null)
    .sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
  for (let i = 0; i < sorted.length; i += 1) {
    const nextStart = sorted[i + 1]?.start;
    if (target >= sorted[i].start && (nextStart == null || target < nextStart)) return sorted[i].block;
  }
  return null;
}

export function CfgPanel() {
  const [cfg, setCfg] = useState<CfgResult | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [currentBlockPc, setCurrentBlockPc] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 20, y: 10 });
  const canvasRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ x: number; y: number } | null>(null);
  const cur = useTraceStore((s) => s.currentInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { void api.cfg().then(setCfg); }, []);

  const blockMap = useMemo(() => new Map(cfg?.blocks.map((b) => [b.pc, b])), [cfg]);
  const matches = useMemo(() => {
    const query = search.trim().toLowerCase();
    return query && cfg ? cfg.blocks.filter((b) => b.pc.toLowerCase().includes(query)) : [];
  }, [cfg, search]);
  const matchingPcs = useMemo(() => new Set(matches.map((b) => b.pc)), [matches]);

  const centerBlock = (block: CfgBlock, targetZoom = zoom) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    setZoom(targetZoom);
    setPan({
      x: canvas.clientWidth / 2 - (block.x + block.width / 2) * targetZoom,
      y: canvas.clientHeight / 2 - (block.y + block.height / 2) * targetZoom,
    });
  };

  const isBlockVisible = (block: CfgBlock) => {
    const canvas = canvasRef.current;
    if (!canvas) return true;
    const left = pan.x + block.x * zoom;
    const top = pan.y + block.y * zoom;
    const right = left + block.width * zoom;
    const bottom = top + block.height * zoom;
    return left >= 0 && top >= 0 && right <= canvas.clientWidth && bottom <= canvas.clientHeight;
  };

  useEffect(() => {
    let cancelled = false;
    void api.disasm(cur, 1).then((result) => {
      if (cancelled) return;
      const block = cfg && result.rows[0] ? blockForPc(cfg.blocks, result.rows[0].pc) : null;
      setCurrentBlockPc(block?.pc ?? null);
      if (block && !isBlockVisible(block)) centerBlock(block);
    });
    return () => { cancelled = true; };
    // pan/zoom intentionally omitted: only a cursor or CFG change should trigger following.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cur, cfg]);

  const fitToScreen = () => {
    const canvas = canvasRef.current;
    if (!canvas || !cfg || cfg.blocks.length === 0) return;
    const minX = Math.min(...cfg.blocks.map((b) => b.x));
    const minY = Math.min(...cfg.blocks.map((b) => b.y));
    const maxX = Math.max(...cfg.blocks.map((b) => b.x + b.width));
    const maxY = Math.max(...cfg.blocks.map((b) => b.y + b.height));
    const width = Math.max(1, maxX - minX);
    const height = Math.max(1, maxY - minY);
    const nextZoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM,
      Math.min((canvas.clientWidth - VIEW_PADDING * 2) / width, (canvas.clientHeight - VIEW_PADDING * 2) / height)));
    setZoom(nextZoom);
    setPan({
      x: (canvas.clientWidth - width * nextZoom) / 2 - minX * nextZoom,
      y: (canvas.clientHeight - height * nextZoom) / 2 - minY * nextZoom,
    });
  };

  const locateSearch = () => { if (matches[0]) centerBlock(matches[0], Math.min(MAX_ZOOM, Math.max(1.2, zoom))); };
  useEffect(() => {
    const query = search.trim().toLowerCase();
    const exact = matches.find((block) => block.pc.toLowerCase() === query);
    if (exact) centerBlock(exact, Math.min(MAX_ZOOM, Math.max(1.2, zoom)));
    // Only a newly entered exact query should trigger automatic location.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, matches]);
  const maxExec = cfg ? Math.max(1, ...cfg.blocks.map((b) => b.executions ?? 1)) : 1;
  const onWheel = (e: React.WheelEvent) => { e.preventDefault(); setZoom((z) => Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, z - e.deltaY * 0.001))); };
  const onDown = (e: React.MouseEvent) => { dragRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMove = (e: React.MouseEvent) => { if (dragRef.current) setPan({ x: e.clientX - dragRef.current.x, y: e.clientY - dragRef.current.y }); };
  const onUp = () => { dragRef.current = null; };
  const gotoBlock = async (pc: string) => { const xref = await api.xref(pc); if (xref.inst_ids.length > 0) navigateTo(xref.inst_ids[0]); };

  return (
    <div className="cfg-panel">
      <div className="cfg-toolbar">
        <Button size="sm" variant="ghost">Run CFG Layout</Button>
        <Input aria-label="搜索块地址" placeholder="Search address…" value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') locateSearch(); }} style={{ width: 150 }} />
        <div className="toolbar-sep" />
        <IconButton title="放大" onClick={() => setZoom((z) => Math.min(MAX_ZOOM, z + 0.2))}><Icon.Forward /></IconButton>
        <span className="dim" style={{ width: 46, textAlign: 'center' }}>{(zoom * 100).toFixed(0)}%</span>
        <IconButton title="缩小" onClick={() => setZoom((z) => Math.max(MIN_ZOOM, z - 0.2))}><Icon.Back /></IconButton>
        <IconButton title="Fit to Screen" onClick={fitToScreen}><Icon.Box /></IconButton>
        <Button size="sm" variant="ghost" onClick={() => { setZoom(1); setPan({ x: 20, y: 10 }); }}>Reset View</Button>
        <span className="dim" style={{ marginLeft: 'auto' }}>{cfg ? `${cfg.blocks.length} blocks · ${cfg.edges.length} edges` : ''}</span>
      </div>
      <div ref={canvasRef} className="cfg-canvas" onWheel={onWheel} onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}>
        <svg width="100%" height="100%">
          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {cfg?.edges.map((e, i) => {
              const a = blockMap.get(e.from), b = blockMap.get(e.to);
              if (!a || !b) return null;
              const x1 = a.x + a.width / 2, y1 = a.y + a.height, x2 = b.x + b.width / 2, y2 = b.y;
              const midY = (y1 + y2) / 2;
              const path = b.y <= a.y ? `M${x1},${y1} C${x1 + 120},${y1 + 40} ${x2 + 120},${y2 - 40} ${x2},${y2}` : `M${x1},${y1} C${x1},${midY} ${x2},${midY} ${x2},${y2}`;
              return <path key={i} d={path} fill="none" stroke={e.kind === 'fallthrough' ? 'var(--hl-read)' : 'var(--hl-branch)'} strokeWidth={1 + Math.min(3, (e.taken_count ?? 1) / 100)} opacity={0.7} markerEnd="url(#arrow)" />;
            })}
            <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--text-tertiary)" /></marker></defs>
            {cfg?.blocks.map((b) => {
              const color = heatColor(b.executions ?? 1, maxExec);
              const isSel = selected === b.pc, isCurrent = currentBlockPc === b.pc, isMatch = matchingPcs.has(b.pc);
              const stroke = isCurrent ? 'var(--success)' : isMatch ? 'var(--warning)' : isSel ? 'var(--accent)' : 'var(--border-strong)';
              return (
                <g key={b.pc} transform={`translate(${b.x},${b.y})`} className={`cfg-block${isCurrent ? ' cfg-block-current' : ''}${isMatch ? ' cfg-block-match' : ''}`} onClick={(ev) => { ev.stopPropagation(); setSelected(b.pc); void gotoBlock(b.pc); }}>
                  <rect width={b.width} height={b.height} rx={8} className="cfg-block-rect" stroke={stroke} strokeWidth={isCurrent ? 3 : isSel || isMatch ? 2 : 1} />
                  <rect width={b.width} height={22} rx={8} fill={color} opacity={0.25} />
                  <rect y={16} width={b.width} height={6} fill="var(--bg-surface)" />
                  <text x={10} y={15} className="cfg-block-head mono" fill={color}>{b.pc}</text>
                  <text x={b.width - 10} y={15} textAnchor="end" className="cfg-block-exec mono">{b.executions}×</text>
                  {b.disasm?.slice(0, 3).map((line, li) => <text key={li} x={10} y={38 + li * 16} className="cfg-block-line mono">{line.length > 30 ? `${line.slice(0, 30)}…` : line}</text>)}
                </g>
              );
            })}
          </g>
        </svg>
      </div>
    </div>
  );
}
