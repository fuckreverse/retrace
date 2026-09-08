/**
 * CFG 面板 —— 函数作用域的可交互控制流图，支持平移、缩放与动态执行信息。
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { CfgBlock, CfgEdge, CfgResult, FunctionEntry } from '@/types/tenet';
import { Button, Empty, IconButton, Input } from '@/components/ui';
import { Icon } from '@/components/icons';
import './cfg.css';

const MIN_ZOOM = 0.2;
const MAX_ZOOM = 4;
const VIEW_PADDING = 40;
const CULL_MARGIN = 100;
const DISASM_LINE_HEIGHT = 14;
const HEADER_HEIGHT = 14;

type Point = { x: number; y: number };
type Terminator = NonNullable<CfgBlock['terminator']>;

const TERMINATORS: { type: Terminator; label: string }[] = [
  { type: 'call', label: 'Call' },
  { type: 'return', label: 'Return' },
  { type: 'indirect_branch', label: 'Indirect' },
  { type: 'conditional_branch', label: 'Conditional' },
  { type: 'branch', label: 'Branch' },
  { type: 'fallthrough', label: 'Fallthrough' },
];

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
  const exact = blocks.find((block) => block.disasm?.some((line) => address(line) === target));
  if (exact) return exact;

  const containing = blocks.find((block) => {
    const start = address(block.pc);
    const end = block.end_pc ? address(block.end_pc) : null;
    // end_pc 为闭区间（块内最后一条指令的 PC），见后端 BasicBlock::end_pc。
    return start != null && end != null && target >= start && target <= end;
  });
  if (containing) return containing;

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

function polylineMidpoint(points: Point[]): Point | null {
  if (points.length === 0) return null;
  if (points.length === 1) return points[0];
  const lengths = points.slice(1).map((point, i) => Math.hypot(point.x - points[i].x, point.y - points[i].y));
  const half = lengths.reduce((sum, length) => sum + length, 0) / 2;
  let walked = 0;
  for (let i = 0; i < lengths.length; i += 1) {
    if (walked + lengths[i] >= half) {
      const ratio = lengths[i] === 0 ? 0 : (half - walked) / lengths[i];
      return {
        x: points[i].x + (points[i + 1].x - points[i].x) * ratio,
        y: points[i].y + (points[i + 1].y - points[i].y) * ratio,
      };
    }
    walked += lengths[i];
  }
  return points[points.length - 1];
}

function truncateLine(line: string, blockWidth: number): string {
  const maxChars = Math.max(8, Math.floor((blockWidth - 20) / 6));
  return line.length > maxChars ? `${line.slice(0, maxChars - 1)}…` : line;
}

export function CfgPanel() {
  const [cfg, setCfg] = useState<CfgResult | null>(null);
  const [functions, setFunctions] = useState<FunctionEntry[]>([]);
  const [selectedFunctionPc, setSelectedFunctionPc] = useState('');
  const [followCurrent, setFollowCurrent] = useState(true);
  const [heatMode, setHeatMode] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [currentBlockPc, setCurrentBlockPc] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [searchIndex, setSearchIndex] = useState(-1);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 20, y: 10 });
  const [canvasSize, setCanvasSize] = useState({ width: 0, height: 0 });
  // CFG 不含当前 PC 时的空态提示（空函数 / 入口前指令 / mock 地址不匹配等）
  const [cfgError, setCfgError] = useState<string | null>(null);
  const canvasRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ x: number; y: number } | null>(null);
  const cfgRequestRef = useRef(0);
  // cfg 的镜像 ref：跟随 effect 依赖只有 [cur, followCurrent]，内部一律读
  // cfgRef.current，避免 setCfg 新对象再次触发 effect 造成无限 fetch 循环。
  const cfgRef = useRef<CfgResult | null>(null);
  const cur = useTraceStore((s) => s.currentInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => {
    let cancelled = false;
    void api.functions().then((entries) => { if (!cancelled) setFunctions(entries); });
    return () => { cancelled = true; };
  }, []);

  // 统一的光标跟随逻辑：先解析当前 PC，仅当它落在已展示 CFG 之外时才
  // 重新拉取所在函数的 CFG（避免同函数内移动光标时全量重取/重排布局），
  // 然后更新当前块高亮并在必要时居中。手动选函数（follow 关闭）时只更新高亮。
  // 注意：依赖里没有 cfg（读 cfgRef.current），setCfg 不会重新触发本 effect；
  // 高亮与居中在 fetch 后内联完成一次，不再依赖下一轮 effect。
  useEffect(() => {
    const requestId = ++cfgRequestRef.current;
    let cancelled = false;
    void api.disasm(cur, 1).then(async (result) => {
      if (cancelled || requestId !== cfgRequestRef.current) return;
      const pc = result.rows[0]?.pc;
      const activeCfg = cfgRef.current;
      const needFetch = followCurrent && pc && (!activeCfg || !blockForPc(activeCfg.blocks, pc));
      if (needFetch) {
        const fetched = await api.cfg({ instId: cur });
        if (cancelled || requestId !== cfgRequestRef.current) return;
        // 后端返回的 CFG 不含任何基本块（空函数 / 当前指令在入口前等）：
        // 不写入 cfg（避免无意义的重渲染与循环），改为显示空态提示。
        if (fetched.blocks.length === 0) {
          setCurrentBlockPc(null);
          setCfgError('当前指令不在任何已识别函数内');
          return;
        }
        setCfg(fetched);
        cfgRef.current = fetched;
        setSelectedFunctionPc(fetched.function?.entry_pc ?? '');
      }
      const block = pc ? blockForPc(cfgRef.current?.blocks ?? [], pc) : null;
      setCurrentBlockPc(block?.pc ?? null);
      if (followCurrent) setCfgError(block ? null : '当前指令不在任何已识别函数内');
      else if (block) setCfgError(null);
      if (block && !isBlockFullyVisible(block)) centerBlock(block);
    });
    return () => { cancelled = true; };
    // centerBlock/isBlockFullyVisible 是不稳定函数引用，刻意不入依赖。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cur, followCurrent]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const updateSize = () => setCanvasSize({ width: canvas.clientWidth, height: canvas.clientHeight });
    updateSize();
    const observer = new ResizeObserver(updateSize);
    observer.observe(canvas);
    return () => observer.disconnect();
  }, []);

  const blockMap = useMemo(() => new Map(cfg?.blocks.map((block) => [block.pc, block])), [cfg]);
  const matches = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query || !cfg) return [];
    return cfg.blocks.filter((block) => block.pc.toLowerCase().includes(query)
      || block.disasm?.some((line) => line.toLowerCase().includes(query)));
  }, [cfg, search]);
  const matchingPcs = useMemo(() => new Set(matches.map((block) => block.pc)), [matches]);

  useEffect(() => { setSearchIndex(-1); }, [search, cfg]);

  const centerBlock = (block: CfgBlock, targetZoom = zoom) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    setZoom(targetZoom);
    setPan({
      x: canvas.clientWidth / 2 - (block.x + block.width / 2) * targetZoom,
      y: canvas.clientHeight / 2 - (block.y + block.height / 2) * targetZoom,
    });
  };

  const visibleRect = useMemo(() => ({
    left: (-pan.x - CULL_MARGIN) / zoom,
    top: (-pan.y - CULL_MARGIN) / zoom,
    right: (canvasSize.width - pan.x + CULL_MARGIN) / zoom,
    bottom: (canvasSize.height - pan.y + CULL_MARGIN) / zoom,
  }), [canvasSize, pan, zoom]);

  const visiblePcs = useMemo(() => new Set((cfg?.blocks ?? []).filter((block) => (
    block.x + block.width >= visibleRect.left
    && block.x <= visibleRect.right
    && block.y + block.height >= visibleRect.top
    && block.y <= visibleRect.bottom
  )).map((block) => block.pc)), [cfg, visibleRect]);

  const isBlockFullyVisible = (block: CfgBlock) => {
    const canvas = canvasRef.current;
    if (!canvas) return true;
    const left = pan.x + block.x * zoom;
    const top = pan.y + block.y * zoom;
    const right = left + block.width * zoom;
    const bottom = top + block.height * zoom;
    return left >= 0 && top >= 0 && right <= canvas.clientWidth && bottom <= canvas.clientHeight;
  };


  const fitToScreen = () => {
    const canvas = canvasRef.current;
    if (!canvas || !cfg || cfg.blocks.length === 0) return;
    const minX = Math.min(...cfg.blocks.map((block) => block.x));
    const minY = Math.min(...cfg.blocks.map((block) => block.y));
    const maxX = Math.max(...cfg.blocks.map((block) => block.x + block.width));
    const maxY = Math.max(...cfg.blocks.map((block) => block.y + block.height));
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

  const locateSearch = () => {
    if (matches.length === 0) return;
    const nextIndex = (searchIndex + 1) % matches.length;
    setSearchIndex(nextIndex);
    centerBlock(matches[nextIndex], Math.min(MAX_ZOOM, Math.max(1.2, zoom)));
  };

  const selectFunction = (entryPc: string) => {
    setSelectedFunctionPc(entryPc);
    setFollowCurrent(false);
    const requestId = ++cfgRequestRef.current;
    if (!entryPc) return;
    void api.cfg({ entryPc }).then((result) => {
      if (requestId !== cfgRequestRef.current) return;
      setCfg(result);
      cfgRef.current = result; // 与 state 保持同步，跟随 effect 读 ref
      setCfgError(result.blocks.length === 0 ? '当前函数没有可显示的基本块' : null);
    });
  };

  const locateCurrentPc = () => {
    const block = currentBlockPc ? blockMap.get(currentBlockPc) : null;
    if (block) centerBlock(block, Math.max(1, zoom));
  };

  const maxExec = cfg ? Math.max(1, ...cfg.blocks.map((block) => block.executions ?? 1)) : 1;
  const onWheel = (event: React.WheelEvent) => { event.preventDefault(); setZoom((value) => Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, value - event.deltaY * 0.001))); };
  const onDown = (event: React.MouseEvent) => { dragRef.current = { x: event.clientX - pan.x, y: event.clientY - pan.y }; };
  const onMove = (event: React.MouseEvent) => { if (dragRef.current) setPan({ x: event.clientX - dragRef.current.x, y: event.clientY - dragRef.current.y }); };
  const onUp = () => { dragRef.current = null; };
  const gotoBlock = async (pc: string) => { const xref = await api.xref(pc); if (xref.inst_ids.length > 0) navigateTo(xref.inst_ids[0]); };

  const renderEdge = (edge: CfgEdge, index: number) => {
    const from = blockMap.get(edge.from);
    const to = blockMap.get(edge.to);
    if (!from || !to || (!visiblePcs.has(edge.from) && !visiblePcs.has(edge.to))) return null;
    const stroke = edge.kind === 'fallthrough' ? 'var(--hl-read)' : 'var(--hl-branch)';
    const strokeWidth = 1 + Math.min(3, (edge.taken_count ?? 1) / 100);
    const showLabel = zoom >= 0.8 && edge.taken_count != null;
    let shape: React.ReactNode;
    let labelPoint: Point | null;

    if (edge.polyline && edge.polyline.length >= 2) {
      shape = <polyline points={edge.polyline.map((point) => `${point.x},${point.y}`).join(' ')} />;
      labelPoint = polylineMidpoint(edge.polyline);
    } else {
      const x1 = from.x + from.width / 2;
      const y1 = from.y + from.height;
      const x2 = to.x + to.width / 2;
      const y2 = to.y;
      const midY = (y1 + y2) / 2;
      const c1 = to.y <= from.y ? { x: x1 + 120, y: y1 + 40 } : { x: x1, y: midY };
      const c2 = to.y <= from.y ? { x: x2 + 120, y: y2 - 40 } : { x: x2, y: midY };
      shape = <path d={`M${x1},${y1} C${c1.x},${c1.y} ${c2.x},${c2.y} ${x2},${y2}`} />;
      labelPoint = { x: (c1.x + c2.x) / 2, y: (c1.y + c2.y) / 2 };
    }

    return (
      <g key={`${edge.from}-${edge.to}-${index}`} className="cfg-edge" fill="none" stroke={stroke} strokeWidth={strokeWidth} opacity={0.75} markerEnd="url(#cfg-arrow)">
        {shape}
        {showLabel && labelPoint && <text x={labelPoint.x} y={labelPoint.y - 4} className="cfg-edge-count" markerEnd="none">{edge.taken_count}</text>}
      </g>
    );
  };

  return (
    <div className="cfg-panel">
      <div className="cfg-toolbar">
        <select className="cfg-function-select" aria-label="选择函数" value={selectedFunctionPc} onChange={(event) => selectFunction(event.target.value)}>
          <option value="">选择函数…</option>
          {functions.map((fn) => <option key={fn.pc} value={fn.pc}>{fn.name} ({fn.pc})</option>)}
        </select>
        <label className="cfg-toggle"><input type="checkbox" checked={followCurrent} onChange={(event) => setFollowCurrent(event.target.checked)} /> 跟随当前函数</label>
        <label className="cfg-toggle"><input type="checkbox" checked={heatMode} onChange={(event) => setHeatMode(event.target.checked)} /> 热力模式</label>
        <span className="cfg-function-name" title={cfg?.function?.name}>{cfg?.function?.name ?? ''}</span>
        <Input aria-label="搜索块地址或反汇编" placeholder="搜索地址 / 反汇编…" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') locateSearch(); }} style={{ width: 190 }} />
        <div className="toolbar-sep" />
        <IconButton title="放大" onClick={() => setZoom((value) => Math.min(MAX_ZOOM, value + 0.2))}><Icon.Forward /></IconButton>
        <span className="dim cfg-zoom">{(zoom * 100).toFixed(0)}%</span>
        <IconButton title="缩小" onClick={() => setZoom((value) => Math.max(MIN_ZOOM, value - 0.2))}><Icon.Back /></IconButton>
        <IconButton title="Fit to Screen" onClick={fitToScreen}><Icon.Box /></IconButton>
        <Button size="sm" variant="ghost" onClick={locateCurrentPc} disabled={!currentBlockPc}>定位当前 PC</Button>
        <Button size="sm" variant="ghost" onClick={() => { setZoom(1); setPan({ x: 20, y: 10 }); }}>Reset View</Button>
        <span className="dim cfg-stats">{cfg ? `${cfg.blocks.length} blocks · ${cfg.edges.length} edges` : ''}</span>
      </div>
      <div ref={canvasRef} className="cfg-canvas" onWheel={onWheel} onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}>
        {cfgError ? <Empty>{cfgError}</Empty> : <>
        <svg width="100%" height="100%">
          <defs><marker id="cfg-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--text-tertiary)" /></marker></defs>
          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {cfg?.edges.map(renderEdge)}
            {cfg?.blocks.filter((block) => visiblePcs.has(block.pc)).map((block) => {
              const color = heatColor(block.executions ?? 1, maxExec);
              const isSel = selected === block.pc;
              const isCurrent = currentBlockPc === block.pc;
              const isMatch = matchingPcs.has(block.pc);
              const stroke = isCurrent ? 'var(--success)' : isMatch ? 'var(--warning)' : isSel ? 'var(--accent)' : 'var(--border-strong)';
              const terminator = block.terminator ?? 'fallthrough';
              return (
                <g key={block.pc} transform={`translate(${block.x},${block.y})`} className={`cfg-block cfg-terminator-${terminator}${isCurrent ? ' cfg-block-current' : ''}${isMatch ? ' cfg-block-match' : ''}`} onClick={(event) => { event.stopPropagation(); setSelected(block.pc); void gotoBlock(block.pc); }}>
                  <rect width={block.width} height={block.height} rx={8} className="cfg-block-rect" style={heatMode ? { fill: color, fillOpacity: 0.24 } : undefined} stroke={stroke} strokeWidth={isCurrent ? 3 : isSel || isMatch ? 2 : 1} />
                  {!heatMode && <><rect width={block.width} height={HEADER_HEIGHT} rx={8} fill={color} opacity={0.25} /><rect y={HEADER_HEIGHT - 4} width={block.width} height={4} fill="var(--bg-surface)" /></>}
                  <rect width={4} height={block.height} className="cfg-terminator-strip" />
                  <text x={10} y={11} className="cfg-block-head mono" fill={color}>{block.pc}</text>
                  <text x={block.width - 10} y={11} textAnchor="end" className="cfg-block-exec mono">{block.executions ?? 0}×</text>
                  {block.disasm?.map((line, lineIndex) => <text key={lineIndex} x={10} y={HEADER_HEIGHT + 11 + lineIndex * DISASM_LINE_HEIGHT} className="cfg-block-line mono">{truncateLine(line, block.width)}</text>)}
                </g>
              );
            })}
          </g>
        </svg>
        <div className="cfg-terminator-legend">
          {TERMINATORS.map(({ type, label }) => <span key={type}><i className={`cfg-legend-${type}`} />{label}</span>)}
        </div>
        </>}
      </div>
    </div>
  );
}
