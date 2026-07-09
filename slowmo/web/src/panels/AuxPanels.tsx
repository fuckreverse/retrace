/**
 * 辅助面板集合。
 * SnapshotsPanel / DwarfPanel / VmWorkspacePanel / LogPanel / CacheManagerPanel / SettingsPanel。
 */
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import {
  useSettingsStore,
  type ZoomLevel,
  type UIDensity,
  type ColorScheme,
  type ScrollbarWidth,
} from '@/store/settingsStore';
import { getDataSource } from '@/api/service';
import { api } from '@/api/service';
import { isTauri } from '@/lib/env';
import { subscribeBackendLog } from '@/lib/backendLog';
import type {
  CacheEntry,
  DwarfEntry,
  LogEntry,
  SnapshotEntry,
  VmHandler,
} from '@/types/tenet';
import { Chip } from '@/components/ui';
import './lists.css';

function fmtBytes(n: number): string {
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB';
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + ' KB';
  return n + ' B';
}

/* ---------- Snapshots ---------- */
export function SnapshotsPanel() {
  const [rows, setRows] = useState<SnapshotEntry[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  useEffect(() => { api.snapshots().then(setRows); }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar"><span className="list-count">{rows.length} ANCHOR 快照</span></div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 50 }}>#</th><th style={{ width: 60 }}>Inst</th><th style={{ width: 130 }}>PC</th><th>Label</th><th style={{ width: 80 }}>Regs</th><th style={{ width: 90 }}>Mem</th></tr></thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id} onClick={() => navigateTo(s.inst_id)}>
                <td className="mono dim">{s.id}</td>
                <td className="mono link">#{s.inst_id}</td>
                <td className="mono dim">{s.pc}</td>
                <td>{s.label}</td>
                <td className="mono num">{s.reg_count}</td>
                <td className="mono num dim">{fmtBytes(s.mem_bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- DWARF ---------- */
export function DwarfPanel() {
  const [rows, setRows] = useState<DwarfEntry[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  useEffect(() => { api.dwarf().then(setRows); }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar"><span className="list-count">{rows.length} DWARF 行信息</span></div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 60 }}>Inst</th><th style={{ width: 130 }}>PC</th><th>File:Line</th><th style={{ width: 160 }}>Function</th><th>Variables</th></tr></thead>
          <tbody>
            {rows.map((d, i) => (
              <tr key={i} onClick={() => navigateTo(d.inst_id)}>
                <td className="mono link">#{d.inst_id}</td>
                <td className="mono dim">{d.pc}</td>
                <td className="mono str-val">{d.file}:{d.line}</td>
                <td className="mono objc-name">{d.func}</td>
                <td className="dim">{d.variables.join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- VM Workspace ---------- */
export function VmWorkspacePanel() {
  const [rows, setRows] = useState<VmHandler[]>([]);
  useEffect(() => { api.vmHandlers().then(setRows); }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar"><span className="list-count">{rows.length} VM handlers · 去虚拟化工作区</span></div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 50 }}>#</th><th style={{ width: 90 }}>Opcode</th><th style={{ width: 140 }}>Handler PC</th><th>Semantics</th><th style={{ width: 90 }}>Hits</th></tr></thead>
          <tbody>
            {rows.map((v) => (
              <tr key={v.id}>
                <td className="mono dim">{v.id}</td>
                <td><span className="cat-tag cat-accent">{v.opcode}</span></td>
                <td className="mono dim">{v.handler_pc}</td>
                <td className="mono">{v.semantics}</td>
                <td className="mono num">{v.hit_count.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Log ---------- */
const LOG_LEVELS = ['all', 'debug', 'info', 'warn', 'error'] as const;
export function LogPanel() {
  const [rows, setRows] = useState<LogEntry[]>([]);
  const [level, setLevel] = useState<(typeof LOG_LEVELS)[number]>('all');

  useEffect(() => {
    api.log().then(setRows);
    // Tauri 环境下日志来自真实的 tenet 后端（sidecar）进程，会持续产生新行
    // （见 src/lib/backendLog.ts）；订阅更新使面板打开时能实时滚动追加，
    // 而不是只在挂载那一刻拍一张快照。浏览器 / mock 模式没有真实后端，
    // 不需要订阅。
    if (!isTauri()) return;
    return subscribeBackendLog(setRows);
  }, []);

  const filtered = level === 'all' ? rows : rows.filter((r) => r.level === level);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        {LOG_LEVELS.map((l) => <Chip key={l} active={level === l} onClick={() => setLevel(l)}>{l}</Chip>)}
        <span className="list-count" style={{ marginLeft: 'auto' }}>{filtered.length} lines</span>
      </div>
      <div className="log-list">
        {filtered.map((r, i) => (
          <div key={i} className={clsx('log-line', `log-${r.level}`)}>
            <span className="log-time">{r.ts}</span>
            <span className="log-level">{r.level.toUpperCase()}</span>
            <span className="log-tag">[{r.source}]</span>
            <span className="log-msg">{r.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Cache Manager ---------- */
function cacheTone(s: CacheEntry['status']): string {
  return s === 'fresh' ? 'cat-accent' : s === 'building' ? 'cat-warning' : 'cat-default';
}
export function CacheManagerPanel() {
  const [rows, setRows] = useState<CacheEntry[]>([]);
  useEffect(() => { api.cache().then(setRows); }, []);
  const total = rows.reduce((a, r) => a + r.size_bytes, 0);

  return (
    <div className="list-panel">
      <div className="list-toolbar"><span className="list-count">{rows.length} caches · {fmtBytes(total)} 合计</span></div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th>Name</th><th style={{ width: 110 }}>Kind</th><th style={{ width: 100 }}>Size</th><th style={{ width: 100 }}>Status</th><th style={{ width: 120 }}>Last Built</th></tr></thead>
          <tbody>
            {rows.map((c, i) => (
              <tr key={i}>
                <td className="mono">{c.name}</td>
                <td className="dim">{c.kind}</td>
                <td className="mono num">{fmtBytes(c.size_bytes)}</td>
                <td><span className={clsx('cat-tag', cacheTone(c.status))}>{c.status}</span></td>
                <td className="mono dim">{c.last_built}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Settings ---------- */
/** 带标签 + 控件的设置行 */
function SettingRow({ label, hint, children }: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="settings-row">
      <div className="settings-row-label">
        <b>{label}</b>
        {hint && <small>{hint}</small>}
      </div>
      <div className="settings-row-control">{children}</div>
    </div>
  );
}

/** 数值滑块 + 显示 */
function SliderRow({ label, hint, value, min, max, step, onChange, fmt }: {
  label: string;
  hint?: string;
  value: number;
  min: number;
  max: number;
  step: number;
  onChange: (v: number) => void;
  fmt?: (v: number) => string;
}) {
  const display = fmt ? fmt(value) : String(value);
  return (
    <div className="settings-row">
      <div className="settings-row-label">
        <b>{label}</b>
        {hint && <small>{hint}</small>}
      </div>
      <div className="settings-row-control slider-control">
        <input
          type="range"
          min={min}
          max={max}
          step={step}
          value={value}
          onChange={(e) => onChange(Number(e.target.value))}
          className="settings-slider"
        />
        <span className="slider-value">{display}</span>
      </div>
    </div>
  );
}

const FONT_SANS_OPTIONS = [
  { value: 'system', label: '系统默认' },
  { value: 'inter', label: 'Inter' },
  { value: 'helvetica', label: 'Helvetica' },
] as const;

const FONT_MONO_OPTIONS = [
  { value: 'system-mono', label: '系统默认' },
  { value: 'jetbrains', label: 'JetBrains Mono' },
  { value: 'fira', label: 'Fira Code' },
  { value: 'menlo', label: 'Menlo' },
  { value: 'source-code', label: 'Source Code Pro' },
  { value: 'iosevka', label: 'Iosevka' },
] as const;

const COLOR_SCHEME_OPTIONS: { value: ColorScheme; label: string }[] = [
  { value: 'dark', label: 'Tenet Dark' },
  { value: 'one-dark', label: 'One Dark' },
  { value: 'dracula', label: 'Dracula' },
  { value: 'solarized-dark', label: 'Solarized Dark' },
  { value: 'nord', label: 'Nord' },
  { value: 'light', label: 'Tenet Light' },
  { value: 'github-light', label: 'GitHub Light' },
];

const DENSITY_OPTIONS: { value: UIDensity; label: string }[] = [
  { value: 'compact', label: '紧凑' },
  { value: 'default', label: '默认' },
  { value: 'comfortable', label: '宽松' },
];

const SCROLLBAR_OPTIONS: { value: ScrollbarWidth; label: string }[] = [
  { value: 'thin', label: '窄' },
  { value: 'default', label: '中' },
  { value: 'wide', label: '宽' },
];

export function SettingsPanel() {
  const settings = useSettingsStore();
  const info = useTraceStore((s) => s.info);
  const total = useTraceStore((s) => s.totalInst);
  const source = getDataSource();

  return (
    <div className="settings-wrap">
      {/* ─── 缩放 ─────────────────────────────────── */}
      <div className="settings-group">
        <div className="settings-group-title">缩放</div>
        <SliderRow
          label="页面缩放"
          hint="全局缩放比例，类似于 IDA 的 DPI 设置"
          value={settings.zoom}
          min={0.6}
          max={2.0}
          step={0.1}
          onChange={(v) => settings.setZoom(v as ZoomLevel)}
          fmt={(v) => `${Math.round(v * 100)}%`}
        />
      </div>

      {/* ─── 字体 ─────────────────────────────────── */}
      <div className="settings-group">
        <div className="settings-group-title">字体</div>
        <SettingRow label="UI 字体" hint="界面文字（菜单/按钮/标题）使用的字体族">
          <select className="settings-select" value={settings.fontSans} onChange={(e) => settings.setFontSans(e.target.value)}>
            {FONT_SANS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </SettingRow>
        <SettingRow label="等宽字体" hint="反汇编/寄存器/地址/代码区域使用的等宽字体">
          <select className="settings-select" value={settings.fontMono} onChange={(e) => settings.setFontMono(e.target.value)}>
            {FONT_MONO_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </SettingRow>
        <SliderRow
          label="UI 字号"
          hint="界面基准字号，所有文字按比例缩放"
          value={settings.fsBase}
          min={11}
          max={16}
          step={1}
          onChange={settings.setFsBase}
          fmt={(v) => `${v}px`}
        />
        <SliderRow
          label="等宽字号系数"
          hint="等宽字体相对于 UI 字号的缩放比例"
          value={settings.fsMonoScale}
          min={0.85}
          max={1.2}
          step={0.05}
          onChange={settings.setFsMonoScale}
          fmt={(v) => `×${v.toFixed(2)}`}
        />
      </div>

      {/* ─── UI 密度 ──────────────────────────────── */}
      <div className="settings-group">
        <div className="settings-group-title">UI 密度</div>
        <SettingRow label="布局密度" hint="紧凑=高信息密度，宽松=更透气">
          <div className="seg">
            {DENSITY_OPTIONS.map((o) => (
              <button
                key={o.value}
                className={clsx(settings.density === o.value && 'active')}
                onClick={() => settings.setDensity(o.value)}
              >
                {o.label}
              </button>
            ))}
          </div>
        </SettingRow>
        <SettingRow label="滚动条宽度" hint="代码/列表区域的滚动条粗细">
          <div className="seg">
            {SCROLLBAR_OPTIONS.map((o) => (
              <button
                key={o.value}
                className={clsx(settings.scrollbarWidth === o.value && 'active')}
                onClick={() => settings.setScrollbarWidth(o.value)}
              >
                {o.label}
              </button>
            ))}
          </div>
        </SettingRow>
      </div>

      {/* ─── 主题色 ───────────────────────────────── */}
      <div className="settings-group">
        <div className="settings-group-title">主题色</div>
        <SettingRow label="色板方案" hint="预设色彩方案，每种包含背景/文字/语法高亮/语义色等完整色板">
          <select className="settings-select" value={settings.colorScheme} onChange={(e) => settings.setColorScheme(e.target.value as ColorScheme)}>
            {COLOR_SCHEME_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </SettingRow>
        <SliderRow
          label="强调色色相"
          hint="覆盖主题默认强调色（蓝色）的色相角度，0=红 120=绿 240=蓝"
          value={settings.accentHue ?? 217}
          min={0}
          max={360}
          step={5}
          onChange={(v) => settings.setAccentHue(v)}
          fmt={(v) => `${v}°`}
        />
        <div className="settings-row">
          <div className="settings-row-label">
            <b>重置强调色</b>
            <small>恢复当前主题方案的默认强调色</small>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={() => settings.setAccentHue(null)}>
            重置
          </button>
        </div>
      </div>

      {/* ─── 数据源 ───────────────────────────────── */}
      <div className="settings-group">
        <div className="settings-group-title">数据源</div>
        <div className="settings-row">
          <div className="settings-row-label">
            <b>后端连接</b>
            <small>TenetService WebSocket · 失败自动降级 Mock</small>
          </div>
          <span className={clsx('cat-tag', source === 'live' ? 'cat-accent' : 'cat-default')}>
            {source === 'live' ? 'Live' : 'Mock'}
          </span>
        </div>
        <div className="settings-row">
          <div className="settings-row-label">
            <b>Trace 模块</b>
            <small>{info?.module_name ?? '—'}</small>
          </div>
          <span className="mono dim">{total.toLocaleString()} insts</span>
        </div>
      </div>

      {/* ─── 重置 ─────────────────────────────────── */}
      <div className="settings-group">
        <div className="settings-group-title">操作</div>
        <div className="settings-row">
          <div className="settings-row-label">
            <b>恢复默认设置</b>
            <small>将所有 UI 设置恢复为出厂默认值</small>
          </div>
          <button className="btn btn-danger btn-sm" onClick={settings.resetToDefaults}>
            重置全部
          </button>
        </div>
      </div>

      {/* ─── 关于 ─────────────────────────────────── */}
      <div className="settings-group">
        <div className="settings-group-title">关于</div>
        <div className="settings-row">
          <div className="settings-row-label">
            <b>Tenet Web</b>
            <small>QBDI trace 离线分析器 · 飞象风格 Web 前端</small>
          </div>
          <span className="mono dim">v0.1</span>
        </div>
      </div>
    </div>
  );
}
