import { useTraceStore } from '@/store/traceStore';
import { useSettingsStore, type ColorScheme } from '@/store/settingsStore';
import { IconButton } from '@/components/ui';
import { Icon } from '@/components/icons';

const COLOR_SCHEME_CYCLE: ColorScheme[] = [
  'dark', 'one-dark', 'dracula', 'solarized-dark', 'nord', 'light', 'github-light',
];

export function Toolbar() {
  const cur = useTraceStore((s) => s.currentInst);
  const total = useTraceStore((s) => s.totalInst);
  const step = useTraceStore((s) => s.step);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const navBack = useTraceStore((s) => s.navBack);
  const navForward = useTraceStore((s) => s.navForward);
  const canBack = useTraceStore((s) => s.canBack());
  const canForward = useTraceStore((s) => s.canForward());

  const zoom = useSettingsStore((s) => s.zoom);
  const setZoom = useSettingsStore((s) => s.setZoom);
  const colorScheme = useSettingsStore((s) => s.colorScheme);
  const setColorScheme = useSettingsStore((s) => s.setColorScheme);

  const pct = total > 1 ? (cur / (total - 1)) * 100 : 0;

  function cycleTheme() {
    const idx = COLOR_SCHEME_CYCLE.indexOf(colorScheme);
    const next = COLOR_SCHEME_CYCLE[(idx + 1) % COLOR_SCHEME_CYCLE.length];
    setColorScheme(next);
  }

  return (
    <div className="toolbar">
      <div className="toolbar-group">
        <IconButton title="后退 (Alt+←)" disabled={!canBack} onClick={navBack}><Icon.Back /></IconButton>
        <IconButton title="前进 (Alt+→)" disabled={!canForward} onClick={navForward}><Icon.Forward /></IconButton>
      </div>
      <div className="toolbar-sep" />
      <div className="toolbar-group">
        <IconButton title="首条指令 (Home)" onClick={() => navigateTo(0)}><Icon.First /></IconButton>
        <IconButton title="上一条 (↑)" onClick={() => step(-1)}><Icon.Prev /></IconButton>
        <IconButton title="下一条 (↓)" onClick={() => step(1)}><Icon.Next /></IconButton>
        <IconButton title="末条指令 (End)" onClick={() => navigateTo(total - 1)}><Icon.Last /></IconButton>
      </div>
      <div className="toolbar-cur">
        <span>
          inst <span className="cur-inst">#{cur}</span> / {total.toLocaleString()}
        </span>
        <span className="dim">{pct.toFixed(1)}%</span>
      </div>

      <div className="toolbar-sep" />
      {/* 缩放控制 */}
      <div className="toolbar-group">
        <IconButton title="缩小 (Ctrl+-)" onClick={() => setZoom(Math.max(0.6, zoom - 0.1))}><Icon.Minus /></IconButton>
        <span className="toolbar-zoom-label dim">{Math.round(zoom * 100)}%</span>
        <IconButton title="放大 (Ctrl++)" onClick={() => setZoom(Math.min(2.0, zoom + 0.1))}><Icon.Plus /></IconButton>
        <IconButton title="重置缩放 (Ctrl+0)" onClick={() => setZoom(1.0)}><Icon.Refresh /></IconButton>
      </div>

      <div className="toolbar-sep" />
      {/* 主题循环切换 */}
      <div className="toolbar-group">
        <IconButton title={`当前: ${colorScheme}（点击切换）`} onClick={cycleTheme}>
          {colorScheme === 'light' || colorScheme === 'github-light' ? <Icon.Moon /> : <Icon.Sun />}
        </IconButton>
      </div>
    </div>
  );
}
