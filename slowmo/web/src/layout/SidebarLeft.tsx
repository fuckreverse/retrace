import { useRef, useState } from 'react';
import { clsx } from 'clsx';
import { Panel, IconButton } from '@/components/ui';
import { Icon } from '@/components/icons';
import { Tabs } from './Tabs';
import { Splitter } from './Splitter';
import { useSelectTab } from '@/hooks/useSelectTab';
import { useSettingsStore } from '@/store/settingsStore';
import { FunctionsPanel } from '@/panels/FunctionsPanel';
import { StringsPanel } from '@/panels/AnalysisResultPanels';

const LEFT_TABS = ['functions', 'strings'] as const;

export function SidebarLeft() {
  const [tab, setTab] = useState<string>('functions');
  useSelectTab('left', setTab, LEFT_TABS);

  const width = useSettingsStore((s) => s.sidebarLeftWidth);
  const collapsed = useSettingsStore((s) => s.sidebarLeftCollapsed);
  const setWidth = useSettingsStore((s) => s.setSidebarLeftWidth);
  const toggleCollapsed = useSettingsStore((s) => s.toggleSidebarLeftCollapsed);

  const [liveWidth, setLiveWidth] = useState(width);
  const liveWidthRef = useRef(width);
  const w = collapsed ? 0 : liveWidth;

  return (
    <>
      <div className={clsx('sidebar-left', collapsed && 'collapsed')} style={{ width: w, position: 'relative' }}>
        {!collapsed && (
          <Panel noPadding className="grow">
            <Tabs
              value={tab}
              onValueChange={setTab}
              tabs={[
                { value: 'functions', label: 'Functions', icon: <Icon.Function />, content: <FunctionsPanel /> },
                { value: 'strings', label: 'Strings', icon: <Icon.Text />, content: <StringsPanel /> },
              ]}
            />
          </Panel>
        )}
      </div>
      {!collapsed && (
        <Splitter
          direction="vertical"
          title="拖拽调整左侧栏宽度"
          onDrag={(delta) => {
            setLiveWidth((w0) => {
              const next = Math.min(Math.max(w0 + delta, 140), Math.round(window.innerWidth * 0.7));
              liveWidthRef.current = next;
              return next;
            });
          }}
          onCommit={() => setWidth(liveWidthRef.current)}
        />
      )}
      <IconButton
        title={collapsed ? '展开 Functions/Strings 侧栏' : '折叠 Functions/Strings 侧栏'}
        className="sidebar-collapse-btn sidebar-collapse-btn-left"
        onClick={toggleCollapsed}
        style={{ left: collapsed ? 4 : w + 4 }}
      >
        {collapsed ? <Icon.Forward /> : <Icon.Back />}
      </IconButton>
    </>
  );
}
