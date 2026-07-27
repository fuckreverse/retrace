import { useRef, useState } from 'react';
import { clsx } from 'clsx';
import { Panel, IconButton } from '@/components/ui';
import { Icon } from '@/components/icons';
import { Tabs } from './Tabs';
import { Splitter } from './Splitter';
import { useSelectTab } from '@/hooks/useSelectTab';
import { useSettingsStore } from '@/store/settingsStore';
import { RegistersPanel } from '@/panels/RegistersPanel';
import { MemoryPanel } from '@/panels/MemoryPanel';
import { HexDumpPanel } from '@/panels/HexDumpPanel';

const RIGHT_TABS = ['hexdump', 'memory'] as const;

export function SidebarRight() {
  const [tab, setTab] = useState<string>('hexdump');
  useSelectTab('right', setTab, RIGHT_TABS);

  const width = useSettingsStore((s) => s.sidebarRightWidth);
  const collapsed = useSettingsStore((s) => s.sidebarRightCollapsed);
  const setWidth = useSettingsStore((s) => s.setSidebarRightWidth);
  const toggleCollapsed = useSettingsStore((s) => s.toggleSidebarRightCollapsed);

  const [liveWidth, setLiveWidth] = useState(width);
  const liveWidthRef = useRef(width);
  const w = collapsed ? 0 : liveWidth;

  return (
    <>
      <IconButton
        title={collapsed ? '展开 Registers/Hex Dump 侧栏' : '折叠 Registers/Hex Dump 侧栏'}
        className="sidebar-collapse-btn sidebar-collapse-btn-right"
        onClick={toggleCollapsed}
        style={{ right: collapsed ? 4 : w + 4 }}
      >
        {collapsed ? <Icon.Back /> : <Icon.Forward />}
      </IconButton>
      {!collapsed && (
        <Splitter
          direction="vertical"
          title="拖拽调整右侧栏宽度"
          onDrag={(delta) => {
            setLiveWidth((w0) => {
              // 右栏在最右侧，向左拖（delta<0）应增宽
              const next = Math.min(Math.max(w0 - delta, 200), Math.round(window.innerWidth * 0.7));
              liveWidthRef.current = next;
              return next;
            });
          }}
          onCommit={() => setWidth(liveWidthRef.current)}
        />
      )}
      <div className={clsx('sidebar-right', collapsed && 'collapsed')} style={{ width: w, position: 'relative' }}>
        {!collapsed && (
          <>
            <Panel title={<><Icon.Cpu style={{ width: 14, marginRight: 6, verticalAlign: -3 }} />Registers</>} noPadding>
              <RegistersPanel />
            </Panel>
            <Panel noPadding>
              <Tabs
                value={tab}
                onValueChange={setTab}
                tabs={[
                  { value: 'hexdump', label: 'Hex Dump', icon: <Icon.Memory />, content: <HexDumpPanel /> },
                  { value: 'memory', label: 'Mem Access', icon: <Icon.Drop />, content: <MemoryPanel /> },
                ]}
              />
            </Panel>
          </>
        )}
      </div>
    </>
  );
}
