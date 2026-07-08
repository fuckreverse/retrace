import { useState } from 'react';
import { Panel } from '@/components/ui';
import { Icon } from '@/components/icons';
import { Tabs } from './Tabs';
import { useSelectTab } from '@/hooks/useSelectTab';
import { RegistersPanel } from '@/panels/RegistersPanel';
import { MemoryPanel } from '@/panels/MemoryPanel';
import { HexDumpPanel } from '@/panels/HexDumpPanel';

const RIGHT_TABS = ['hexdump', 'memory'] as const;

export function SidebarRight() {
  const [tab, setTab] = useState<string>('hexdump');
  useSelectTab('right', setTab, RIGHT_TABS);

  return (
    <div className="sidebar-right">
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
    </div>
  );
}
