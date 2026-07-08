import { useState } from 'react';
import { Panel } from '@/components/ui';
import { Icon } from '@/components/icons';
import { Tabs } from './Tabs';
import { useSelectTab } from '@/hooks/useSelectTab';
import { FunctionsPanel } from '@/panels/FunctionsPanel';
import { StringsPanel } from '@/panels/AnalysisResultPanels';

const LEFT_TABS = ['functions', 'strings'] as const;

export function SidebarLeft() {
  const [tab, setTab] = useState<string>('functions');
  useSelectTab('left', setTab, LEFT_TABS);

  return (
    <div className="sidebar-left">
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
    </div>
  );
}
