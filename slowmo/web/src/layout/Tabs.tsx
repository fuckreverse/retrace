import * as RadixTabs from '@radix-ui/react-tabs';
import type { ReactNode } from 'react';

export interface TabDef {
  value: string;
  label: string;
  icon?: ReactNode;
  content: ReactNode;
}

export function Tabs({
  tabs,
  defaultValue,
  value,
  onValueChange,
}: {
  tabs: TabDef[];
  defaultValue?: string;
  /** 受控模式：外部驱动当前 tab（如原生菜单切换） */
  value?: string;
  onValueChange?: (value: string) => void;
}) {
  return (
    <RadixTabs.Root
      className="tabs-root"
      defaultValue={value === undefined ? defaultValue ?? tabs[0]?.value : undefined}
      value={value}
      onValueChange={onValueChange}
    >
      <RadixTabs.List className="tabs-list">
        {tabs.map((t) => (
          <RadixTabs.Trigger key={t.value} value={t.value} className="tab-trigger">
            {t.icon}
            {t.label}
          </RadixTabs.Trigger>
        ))}
      </RadixTabs.List>
      {tabs.map((t) => (
        <RadixTabs.Content key={t.value} value={t.value} className="tab-content">
          {t.content}
        </RadixTabs.Content>
      ))}
    </RadixTabs.Root>
  );
}
