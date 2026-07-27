import * as RadixTabs from '@radix-ui/react-tabs';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { clsx } from 'clsx';

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

/* ------------------------------------------------------------------ */
/*  GroupedTabs —— 二级导航：一级分类 + 分类内 tab 列表                  */
/*  用于 tab 数量较多（如中央下栏 25 个）的场景，避免单行 tab 横向溢出。 */
/* ------------------------------------------------------------------ */

export interface TabCategory {
  id: string;
  label: string;
  icon?: ReactNode;
  tabs: TabDef[];
}

export function GroupedTabs({
  categories,
  value,
  onValueChange,
}: {
  categories: TabCategory[];
  /** 受控模式：外部驱动当前 tab（如原生菜单切换），值为具体 tab 的 value */
  value: string;
  onValueChange: (value: string) => void;
}) {
  // 根据当前受控 value 反查所属分类，保证从菜单跳转到某个 tab 时分类栏也跟着切换
  const activeCategoryId = useMemo(() => {
    for (const cat of categories) {
      if (cat.tabs.some((t) => t.value === value)) return cat.id;
    }
    return categories[0]?.id;
  }, [categories, value]);

  const [displayCategoryId, setDisplayCategoryId] = useState(activeCategoryId);
  // 外部受控 value 变化（如菜单跳转）导致 tab 所属分类变化时，同步分类栏高亮
  useEffect(() => {
    setDisplayCategoryId(activeCategoryId);
  }, [activeCategoryId]);
  const activeCategory = categories.find((c) => c.id === displayCategoryId) ?? categories[0];
  const allTabs = useMemo(() => categories.flatMap((c) => c.tabs), [categories]);

  return (
    <RadixTabs.Root
      className="tabs-root grouped-tabs-root"
      value={value}
      onValueChange={onValueChange}
    >
      {/* 一级：分类 */}
      <div className="tabs-category-list">
        {categories.map((cat) => (
          <button
            key={cat.id}
            className={clsx('tab-category-trigger', cat.id === displayCategoryId && 'active')}
            onClick={() => {
              setDisplayCategoryId(cat.id);
              // 切换分类时若当前 tab 不属于新分类，自动选中新分类的第一个 tab
              if (!cat.tabs.some((t) => t.value === value) && cat.tabs[0]) {
                onValueChange(cat.tabs[0].value);
              }
            }}
          >
            {cat.icon}
            {cat.label}
            <span className="tab-category-count">{cat.tabs.length}</span>
          </button>
        ))}
      </div>
      {/* 二级：当前分类下的 tab */}
      <RadixTabs.List className="tabs-list">
        {(activeCategory?.tabs ?? []).map((t) => (
          <RadixTabs.Trigger key={t.value} value={t.value} className="tab-trigger">
            {t.icon}
            {t.label}
          </RadixTabs.Trigger>
        ))}
      </RadixTabs.List>
      {/* content 始终渲染全部 tab（跨分类保留状态），仅显示当前选中的一个 */}
      {allTabs.map((t) => (
        <RadixTabs.Content key={t.value} value={t.value} className="tab-content">
          {t.content}
        </RadixTabs.Content>
      ))}
    </RadixTabs.Root>
  );
}
