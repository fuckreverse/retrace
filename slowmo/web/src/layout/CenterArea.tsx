import { useRef, useState } from 'react';
import { Panel } from '@/components/ui';
import { Icon } from '@/components/icons';
import { Tabs, GroupedTabs, type TabCategory } from './Tabs';
import { Splitter } from './Splitter';
import { useSelectTab } from '@/hooks/useSelectTab';
import { useSettingsStore } from '@/store/settingsStore';
import { InstructionsPanel } from '@/panels/InstructionsPanel';
import { CfgPanel } from '@/panels/CfgPanel';
import { StringsPanel, PatternsPanel, ObjcPanel, CallGraphPanel } from '@/panels/AnalysisResultPanels';
import { ConstantsPanel, AlgorithmPanel, ApiInterceptsPanel, LoopsPanel, RegTimelinePanel } from '@/panels/MoreAnalysisPanels';
import { AnalysisPanel } from '@/panels/AnalysisPanel';
import { CallStackPanel } from '@/panels/CallStackPanel';
import { MemorySearchPanel, MemoryStringsPanel, EntropyPanel, YaraPanel } from '@/panels/MemoryStringPanels';
import { WindowStatsPanel, TraceFoldPanel, TraceDiffPanel } from '@/panels/ProfileTracePanels';
import { TaintSourcesPanel, DataflowGraphPanel, BackwardTaintPanel, ObjcCryptoPanel } from '@/panels/TaintDataflowPanels';
import { SnapshotsPanel, DwarfPanel, VmWorkspacePanel, LogPanel, CacheManagerPanel, SettingsPanel } from '@/panels/AuxPanels';
import { ThreadsPanel, XThreadDataflowPanel } from '@/panels/ThreadsPanel';

const TOP_TABS = ['instructions', 'cfg', 'strings', 'regtl', 'dataflow'] as const;
const BOTTOM_TABS = [
  'analysis', 'callstack', 'patterns', 'algorithms', 'constants', 'loops', 'api', 'objc',
  'objccrypto', 'callgraph', 'threads', 'xdataflow', 'taintsrc', 'backtaint', 'memsearch', 'memstrings', 'entropy',
  'yara', 'winstats', 'tracefold', 'tracediff', 'snapshots', 'dwarf', 'vm', 'cache', 'log', 'settings',
] as const;

export function CenterArea() {
  // 上/下 tab 均受控，供菜单（View/Analysis/Export/Tools）定向跳转到指定面板
  const [topTab, setTopTab] = useState<string>('instructions');
  const [bottomTab, setBottomTab] = useState<string>('analysis');

  useSelectTab('center-top', setTopTab, TOP_TABS);
  useSelectTab('center-bottom', setBottomTab, BOTTOM_TABS);

  const splitRatio = useSettingsStore((s) => s.centerSplitRatio);
  const setSplitRatio = useSettingsStore((s) => s.setCenterSplitRatio);
  const containerRef = useRef<HTMLDivElement>(null);
  const [liveRatio, setLiveRatio] = useState(splitRatio);
  const liveRatioRef = useRef(splitRatio);

  const bottomCategories: TabCategory[] = [
    {
      id: 'analysis',
      label: 'Analysis',
      icon: <Icon.Layers />,
      tabs: [
        { value: 'analysis', label: 'Analysis', icon: <Icon.Layers />, content: <AnalysisPanel /> },
        { value: 'patterns', label: 'Patterns', icon: <Icon.Shield />, content: <PatternsPanel /> },
        { value: 'algorithms', label: 'Algorithms', icon: <Icon.Cpu />, content: <AlgorithmPanel /> },
        { value: 'constants', label: 'Constants', icon: <Icon.Dot />, content: <ConstantsPanel /> },
        { value: 'loops', label: 'Loops', icon: <Icon.Refresh />, content: <LoopsPanel /> },
      ],
    },
    {
      id: 'taint',
      label: 'Taint & Dataflow',
      icon: <Icon.Drop />,
      tabs: [
        { value: 'taintsrc', label: 'Taint Sources', icon: <Icon.Drop />, content: <TaintSourcesPanel /> },
        { value: 'backtaint', label: 'Backward Taint', icon: <Icon.Target />, content: <BackwardTaintPanel /> },
        { value: 'objccrypto', label: 'ObjC×Crypto', icon: <Icon.Shield />, content: <ObjcCryptoPanel /> },
      ],
    },
    {
      id: 'calls',
      label: 'Calls & API',
      icon: <Icon.Stack />,
      tabs: [
        { value: 'callstack', label: 'Call Stack', icon: <Icon.Stack />, content: <CallStackPanel /> },
        { value: 'callgraph', label: 'Call Graph', icon: <Icon.Graph />, content: <CallGraphPanel /> },
        { value: 'threads', label: 'Threads', icon: <Icon.List />, content: <ThreadsPanel /> },
        { value: 'xdataflow', label: 'XThread Data', icon: <Icon.Flow />, content: <XThreadDataflowPanel /> },
        { value: 'api', label: 'API Intercepts', icon: <Icon.Terminal />, content: <ApiInterceptsPanel /> },
        { value: 'objc', label: 'ObjC', icon: <Icon.Chip />, content: <ObjcPanel /> },
      ],
    },
    {
      id: 'memory',
      label: 'Memory & Strings',
      icon: <Icon.Memory />,
      tabs: [
        { value: 'memsearch', label: 'Mem Search', icon: <Icon.Search />, content: <MemorySearchPanel /> },
        { value: 'memstrings', label: 'Mem Strings', icon: <Icon.Text />, content: <MemoryStringsPanel /> },
        { value: 'entropy', label: 'Entropy', icon: <Icon.Chart />, content: <EntropyPanel /> },
        { value: 'yara', label: 'YARA', icon: <Icon.Tag />, content: <YaraPanel /> },
      ],
    },
    {
      id: 'profiling',
      label: 'Profiling & Trace',
      icon: <Icon.Chart />,
      tabs: [
        { value: 'winstats', label: 'Window Stats', icon: <Icon.Chart />, content: <WindowStatsPanel /> },
        { value: 'tracefold', label: 'Trace Fold', icon: <Icon.Layers />, content: <TraceFoldPanel /> },
        { value: 'tracediff', label: 'Trace Diff', icon: <Icon.Diff />, content: <TraceDiffPanel /> },
        { value: 'snapshots', label: 'Snapshots', icon: <Icon.Camera />, content: <SnapshotsPanel /> },
      ],
    },
    {
      id: 'system',
      label: 'System',
      icon: <Icon.Settings />,
      tabs: [
        { value: 'dwarf', label: 'DWARF', icon: <Icon.Box />, content: <DwarfPanel /> },
        { value: 'vm', label: 'VM Workspace', icon: <Icon.Cpu />, content: <VmWorkspacePanel /> },
        { value: 'cache', label: 'Cache', icon: <Icon.Database />, content: <CacheManagerPanel /> },
        { value: 'log', label: 'Log', icon: <Icon.Terminal />, content: <LogPanel /> },
        { value: 'settings', label: 'Settings', icon: <Icon.Filter />, content: <SettingsPanel /> },
      ],
    },
  ];

  return (
    <div className="center-area" ref={containerRef}>
      <div className="center-top" style={{ flex: `${liveRatio} 1 0`, minHeight: 80 }}>
        <Panel noPadding>
          <Tabs
            value={topTab}
            onValueChange={setTopTab}
            tabs={[
              { value: 'instructions', label: 'Instructions', icon: <Icon.List />, content: <InstructionsPanel /> },
              { value: 'cfg', label: 'CFG', icon: <Icon.Flow />, content: <CfgPanel /> },
              { value: 'strings', label: 'Strings', icon: <Icon.Text />, content: <StringsPanel /> },
              { value: 'regtl', label: 'Reg Timeline', icon: <Icon.Graph />, content: <RegTimelinePanel /> },
              { value: 'dataflow', label: 'Dataflow', icon: <Icon.Flow />, content: <DataflowGraphPanel /> },
            ]}
          />
        </Panel>
      </div>
      <Splitter
        direction="horizontal"
        title="拖拽调整上下面板比例"
        onDrag={(delta) => {
          const total = containerRef.current?.clientHeight || 800;
          setLiveRatio((r0) => {
            const next = Math.min(Math.max(r0 + delta / total, 0.15), 0.85);
            liveRatioRef.current = next;
            return next;
          });
        }}
        onCommit={() => setSplitRatio(liveRatioRef.current)}
      />
      <div className="center-bottom" style={{ flex: `${1 - liveRatio} 1 0`, minHeight: 80 }}>
        <Panel noPadding>
          <GroupedTabs
            categories={bottomCategories}
            value={bottomTab}
            onValueChange={setBottomTab}
          />
        </Panel>
      </div>
    </div>
  );
}
