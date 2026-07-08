import { useState } from 'react';
import { Panel } from '@/components/ui';
import { Icon } from '@/components/icons';
import { Tabs } from './Tabs';
import { useSelectTab } from '@/hooks/useSelectTab';
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

const TOP_TABS = ['instructions', 'cfg', 'strings', 'regtl', 'dataflow'] as const;
const BOTTOM_TABS = [
  'analysis', 'callstack', 'patterns', 'algorithms', 'constants', 'loops', 'api', 'objc',
  'objccrypto', 'callgraph', 'taintsrc', 'backtaint', 'memsearch', 'memstrings', 'entropy',
  'yara', 'winstats', 'tracefold', 'tracediff', 'snapshots', 'dwarf', 'vm', 'cache', 'log', 'settings',
] as const;

export function CenterArea() {
  // 上/下 tab 均受控，供菜单（View/Analysis/Export/Tools）定向跳转到指定面板
  const [topTab, setTopTab] = useState<string>('instructions');
  const [bottomTab, setBottomTab] = useState<string>('analysis');

  useSelectTab('center-top', setTopTab, TOP_TABS);
  useSelectTab('center-bottom', setBottomTab, BOTTOM_TABS);

  return (
    <div className="center-area">
      <div className="center-top">
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
      <div className="center-bottom">
        <Panel noPadding>
          <Tabs
            value={bottomTab}
            onValueChange={setBottomTab}
            tabs={[
              { value: 'analysis', label: 'Analysis', icon: <Icon.Layers />, content: <AnalysisPanel /> },
              { value: 'callstack', label: 'Call Stack', icon: <Icon.Stack />, content: <CallStackPanel /> },
              { value: 'patterns', label: 'Patterns', icon: <Icon.Shield />, content: <PatternsPanel /> },
              { value: 'algorithms', label: 'Algorithms', icon: <Icon.Cpu />, content: <AlgorithmPanel /> },
              { value: 'constants', label: 'Constants', icon: <Icon.Dot />, content: <ConstantsPanel /> },
              { value: 'loops', label: 'Loops', icon: <Icon.Refresh />, content: <LoopsPanel /> },
              { value: 'api', label: 'API Intercepts', icon: <Icon.Terminal />, content: <ApiInterceptsPanel /> },
              { value: 'objc', label: 'ObjC', icon: <Icon.Chip />, content: <ObjcPanel /> },
              { value: 'objccrypto', label: 'ObjC×Crypto', icon: <Icon.Shield />, content: <ObjcCryptoPanel /> },
              { value: 'callgraph', label: 'Call Graph', icon: <Icon.Graph />, content: <CallGraphPanel /> },
              { value: 'taintsrc', label: 'Taint Sources', icon: <Icon.Drop />, content: <TaintSourcesPanel /> },
              { value: 'backtaint', label: 'Backward Taint', icon: <Icon.Target />, content: <BackwardTaintPanel /> },
              { value: 'memsearch', label: 'Mem Search', icon: <Icon.Search />, content: <MemorySearchPanel /> },
              { value: 'memstrings', label: 'Mem Strings', icon: <Icon.Text />, content: <MemoryStringsPanel /> },
              { value: 'entropy', label: 'Entropy', icon: <Icon.Chart />, content: <EntropyPanel /> },
              { value: 'yara', label: 'YARA', icon: <Icon.Tag />, content: <YaraPanel /> },
              { value: 'winstats', label: 'Window Stats', icon: <Icon.Chart />, content: <WindowStatsPanel /> },
              { value: 'tracefold', label: 'Trace Fold', icon: <Icon.Layers />, content: <TraceFoldPanel /> },
              { value: 'tracediff', label: 'Trace Diff', icon: <Icon.Diff />, content: <TraceDiffPanel /> },
              { value: 'snapshots', label: 'Snapshots', icon: <Icon.Camera />, content: <SnapshotsPanel /> },
              { value: 'dwarf', label: 'DWARF', icon: <Icon.Box />, content: <DwarfPanel /> },
              { value: 'vm', label: 'VM Workspace', icon: <Icon.Cpu />, content: <VmWorkspacePanel /> },
              { value: 'cache', label: 'Cache', icon: <Icon.Database />, content: <CacheManagerPanel /> },
              { value: 'log', label: 'Log', icon: <Icon.Terminal />, content: <LogPanel /> },
              { value: 'settings', label: 'Settings', icon: <Icon.Filter />, content: <SettingsPanel /> },
            ]}
          />
        </Panel>
      </div>
    </div>
  );
}
