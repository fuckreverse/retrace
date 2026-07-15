import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { api } from '@/api/service';
import type { ProgressTask } from '@/api/ws-api';
import type { PassInfo, PassState } from '@/types/tenet';
import { Button } from '@/components/ui';
import { Icon } from '@/components/icons';
import './analysis.css';

const CATEGORY_ORDER = [
  'Structure', 'Taint', 'Crypto-Pattern', 'Memory-String',
  'ObjC-Platform', 'Profile-Trace', 'Misc',
];

const STATE_ICON: Record<PassState, string> = {
  not_run: '·', running: '▶', completed: '✓', failed: '✕',
};

function passState(task: ProgressTask | undefined, fallback: PassState): PassState {
  if (!task) return fallback;
  if (task.state === 'running' || task.state === 'pending') return 'running';
  if (task.state === 'completed') return 'completed';
  return 'failed';
}

export function AnalysisPanel() {
  const [passes, setPasses] = useState<PassInfo[]>([]);
  const [tasks, setTasks] = useState<Map<string, ProgressTask>>(new Map());
  const [submitting, setSubmitting] = useState<Set<string>>(new Set());

  const refreshPasses = useCallback(() => { void api.passes().then(setPasses); }, []);
  const refreshProgress = useCallback(async () => {
    const snapshot = await api.progress();
    setTasks(new Map(snapshot.filter((task) => task.kind === 'pass')
      .map((task) => [task.id.slice('pass:'.length), task])));
  }, []);

  useEffect(() => { refreshPasses(); void refreshProgress(); }, [refreshPasses, refreshProgress]);
  useEffect(() => {
    const timer = window.setInterval(() => { void refreshProgress(); }, 250);
    return () => window.clearInterval(timer);
  }, [refreshProgress]);

  const grouped = useMemo(() => {
    const groups = new Map<string, PassInfo[]>();
    for (const pass of passes) {
      if (!groups.has(pass.category)) groups.set(pass.category, []);
      groups.get(pass.category)!.push(pass);
    }
    return groups;
  }, [passes]);

  const runningCount = [...tasks.values()].filter((task) => task.state === 'running').length;

  const runPass = async (name: string) => {
    setSubmitting((current) => new Set(current).add(name));
    try {
      const result = await api.runPass(name);
      if (!result.ok) return;
      await refreshProgress();
    } finally {
      setSubmitting((current) => {
        const next = new Set(current);
        next.delete(name);
        return next;
      });
    }
  };

  const clearAll = async () => {
    await api.clearAnalysis();
    await Promise.all([refreshProgress(), Promise.resolve(refreshPasses())]);
  };

  return (
    <div className="analysis-panel">
      <div className={clsx('analysis-banner', runningCount > 0 && 'running')}>
        {runningCount > 0 ? <>
          <div className="mini-spinner" />
          <span>分析进行中… ({runningCount})</span>
        </> : <>
          <Icon.Dot style={{ color: 'var(--success)', width: 14 }} />
          <span>就绪 · {passes.filter((pass) => passState(tasks.get(pass.name), pass.state) === 'completed').length}/{passes.length} 已完成</span>
          <Button size="sm" variant="ghost" style={{ marginLeft: 'auto' }} onClick={clearAll}>Clear All</Button>
        </>}
      </div>

      <div className="analysis-scroll">
        {CATEGORY_ORDER.filter((category) => grouped.has(category)).map((category) => (
          <div key={category} className="pass-group">
            <div className="pass-group-title">{category}</div>
            {grouped.get(category)!.map((pass) => {
              const task = tasks.get(pass.name);
              const state = passState(task, pass.state);
              const busy = state === 'running' || submitting.has(pass.name);
              return (
                <div key={pass.name} className={clsx('pass-row', `state-${state}`)}>
                  <span className={clsx('pass-icon', `pi-${state}`)}>{STATE_ICON[state]}</span>
                  <div className="pass-main">
                    <div className="pass-name">{pass.display_name}</div>
                    {busy ? <>
                      <div className="pass-progress">
                        <div className="pass-progress-fill" style={{ width: `${Math.round((task?.progress ?? 0) * 100)}%` }} />
                      </div>
                      <div className="pass-summary dim">{Math.round((task?.progress ?? 0) * 100)}% · {task?.message || task?.phase}</div>
                    </> : <div className="pass-summary dim">
                      {task?.error || task?.message || pass.summary || (state === 'not_run' ? '未运行' : state === 'failed' ? '运行失败' : '')}
                    </div>}
                  </div>
                  <div className="pass-ctrl">
                    {!busy && <button className="pass-btn" onClick={() => void runPass(pass.name)}>
                      {state === 'completed' ? <Icon.Refresh /> : <Icon.Play />}
                    </button>}
                    {busy && <span className="dim mono">运行中…</span>}
                  </div>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}
