import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { api } from '@/api/service';
import type { PassInfo, PassState } from '@/types/tenet';
import { appendUiLog } from '@/lib/backendLog';
import {
  useTaskStore,
  selectPassTasks,
  selectBackgroundTasks,
  refreshTasks,
} from '@/store/taskStore';
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

function passState(task: { state: string } | undefined, fallback: PassState): PassState {
  if (!task) return fallback;
  if (task.state === 'running' || task.state === 'pending') return 'running';
  if (task.state === 'completed') return 'completed';
  return 'failed';
}

/** 后台（非 pass）任务的展示状态映射。 */
function bgTaskState(state: string): PassState {
  if (state === 'running' || state === 'pending') return 'running';
  if (state === 'failed') return 'failed';
  return 'completed';
}

export function AnalysisPanel() {
  const [passes, setPasses] = useState<PassInfo[]>([]);
  const [submitting, setSubmitting] = useState<Set<string>>(new Set());
  const [runningDefault, setRunningDefault] = useState(false);

  // 任务进度来自全局 taskStore（Shell 启动的 500ms 轮询单一数据源），
  // 面板自身不再维护轮询定时器。
  const tasks = useTaskStore((s) => s.tasks);
  const taskMap = useMemo(() => selectPassTasks(tasks), [tasks]);
  const bgTasks = useMemo(() => selectBackgroundTasks(tasks), [tasks]);

  const refreshPasses = useCallback(() => { void api.passes().then(setPasses); }, []);

  useEffect(() => { refreshPasses(); }, [refreshPasses]);

  // 服务端推送（EvtPassCompleted）：pass 一结束就立即刷新目录状态与任务快照
  //（任务快照同时由 taskStore 全局订阅刷新，这里再拉一次目录状态）。
  useEffect(() => {
    return api.onPassCompleted(() => {
      refreshPasses();
      void refreshTasks();
    });
  }, [refreshPasses]);

  const grouped = useMemo(() => {
    const groups = new Map<string, PassInfo[]>();
    for (const pass of passes) {
      if (!groups.has(pass.category)) groups.set(pass.category, []);
      groups.get(pass.category)!.push(pass);
    }
    return groups;
  }, [passes]);

  const runningCount = [...taskMap.values()].filter((task) => task.state === 'running' || task.state === 'pending').length;

  const runPass = async (name: string) => {
    setSubmitting((current) => new Set(current).add(name));
    try {
      const result = await api.runPass(name);
      if (!result.ok) {
        // 请求本身被拒（非法 pass 名 / 后端忙等）：写统一日志流，
        // 不弹 toast——面板内已有即时反馈，toast 留给“用户看不到的地方”。
        appendUiLog('error', 'pass', `pass "${name}" 启动失败：${result.message}`);
        return;
      }
      await refreshTasks();
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
    await Promise.all([refreshTasks(), Promise.resolve(refreshPasses())]);
  };

  // 一键运行后端默认 pass 集（RunDefaultPassesReq，后端串行排队执行）
  const runDefault = async () => {
    setRunningDefault(true);
    try {
      const result = await api.runDefaultPasses();
      if (result.ok) await refreshTasks();
    } finally {
      setRunningDefault(false);
    }
  };

  return (
    <div className="analysis-panel">
      <div className={clsx('analysis-banner', runningCount > 0 && 'running')}>
        {runningCount > 0 ? <>
          <div className="mini-spinner" />
          <span>分析进行中… ({runningCount})</span>
        </> : <>
          <span>已完成 {passes.filter((pass) => passState(taskMap.get(pass.name), pass.state) === 'completed').length}/{passes.length}</span>
          <Button size="sm" variant="ghost" disabled={runningDefault} onClick={() => void runDefault()}>{runningDefault ? '启动中…' : 'Run Default'}</Button>
          <Button size="sm" variant="ghost" style={{ marginLeft: 'auto' }} onClick={clearAll}>Clear All</Button>
        </>}
      </div>

      <div className="analysis-scroll">
        {/* 非 pass 后台任务（索引重建 / 流式传输等）：此前在任何 UI 都不可见 */}
        {bgTasks.length > 0 && (
          <div className="pass-group">
            <div className="pass-group-title">后台任务 · 非 pass</div>
            {bgTasks.map((task) => {
              const state = bgTaskState(task.state);
              return (
                <div key={task.id} className={clsx('pass-row', `state-${state}`)}>
                  <span className={clsx('pass-icon', `pi-${state}`)}>{STATE_ICON[state]}</span>
                  <div className="pass-main">
                    <div className="pass-name">{task.label || task.id}</div>
                    {state === 'running' && <>
                      <div className="pass-progress">
                        <div className="pass-progress-fill" style={{ width: `${Math.round(task.progress * 100)}%` }} />
                      </div>
                      <div className="pass-summary dim">
                        {Math.round(task.progress * 100)}% · [{task.kind}] {task.message || task.phase}
                      </div>
                    </>}
                    {state === 'failed' && (
                      <div className="pass-summary dim">{task.error || `任务失败（${task.kind}）`}</div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {CATEGORY_ORDER.filter((category) => grouped.has(category)).map((category) => (
          <div key={category} className="pass-group">
            <div className="pass-group-title">{category}</div>
            {grouped.get(category)!.map((pass) => {
              const task = taskMap.get(pass.name);
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
