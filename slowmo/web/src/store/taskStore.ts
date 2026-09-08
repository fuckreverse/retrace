/**
 * 全局后台任务状态 —— 把 GetProgress 轮询从 AnalysisPanel 私有逻辑
 * 提升为应用级单一数据源。
 *
 * 此前的缺口：
 *   1. 只有 AnalysisPanel 轮询进度，且只消费 kind === 'pass' 的任务——
 *      索引重建、流式传输等非 pass 后台任务在任何 UI 上都不可见；
 *   2. StatusBar 对后台活动完全无感知，用户必须切到 Analysis 面板；
 *   3. pass 完成事件只在面板内部消化，不进日志流、无全局提示。
 *
 * 本 store（应用生命周期单例，随 Shell 启动）：
 *   - 500ms 轮询 GetProgress，保存全量任务快照（所有 kind）；
 *   - 订阅 EvtPassCompleted：写入统一日志流（backendLog.appendUiLog），
 *     失败时弹 toast；完成时立即触发一次补拉（不等下一轮轮询）。
 *
 * 消费方：AnalysisPanel（pass + 非 pass 任务）、StatusBar（运行指示器）。
 */
import { create } from 'zustand';
import { api } from '@/api/service';
import type { ProgressTask } from '@/api/ws-api';
import { appendUiLog } from '@/lib/backendLog';
import { showToast } from '@/lib/toast';

/** 轮询间隔：进度条刷新粒度（原 AnalysisPanel 为 250ms，500ms 足够平滑）。 */
const POLL_INTERVAL_MS = 500;

interface TaskState {
  /** 最近一帧全量任务快照（所有 kind，含 pass/索引/流式等）。 */
  tasks: ProgressTask[];
}

export const useTaskStore = create<TaskState>(() => ({ tasks: [] }));

let started = false;
let timer: number | null = null;
let unlistenPass: (() => void) | null = null;
let polling = false;

/** 拉取一帧任务快照（带重入保护：慢响应时跳过本轮，不排队堆积）。 */
export async function refreshTasks(): Promise<void> {
  if (polling) return;
  polling = true;
  try {
    const tasks = await api.progress();
    useTaskStore.setState({ tasks });
  } catch {
    // 后端暂不可达（切换 trace 的窗口期等）：保留上一帧快照，等下次轮询。
    // mock 模式下 api.progress() 固定返回 []，不会走到这里。
  } finally {
    polling = false;
  }
}

/**
 * 启动全局任务监视。幂等，应用生命周期内只启动一次（Shell 挂载时调用）。
 * 不提供 stop：轮询是一条 500ms 的轻量 WS 请求，且切换 trace 期间保持
 * 监听反而能捕获旧后端退出/新后端就绪的边界事件。
 */
export function startTaskMonitor(): void {
  if (started) return;
  started = true;

  void refreshTasks();
  timer = window.setInterval(() => { void refreshTasks(); }, POLL_INTERVAL_MS);

  // pass 结束推送：写统一日志 + 失败 toast + 立即补拉一帧任务快照。
  // 成功完成不弹 toast（Run Default 一次会完成十几个 pass，逐条弹是刷屏），
  // 只写日志流，失败的才升级为 toast。
  unlistenPass = api.onPassCompleted((evt) => {
    const summary = evt.summary ? `：${evt.summary}` : '';
    if (evt.ok) {
      appendUiLog('info', 'pass', `pass "${evt.name}" 完成${summary}`);
    } else {
      appendUiLog('error', 'pass', `pass "${evt.name}" 失败${summary}`);
      showToast('error', `pass "${evt.name}" 运行失败${summary}`);
    }
    void refreshTasks();
  });
}

/** 仅供测试/热重载清理；正常应用流程不调用。 */
export function stopTaskMonitor(): void {
  if (timer !== null) {
    window.clearInterval(timer);
    timer = null;
  }
  unlistenPass?.();
  unlistenPass = null;
  started = false;
}

/* ------------------------------------------------------------------ */
/*  派生选择器（纯函数，供组件 useMemo 消费）                           */
/* ------------------------------------------------------------------ */

/** kind === 'pass' 的任务 → Map<pass 名, 任务>（id 形如 "pass:<name>"）。 */
export function selectPassTasks(tasks: ProgressTask[]): Map<string, ProgressTask> {
  const map = new Map<string, ProgressTask>();
  for (const task of tasks) {
    if (task.kind === 'pass' && task.id.startsWith('pass:')) {
      map.set(task.id.slice('pass:'.length), task);
    }
  }
  return map;
}

/**
 * 非 pass 后台任务（索引重建、流式传输等），过滤掉已完成的历史任务
 * （只保留运行中/排队/失败，避免瞬态任务长期占着列表）。
 */
export function selectBackgroundTasks(tasks: ProgressTask[]): ProgressTask[] {
  return tasks.filter(
    (task) => task.kind !== 'pass' && task.state !== 'completed' && task.state !== 'cancelled',
  );
}

/** 运行中（含排队）的任务。 */
export function selectRunningTasks(tasks: ProgressTask[]): ProgressTask[] {
  return tasks.filter((task) => task.state === 'running' || task.state === 'pending');
}
