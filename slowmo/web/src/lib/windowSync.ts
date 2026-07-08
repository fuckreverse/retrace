/**
 * 跨窗口状态同步（同源多窗口 / 多 webview 通用）。
 *
 * 场景：把某个面板（如 VM 工作区）弹出到独立窗口，且要与主窗口「实时联动」——
 * 主窗口移动指令游标 / 改变高亮时，子窗口跟着刷新。
 *
 * 机制：BroadcastChannel（浏览器与 Tauri webview 均原生支持，同源即可通信）。
 *   - 主窗口：订阅 traceStore，变化时广播「可同步切片」。
 *   - 子窗口：监听广播，写回自己的 traceStore（不回传，避免回环）。
 *
 * 只同步「视图游标 / 高亮」这类轻量派生状态；trace 元数据由各窗口自行 init() 拉取，
 * 避免广播大对象。
 */
import { useTraceStore } from '@/store/traceStore';
import { isPanelWindow } from './panelWindow';

const CHANNEL = 'tenet-window-sync';

/** 参与同步的 store 切片 */
export interface SyncState {
  currentInst: number;
  hexAddr: string | null;
  taintForward: number[];
  taintBackward: number[];
  producerChain: number[];
}

interface SyncMessage {
  type: 'state';
  payload: SyncState;
}

function readSyncState(): SyncState {
  const s = useTraceStore.getState();
  return {
    currentInst: s.currentInst,
    hexAddr: s.hexAddr,
    taintForward: [...s.taintForward],
    taintBackward: [...s.taintBackward],
    producerChain: [...s.producerChain],
  };
}

/** 应用远端切片到本地 store（不再触发广播 —— 见 applying 标志） */
let applying = false;
function applySyncState(p: SyncState) {
  applying = true;
  try {
    // 不 push 历史，避免子窗口污染主窗口导航历史语义
    useTraceStore.getState().navigateTo(p.currentInst, false);
    useTraceStore.getState().setHexAddr(p.hexAddr);
    useTraceStore.getState().setTaintForward(p.taintForward);
    useTraceStore.getState().setTaintBackward(p.taintBackward);
    useTraceStore.getState().setProducerChain(p.producerChain);
  } finally {
    applying = false;
  }
}

/**
 * 初始化跨窗口同步。返回清理函数。
 * 只在支持 BroadcastChannel 的环境生效；否则静默 no-op。
 */
export function initWindowSync(): () => void {
  if (typeof window === 'undefined' || typeof BroadcastChannel === 'undefined') {
    return () => {};
  }

  const channel = new BroadcastChannel(CHANNEL);
  const childWindow = isPanelWindow();

  let unsubStore: (() => void) | undefined;
  let lastSent = '';

  if (childWindow) {
    // 子窗口：监听主窗口广播 → 应用到本地
    channel.onmessage = (e: MessageEvent<SyncMessage>) => {
      if (e.data?.type === 'state') applySyncState(e.data.payload);
    };
    // 子窗口打开后主动索要一次当前状态
    channel.postMessage({ type: 'request-state' } as unknown as SyncMessage);
  } else {
    // 主窗口：订阅 store 变化 → 广播；并响应子窗口的初始索取
    const broadcast = () => {
      if (applying) return;
      const state = readSyncState();
      const serialized = JSON.stringify(state);
      if (serialized === lastSent) return;
      lastSent = serialized;
      channel.postMessage({ type: 'state', payload: state } satisfies SyncMessage);
    };
    unsubStore = useTraceStore.subscribe(broadcast);
    channel.onmessage = (e: MessageEvent<{ type?: string }>) => {
      if (e.data?.type === 'request-state') {
        lastSent = ''; // 强制下一次广播
        broadcast();
      }
    };
  }

  return () => {
    unsubStore?.();
    channel.close();
  };
}
