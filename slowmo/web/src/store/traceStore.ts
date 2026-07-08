/**
 * 全局 trace 状态 —— 复刻 GUI 的"Instructions 游标驱动一切"模型。
 * navigate_to(instId) 会联动刷新 Registers / Memory / CallStack / CFG 高亮。
 */
import { create } from 'zustand';
import { api, getDataSource, type DataSource } from '@/api/service';
import type { TraceInfo } from '@/types/tenet';

/** 服务端导航推送订阅句柄（模块级，跨 init 复用避免重复订阅） */
let serverNavUnsub: (() => void) | null = null;

interface TraceState {
  info: TraceInfo | null;
  totalInst: number;
  currentInst: number;
  dataSource: DataSource;
  loading: boolean;

  // 导航历史
  history: number[];
  historyPos: number;

  // 书签
  bookmarks: Set<number>;

  // 搜索
  searchQuery: string;
  searchResults: number[];
  searchCurrent: number;

  // Hex Dump 联动地址
  hexAddr: string | null;

  // 高亮集合(taint / producer chain)
  taintForward: Set<number>;
  taintBackward: Set<number>;
  producerChain: Set<number>;

  // actions
  init: () => Promise<void>;
  navigateTo: (instId: number, pushHistory?: boolean, notifyBackend?: boolean) => void;
  step: (delta: number) => void;
  navBack: () => void;
  navForward: () => void;
  canBack: () => boolean;
  canForward: () => boolean;
  toggleBookmark: (instId: number) => void;
  setHexAddr: (addr: string | null) => void;
  setSearch: (query: string, results: number[]) => void;
  searchNext: () => void;
  searchPrev: () => void;
  clearSearch: () => void;
  setTaintForward: (ids: number[]) => void;
  setTaintBackward: (ids: number[]) => void;
  setProducerChain: (ids: number[]) => void;
  clearHighlights: () => void;
}

export const useTraceStore = create<TraceState>((set, get) => ({
  info: null,
  totalInst: 0,
  currentInst: 0,
  dataSource: 'unknown',
  loading: true,
  history: [0],
  historyPos: 0,
  bookmarks: new Set(),
  searchQuery: '',
  searchResults: [],
  searchCurrent: -1,
  hexAddr: null,
  taintForward: new Set(),
  taintBackward: new Set(),
  producerChain: new Set(),

  async init() {
    set({ loading: true });
    const info = await api.traceInfo();
    set({
      info,
      totalInst: info.instruction_count,
      dataSource: getDataSource(),
      loading: false,
      currentInst: 0,
      history: [0],
      historyPos: 0,
    });

    // 订阅服务端导航推送（GUI / 其他客户端触发）——不回推、不入历史，避免回环
    if (!serverNavUnsub) {
      serverNavUnsub = api.onServerNavigation((instId) => {
        if (instId === get().currentInst) return;
        get().navigateTo(instId, true, /* notifyBackend */ false);
      });
    }
  },

  navigateTo(instId, pushHistory = true, notifyBackend = true) {
    const { totalInst, history, historyPos } = get();
    const clamped = Math.max(0, Math.min(instId, Math.max(0, totalInst - 1)));
    if (pushHistory) {
      const newHist = history.slice(0, historyPos + 1);
      newHist.push(clamped);
      set({ currentInst: clamped, history: newHist, historyPos: newHist.length - 1 });
    } else {
      set({ currentInst: clamped });
    }
    // 同步给后端（best-effort，WS 可用才生效）
    if (notifyBackend) void api.navigate(clamped);
  },

  step(delta) {
    get().navigateTo(get().currentInst + delta);
  },

  navBack() {
    const { history, historyPos } = get();
    if (historyPos > 0) {
      const pos = historyPos - 1;
      set({ historyPos: pos, currentInst: history[pos] });
    }
  },

  navForward() {
    const { history, historyPos } = get();
    if (historyPos < history.length - 1) {
      const pos = historyPos + 1;
      set({ historyPos: pos, currentInst: history[pos] });
    }
  },

  canBack: () => get().historyPos > 0,
  canForward: () => get().historyPos < get().history.length - 1,

  toggleBookmark(instId) {
    const bm = new Set(get().bookmarks);
    if (bm.has(instId)) bm.delete(instId);
    else bm.add(instId);
    set({ bookmarks: bm });
  },

  setHexAddr(addr) {
    set({ hexAddr: addr });
  },

  setSearch(query, results) {
    set({ searchQuery: query, searchResults: results, searchCurrent: results.length ? 0 : -1 });
    if (results.length) get().navigateTo(results[0]);
  },

  searchNext() {
    const { searchResults, searchCurrent } = get();
    if (!searchResults.length) return;
    const next = (searchCurrent + 1) % searchResults.length;
    set({ searchCurrent: next });
    get().navigateTo(searchResults[next]);
  },

  searchPrev() {
    const { searchResults, searchCurrent } = get();
    if (!searchResults.length) return;
    const prev = (searchCurrent - 1 + searchResults.length) % searchResults.length;
    set({ searchCurrent: prev });
    get().navigateTo(searchResults[prev]);
  },

  clearSearch() {
    set({ searchQuery: '', searchResults: [], searchCurrent: -1 });
  },

  setTaintForward(ids) {
    set({ taintForward: new Set(ids) });
  },
  setTaintBackward(ids) {
    set({ taintBackward: new Set(ids) });
  },
  setProducerChain(ids) {
    set({ producerChain: new Set(ids) });
  },
  clearHighlights() {
    set({ taintForward: new Set(), taintBackward: new Set(), producerChain: new Set() });
  },
}));
