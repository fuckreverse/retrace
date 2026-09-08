/**
 * 全局 trace 状态 —— 复刻 GUI 的"Instructions 游标驱动一切"模型。
 * navigate_to(instId) 会联动刷新 Registers / Memory / CallStack / CFG 高亮。
 */
import { create } from 'zustand';
import { api, getDataSource, type DataSource } from '@/api/service';
import type { TraceInfo } from '@/types/tenet';

/** 服务端导航推送订阅句柄（模块级，跨 init 复用避免重复订阅） */
let serverNavUnsub: (() => void) | null = null;

/** 服务端书签变更推送订阅句柄（同上，模块级复用） */
let bookmarkEvtUnsub: (() => void) | null = null;

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

  // Instructions 面板当前可视区间
  viewportStart: number;
  viewportEnd: number;

  // 高亮集合(taint / producer chain)
  taintForward: Set<number>;
  taintBackward: Set<number>;
  producerChain: Set<number>;

  // Goto / Search 弹窗（对齐 GUI nav_goto / nav_search，快捷键 G / ）
  showGotoDialog: boolean;
  showSearchDialog: boolean;
  openGotoDialog: () => void;
  closeGotoDialog: () => void;
  openSearchDialog: () => void;
  closeSearchDialog: () => void;

  // 线程过滤（多线程 trace）：选中线程集合 → 指令视图只显示这些线程的指令。
  // includedInstSet 为压缩的区间并集（[start, end) 半开），由 thread_filter
  // MCP 工具返回的 filtered_ranges 展开；空集合 = 无过滤。
  threadFilterIds: number[];
  threadFilterRanges: Array<[number, number]>;
  threadFilterCount: number;
  setThreadFilter: (ids: number[], ranges: Array<[number, number]>, count: number) => void;
  clearThreadFilter: () => void;
  threadFilterIncludes: (instId: number) => boolean;
  threadFilterFirstInst: () => number | null;

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
  setViewport: (start: number, end: number) => void;
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
  viewportStart: 0,
  viewportEnd: 0,
  taintForward: new Set(),
  taintBackward: new Set(),
  producerChain: new Set(),
  showGotoDialog: false,
  showSearchDialog: false,
  openGotoDialog() { set({ showGotoDialog: true }); },
  closeGotoDialog() { set({ showGotoDialog: false }); },
  openSearchDialog() { set({ showSearchDialog: true }); },
  closeSearchDialog() { set({ showSearchDialog: false }); },

  async init() {
    set({ loading: true });
    const [info, bookmarks] = await Promise.all([api.traceInfo(), api.getBookmarks()]);
    set({
      info,
      totalInst: info.instruction_count,
      dataSource: getDataSource(),
      loading: false,
      currentInst: 0,
      history: [0],
      historyPos: 0,
      bookmarks: new Set(bookmarks),
    });

    // 订阅服务端导航推送（GUI / 其他客户端触发）——不回推、不入历史，避免回环
    if (!serverNavUnsub) {
      serverNavUnsub = api.onServerNavigation((instId) => {
        if (instId === get().currentInst) return;
        get().navigateTo(instId, true, /* notifyBackend */ false);
      });
    }

    // 订阅服务端书签变更推送（EvtBookmarkChanged，GUI / 其他客户端触发的
    // 书签操作）。本窗口自己的 toggleBookmark 也广播此事件，但服务端返回
    // 的是权威集合，重复 set 同值无副作用且不会回环（不触发新的 WS 调用）。
    if (!bookmarkEvtUnsub) {
      bookmarkEvtUnsub = api.onBookmarkChanged((bookmarks) => {
        set({ bookmarks: new Set(bookmarks) });
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
    // 乐观本地更新，保证点击的即时反馈
    const bm = new Set(get().bookmarks);
    if (bm.has(instId)) bm.delete(instId);
    else bm.add(instId);
    set({ bookmarks: bm });
    // 同步到服务端（真实持久化 + 跨客户端同步），以服务端返回的权威集合为准
    void api.toggleBookmark(instId).then((serverBm) => {
      set({ bookmarks: new Set(serverBm) });
    });
  },

  setHexAddr(addr) {
    set({ hexAddr: addr });
  },

  setViewport(start, end) {
    set({ viewportStart: start, viewportEnd: end });
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

  // ── 线程过滤 ─────────────────────────────────────────────────────────
  threadFilterIds: [],
  threadFilterRanges: [],
  threadFilterCount: 0,
  setThreadFilter(ids, ranges, count) {
    set({ threadFilterIds: ids, threadFilterRanges: ranges, threadFilterCount: count });
    // 过滤开启后，若当前指令不在过滤集内，跳到第一条可见指令
    const { currentInst, navigateTo } = get();
    if (!get().threadFilterIncludes(currentInst)) {
      const first = get().threadFilterFirstInst();
      if (first !== null) navigateTo(first, true, false);
    }
  },
  clearThreadFilter() {
    set({ threadFilterIds: [], threadFilterRanges: [], threadFilterCount: 0 });
  },
  threadFilterIncludes(instId) {
    const ranges = get().threadFilterRanges;
    if (ranges.length === 0) return true;
    // 二分：ranges 按升序、互不重叠（Roaring 迭代序保证）
    let lo = 0, hi = ranges.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const r = ranges[mid]!;
      if (instId < r[0]) hi = mid - 1;
      else if (instId >= r[0] + r[1]) lo = mid + 1;
      else return true;
    }
    return false;
  },
  threadFilterFirstInst() {
    const ranges = get().threadFilterRanges;
    return ranges.length > 0 ? ranges[0]![0] : null;
  },
}));
