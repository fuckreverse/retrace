/**
 * 应用外壳布局 —— 复刻 GUI 主窗口：
 * 标题栏 / 工具栏 / (左栏 · 中央上下 · 右栏上下) / 时间线 / 状态栏
 */
import { useCallback, useEffect } from 'react';
import * as Tooltip from '@radix-ui/react-tooltip';
import { useTraceStore } from '@/store/traceStore';
import { useNativeMenu } from '@/hooks/useNativeMenu';
import { initWindowSync } from '@/lib/windowSync';
import { api, subscribeDataSource } from '@/api/service';
import { startTaskMonitor } from '@/store/taskStore';
import { showToast } from '@/lib/toast';
import { followCall, followReturn } from '@/lib/nav';
import { ToastHost } from '@/components/ToastHost';
import { TitleBar } from './TitleBar';
import { Toolbar } from './Toolbar';
import { Timeline } from './Timeline';
import { StatusBar } from './StatusBar';
import { CenterArea } from './CenterArea';
import { SidebarLeft } from './SidebarLeft';
import { SidebarRight } from './SidebarRight';
import { GotoDialog, SearchDialog } from './GotoSearchDialog';
import './shell.css';

/* ------------------------------------------------------------------ */
/*  函数起始点缓存（n / p 键跳转用，模块级，跨 keydown 事件复用）          */
/* ------------------------------------------------------------------ */

/** 全部函数首次执行指令 id（升序）；null = 尚未构建，[] = 构建过但为空/失败 */
let funcStarts: number[] | null = null;
/** 缓存构建中标志：重复按键去重，避免并发构建 */
let funcStartsBuilding = false;

/**
 * 构建函数起始指令 id 缓存：
 * 对每个函数入口 pc 调 xref 取 inst_ids[0]（首次执行点）。
 * 用并发池（每批 8 个）避免一次性数百请求；函数数 > 500 时放弃构建
 * （避免真实大 trace 首次按 n 卡顿）。
 */
async function buildFuncStarts(): Promise<number[]> {
  const funcs = await api.functions();
  if (funcs.length > 500) return [];

  const starts: number[] = [];
  const CONCURRENCY = 8;
  let next = 0;
  const worker = async () => {
    while (next < funcs.length) {
      const f = funcs[next++];
      try {
        const res = await api.xref(f.pc);
        if (res.inst_ids.length > 0) starts.push(res.inst_ids[0]);
      } catch {
        // 单个函数 xref 失败不影响整体，跳过
      }
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, funcs.length) }, worker),
  );
  starts.sort((a, b) => a - b);
  return starts;
}

export function Shell() {
  const init = useTraceStore((s) => s.init);
  const loading = useTraceStore((s) => s.loading);
  const navBack = useTraceStore((s) => s.navBack);
  const navForward = useTraceStore((s) => s.navForward);
  const step = useTraceStore((s) => s.step);
  const openGotoDialog = useTraceStore((s) => s.openGotoDialog);
  const openSearchDialog = useTraceStore((s) => s.openSearchDialog);
  const toggleBookmark = useTraceStore((s) => s.toggleBookmark);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const currentInst = useTraceStore((s) => s.currentInst);
  const totalInst = useTraceStore((s) => s.totalInst);

  /** 跳转到下一个（dir=1）/ 上一个（dir=-1）函数的首次执行指令 */
  const nextFunction = useCallback(async (dir: 1 | -1) => {
    if (funcStarts === null) {
      if (funcStartsBuilding) return; // 构建中重复按键去重
      funcStartsBuilding = true;
      try {
        funcStarts = await buildFuncStarts();
      } catch {
        funcStarts = []; // 构建失败按空处理，不再重试
      } finally {
        funcStartsBuilding = false;
      }
    }
    if (funcStarts.length === 0) return;
    // 读最新游标，避免闭包里 currentInst 过期
    const cur = useTraceStore.getState().currentInst;
    let target: number | undefined;
    if (dir === 1) {
      target = funcStarts.find((s) => s > cur); // 最小的大于 cur 的起点
    } else {
      for (let i = funcStarts.length - 1; i >= 0; i--) {
        if (funcStarts[i] < cur) { target = funcStarts[i]; break; } // 最大的小于 cur 的起点
      }
    }
    if (target !== undefined) navigateTo(target);
  }, [navigateTo]);

  // 原生菜单事件桥接（仅 Tauri 生效，浏览器 no-op）
  useNativeMenu();

  useEffect(() => {
    init();
  }, [init]);

  // 主窗口：广播 store 状态给弹出的面板窗口（跨窗口实时联动）
  useEffect(() => initWindowSync(), []);

  // 全局后台任务监视（GetProgress 轮询 + pass 完成事件 → 日志/toast），
  // 供 StatusBar 运行指示器与 AnalysisPanel 共享；幂等，应用生命周期一次。
  useEffect(() => { startTaskMonitor(); }, []);

  // 后端连接降级提示：live → mock 的转换只发生一次（service.ts 内部去重），
  // 用 toast 明确告知“当前看到的是假数据”，避免用户把 mock 当成真实结果。
  useEffect(() => subscribeDataSource((s) => {
    if (s === 'mock') {
      showToast('error', '后端连接不可用，已降级 Mock 数据（当前展示的不是真实分析结果）');
    }
  }), []);

  // 全局快捷键
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      // 排除任何"主修饰键"（macOS: Cmd/metaKey；Windows/Linux: Ctrl/ctrlKey）
      // 组合，避免和菜单快捷键 / 浏览器或系统快捷键（如 Ctrl+↓ 的桌面切换、
      // Cmd/Ctrl+G 的浏览器"查找下一个"、Cmd/Ctrl+B 的书签栏切换）冲突。
      // 这些单键绑定都是无修饰键的裸键快捷键，一旦按下 Cmd/Ctrl 就必须放行
      // 给浏览器/系统/原生菜单处理，而不是仍按 e.key 命中触发。
      const modPressed = e.metaKey || e.ctrlKey;
      if (e.altKey && e.key === 'ArrowLeft') { navBack(); e.preventDefault(); }
      else if (e.altKey && e.key === 'ArrowRight') { navForward(); e.preventDefault(); }
      else if (modPressed) { /* 交给浏览器/系统/原生菜单处理，不拦截 */ }
      else if (e.key === 'ArrowDown') { step(1); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { step(-1); e.preventDefault(); }
      else if (e.key === 'g' || e.key === 'G') { openGotoDialog(); e.preventDefault(); }
      else if (e.key === '/') { openSearchDialog(); e.preventDefault(); }
      else if (e.key === 'b' || e.key === 'B') { toggleBookmark(currentInst); e.preventDefault(); }
      else if (e.key === 'Home') { navigateTo(0); e.preventDefault(); }
      else if (e.key === 'End') { navigateTo(Math.max(0, totalInst - 1)); e.preventDefault(); }
      else if (e.key === 'PageDown') { step(64); e.preventDefault(); }   // 大步快进
      else if (e.key === 'PageUp') { step(-64); e.preventDefault(); }    // 大步快退
else if (e.key === 'n' || e.key === 'N') { void nextFunction(1); e.preventDefault(); }
else if (e.key === 'p' || e.key === 'P') { void nextFunction(-1); e.preventDefault(); }
else if (e.key === 'f' || e.key === 'F') {
  // 跟踪调用：当前指令是 bl 时跳到被调函数首次执行点
  void followCall(currentInst).then((ok) => { if (!ok) showToast('info', '当前指令不是直接调用（bl）'); });
  e.preventDefault();
}
else if (e.key === 'r' || e.key === 'R') {
  // 跟踪返回：当前指令是 ret 时跳回调用点下一条指令
  void followReturn(currentInst).then((ok) => { if (!ok) showToast('info', '当前指令不是返回（ret）或无调用者帧'); });
  e.preventDefault();
}
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navBack, navForward, step, openGotoDialog, openSearchDialog, toggleBookmark, currentInst, navigateTo, totalInst, nextFunction]);

  if (loading) {
    return (
      <div className="boot-screen">
        <div className="boot-logo">tenet</div>
        <div className="boot-spinner" />
        <div className="boot-hint">正在加载 trace…</div>
      </div>
    );
  }

  return (
    <Tooltip.Provider delayDuration={400}>
      <div className="shell">
        <TitleBar />
        <Toolbar />
        <div className="shell-main">
          <SidebarLeft />
          <CenterArea />
          <SidebarRight />
        </div>
        <Timeline />
        <StatusBar />
        <ToastHost />
        <GotoDialog />
        <SearchDialog />
      </div>
    </Tooltip.Provider>
  );
}
