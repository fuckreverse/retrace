/**
 * 菜单单一事实源 —— 对照 tenet GUI (src/gui/gui_chrome.cpp render_menu_bar) 的完整层级移植。
 *
 * 同一份定义同时驱动：
 *   1. 浏览器：TitleBar 里的 HTML 下拉菜单（MenuBar 组件）
 *   2. Tauri：macOS 原生菜单栏（Rust lib.rs 依据同样的 id/label 构建）
 *   3. 事件处理：useNativeMenu.handleMenu(id) 按 id 分发到 store actions / tab 跳转
 *
 * GUI 菜单结构（移植来源）：
 *   File     : Open Trace… / Open Recent / Quit
 *   View     : Core Panels / Visualization / Analysis Results / Profiling & Diff / Output / Cache / Settings
 *   Navigate : Go to / Search / Back / Forward / First / Last / Bookmark / Follow Call·Return / Taint jumps
 *   Analysis : Data Flow / Structure / Crypto & Pattern / ObjC·API / Profiling / Clear Taint / Clear All
 *   Export   : CFG / Call Graph / Backward Taint Graph / Dataflow Graph
 *   Tools    : Entropy / Memory Snapshot / Mem Search / YARA / Mem Write History / Call Context / Dataflow from Cursor
 *
 * 由于 Web 端与 GUI 面板并非一一对应，映射规则见 useNativeMenu.handleMenu：
 *   - "打开某面板" 类项 → 切换到对应 tab 组的 tab（tabTarget）
 *   - 导航 / 主题 / 清理 类项 → 直接调用 store action（storeAction）
 *   - 尚未接入后端的项标记 disabled，保留结构以对齐 GUI
 */

/** tab 所在的 4 个分组容器（与 SidebarLeft / SidebarRight / CenterArea 对应） */
export type TabGroup = 'left' | 'right' | 'center-top' | 'center-bottom';

/** 叶子菜单项 */
export interface MenuLeaf {
  kind: 'item';
  /** 全局唯一 id，Rust 侧构建原生菜单项时复用；也是事件名 `menu://<id>` 的后缀 */
  id: string;
  label: string;
  /** 展示用快捷键提示（如 "Cmd+O"），不绑定实际按键触发，仅对齐 GUI 观感 */
  shortcut?: string;
  /** 灰显（功能尚未接入或依赖未满足），仅展示结构 */
  disabled?: boolean;
}

/** 分隔线 */
export interface MenuSeparator {
  kind: 'separator';
}

/** 子菜单（可嵌套） */
export interface MenuSubmenu {
  kind: 'submenu';
  id: string;
  label: string;
  items: MenuNode[];
}

export type MenuNode = MenuLeaf | MenuSeparator | MenuSubmenu;

/** 顶级菜单 */
export interface TopMenu {
  id: string;
  label: string;
  items: MenuNode[];
}

const sep: MenuSeparator = { kind: 'separator' };
const item = (id: string, label: string, shortcut?: string, disabled?: boolean): MenuLeaf => ({
  kind: 'item',
  id,
  label,
  shortcut,
  disabled,
});
const sub = (id: string, label: string, items: MenuNode[]): MenuSubmenu => ({
  kind: 'submenu',
  id,
  label,
  items,
});

/**
 * 顶级菜单栏定义（对照 GUI）。
 * 注意：macOS 原生第一个子菜单会成为「应用菜单」（About/Quit 区），
 * 因此 Rust 侧会在这些之前额外插入一个 "Tenet" 应用菜单，此处只列业务菜单。
 */
export const MENU_BAR: TopMenu[] = [
  // ── File ──────────────────────────────────────────────────────────────
  {
    id: 'file',
    label: 'File',
    items: [
      item('file_open', 'Open Trace…', 'Cmd+O', true),
      sub('file_recent', 'Open Recent', [
        item('file_recent_empty', '(No Recent Files)', undefined, true),
      ]),
      sep,
      item('file_quit', 'Quit', 'Cmd+Q'),
    ],
  },

  // ── View ──────────────────────────────────────────────────────────────
  {
    id: 'view',
    label: 'View',
    items: [
      sub('view_core', 'Core Panels', [
        item('view_registers', 'Registers', 'Cmd+R'),
        item('view_memory', 'Mem Access', 'Cmd+M'),
        item('view_hexdump', 'Hex Dump'),
        sep,
        item('view_callstack', 'Call Stack'),
        item('view_functions', 'Functions'),
        item('view_strings', 'Strings'),
        sep,
        item('view_analysis', 'Analysis'),
      ]),
      sub('view_visual', 'Visualization', [
        item('view_cfg', 'CFG View'),
        item('view_callgraph', 'Call Graph'),
        item('view_regtimeline', 'Register Timeline'),
        item('view_dataflow', 'Dataflow Graph'),
      ]),
      sub('view_results', 'Analysis Results', [
        item('view_patterns', 'Patterns'),
        item('view_constants', 'Constants'),
        item('view_loops', 'Loops'),
        item('view_algorithms', 'Algorithm Summary'),
        sep,
        item('view_objc', 'ObjC Messages'),
        item('view_objccrypto', 'ObjC Crypto'),
        item('view_api', 'API Intercepts'),
        sep,
        item('view_memstrings', 'Memory Strings'),
      ]),
      sub('view_profiling', 'Profiling & Diff', [
        item('view_tracefold', 'Trace Fold'),
        item('view_winstats', 'Window Stats'),
        item('view_dataflow2', 'Dataflow Graph'),
        item('view_regtimeline2', 'Register Timeline'),
        item('view_tracediff', 'Trace Diff'),
        sep,
        item('view_dwarf', 'Symbol Info (DWARF)'),
      ]),
      sep,
      item('view_log', 'Output (Log)'),
      item('view_cache', 'Cache Manager'),
      sep,
      sub('view_newwindow', 'Open in New Window', [
        item('popout_vm', 'VM Workspace'),
      ]),
      sep,
      item('view_settings', 'Settings…', 'Cmd+,'),
      item('view_theme_toggle', 'Toggle Theme'),
    ],
  },

  // ── Navigate ─────────────────────────────────────────────────────────
  {
    id: 'navigate',
    label: 'Navigate',
    items: [
      item('nav_goto', 'Go to Instruction…', 'G', true),
      item('nav_search', 'Search…', '/', true),
      sep,
      item('nav_back', 'Back', 'Alt+←'),
      item('nav_forward', 'Forward', 'Alt+→'),
      sep,
      item('nav_first', 'First Instruction', 'Home'),
      item('nav_last', 'Last Instruction', 'End'),
      sep,
      item('nav_bookmark', 'Toggle Bookmark', 'B'),
    ],
  },

  // ── Analysis ─────────────────────────────────────────────────────────
  {
    id: 'analysis',
    label: 'Analysis',
    items: [
      sub('an_dataflow', 'Data Flow', [
        item('an_taint_fwd', 'Forward Taint…', 'Cmd+T'),
        item('an_taint_back', 'Backward Taint…', 'Cmd+Shift+T'),
        sep,
        item('an_regtimeline', 'Register Timeline'),
        item('an_dataflow_graph', 'Dataflow Graph'),
      ]),
      sub('an_structure', 'Structure', [
        item('an_functions', 'Function Analysis'),
        item('an_strings', 'String Analysis'),
        sep,
        item('an_callgraph', 'Call Graph'),
        item('an_loops', 'Loop Analysis'),
        item('an_cfg', 'CFG Layout'),
      ]),
      sub('an_crypto', 'Crypto & Pattern', [
        item('an_patterns', 'Pattern Detection'),
        item('an_constants', 'Constants'),
        item('an_algorithms', 'Algorithm Summary'),
        item('an_objccrypto', 'ObjC Crypto'),
      ]),
      sub('an_objcapi', 'ObjC / API', [
        item('an_objc', 'ObjC Messages'),
        item('an_api', 'API Intercepts'),
      ]),
      sub('an_profiling', 'Profiling', [
        item('an_tracefold', 'Trace Fold'),
        item('an_winstats', 'Window Stats'),
        item('an_tracediff', 'Trace Diff'),
        item('an_memstrings', 'Memory Strings'),
      ]),
      sep,
      item('an_clear', 'Clear All Analysis'),
    ],
  },

  // ── Export ────────────────────────────────────────────────────────────
  {
    id: 'export',
    label: 'Export',
    items: [
      item('export_cfg', 'Export CFG… (DOT)'),
      item('export_callgraph', 'Export Call Graph… (DOT)'),
      sep,
      item('export_backtaint', 'Export Backward Taint Graph… (DOT)'),
      item('export_dataflow', 'Export Dataflow Graph… (DOT)'),
    ],
  },

  // ── Tools ─────────────────────────────────────────────────────────────
  {
    id: 'tools',
    label: 'Tools',
    items: [
      item('tools_entropy', 'Entropy…'),
      item('tools_snapshot', 'Memory Snapshot…'),
      sep,
      item('tools_memsearch', 'Memory / Value Search…'),
      item('tools_yara', 'YARA Scan…'),
      sep,
      item('tools_memhistory', 'Memory Write History…'),
      item('tools_dataflow_cursor', 'Dataflow Graph from Cursor…'),
    ],
  },
];

/** 递归收集所有叶子 item 的 id（Rust 侧与事件监听按此列表建立 listener / 事件映射） */
export function collectMenuIds(nodes: MenuNode[] = MENU_BAR.flatMap((m) => m.items)): string[] {
  const ids: string[] = [];
  for (const n of nodes) {
    if (n.kind === 'item') ids.push(n.id);
    else if (n.kind === 'submenu') ids.push(...collectMenuIds(n.items));
  }
  return ids;
}

/** 全部可点击叶子 id（供 useNativeMenu 建立监听） */
export const ALL_MENU_IDS: string[] = collectMenuIds();
