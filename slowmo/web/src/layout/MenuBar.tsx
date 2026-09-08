/**
 * 浏览器环境下的 HTML 下拉菜单栏 —— 基于 src/lib/menu.ts 渲染，
 * 结构对照 tenet GUI。点击叶子项调用 runMenuAction(id)。
 *
 * Tauri 环境不渲染本组件（由 macOS 原生菜单栏承载，见 TitleBar）。
 */
import * as DropdownMenu from '@radix-ui/react-dropdown-menu';
import { MENU_BAR, type MenuNode } from '@/lib/menu';
import { runMenuAction } from '@/hooks/useNativeMenu';
import { displayShortcut, isTauri } from '@/lib/env';
import './menubar.css';

function renderNodes(nodes: MenuNode[]) {
  return nodes.map((node, i) => {
    if (node.kind === 'separator') {
      return <DropdownMenu.Separator key={`sep-${i}`} className="menu-separator" />;
    }
    if (node.kind === 'submenu') {
      return (
        <DropdownMenu.Sub key={node.id}>
          <DropdownMenu.SubTrigger className="menu-item menu-subtrigger">
            <span className="menu-item-label">{node.label}</span>
            <span className="menu-item-arrow">›</span>
          </DropdownMenu.SubTrigger>
          <DropdownMenu.Portal>
            <DropdownMenu.SubContent className="menu-content" sideOffset={2} alignOffset={-4}>
              {renderNodes(node.items)}
            </DropdownMenu.SubContent>
          </DropdownMenu.Portal>
        </DropdownMenu.Sub>
      );
    }
    // leaf item
    // 快捷键提示诚实化：Tauri 下原生菜单加速键真实生效，一律展示；
    // 浏览器下仅展示 Shell 真实绑定了裸键的项（browserBound），
    // 避免 Cmd+R/Cmd+M 等与浏览器冲突、根本不生效的误导性提示。
    const showShortcut = isTauri() || !!node.browserBound;
    return (
      <DropdownMenu.Item
        key={node.id}
        className="menu-item"
        disabled={node.disabled}
        onSelect={() => runMenuAction(node.id)}
      >
        <span className="menu-item-label">{node.label}</span>
        {node.shortcut && showShortcut && (
          <span className="menu-item-shortcut">{displayShortcut(node.shortcut)}</span>
        )}
      </DropdownMenu.Item>
    );
  });
}

export function MenuBar() {
  return (
    <nav className="titlebar-menu">
      {MENU_BAR.map((top) => (
        <DropdownMenu.Root key={top.id}>
          <DropdownMenu.Trigger asChild>
            <button className="menu-top-trigger">{top.label}</button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="menu-content" sideOffset={4} align="start">
              {renderNodes(top.items)}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      ))}
    </nav>
  );
}
