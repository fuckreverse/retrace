/**
 * 统一剪贴板复制助手 —— 补齐"复制操作无反馈"的缺口。
 *
 * 以前各面板直接调 navigator.clipboard?.writeText(...)：
 *   - 权限受限 / 非安全上下文（HTTP、headless）下静默 reject，用户以为复制了实际没有；
 *   - 各面板零散处理，无法统一提示。
 *
 * 本助手：
 *   - 优先走 Clipboard API；
 *   - 失败时回退 execCommand('copy')（覆盖 http / 旧内核场景）；
 *   - 仍然失败则 toast 明确报错（不再静默）。成功不弹 toast（保持安静）。
 */
import { showToast } from './toast';

/** execCommand 兜底：创建临时 textarea 完成复制（同步、兼容旧环境）。 */
function fallbackCopy(text: string): boolean {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

/**
 * 复制文本到剪贴板。成功静默；失败 toast 报错（label 用于提示内容类别，
 * 如 '地址' / '函数名' / '调用栈'）。
 */
export async function copyText(text: string, label?: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch {
    /* Clipboard API 不可用或被拒 → 走兜底 */
  }
  if (fallbackCopy(text)) return;
  showToast('error', `复制失败${label ? `：${label}` : ''}（浏览器剪贴板权限受限）`);
}
