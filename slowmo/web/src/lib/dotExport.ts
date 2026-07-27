/**
 * Graphviz DOT 导出工具：把分析结果序列化为可移植的文本图，并触发浏览器下载。
 */
import { isTauri } from '@/lib/env';
import type {
  BackwardTaintStep,
  CallGraphResult,
  CfgResult,
  DataflowGraph,
  DataflowNode,
} from '@/types/tenet';

/** 转义 DOT 双引号字符串中的特殊字符。 */
function escapeDot(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r\n|\r|\n/g, '\\n');
}

function quoted(value: string): string {
  return `"${escapeDot(value)}"`;
}

export function blocksToDot(cfg: CfgResult): string {
  const lines = [
    'digraph CFG {',
    '  rankdir=TB;',
    '  node [shape=box, fontname="monospace"];',
  ];

  for (const block of cfg.blocks) {
    const label = [
      block.pc,
      block.executions != null ? `executions: ${block.executions}` : undefined,
      ...(block.disasm ?? []),
    ].filter((part): part is string => part != null);
    lines.push(`  ${quoted(block.pc)} [label=${quoted(label.join('\n'))}];`);
  }

  for (const edge of cfg.edges) {
    const label = [
      edge.kind,
      edge.taken_count != null ? String(edge.taken_count) : undefined,
    ].filter((part): part is string => part != null).join(' · ');
    lines.push(`  ${quoted(edge.from)} -> ${quoted(edge.to)}${label ? ` [label=${quoted(label)}]` : ''};`);
  }

  lines.push('}');
  return `${lines.join('\n')}\n`;
}

export function callGraphToDot(cg: CallGraphResult): string {
  const lines = [
    'digraph callgraph {',
    '  node [shape=box, style=filled, fillcolor=lightyellow];',
    '  edge [color=gray40];',
    '',
  ];

  for (const node of cg.nodes) {
    const label = `${node.name}\n${node.pc}\ncalls: ${node.calls_made} / received: ${node.calls_received}`;
    const rootStyle = node.is_root ? ', fillcolor=lightgreen' : '';
    lines.push(`  ${quoted(node.pc)} [label=${quoted(label)}${rootStyle}];`);
  }

  for (const edge of cg.edges) {
    lines.push(`  ${quoted(edge.caller)} -> ${quoted(edge.callee)} [label=${quoted(String(edge.call_count))}];`);
  }

  lines.push('}');
  return `${lines.join('\n')}\n`;
}

const DATAFLOW_COLORS: Record<DataflowNode['kind'], string> = {
  reg: 'lightblue',
  mem: 'lightyellow',
  const: 'lightgray',
  op: 'lightpink',
};

export function dataflowToDot(df: DataflowGraph): string {
  const lines = [
    'digraph dataflow {',
    '  rankdir=TB;',
    '  node [shape=box, style=filled, fillcolor="#e8e8e8", fontname="Courier", fontsize=10];',
    '  edge [fontname="Courier", fontsize=9];',
    '',
  ];

  for (const node of df.nodes) {
    const label = node.inst_id != null ? `#${node.inst_id}: ${node.label}` : node.label;
    const id = node.inst_id != null ? `n${node.inst_id}` : node.id;
    lines.push(`  ${quoted(id)} [label=${quoted(label)}, fillcolor=${DATAFLOW_COLORS[node.kind]}];`);
  }

  const nodeIds = new Map(df.nodes.map((node) => [
    node.id,
    node.inst_id != null ? `n${node.inst_id}` : node.id,
  ]));
  for (const edge of df.edges) {
    const label = edge.label ? ` [label=${quoted(edge.label)}]` : '';
    lines.push(`  ${quoted(nodeIds.get(edge.from) ?? edge.from)} -> ${quoted(nodeIds.get(edge.to) ?? edge.to)}${label};`);
  }

  lines.push('}');
  return `${lines.join('\n')}\n`;
}

export function backwardTaintToDot(
  steps: BackwardTaintStep[],
  instId: number,
  reg: string,
): string {
  const title = `Backward taint from inst #${instId} register ${reg}`;
  const lines = [
    `// Export parameters: current instruction #${instId}, default register ${reg}`,
    'digraph backward_taint {',
    `  label=${quoted(title)};`,
    '  labelloc=t;',
    '  rankdir=BT;',
    '  node [shape=box, style=filled, fillcolor=lightyellow, fontsize=10];',
    '  edge [color=gray40];',
    '',
  ];

  steps.forEach((step, index) => {
    const id = `n${step.inst_id}`;
    const label = `#${step.inst_id} pc=${step.pc} def:${step.reg}\n${step.contribution}`;
    lines.push(`  ${quoted(id)} [label=${quoted(label)}];`);
    if (index > 0) {
      // BackwardTaintStep 暂无 via_reg/via_mem，后端补充字段后可在此扩展边标签。
      lines.push(`  ${quoted(`n${steps[index - 1].inst_id}`)} -> ${quoted(id)};`);
    }
  });

  lines.push('}');
  return `${lines.join('\n')}\n`;
}

export function downloadTextFile(filename: string, content: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: 'text/vnd.graphviz;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.style.display = 'none';
  document.body.appendChild(link);

  try {
    link.click();
  } finally {
    link.remove();
    URL.revokeObjectURL(url);
  }
}

/**
 * 浏览器：直接触发 Blob 下载。
 * Tauri：弹出原生保存对话框选择路径，再通过 Rust 端 `write_text_file` 命令
 * 写入该路径（而非拉入完整的 tauri-plugin-fs——保存路径已经来自可信的原生
 * 对话框，一个窄接口的 command 就够用，也让 capabilities 文件保持最小化）。
 */
export async function saveTextFile(filename: string, content: string): Promise<void> {
  if (!isTauri()) {
    downloadTextFile(filename, content);
    return;
  }

  const { save } = await import('@tauri-apps/plugin-dialog');
  const path = await save({
    defaultPath: filename,
    filters: [{ name: 'Graphviz DOT', extensions: ['dot'] }],
  });
  if (path == null) return;

  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('write_text_file', { path, content });
}
