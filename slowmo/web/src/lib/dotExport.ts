/**
 * Graphviz DOT 导出工具：把分析结果序列化为可移植的文本图，并触发浏览器下载。
 */
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
    'digraph CallGraph {',
    '  rankdir=TB;',
    '  node [shape=box, fontname="sans-serif"];',
  ];

  for (const node of cg.nodes) {
    const label = `${node.name}\n${node.pc}\ncalls: ${node.calls_made} / received: ${node.calls_received}`;
    const rootStyle = node.is_root ? ', style=filled, fillcolor=lightgreen' : '';
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
    'digraph Dataflow {',
    '  rankdir=LR;',
    '  node [shape=box, style=filled, fontname="monospace"];',
  ];

  for (const node of df.nodes) {
    const label = node.inst_id != null ? `${node.label}\ninst #${node.inst_id}` : node.label;
    lines.push(`  ${quoted(node.id)} [label=${quoted(label)}, fillcolor=${DATAFLOW_COLORS[node.kind]}];`);
  }

  for (const edge of df.edges) {
    const label = edge.label ? ` [label=${quoted(edge.label)}]` : '';
    lines.push(`  ${quoted(edge.from)} -> ${quoted(edge.to)}${label};`);
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
    'digraph BackwardTaint {',
    `  label=${quoted(title)};`,
    '  labelloc=t;',
    '  rankdir=LR;',
    '  node [shape=box, fontname="monospace"];',
  ];

  steps.forEach((step, index) => {
    const id = `step-${index}`;
    const label = `#${step.inst_id} ${step.pc}\n${step.reg}\n${step.contribution}`;
    lines.push(`  ${quoted(id)} [label=${quoted(label)}];`);
    if (index > 0) {
      lines.push(`  ${quoted(`step-${index - 1}`)} -> ${quoted(id)};`);
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
