import type { Locale } from './i18n';

export const copy = {
  en: {
    nav: { product: 'Product', workflow: 'Workflow', useCases: 'Use cases', docs: 'Docs', download: 'Download' },
    home: {
      eyebrow: 'DYNAMIC TRACE ANALYSIS',
      title: 'Instruction trace analysis',
      accent: 'at billion-instruction scale.',
      intro: 'Tenet indexes instruction-level execution traces for random-access state reconstruction and offline analysis. Inspect registers and memory at any recorded instruction, recover executed control flow, and run data-flow, algorithm, and platform analyses.',
      start: 'Get started', download: 'Download Tenet',
    },
    footer: 'Instruction trace indexing, state reconstruction, and offline analysis.',
  },
  'zh-CN': {
    nav: { product: '产品', workflow: '工作流', useCases: '应用场景', docs: '文档', download: '下载' },
    home: {
      eyebrow: '动态 Trace 分析',
      title: '大规模指令 Trace 分析',
      accent: '支持十亿级执行记录。',
      intro: 'Tenet 为指令级执行 Trace 建立索引，支持随机访问状态重建和离线分析。你可以查询任意已录制指令点的寄存器与内存，恢复实际执行过的控制流，并运行数据流、算法和平台分析。',
      start: '快速开始', download: '下载 Tenet',
    },
    footer: '指令 Trace 索引、状态重建与离线分析。',
  },
} satisfies Record<Locale, unknown>;

export function t(locale: Locale) { return copy[locale]; }
