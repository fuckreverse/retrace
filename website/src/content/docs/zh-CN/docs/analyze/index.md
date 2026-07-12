---
title: 分析 Trace
sidebar:
  order: 1
---

Tenet 在 Desktop、TUI、CLI、RPC 和 MCP 入口使用相同的核心与分析 Pass。选择下方主题查看完整指南。

## 指南

| 主题 | 目标 |
|---|---|
| [恢复程序结构](./structure/) | 函数、CFG、XRef、循环、调用图 |
| [污点与数据流](./taint/) | 前向污点、反向污点、关键路径、数据流图 |
| [内存、字符串与值搜索](./memory/) | 快照、搜索、熵、YARA、字符串发现 |
| [算法与模式识别](./algorithms/) | 模式扫描、常量、循环语义、算法摘要 |
| [ObjC、系统调用与平台 API](./platform/) | ObjC 消息、系统调用、C API 拦截 |
| [Trace 工具](./trace-tools/) | 折叠、差异、剖析、窗口统计 |
| [虚拟机分析](./vmp/) | VM handler 识别、派发恢复、状态映射 |

## 快速参考

每项分析都是一个 Pass。默认开启的 Pass 自动运行；其余按需启动。完整列表含 CLI 标志和依赖见 [Pass 目录](/zh-CN/docs/reference/pass-catalog/)。

## 分析流程

1. 打开 Trace，等待默认 Pass 完成。
2. 检查恢复的函数、CFG 和 XRef，定位感兴趣区域。
3. 运行目标 Pass：前向/反向污点、模式、内存搜索。
4. 合并证据：算法摘要交叉引用模式+常量+循环+调用图。
5. 导出结果：DOT 图、JSON 报告、剖析数据。
