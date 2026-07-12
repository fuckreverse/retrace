---
title: MCP 服务
sidebar:
  order: 4
---

Model Context Protocol (MCP) 服务允许 LLM 代理和 IDE 集成通过结构化工具接口查询分析结果、导航时间轴和触发 Pass。

## 启动服务

```bash
./tenet trace.bin --mcp-port 13337
```

或从 GUI 会话中使用 **File → Start MCP Server**。服务使用与运行中 GUI/TUI/CLI 相同的会话和 Pass 结果。

## 可用工具

MCP 工具镜像 JSON-RPC 方法，并附加元数据和结构化参数 schema：

### 会话与 Trace

- `trace_info` — Trace 元数据、格式版本、模块信息
- `list_passes` — 可用 Pass 目录及状态
- `run_pass` — 按名称运行 Pass，支持可选参数
- `pass_result` — 获取已完成 Pass 的缓存结果
- `cancel_pass` — 取消正在运行的 Pass

### 导航

- `goto_inst` — 跳转到指令 ID
- `goto_pc` — 跳转到运行时 PC
- `set_breakpoint` / `set_watchpoint` — 设置 PC 或内存断点
- `list_breakpoints` — 列出活跃断点

### 状态查询

- `get_registers` — 指令处的 GPR 状态
- `get_memory` — 某时刻的内存区域
- `get_hex_dump` — 原始字节 dump
- `get_call_stack` — 动态调用栈

### 分析

- `taint_forward` / `taint_backward` — 污点分析
- `cfg_export` — 导出 CFG 为 DOT
- `call_graph` — 导出调用图
- `functions` / `find_function` — 函数查询
- `xref` — PC 的 XRef 出现
- `strings` — 已发现字符串
- `objc_messages` — ObjC 消息分析
- `loops` — 循环信息
- `algorithm_summary` — 算法候选
- `pattern_results` — 模式扫描结果
- `entropy_analysis` — 熵测量
- `mem_search` — 内存值/模式搜索
- `vm_abstract` — VM handler 分析

### 地址重基

- `rebase_addr` — 使用 Trace 的 `module_slide` 在运行时地址与静态地址间转换。携带地址到/从 IDA 或 Ghidra 时使用此工具，而非手工算术。

## 与 IDA 集成

Tenet 的 MCP 服务设计为与 IDA 自身的 MCP hub 协同工作。典型流程：

1. 在 Tenet 中用 `--mcp-port` 打开 Trace。
2. 在 IDA 中打开同一二进制文件及其 MCP 服务。
3. 使用同时连接两个服务的 MCP 客户端（或 IDE 集成）。
4. 用 IDA 获得的地址在 Tenet 中查询动态证据（污点、值、调用栈）。
5. 使用 `rebase_addr` 在运行时（Tenet）和静态（IDA）地址间翻译。

## 限制

- MCP 服务要求有活跃的 Tenet 进程和已打开的 Trace。
- 共享相同的会话锁：同一 Trace 同时只能被一个进程拥有。
- 长时间 Pass 返回进度通知；客户端必须处理这些通知。
- 部分高级参数未通过 MCP 暴露；精细控制请使用 JSON-RPC 或 CLI。
