---
title: JSON-RPC 服务
sidebar:
  order: 3
---

JSON-RPC 服务通过标准协议暴露全部分析能力。启动方式：

```bash
./tenet trace.bin --rpc-port 4321
```

或从 GUI 会话中使用 **File → Start RPC Server**。

## 协议

TCP 上的 JSON-RPC 2.0。每个请求是一个 JSON 对象，每个响应也是一个 JSON 对象。进度事件支持 Notification（无 `id`）。

## 核心方法

| 方法 | 描述 |
|---|---|
| `open_trace` | 按路径打开 Trace 文件 |
| `close_trace` | 关闭当前 Trace |
| `trace_info` | 获取元数据与会话状态 |
| `list_passes` | 列出可用 Pass 及其状态 |
| `run_pass` | 按名称运行 Pass，支持可选参数 |
| `pass_result` | 获取缓存的 Pass 结果 |
| `cancel_pass` | 取消正在运行的 Pass |

## 状态查询

| 方法 | 描述 |
|---|---|
| `get_registers` | 指令 ID 处的寄存器值 |
| `get_memory` | 指令 ID 处的内存区域 |
| `get_hex_dump` | 指定地址和时刻的原始字节 |
| `get_call_stack` | 指令 ID 处的动态调用栈 |
| `get_functions` | 列出已观察函数 |
| `get_xrefs` | PC 的 XRef 出现 |

## 导航

| 方法 | 描述 |
|---|---|
| `goto_inst` | 跳转到指令 ID |
| `goto_pc` | 跳转到运行时 PC |
| `set_breakpoint` | 设置 PC 断点 |
| `set_watchpoint` | 设置内存写观察点 |
| `list_breakpoints` | 列出活跃断点/观察点 |

## 分析快捷方法

| 方法 | 描述 |
|---|---|
| `taint_forward` | 运行前向污点 |
| `taint_backward` | 运行反向污点 |
| `cfg_export` | 导出 CFG 为 DOT |
| `call_graph` | 导出调用图为 DOT |
| `functions` | 列出/搜索函数 |
| `find_function` | 按名称或地址查找函数 |
| `strings` | 列出已发现字符串 |
| `objc_messages` | 列出 ObjC 消息 |
| `loops` | 列出循环 |
| `algorithm_summary` | 获取算法候选 |
| `pattern_results` | 获取模式扫描结果 |
| `entropy_analysis` | 运行熵分析 |
| `mem_search` | 搜索内存 |
| `vm_abstract` | 运行 VM abstract 分析 |

## 进度与取消

长时间分析会发送进度通知。使用 `cancel_pass` 取消。取消后结果保留在最近完成的 checkpoint 缓存中。

## 集成模式

- 用 Python JSON-RPC 客户端库连接。
- 自动化重复分析：打开、运行 Pass、导出、关闭。
- 桥接到需要结构化分析结果的其他工具。
- 与 MCP 服务配合，构建 LLM 分析工作流。
