---
title: 文档
description: 按捕获、浏览、分析与自动化目标选择路径。
sidebar:
  order: 0
  label: 概览
---

Tenet 将聚焦的设备端捕获与可复现的离线分析连接起来。请按当前目标选择路径。

## 从这里开始

1. [安装 Tenet](./getting-started/install/)
2. 用 QBDITrace 或兼容采集器[录制 Trace](./capture/)
3. [打开并验证](./getting-started/open-a-trace/)

## 浏览执行历史

[导航时间轴](./explore/)，在任意时刻检查寄存器和内存，在静态历史中设置断点，跟随动态调用和返回。支持 [Desktop GUI](./explore/desktop/) 和 [TUI](./explore/tui/)。

## 分析 Trace

- [恢复程序结构](./analyze/structure/) — 函数、CFG、XRef、循环
- [追踪数据流](./analyze/taint/) — 前向/反向污点、关键路径
- [检查内存与字符串](./analyze/memory/) — 快照、搜索、熵、YARA
- [识别算法](./analyze/algorithms/) — 模式、常量、循环语义
- [平台语义](./analyze/platform/) — ObjC、系统调用、C API 拦截
- [Trace 工具](./analyze/trace-tools/) — 折叠、差异、剖析
- [虚拟机分析](./analyze/vmp/) — handler 识别与派发恢复

## 自动化调查流程

使用 [CLI](./automate/cli/) 执行批处理、[JSON-RPC](./automate/rpc/) 编程访问、[MCP Hub 与 IDA Bridge](./automate/mcp/) 完成静态/动态导航和 LLM 集成，或通过独立的 [WebSocket 协议](./automate/websocket/) 提供本地 JSON-RPC 与高吞吐前端访问。

## 参考

- [Pass 目录](./reference/pass-catalog/) — 每个分析 Pass 的 CLI 标志和依赖
- [兼容性与限制](./reference/compatibility/) — 各能力所需证据及降级行为
- [Trace 格式](./reference/) — 面向自定义采集器的二进制格式规范

> Tenet Desktop 在本地分析 Trace。本网站不会接收你的 Trace 数据。
