---
title: 自动化分析
sidebar:
  order: 1
---

选择最窄的接口匹配集成需求。所有接口使用相同的 Pass 实现和缓存结果。

## 接口

| 接口 | 适用场景 | 协议 |
|---|---|---|
| [CLI](./cli/) | 批处理、CI、文件导出 | 命令行标志与 stdout |
| [JSON-RPC](./rpc/) | 脚本编程访问 | TCP 上的 JSON-RPC 2.0 |
| [MCP](./mcp/) | LLM 与 IDE 集成 | Model Context Protocol |
| [WebSocket](./websocket/) | 实时仪表板、流式推送 | WebSocket 上的 FlatBuffers |

## 快速开始

```bash
# CLI 批量分析
./tenet trace.bin --pattern --algorithm-summary --export-cfg func.dot

# 启动 JSON-RPC 服务
./tenet trace.bin --rpc-port 4321

# 启动 MCP Hub（LLM 集成，默认 127.0.0.1:10444）
./tenet trace.bin --mcp-hub

# 启动 WebSocket 流式推送
./tenet trace.bin --ws-port 9090
```

所有接口共享同一会话锁：同一 Trace 同时只能被一个进程拥有。结果被缓存并跨接口共享。
