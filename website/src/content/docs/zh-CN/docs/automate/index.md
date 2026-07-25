---
title: 自动化分析
sidebar:
  order: 1
---

选择最窄的接口匹配集成需求。所有接口共享同一份后端实现和持久化 Pass 缓存。

## 接口

| 接口 | 适用场景 | 协议 |
|---|---|---|
| [CLI](./cli/) | 批处理、CI、文件导出 | 命令行标志与 stdout |
| [JSON-RPC](./rpc/) | 脚本编程访问 | TCP 上的 JSON-RPC 2.0 |
| [MCP 与 IDA](./mcp/) | LLM、IDE 与 IDAPython 集成 | MCP HTTP 与实例绑定 JSON WebSocket |
| [WebSocket](./websocket/) | 本地 IDA Bridge 或高吞吐前端 | 独立端点上的 Hub JSON-RPC 或 FlatBuffers |

## 快速开始

```bash
# CLI 批量分析
./tenet trace.bin --pattern --algorithm-summary --export-cfg func.dot

# 启动 JSON-RPC 服务
./tenet trace.bin --rpc 4321
# 裸 --rpc 默认监听 127.0.0.1:0，由操作系统自动分配端口

# 启动 MCP Hub（LLM 与 IDA 集成，默认 127.0.0.1:10444）
./tenet trace.bin --mcp-hub
# IDA 使用 ws://127.0.0.1:10444/ws/<instance-id>

# 启动独立 FlatBuffers WebSocket
./tenet trace.bin --ws-port 9090
```

这些接口复用同一份后端实现，并可复用持久化 Pass 缓存；这不表示多个进程能够并发共享同一个 Trace 会话。同一 Trace 受独占会话锁保护，同时只能由一个进程拥有。
