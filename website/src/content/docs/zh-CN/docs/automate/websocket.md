---
title: WebSocket 与流式推送
sidebar:
  order: 5
---

Tenet 提供两套不同的 WebSocket 协议。请按客户端类型选择端点；两者的线上格式不兼容。

| 端点 | 协议 | 适用客户端 |
|---|---|---|
| `ws://127.0.0.1:10444/ws/<instance-id>` | JSON-RPC/MCP 文本帧 | IDAPython 与本地交互式集成 |
| `--ws-port` 提供的 `ws://127.0.0.1:<port>` | FlatBuffers 二进制帧 | Tauri Web 前端与高吞吐可视化 |

## Hub JSON WebSocket

以 Hub 模式启动 Tenet；在 Tauri 桌面应用中打开 Trace 时，对应 sidecar 会以 Hub 模式启动或加入现有 Hub：

```bash
./tenet trace.bin --mcp-hub
```

先通过 `http://127.0.0.1:10444/mcp` 发现实例 ID，再连接：

```text
ws://127.0.0.1:10444/ws/<instance-id>
```

URL 将连接固定绑定到一份 Trace。文本帧承载与 `tools/call` 相同的 JSON-RPC/MCP 请求和响应。端点支持 ping/pong 与 close，校验 RFC 6455 帧和 UTF-8，拒绝二进制应用消息，并限制 payload 大小。

Hub JSON 端点刻意限制为**仅回环访问**，用于 [IDA Pro Bridge](./mcp/#连接-ida-pro) 等本地工具，不应直接暴露到网络。目标 Worker 退出时，Hub 会关闭绑定到该实例的会话，避免客户端继续查询失效状态。

## FlatBuffers WebSocket

在显式端口启动独立二进制服务：

```bash
./tenet trace.bin --ws-port 9090
```

服务端点为 `ws://127.0.0.1:9090`。当前实现固定绑定本机 loopback，没有 CLI 参数可以修改监听 host。

:::caution[Windows 限制]
Windows 上 `TENET_ENABLE_WS` 默认关闭且当前不支持开启：uSockets 的事件循环只有 POSIX epoll/kqueue 后端，尚无接入此构建的 Windows IOCP 后端。因此 `--ws-port` 和供 Tauri Web 前端使用的 FlatBuffers WebSocket 通道暂不支持 Windows。MCP Hub 的 JSON WebSocket 不使用这套 uSockets/FlatBuffers 服务，不受此限制；CLI 批处理、TUI、TCP JSON-RPC 与 MCP 也可正常使用。
:::

### 协议

- **传输层：** 配置端口上的 WebSocket；
- **Schema：** Tenet 源码中的 FlatBuffers `.fbs` 定义；
- **编码：** 二进制帧，无 JSON 解析开销；
- **用途：** 高吞吐前端查询、分析任务与可视化。

该服务独立于 MCP Hub。不要让 IDAPython Bridge 或 JSON-RPC 客户端连接 `--ws-port`，也不要向 `10444` 发送 FlatBuffers 消息。

## 流式索引

WebSocket 传输也不同于 `--streaming`。Streaming 模式会 tail 正在增长的 Trace，并增量更新索引：

```bash
./tenet trace.bin --streaming
```

适合在录制仍进行时提前构建索引；它本身不会创建任何 WebSocket 端点。

## 运行边界

- 两套 WebSocket 都依赖活跃 Tenet 进程和已打开 Trace；
- Hub JSON 会话绑定实例，Worker 消失时会关闭；
- FlatBuffers schema 跨版本不保证稳定，自定义客户端应随 Tenet 更新；
- 交互客户端应限制高数据量请求，并对光标更新做防抖。
