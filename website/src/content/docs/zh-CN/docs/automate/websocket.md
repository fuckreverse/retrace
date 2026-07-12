---
title: WebSocket 与流式推送
sidebar:
  order: 5
---

WebSocket 服务使用二进制 FlatBuffers 协议实时流式推送分析结果、Trace 事件和状态变化到远程客户端。

## 启动服务

```bash
./tenet trace.bin --ws-port 9090
```

## 协议

- **传输层：** WebSocket，使用配置端口。
- **Schema：** FlatBuffers（`.fbs` 定义在 Tenet 源码中）。二进制编码，无 JSON 解析开销。
- **方向：** 服务端推送事件；客户端订阅主题。

## 事件主题

| 主题 | 内容 |
|---|---|
| `timeline` | 指令光标移动、导航事件 |
| `pass_state` | Pass 状态变更（启动、进度、完成、失败） |
| `analysis_result` | 结构化 Pass 完成结果 |
| `register_update` | 当前光标处寄存器值变化 |
| `memory_update` | 内存区域变化 |
| `breakpoint` | 断点/观察点命中事件 |

## 使用模式

- **实时仪表板：** 构建基于 Web 的 Trace 监控，随分析进展更新。
- **远程协作：** 多个客户端连接同一 Tenet 实例，看到相同光标和结果。
- **CI 集成：** CI 任务打开 Trace、运行 Pass、流式传输结果后退出。
- **自定义可视化：** 使用流式事件在 Web UI 中渲染 CFG、污点图或内存热图。

## 连接生命周期

1. 客户端连接 `ws://host:port`。
2. 客户端订阅一个或多个主题。
3. 服务端推送已订阅主题的事件。
4. 客户端也可在同一连接上发送 JSON-RPC 请求进行交互查询。
5. 断开后服务端继续会话；下一个客户端重连到同一状态。

## 限制

- WebSocket 流式推送需要活跃的 Tenet 进程，不是离线 API。
- FlatBuffers schema 跨版本不保证稳定；升级 Tenet 时客户端可能需要更新。
- 高频事件（如每条指令的光标移动）可能需要客户端节流或防抖。
