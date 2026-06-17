# tenet MCP Server

通过 Model Context Protocol (MCP) 将 tenet trace 分析能力暴露给 AI 工具（Claude Desktop、CatDesk、Cursor 等）。

## 架构

```
AI Client (Claude/CatDesk/Cursor)
        │ JSON-RPC over stdio
        ▼
tenet_mcp_server.py  (14 tools)
        │ subprocess
        ▼
tenet CLI binary  (C++17, Triton, RocksDB)
        │ mmap zero-copy
        ▼
QBDI trace file (.bin)
```

## 快速开始

### 1. 编译 tenet

```bash
cd tools/tenet
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --target tenet -j$(sysctl -n hw.ncpu)
```

### 2. 配置 MCP client

**CatDesk / Claude Desktop** — 编辑 MCP 配置文件：

```json
{
  "mcpServers": {
    "tenet": {
      "command": "python3",
      "args": ["/path/to/tenet/mcp/tenet_mcp_server.py"],
      "env": {
        "TENET_BIN": "/path/to/tenet/build/tenet"
      }
    }
  }
}
```

**Cursor** — 在 `.cursor/mcp.json` 中添加同样的配置。

### 3. 使用

配置完成后，AI 对话中直接自然语言指示即可：

> "打开 /tmp/trace.bin，帮我看看有哪些加密算法"
>
> "从 x0 在 #1000 开始做前向 taint，看数据流到哪里"
>
> "搜索 PC 0x100abc000 执行了几次"

## 暴露的工具 (14 个)

| 工具 | 说明 |
|------|------|
| `trace_open` | 加载 .bin trace 文件，返回元数据 |
| `trace_info` | 获取已加载 trace 的信息 |
| `disasm` | 反汇编指定范围的指令 |
| `taint_forward` | 基于 Triton 的精确前向污点分析 |
| `taint_backward` | 反向数据流追踪（value 从哪来） |
| `cfg_export` | 导出控制流图 (DOT/JSON) |
| `call_graph` | 构建调用图 |
| `pattern_scan` | 扫描加密/反调试/混淆模式 |
| `strings_scan` | 提取 trace 中的字符串 |
| `regstate` | 查询某条指令处的寄存器状态 |
| `memread` | 时间感知的内存读取 |
| `mem_write_history` | 查某地址的所有写入历史 |
| `critical_path` | 前向+反向 taint 交集，提取关键路径 |
| `search_pc` | 搜索某 PC 在 trace 中出现的所有位置 |

## 协议细节

- **MCP 版本**: 2024-11-05
- **传输**: JSON-RPC 2.0 over stdio (newline-delimited)
- **依赖**: Python 3.9+ 标准库（零外部依赖）
- **超时**: 普通查询 120s，taint/critical_path 300-600s

## 典型 AI 工作流

1. `trace_open` — 加载 trace
2. `pattern_scan` — 快速定位关键区域
3. `search_pc` — 找到目标函数执行点
4. `disasm` — 查看上下文
5. `taint_forward` — 追踪数据流
6. `memread` — 查看具体内存
7. `critical_path` — 提取最小算法路径

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `TENET_BIN` | tenet 二进制路径 | `tenet` (从 PATH 查找) |

## 手动测试

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}' | \
  TENET_BIN=./build/tenet python3 mcp/tenet_mcp_server.py
```

期望返回：
```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"tenet-trace-analyzer","version":"0.1.0"}}}
```
