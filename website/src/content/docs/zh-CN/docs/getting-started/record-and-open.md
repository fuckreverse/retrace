---
title: 录制、打开与第一次分析
sidebar:
  order: 3
---

**目标：** 录制一个 iOS 函数并完成第一次分析。  
**前置条件：** 已部署 QBDITrace、Frida 可连接，并掌握目标静态入口偏移。

本教程以 iOS 为例；Android 捕获请参见对应的[平台指南](/zh-CN/docs/capture/android/)。

## 录制

```bash
python3 tools/qbditrace/qbditrace_runner.py \
  --target com.example.app \
  --entry 0xEE91EC \
  --output /var/mobile/Documents/trace.bin
```

直接配置 C ABI 时必须使用包含 ASLR slide 的运行时地址。Runner 会在其支持的流程中解析模块与 ASLR 信息。

## 打开并导航

在独立的 Tauri 桌面应用中打开 `.bin`。也可以直接运行后端进入默认的终端 TUI：

```bash
./tenet trace.bin
```

首次打开会构建持久化索引，之后可复用。按指令 ID 或 PC 导航，并观察选中指令前后的寄存器变化。

## 运行第一次分析

先运行函数、XRef、CFG 与调用图等结构恢复，再针对输出寄存器或内存 sink 执行反向污点，寻找贡献源。

## 预期结果

你可以在同一 PC 的多次执行之间移动、检查寄存器状态，并沿证据追踪某个值的来源，而不是只阅读一条可能从未执行过的静态路径。
