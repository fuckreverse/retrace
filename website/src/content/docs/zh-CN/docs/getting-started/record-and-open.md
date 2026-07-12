---
title: 录制、打开与第一次分析
sidebar:
  order: 3
---

**目标：** 录制一个 iOS 函数并完成第一次分析。  
**前置条件：** 已部署 QBDITrace、Frida 可连接，并掌握目标静态入口偏移。

```bash
python3 tools/qbditrace/qbditrace_runner.py \
  --target com.example.app \
  --entry 0xEE91EC \
  --output /var/mobile/Documents/trace.bin
```

直接配置 C ABI 时必须使用包含 ASLR slide 的运行时地址。Runner 会在其支持的流程中解析模块与 ASLR 信息。

在 Tenet Desktop 中打开 `.bin`。首次打开会构建持久化索引，之后可复用。按指令 ID 或 PC 导航，并观察选中指令前后的寄存器变化。

先运行函数、XRef、CFG 与调用图等结构恢复，再针对输出寄存器或内存 sink 执行反向污点，寻找贡献源。
