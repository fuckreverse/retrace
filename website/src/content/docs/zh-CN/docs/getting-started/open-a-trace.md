---
title: 打开 Trace
sidebar:
  order: 3
---

## 本地打开

在 Tenet Desktop 中选择 `.bin` 文件，或运行：

```bash
./tenet /path/to/trace.bin
./tenet --tui /path/to/trace.bin
```

Trace 始终在你的 Mac 本地分析，文档网站不会接收任何数据。

## 首次索引

首次打开会扫描记录流，并在 Trace 同目录创建持久化 RocksDB 索引 `<trace-name>.tenet/`。其中包含指令偏移、ANCHOR、寄存器写入、内存历史和内嵌代码索引。大型 Trace 可能需要一分钟以上；之后打开会复用索引及 Pass 结果缓存。

不要日常删除该目录：书签、最后光标位置和 Pass blob 也保存在其中。Tenet 会校验索引与 Trace，必要时自动重建失效数据。

## 会话独占

同一 Trace 同时只能由一个 Tenet 进程打开，因为所有模式共享索引与会话状态。若另一个 GUI、TUI、批处理、RPC 或 MCP 进程已占用，Tenet 会显示其 PID、主机、模式和打开时间。请退出占用进程，不要删除锁文件；进程崩溃后内核 `flock` 会自动释放。

## 缺少代码字节

含 `HF_HAS_CODE` 的 Trace 通常无需镜像即可反汇编。对 sampling 或缺码的旧 Trace，可提供匹配的 Mach-O/ELF：

```bash
./tenet trace.bin --image /path/to/binary
```

镜像必须与录制模块对应。Tenet 通过 `module_slide` 映射运行时 PC，仅把镜像作为代码和字符串回退源。

## 检查会话

打开后确认：

1. 指令时间轴数量非零。
2. PC 与模块元数据合理。
3. 移动时间轴时寄存器值发生变化。
4. 指令可反汇编，或已配置外部镜像。
5. Functions 与 XRef 能完成且没有证据缺失警告。

然后阅读[浏览执行历史](/zh-CN/docs/explore/)或[分析 Trace](/zh-CN/docs/analyze/)。
