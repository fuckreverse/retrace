---
title: 命令行界面
sidebar:
  order: 2
---

CLI 运行分析、导出数据和生成报告，无需交互会话。所有批处理模式使用与 GUI/TUI 相同的 Pass 实现。

## 批量分析

```bash
# 结构
./tenet trace.bin --export-cfg func.dot
./tenet trace.bin --call-graph cg.dot
./tenet trace.bin --symbol-annotation

# 污点
./tenet trace.bin --taint 0 --taint-inst 12000
./tenet trace.bin --backward-taint 58000 0
./tenet trace.bin --critical-path --taint 0 --backward-taint 58000 0

# 算法
./tenet trace.bin --pattern
./tenet trace.bin --constants
./tenet trace.bin --algorithm-summary
./tenet trace.bin --loop-semantics

# 内存与字符串
./tenet trace.bin --strings
./tenet trace.bin --memory-strings
./tenet trace.bin --memread 0x16fdff200 32 50000
./tenet trace.bin --mem-history 0x16fdff200 32
./tenet trace.bin --memory-snapshot 5000

# 平台
./tenet trace.bin --objc
./tenet trace.bin --objc --objc-class NSString
./tenet trace.bin --syscall-intercept

# VM 分析
./tenet trace.bin --vm-abstract
./tenet trace.bin --backward-taint 10000 0 --taint-source-annotation

# Trace 工具（参数为 instruction ID 区间）
./tenet trace.bin --trace-fold 10000 50000 --trace-fold-min-iter 3
./tenet trace.bin --trace-diff 10000 20000 30000 40000 --trace-diff-file other.bin
./tenet trace.bin --window-stats 0 100000 --window-stats-size 10000
./tenet trace.bin --reg-timeline 0 --reg-timeline-range 10000 50000
```

## 显式选择 Pass

```bash
./tenet trace.bin --run-pass function --run-pass xref --run-pass cfg
```

当便利标志不映射到所需 Pass 集时，使用 `--run-pass` 进行精细控制。

## 排除区间

```bash
./tenet trace.bin --exclude-range 0x1001000 0x1002000 --exclude-range 0x2001000 0x2002000
```

排除区间在分析时过滤指令，不会修改 Trace 文件。

## 外部镜像

```bash
./tenet trace.bin --image /path/to/binary
```

## 输出与报告

大多数 CLI 模式向 stdout 输出结构化文本。图导出（CFG、调用图、数据流图）写入 Graphviz DOT 文件。Profile 支持 JSON 和 CSV。Diff 写入 JSON。污点图可用 `--backward-taint-graph` 导出为 JSON。

## 无界面注意事项

- CLI 读写与 GUI/TUI 相同的 `.tenet/` 索引，遵守相同的会话锁。
- 长时间批处理不渲染 UI，比 TUI 更快。
- Pass 结果会被缓存；相同参数重复运行完成很快。
