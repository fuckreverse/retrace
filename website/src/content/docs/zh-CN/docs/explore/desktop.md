---
title: Desktop GUI
sidebar:
  order: 2
---

Tenet Desktop 是 Apple Silicon 上默认的长时间调查界面。它把即时状态视图与异步分析窗口组合起来，但不复制分析逻辑。

## 主工作区

| 视图 | 内容 |
|---|---|
| Instructions | `inst_id`、运行时 PC、反汇编与已记录内存访问 |
| Registers | 当前 GPR；绿色=读、红色=写、黄色=读写 |
| Memory | 访问类型、地址、值、Hex Dump 与最后写入者 |
| Call Stack | 光标处动态栈帧；可跳转调用点或函数入口 |
| Functions | 名称/地址、调用次数、执行指令数、caller/callee |
| CFG | 带热度的已执行基本块和边；点击块即可导航 |
| Strings | 最终快照与时间感知字符串 |
| Output | 按级别、子系统和文本过滤日志 |

所有视图共享光标。选择函数、栈帧、CFG 块或分析命中都会导航同一条指令时间轴。

## 导航流程

1. 选择指令并比较寄存器读写。
2. 检查已记录内存访问，对指针打开 Hex Dump。
3. 通过 Call Stack 与 Functions 确定行为上下文。
4. 使用 XRef 在重复执行间移动。
5. 为重要 source、变换和 sink 添加书签。

## Analysis 控制台

**Analysis** 窗口按类别列出 Pass，并显示 Not Run、Running、Completed 或 Failed。运行中的 Pass 可查看进度并取消；完成结果可在丢弃缓存后重跑。

需要参数的查询使用独立窗口，包括：

- Memory Search 与 YARA Memory Scan
- Register Timeline 与 Call Context
- Memory Snapshots 与 Entropy
- Dataflow Graph 与 Window Stats
- Trace Fold 与 Trace Diff
- VM Abstract / VM Workspace

Patterns、Constants、Loop Semantics、Algorithm Summary、ObjC Messages、ObjC × Crypto、API Intercepts、Call Graph 和 CFG 也有独立结果窗口。

## 上下文操作

右键指令可运行 XRef、前向/反向污点、查看 producer、设置断点/观察点、打开 CFG、复制地址或跳转相关证据。长分析在后台运行，界面仍可导航；退出时会安全取消活动任务。

## 符号与缺码

Symbol Info 可读取支持的符号导出。如果 Trace 缺少部分代码字节，使用 `--image` 重新打开，使反汇编与依赖代码的 Pass 从匹配镜像回填。
