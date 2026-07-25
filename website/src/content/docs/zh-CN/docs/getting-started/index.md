---
title: 快速开始
description: 安装、录制、打开和浏览你的第一个 Trace。
sidebar:
  order: 0
  label: 概览
---

## 路径

1. 在 Apple Silicon Mac 上[安装 Tenet](./install/)。Tenet 后端已支持 Windows、Linux 和 macOS（x86_64/arm64），但当前公开发布的桌面安装包仍只有 macOS Apple Silicon 预览版 DMG；其他平台的独立安装包正在制作中。
2. 用 QBDITrace 或兼容采集器[录制 Trace](../capture/)。
3. [在 Tenet 中打开](./open-a-trace/)并等待首次索引完成。
4. [理解核心概念](./core-concepts/) — 指令 ID、时间感知状态、分析 Pass。
5. [浏览执行历史](../explore/) — 导航、检查、设断点、跟随调用。

## Trace 要求

Tenet 接受格式版本 4 及以上。为获得最丰富分析，Trace 应包含寄存器 diff 和内嵌代码。PC-delta（v5）和 FPR（v7）录制由 `tenet --dump` 及所有分析模式完全支持。

## 成功标志

指令时间轴打开，导航时寄存器值变化，默认结构 Pass 识别出已执行函数和交叉引用。之后可运行目标分析 Pass 来追踪数据流、识别算法或检查平台 API 调用。
