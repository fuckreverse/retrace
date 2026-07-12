---
title: 算法与模式识别
sidebar:
  order: 5
---

算法识别回答"这次执行是否类似已知构造？"，它组合结构模式、物化常量、循环语义和调用图上下文。

## Pass 链

```text
pattern + loop_semantics + function + call_graph ──> algorithm_summary
                                              └──> objc_crypto
```

## 模式扫描

`pattern` 将执行指令分类为密码学、反调试、反篡改、混淆和网络模式。`constants`（原独立 `constant_materialization` Pass 已合并）提取 `movz` + `movk` 链和已知算法常量，如 AES S-box、SHA K/W、ChaCha quarter-round 常量、ARIA S-box 值等。

```bash
./tenet trace.bin --pattern
./tenet trace.bin --constants --constants-min-parts 3
```

## 循环语义

`loop_semantics` 分类循环体：

| 分类 | 含义 |
|---|---|
| Feistel | Feistel 轮结构 |
| SPN | 替换-置换网络 |
| ARX | Add-Rotate-XOR 构造 |
| Shift/Rotate | 移位或旋转主导 |
| Accumulator | 累加 |
| Memcpy-like | 内存复制或变换 |
| Counter Loop | 简单计数迭代 |

一个循环可有多个标签。分类依赖已记录代码；sampling 或缺码会降低置信度。

```bash
./tenet trace.bin --loop-semantics
```

## 算法摘要

`algorithm_summary` 合并模式、常量、循环证据和调用图结构，生成算法候选。每个候选属于结构化 `AlgorithmFamily`（AES、SHA256、ChaCha 等），并携带：

- 证据项及来源（pattern、constant、loop、call-graph）。
- `is_speculative` 标记——仅凭高频调用等弱证据得出的候选会被单独标出，`confirmed_candidates()` 可过滤。

这是**证据聚合** Pass。它不证明识别到的算法是唯一可能，而是报告哪些已知构造与观察到的证据匹配。

```bash
./tenet trace.bin --algorithm-summary
```

## ObjC × Crypto

`objc_crypto` 将模式命中与 ObjC 调用栈关联，回答"哪个 ObjC 方法触发了这个加密操作"。仅 Darwin；Android/Linux Trace 返回空结果。

```bash
./tenet trace.bin --objc --pattern --objc-crypto
```

## 解读结果

1. **模式 + 常量证据**识别算法族。
2. **循环语义**确认轮结构（Feistel/SPN/ARX/…）。
3. **算法摘要**交叉引用全部证据给出置信度。
4. **Speculative 候选**需进一步验证——先看 confirmed candidates。
5. 结果受录制内容约束。若目标走了未记录路径或使用了已知常量表中没有的算法，检测会不完整。
