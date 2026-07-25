---
title: 算法与模式识别
sidebar:
  order: 5
---

算法识别回答"这次执行是否类似已知构造？"，它组合结构模式、物化常量、循环语义和调用图上下文。它是证据聚合，不是证明。

## Pass 链

```text
pattern（含 constants 子检测）
     + loop_semantics（依赖：loop, xref）
     + function
     + call_graph
          └──> algorithm_summary（声明依赖；缺失结果可优雅降级）
                    │
                    └──> objc_crypto（依赖：pattern, objc）
```

`algorithm_summary` 在 Pass 依赖表中声明全部四项，正常调度会先运行它们；若某项没有产出可用结果，汇总阶段仍会优雅降级。

## 模式扫描

`pattern` 把执行指令分入六个分类：

| 分类 | 信号 |
|---|---|
| Crypto | AES / SHA 硬件加速助记符、S-box 查找、常见加密序列 |
| AntiDebug | ptrace syscall、反调试字符串常量 |
| AntiTamper | 完整性校验签名 |
| Obfuscation | MBA / CFF / 不透明谓词签名 |
| Networking | TLS、HTTP、DNS 序列特征 |
| KeySchedule | 通过已知 S-box / K/W 常量数据库匹配识别 |

置信度：

| 置信度 | 何时赋予 |
|---|---|
| High | YARA 规则 `meta: confidence = "high"`；已知常量数据库命中 |
| Medium | YARA 规则 `meta: confidence = "medium"`；类循环 XOR 环；较长（≥ 3 段）movz+movk 序列但未命中任何已知常量 |
| Low | 直线型 XOR 密集代码（多唯一 PC，非紧循环）；YARA 规则 `meta: confidence = "low"` |

### XOR 启发式

仅凭"大量 EOR 指令"滑动窗口**不构成**充分证据。检测器还追踪每次运行中出现的唯一 PC 数：真正循环体反复执行少量固定 PC（Medium 置信度 "XOR loop"），而直线代码每步都访问新 PC（Low 置信度 "XOR-dense code (non-loop)"）。

### 硬件密码学检测

`PatternCollector` 预先把循环体 PC 分类为 `MC_HW_AES` / `MC_HW_SHA` / `MC_EOR` / `MC_MOVZ` / `MC_MOVK` / `MC_SVC`，然后按站点聚合并报告硬件加速器使用次数。

## constants：pattern 的子检测

`--constants` 不是独立 Pass——它是 `pattern` 内嵌的子检测器。`PatternCollector` 在同一次扫描中跟踪进行中的 `movz` + `movk` 构建序列（按目标寄存器维护状态）：

- 完成序列若匹配已知算法常量 → High 置信度 KeySchedule 命中，含 `MaterializedConstant` 详情（值、寄存器、段数、匹配项）。
- 较长序列（>= `constants-min-parts`，默认 2）未命中任何已知常量 → Medium 置信度 "Constant loading sequence"。

```bash
./tenet [options] trace.bin --pattern
./tenet [options] trace.bin --constants --constants-min-parts 3
```

`PatternResult::constants` 持有原始 `ConstantMaterializationResult`；`PatternResult::matches` 为每个识别出的常量包含一条 KeySchedule 分类条目，以便下游统一消费。

## 循环语义

`loop_semantics` 对每个循环体（迭代次数 >= 2）采样 2-3 轮迭代，分析特征标记：

| 特征标记 | 检测内容 |
|---|---|
| `has_sbox_pattern` | 寄存器偏移量数据依赖的 `LDR`（查表） |
| `has_xor_mix` | 存在 `EOR` |
| `has_shift_rotate` | `LSL`、`LSR`、`ASR`、`ROR` |
| `has_addition_chain` | 3 个以上 `ADD`/`SUB` |
| `has_modular_arithmetic` | `MUL`/`UDIV` |
| `sbox_pattern_data_dependent` | S-box 数据流：load 索引被验证由同一循环体内的混合操作产生 |

分类表：

| 分类 | 所需特征 | 典型迭代数 | 置信度 |
|---|---|---|---|
| Feistel Round | `add_sub >= 2` + 左右交换模式 | 接近经典轮数 | 0.7–0.85 |
| SPN Round | `has_xor_mix` + `has_sbox_pattern` | 8 / 10 / 12 / 14 / 16 / 32 | 0.55–0.85 |
| ARX | `add_sub >= 1` + `shift_rotate >= 1` + `xor >= 1` | 密码学常见 | 0.55–0.7 |
| Accumulator | 简单加法体 | — | 0.5 |
| Memcpy-like | `load_with_reg_offset_count >= total / 3` 且无加密操作 | — | 0.6 |
| Counter Loop | 1–2 个活跃寄存器，其一为计数器 | — | 0.6 |

**置信度门控**：SPN 在 `sbox_pattern_data_dependent = true` 时置信度 0.8，否则降至 0.55（较弱的结构启发式）。Feistel/SPN/ARX 在迭代数为已知密码学数值（8/10/12/14/16/32）时获得小幅加成；未知迭代数会压低置信度。

依赖：`loop` + `xref`。

```bash
./tenet [options] trace.bin --loop-semantics
```

MCP：`loop_semantics` tool；Tauri 前端：Loop Semantics 面板。

## 算法摘要

`algorithm_summary` 把四个声明依赖（pattern、loop_semantics、function、call_graph）的证据合成为算法候选。正常调度会先运行依赖链；汇总阶段对缺失或不可用结果采取优雅降级。

### 阶段分解

| 阶段 | 消费内容 |
|---|---|
| 1a | Pattern 匹配（Crypto 分类） |
| 1b | 已知常量匹配（来自 `pattern.constants`） |
| 1c | 循环语义 —— 若循环的结构形状（Feistel/SPN/ARX）与一个已命名候选的 `AlgorithmStructure` 匹配，则并入该候选累加器；否则在无名结构键桶下累加 |
| 1d | 调用图热点函数 —— 把同时超过绝对阈值（`hot_function_min_calls = 25`）和相对阈值（`hot_function_min_ratio = 20%`）的被调函数标为**推测性**旁证。真实证据永远不会被打上 speculative 标记 |

### 证据累加

不同检测器对同一算法措辞不同（"AES instruction"、"AES"（常量）、SPN 环 + `loop_kind_algorithm_hint`）。三者都通过 `normalize_algorithm_name()` 归一化到同一个 `AlgorithmFamily` 累加器，从而把措辞变体折叠。一条 AES 常量 + 一个 SPN 环 + 一条硬件 AES 模式轻松合并为一个候选。

每个候选携带：
- `AlgorithmFamily` 分组（如 AES、DES、Blowfish、Camellia、TEA、SM4、Serpent、ChaCha、Salsa、SHA 系列、MD5、SM3、HMAC、Poly1305、SipHash、CRC32、ZUC、ECDSA、Ed25519、Curve25519、GCM 或 Unknown）。
- AlgorithmStructure（Unknown / Feistel / SPN / ARX），仅用于与 loop_semantics 形状交叉引用。
- `EvidenceAccumulator` 项：文本、置信度加成、PC / inst_id 范围。
- `is_speculative` 标记 —— 仅对 1d 热点函数且**无真实旁证**条目置 true。`confirmed_candidates()` 可过滤掉它们。
- `confidence` ∈ [0, 1]，按降序排列。

```bash
./tenet [options] trace.bin --algorithm-summary
```

MCP：`algorithm_summary` tool；Tauri 前端：Algorithm Summary 面板；TUI：`:algosum`。

## ObjC × Crypto

`objc_crypto` 把 PatternMatch 命中与其发生时刻的 ObjC 调用栈关联，回答"哪个 ObjC 方法链触发了这个加密算法"。对每条 PatternMatch，从 `start_inst_id` 在有序 ObjC 消息列表中向前回溯，最多收集 8 帧（或遇到超过 500,000 条指令的间隙即停止）。处于 ObjC 派发内的命中按 `class_name` 和 `selector_name` 索引。

仅 Darwin：当 `target_os` 既非 Darwin 也非 Unknown（头显式表明 Android / Linux），Pass 立即返回空结果。

硬依赖：`pattern` + `objc`。

```bash
./tenet [options] trace.bin --objc --pattern --objc-crypto
```

MCP：`objc_crypto` tool；Tauri 前端：ObjC × Crypto 面板。

## CLI / Tauri 前端 / TUI / MCP 速查

| 能力 | CLI | Tauri 前端 | TUI | MCP |
|---|---|---|---|---|
| 模式扫描 | `--pattern` | Patterns 面板 | `:pattern` | `pattern_scan` |
| 常量 | `--constants --constants-min-parts 3` | Constants 面板 | — | `constants_scan` |
| 循环语义 | `--loop-semantics` | Loop Semantics | `:loop` | `loop_semantics` |
| 算法摘要 | `--algorithm-summary` | Algorithm Summary | `:algosum` | `algorithm_summary` |
| ObjC × Crypto | `--objc-crypto` | ObjC × Crypto | `:objc` | `objc_crypto` |

## 证据组合实践

1. **模式 + 已知常量证据**通过 `movz+movk` 常量识别 + YARA 规则命中锁定算法族。
2. **循环语义**确认轮**形状**（Feistel/SPN/ARX）。结构形状本身不能命名算法（AES/SM4/Serpent 都是 SPN）；它作为候选族存在时的旁证。
3. **单一密码学硬件助记符**（仅一条 AESENC 指令）无常量或无循环证据 → 弱信号；需通过 taint / memread 作旁证。
4. **推测性热点候选**没有真实证据支持 —— 导航到该 PC 手动检查，或通过已知密钥的 taint 验证。
5. 组合套路：`--pattern --loop-semantics --algorithm-summary` 是最小的端到端命令。
6. 追加 `--objc-crypto` 仅对有 ObjC 加密派发的 Darwin Trace 有意义。
7. `mem_search` 和 `entropy` 属于旁证，不直接喂入 `algorithm_summary` —— 单独运行以确认地址级细节。

## 排查

### `pattern` 报告零命中

- 确认构建时启用了 `TENET_ENABLE_YARA=ON`。无 YARA 时仍会运行基于助记符的检测器（硬件加密、常量物化、XOR 循环），但依赖规则的模式不会出现。
- 包含大量小函数的长 Trace 可能需要 `--sampling` 或 `--exclude-range` 控制耗时后再让 pattern 完成扫描。

### `loop_semantics` 报告 "requires 'loop' and 'xref'"

`--loop-semantics` 隐式注册 `loop`、`cfg` 和 `xref`。若你手工配置了 Pass 依赖，确保三者都可用。程序化配置时显式注册 `xref`、`cfg`、`loop`、`loop_semantics`；直接使用 CLI `--loop-semantics` 时会自动处理整条链。

### `algorithm_summary` 出现不认识的候选

`normalize_algorithm_name()` 使用模糊子串匹配。缩写检测器名称可能冲突（如 "AES-192" vs "AES"）。检查 `family` 字段 —— `AlgorithmFamily::Unknown` 表示名字无法归一化，它在自己独立的桶里。查看 `key_pcs` 手动确认。

### 推测性热点命中已知工具函数（memcpy / allocator）

热点函数启发式被故意做弱：内部阈值默认为至少 25 次调用，且达到最热 callee 的 20%；普通 CLI 当前不暴露这两个调节项，因此热度相当的工具函数仍可能出现。通过 `confirmed_candidates()` 过滤，或先寻找旁证 pattern / 常量证据再判定为加密。

### ObjC × Crypto 返回空结果

- 确认 `target_os` = Darwin 或 Unknown（启发式允许 Unknown）。Android / Linux Trace 直接短路到空。
- 确认 `--objc --pattern` 与 `--objc-crypto` 一同注册。无 ObjC 消息或模式则无可关联。
- `max_lookback_` = 500,000：若最近的 ObjC 消息还在更前面，该 pattern 被归入 "bare"。必要时通过 C++ `ObjcCryptoPass::set_max_lookback()` 调大。
