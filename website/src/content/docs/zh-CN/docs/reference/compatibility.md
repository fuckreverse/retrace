---
title: 兼容性与限制
sidebar:
  order: 2
---

Tenet 在 Trace 证据不完整时优雅降级。本页记录每项能力所需证据及缺失时的行为。

## 格式版本要求

| 版本 | 标志 | 用途 |
|---|---|---|
| v4 | 基线 | 所有功能 |
| v5 | `HF_PC_DELTA` | 减小文件体积（pc_delta 模式）；Tenet 自动检测 |
| v7 | `HF_HAS_FPR` | FPR（NEON v0-v31）重建 |
| v8 | `HF_CALL_META`（必需；可与 `HF_PC_DELTA` / `HF_HAS_FPR` 组合） | 调用元数据：真实返回值（`REC_RETVAL`）、在线 selector 与更宽的 API ID |
| v9 | `HF_MEMIMG`（v9 必需；与所有布局 flag 正交） | configure 时内存快照（`REC_MEMIMG`）；由 `qbditrace --snapshot-range` 录制，全部记录位于首个 `INST` 之前 |
| v6 | `HF_OLD_VALUE` | 写前内存值（writer 已移除；当前无 Trace 生成此格式） |

Tenet 可打开 version ≥ 4 的任何 Trace。

## 各能力证据要求

### 时间轴与导航

| 证据 | 是否必需 | 缺失时降级 |
|---|---|---|
| PC 流 | 是 | 无法打开 |
| `inst_id` 序列 | 是 | 无法导航 |
| GPR ANCHOR/diff | 寄存器查询需要 | 寄存器始终显示 0 |
| 内存访问 | 内存历史需要 | 内存读取返回未知 |
| 内嵌代码（`HF_HAS_CODE`） | 反汇编需要 | 需要 `--image` 回退 |
| Branch hint（`HF_BRANCH_HINT`） | call/return 分类需要 | 仅启发式分类 |

### 结构恢复

| 证据 | 是否必需 | 缺失时降级 |
|---|---|---|
| 内嵌代码或外部镜像 | 是 | 无 CFG、无循环检测 |
| Branch hint 或 event | call/return 需要 | Function Pass 仅启发式 |
| GPR diff | 基于 SP 的栈遍历需要 | 调用栈可能不完整 |

### 污点与数据流

| 证据 | 是否必需 | 缺失时降级 |
|---|---|---|
| GPR ANCHOR/diff | 是 | 无污点传播 |
| 内存访问 | 内存污点需要 | 内存传播禁用 |
| Triton（可选） | 精确语义需要 | 仅回退语义 |

### 内存与字符串

| 证据 | 是否必需 | 缺失时降级 |
|---|---|---|
| 内存访问（写） | 是 | 无内存重建 |
| 内存访问（读） | 未插桩数据需要 | 未读页面为未知字节 |
| `REC_MEMIMG` 快照（v9，可选） | 从未被触碰的全局量需要 | 未触碰页面保持未知；快照字节以 `kSnapshotWriterId` 标注为 trace 起始时刻的近似值 |
| 内嵌代码或镜像 | 字符串扫描需要 | 仅栈/堆 |

### 平台 API

| 证据 | 是否必需 | 缺失时降级 |
|---|---|---|
| `REC_CAPICALL` 记录 | 最佳质量 | 启发式回退 |
| `REC_SVC` 记录 | 系统调用拦截需要；可分类 Darwin BSD syscall、负号 Mach trap 与可读的发送 Mach 消息头 | 无系统调用数据；消息头缺失或不可读时保留 trap 级结果 |
| `REC_OBJC` 记录 | ObjC 消息需要 | 无 ObjC 分析 |
| `REC_RETVAL` 记录 | 真实返回值需要 | 返回值显示为未知；旧版 v4-v7 Trace 不含此记录 |
| Darwin 目标 | ObjC / CryptoKit 需要 | Android/Linux 跳过 |

### 算法与模式

| 证据 | 是否必需 | 缺失时降级 |
|---|---|---|
| 内嵌代码或镜像 | 是 | 无模式或常量检测 |
| 循环结构 | 循环语义需要 | 无循环分类 |
| 调用图 | 算法摘要需要 | 无交叉引用 |
| 平台 API | `objc_crypto` 需要 | 无 ObjC 关联 |
| 静态分析 VM hints + 循环结构/CFG/xref | `vm_abstract` 需要 | 无 VM 执行抽象；该 Pass 不自动发现 dispatcher |

## Trace 采集目标平台支持

此处的平台是被 qbditrace 插桩并写入 `target_os` 的目标进程平台，不是运行 `tenet` 后端的宿主系统。

| 平台 | ObjC | API 拦截 | FPR | 备注 |
|---|---|---|---|---|
| iOS (Darwin) | 完整 | CommonCrypto、Security、CryptoKit、BoringSSL | v7 | 全部能力 |
| Android | 跳过 | BoringSSL、JNI | v7 | 无 ObjC |
| Linux | 跳过 | OpenSSL、系统调用 | v7 | 无 ObjC |
| Unknown | 启发式 | 基于模块名的启发式 | — | 降低精度 |

## Tenet 后端宿主平台

纯后端 `tenet` 可执行文件的目标宿主平台是 Windows、Linux 和 macOS，覆盖 x86_64 与 arm64。它与上面的 Trace 采集目标平台是独立维度：iOS、Android 或 Linux 上采集的 Trace 都是离线文件，可在任意受支持宿主平台上通过 CLI、TUI、TCP loopback RPC 或 MCP 分析。

macOS 和 Linux 构建默认启用 WebSocket 服务。Windows 上由于 uSockets 尚无接入当前构建的 IOCP 后端，`TENET_ENABLE_WS` 默认为 `OFF`，且当前不支持强制开启；因此独立的 Tauri 桌面/Web 前端暂时无法通过 FlatBuffers WebSocket 连接 Windows 版后端。这一限制不影响 Windows 后端上的离线 CLI/TUI/RPC/MCP 分析。

## Sampling Trace

Sampling Trace（设置了 `REG_DIFF`、`HAS_MEM` 或 `HAS_NZCV` 采样标志）仅包含部分证据。能力相应降级：

- 减少 GPR diff → 更少污点传播步骤、寄存器状态精度更低。
- 缺少内存访问 → 无内存重建、无内存污点。
- 缺少代码 → 需 `--image` 才能使用依赖反汇编的功能。

Tenet 可打开并索引 Sampling Trace；分析 Pass 会报告可用的证据类别并相应限制结果。

## 单线程假设

Tenet 当前假设单线程 Trace。`THREAD` 记录会被解析但不分割时间轴。多线程 Trace 打开时会有警告；分析应用于交错指令流。如需隔离单线程指令，可使用 `thread_filter`。
