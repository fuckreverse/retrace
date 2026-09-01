# Trace Format 接口契约（v4–v9）

## 概述

本文档是 **tenet 分析器**与 **qbditrace 记录器**之间的接口契约。
tenet 依赖 `TraceFormat.h`（支持 v4/v5/v6/v7/v8/v9）定义的格式读取 `.bin` trace 文件。

**权威来源**：`tools/qbditrace/TraceFormat.h`。本文档是该头文件的人类可读解释，
并标注 tenet 特有的处理策略和未来增强方向。如有冲突，以 `.h` 文件为准。

---

## 文件布局

**未压缩格式：**

```
┌──────────────────────────────────────────┐
│ File Header (536 bytes, aligned)         │  ← qbditrace_file_header_t
├──────────────────────────────────────────┤
│ Record 0 (variable length)              │
│ Record 1                                 │
│ ...                                      │
│ Record N                                 │
└──────────────────────────────────────────┘
```

**分块压缩格式（HF_BLOCK_COMPRESSED）：**

```
┌──────────────────────────────────────────┐
│ File Header (536 bytes, 明文)             │  ← qbditrace_file_header_t
├──────────────────────────────────────────┤
│ Block 0 (独立 zstd frame)                │
│ Block 1 (独立 zstd frame)                │
│ ...                                      │
│ Block N-1                                │
├──────────────────────────────────────────┤
│ Block Index Table (N × 24 bytes)        │  ← qbditrace_block_entry_t 数组
├──────────────────────────────────────────┤
│ Block Index Footer (16 bytes)           │  ← qbditrace_block_footer_t
└──────────────────────────────────────────┘
```

所有数据均为 **小端序**（AArch64 native）。

---

## File Header — `qbditrace_file_header_t` (536 字节)

| 偏移 | 大小 | 字段 | 值/说明 |
|------|------|------|---------|
| 0x00 | 4 | magic | `0x51424454` ("QBDT") |
| 0x04 | 4 | version | 4（基线）/ 5（+PC_DELTA）/ 6（+OLD_VALUE）/ 7（+HAS_FPR）/ 8（+CALL_META）/ 9（+MEMIMG） |
| 0x08 | 4 | arch | `QBDITRACE_ARCH_AARCH64 = 1` |
| 0x0C | 4 | num_gpr | 34 (AArch64) |
| 0x10 | 8 | module_base | 被追踪模块的运行时基址 |
| 0x18 | 8 | module_slide | ASLR slide |
| 0x20 | 8 | trace_start | 追踪范围起始地址 |
| 0x28 | 8 | trace_end | 追踪范围结束地址（excluded） |
| 0x30 | 8 | flags | `qbditrace_header_flags` 位组合 |
| 0x38 | 256 | module_name | NUL 终止的模块路径 |
| 0x138 | 4 | target_os | `qbditrace_target_os_t`（见下方），旧 trace 为 0 (Unknown) |
| 0x13C | 220 | reserved | 填充至 536 字节 |

**Header Flags**：

| Flag | 位 | 说明 |
|------|-----|------|
| HAS_MEM | bit 0 | 记录包含内存访问 |
| HAS_NZCV | bit 1 | INST 记录包含 NZCV |
| REG_DIFF | bit 2 | INST 使用 diff 模式（非全量快照） |
| HAS_CODE | bit 3 | 流中包含 REC_CODE 记录 |
| PC_DELTA | bit 4 | v5: INST 使用 pc_delta (int16) 代替绝对 PC |
| OLD_VALUE | bit 5 | v6: 内存写操作记录旧值（memacc 扩展为 48B） |
| HAS_FPR | bit 6 | v7: ANCHOR/INST 包含 FPR 快照/差值（NEON v0-v31） |
| COMPRESSED | bit 7 | Header 后所有数据为单个 zstd 压缩流（见下方"流式压缩"节） |
| BLOCK_COMPRESSED | bit 8 | 分块压缩格式：多个独立 zstd frame + 尾部索引（见下方"分块压缩"节） |
| BRANCH_HINT | bit 9 | INST nzcv 字节高 4 位编码分支类别（见下方"Branch Hint"节） |
| CALL_META | bit 10 | v8：OBJC/CAPICALL 使用 v8 布局，且允许 REC_RETVAL |
| MEMIMG | bit 11 | v9：流中包含 REC_MEMIMG 内存快照记录（位于首个 INST 之前） |

> **注**：`COMPRESSED` 与 `BLOCK_COMPRESSED` 互斥。当前 qbditrace writer 默认产生
> `BLOCK_COMPRESSED`；`COMPRESSED` 单帧流格式仅为历史读取兼容，当前 writer 不产生。

**版本与 Flag 对应关系**：

| version | 新增 Flag | 含义 |
|---------|-----------|------|
| 4 | — | 基线格式 |
| 5 | PC_DELTA | INST 头缩小为 6B |
| 7 | HAS_FPR | ANCHOR + INST 携带 FPR 快照/差值 |
| 8 | CALL_META | OBJC/CAPICALL v8 布局，并增加 RETVAL 返回事实记录 |
| 9 | MEMIMG | 增加 REC_MEMIMG 内存快照记录（configure 时发射） |

> v6 (`OLD_VALUE`) 已从 writer 移除（`config_t._reserved_old_value` 被忽略），但格式定义保留以支持旧 trace 读取。

**Target OS**：

| 值 | 枚举 | 说明 |
|------|------|------|
| 0 | UNKNOWN | 旧 trace（reserved 全零），tenet 会根据 module_name 路径启发式推断 |
| 1 | iOS | iOS / macOS (Darwin) |
| 2 | Android | Android (Linux kernel + Bionic) |
| 3 | Linux | Linux (glibc) |

qbditrace 在录制时通过编译期宏自动填写此字段。tenet 读取时会校验值是否在 0-3 范围，超过则回退为 Unknown。

**tenet 打开条件**：magic == `0x51424454` 且 version >= 4。`REG_DIFF`、`HAS_MEM`、
`HAS_NZCV` 可关闭（sampling trace 即如此）；缺少 `HAS_CODE` 时仍可解析记录流，但依赖
反汇编的分析需要外部镜像或会降级。`HF_CALL_META` 仅允许 version=8，且 version=8 必须设置
`HF_CALL_META`；v8 可与 `PC_DELTA`、`HAS_FPR`、`OLD_VALUE` 组合。`HF_MEMIMG` 仅允许
version=9，且 version=9 必须设置 `HF_MEMIMG`；v9 与上述所有布局 flag 正交组合。

---

## AArch64 GPR 映射

```
QBDITRACE_AARCH64_NUM_GPR = 34
```

| 索引 | 寄存器 | 说明 |
|------|--------|------|
| 0-28 | x0-x28 | 通用寄存器（x29 = fp） |
| 29 | — | x29/fp 通过 index 29 访问（与 x29 是同一个） |
| 30 | lr | Link Register (x30) |
| 31 | sp | Stack Pointer |
| 32 | nzcv | 条件标志（低 4 位 = N,Z,C,V） |
| 33 | pc | Program Counter |

**AArch64 FPR 映射（v7）**：

```
QBDITRACE_AARCH64_NUM_FPR = 32  // v0-v31
```

每个 FPR 为 128 位（NEON 向量寄存器），分为 `lo` (bits[63:0]) 和 `hi` (bits[127:64]) 两个 uint64_t 记录。

**注意**：

- fp (frame pointer) = x29，索引 29，不是一个独立的额外寄存器
- wN 寄存器不单独索引，是 xN 的低 32 位
- **fpcr 不在 GPR 快照中**（如需，未来通过新记录类型扩展）
- **浮点/向量寄存器 v0-v31 在 v7 (`HAS_FPR`) 格式中记录**；v4/v5 格式不记录

**tenet 中对应**：

```cpp
constexpr uint8_t AARCH64_NUM_GPR = 34;
constexpr uint8_t IDX_LR = 30;
constexpr uint8_t IDX_SP = 31;
constexpr uint8_t IDX_NZCV = 32;
constexpr uint8_t IDX_PC = 33;

struct RegState {
    uint64_t gpr[34];  // 272 bytes
    uint64_t pc() const { return gpr[IDX_PC]; }
    uint64_t sp() const { return gpr[IDX_SP]; }
    uint64_t lr() const { return gpr[IDX_LR]; }
    uint64_t fp() const { return gpr[29]; }
    uint32_t nzcv() const { return static_cast<uint32_t>(gpr[IDX_NZCV] & 0xF); }
};
```

---

## 记录类型

每条记录以 1 字节 `kind` 开头：

| Kind | 值 | C 类型 | 说明 |
|------|-----|--------|------|
| INST | 0 | `qbditrace_inst_head_t` + diffs + memaccs | 指令增量记录 |
| ANCHOR | 1 | `qbditrace_anchor_head_t` + regs[] | 完整寄存器快照 |
| THREAD | 2 | `qbditrace_thread_head_t` | 线程切换 |
| EVENT | 3 | `qbditrace_event_head_t` | 执行权转移/事件 |
| SVC | 4 | `qbditrace_svc_head_t` | 系统调用 |
| OBJC | 5 | `qbditrace_objc_head_t` | ObjC 消息发送 |
| CODE | 6 | `qbditrace_code_head_t` + bytes[] | 指令原始字节 |
| CAPICALL | 7 | `qbditrace_capicall_head_t`/`_v8_t` + str_caps[] | C/平台 API 调用（含参数快照） |
| RETVAL | 8 | `qbditrace_retval_t` | OBJC/CAPICALL/SVC 的返回事实 |
| MEMIMG | 9 | `qbditrace_memimg_t` + bytes[] | 内存快照块（v9，configure 时发射） |

> **磁盘布局说明**：所有记录以 C struct 自然对齐方式存储（writer 用 `memcpy(p, &struct, sizeof)`），
> 磁盘大小 = `sizeof(struct)`，**含对齐 padding**。下方各记录的 "Total" 均为 sizeof 口径，
> 与 `TraceFormat.h` 的 `static_assert` 一致。解析时必须用 `sizeof()` 推进，不能按字段裸和计算
> （例如 `qbditrace_inst_head_t` 逻辑字段 12 字节，但 sizeof = 16 字节，含 4 字节 padding）。

---

## REC_INST — 指令增量记录

REC_INST 根据 header flags 有四种变体，**解析时必须根据 flags 选择对应的头部结构**：

### v4 基线 (无 PC_DELTA, 无 HAS_FPR) — 头部 16 字节

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=0)                                                  │
│ u8  nzcv         ← 低 4 位 = N,Z,C,V；若 BRANCH_HINT 则高 4 位 │
│                    编码分支类别（见"Branch Hint"节）            │
│ u8  n_regdiff    ← 修改了几个 GPR                              │
│ u8  n_mem        ← 几次内存访问                                │
│ u64 pc           ← 指令的运行时绝对地址                        │
├────────────────────────────────────────────────────────────────┤
│ n_regdiff × { u8 reg_index; padding[7]; u64 value; }           │  各 16 字节
├────────────────────────────────────────────────────────────────┤
│ n_mem × { u8 type; u8 flags; u16 size; u64 addr;               │
│           u64 value; u64 value_hi; }                           │  各 32 字节
└────────────────────────────────────────────────────────────────┘
```

### v5 (PC_DELTA, 无 HAS_FPR) — 头部 6 字节

```
┌────────────────────────────────────────────────────────────────┐
│ u8   kind (=0)                                                 │
│ u8   nzcv                                                      │
│ u8   n_regdiff                                                 │
│ u8   n_mem                                                     │
│ i16  pc_delta    ← 与前一条 INST 的 PC 差（有符号，字节单位）  │
│                    首条 INST 的 delta 为 0                      │
├────────────────────────────────────────────────────────────────┤
│ n_regdiff × regdiff_t  (各 16 字节)                            │
├────────────────────────────────────────────────────────────────┤
│ n_mem × memacc_t  (各 32 字节)                                 │
└────────────────────────────────────────────────────────────────┘
```

### v7 (HAS_FPR, 无 PC_DELTA) — 头部 24 字节

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=0)                                                  │
│ u8  nzcv                                                       │
│ u8  n_regdiff                                                  │
│ u8  n_mem                                                      │
│ u64 pc                                                         │
│ u8  n_fprdiff    ← 修改了几个 FPR (v0-v31)                    │
│ u8  reserved[7]  ← 对齐到 8 字节                               │
├────────────────────────────────────────────────────────────────┤
│ n_regdiff × regdiff_t  (各 16 字节)                            │
├────────────────────────────────────────────────────────────────┤
│ n_fprdiff × fprdiff_t  (各 24 字节)                            │
├────────────────────────────────────────────────────────────────┤
│ n_mem × memacc_t  (各 32 字节)                                 │
└────────────────────────────────────────────────────────────────┘
```

### v7+v5 (HAS_FPR + PC_DELTA) — 头部 8 字节

```
┌────────────────────────────────────────────────────────────────┐
│ u8   kind (=0)                                                 │
│ u8   nzcv                                                      │
│ u8   n_regdiff                                                 │
│ u8   n_mem                                                     │
│ i16  pc_delta                                                  │
│ u8   n_fprdiff                                                 │
│ u8   reserved    ← 对齐到 8 字节                               │
├────────────────────────────────────────────────────────────────┤
│ n_regdiff × regdiff_t  (各 16 字节)                            │
├────────────────────────────────────────────────────────────────┤
│ n_fprdiff × fprdiff_t  (各 24 字节)                            │
├────────────────────────────────────────────────────────────────┤
│ n_mem × memacc_t  (各 32 字节)                                 │
└────────────────────────────────────────────────────────────────┘
```

**有效载荷结构（各变体共用）**：

**GPR 差值（`qbditrace_regdiff_t`，16 字节）**：

```
u8   reg_index   ← GPR 索引（0-33，见 AArch64 GPR 映射表）
u8   padding[7]  ← 对齐 padding
u64  value       ← 指令执行后该寄存器的新值（绝对值）
```

**FPR 差值（`qbditrace_fprdiff_t`，24 字节，仅 v7）**：

```
u8   fpr_index   ← FPR 索引（0-31，对应 v0-v31）
u8   padding[7]  ← 对齐 padding
u64  lo          ← 执行后 bits[63:0]
u64  hi          ← 执行后 bits[127:64]
```

**内存访问（`qbditrace_memacc_t`，32 字节）**：

```
u8   mem_type    ← bit0=read, bit1=write
u8   mem_flags   ← bit0=unknown_size, bit1=minimum_size, bit2=unknown_value
u16  size        ← 访问字节数
u64  addr        ← 访问地址
u64  value       ← 低 8 字节数据（≤8B 时为全部）
u64  value_hi    ← 高字节（9-16B 时存高字节，否则为 0）
```

**内存访问 v6 扩展（`qbditrace_memacc_v6_t`，48 字节，当 `HF_OLD_VALUE` 设置时）**：

```
... (同上 32 字节) ...
u64  old_value    ← 写前低 8 字节（仅 WRITE；READ 时为 0）
u64  old_value_hi ← 写前高字节；mem_flags bit3=OLD_UNKNOWN 表示无法捕获
```

> **注**：v6 old_value 捕获已从 writer 移除，此扩展格式仅用于读取旧版 trace。

**字段解释**：

- `nzcv` 低 4 位：指令执行后的条件标志（如果 HAS_NZCV flag 未设则为 0）
- `nzcv` 高 4 位：分支类别（仅当 `HF_BRANCH_HINT` 设置时有效，见下方"Branch Hint"节）
- `reg_index`：修改的寄存器在 GPR 映射表中的索引
- `value`：指令执行**后**该寄存器的新值（旧值由 decoder 从运行状态推导）

---

## REC_ANCHOR — 完整寄存器快照

ANCHOR 大小取决于是否有 `HF_HAS_FPR`：

**v4/v5/v6（无 HAS_FPR） — 共 288 字节**：

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=1)                                                  │
│ u8  reserved[3]                                                │
│ u64 pc              ← 快照时的 PC                              │
│ u64 regs[num_gpr]   ← 34 × 8 = 272 字节的完整 GPR 快照       │
└────────────────────────────────────────────────────────────────┘
Total: 16 + 272 = 288 字节
```

**v7（有 HAS_FPR） — 共 800 字节**：

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=1)                                                  │
│ u8  reserved[3]                                                │
│ u64 pc              ← 快照时的 PC                              │
│ u64 regs[num_gpr]   ← 34 × 8 = 272 字节的完整 GPR 快照       │
│ u64 fpr[32][2]      ← 32 × 16 = 512 字节的完整 FPR 快照       │
│                       每个 FPR：u64 lo + u64 hi = 16 字节      │
└────────────────────────────────────────────────────────────────┘
Total: 16 + 272 + 512 = 800 字节
```

**语义**：在该 ANCHOR 之后的第一条 INST 执行**前**，CPU 的完整寄存器状态。

**频率**：qbditrace 默认每 1024 条 INST 记录一个 ANCHOR（可通过 `config_t.anchor_interval` 配置）。
另外在 XFER_CALL/XFER_RETURN（跨 instrumented range 边界的调用/返回）之后也会强制写入下一条 ANCHOR，
作为“重新进入追踪范围”的重同步检查点；SEQ_ENTRY/SEQ_EXIT（普通基本块/序列切换，频率远高于
XFER_CALL/RETURN）**不**触发 ANCHOR——寄存器 diff 存的是绝对值，跨 sequence 边界无需重同步。

**tenet 使用**：RegisterFile 的重建基准点。通过 RocksDB "anchor" CF 缓存所有 ANCHOR 的位置，实现 O(1) 定位最近的 ANCHOR。

---

## REC_THREAD — 线程标记

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=2)                                                  │
│ u8  reserved[3]                                                │
│ u64 thread_id                                                  │
└────────────────────────────────────────────────────────────────┘
Total: 16 字节 (`sizeof(qbditrace_thread_head_t)`，含对齐 padding)
```

标记后续记录属于哪个线程。qbditrace 会在线程切换（QBDI 执行权移交）时写入；`qbditrace_run_thread`（pthread_create 拦截）启动的新线程也以 THREAD 记录开头。

tenet 已支持多线程 trace 分析：`TraceIndex` 为每个 anchor 标注写者线程并维护线程 chunk 表；`thread` / `thread_filter` / `cross_thread_dataflow` pass 基于这些标注工作（详见 analysis-layer.md）。单线程语义的分析（如调用栈）以线程隔离 cursor 重建，不会跨线程串扰。

---

## REC_EVENT — 执行权转移

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=3)                                                  │
│ u8  event          ← qbditrace_event_t 枚举                   │
│ u8  reserved[2]                                                │
│ u64 addr           ← 目标地址                                  │
│ u64 site           ← 调用者 PC（仅 XFER_CALL 时有意义）       │
└────────────────────────────────────────────────────────────────┘
Total: 24 字节 (`sizeof(qbditrace_event_head_t)`，含对齐 padding)
```

**Event 类型**：

| 值 | 名称 | 含义 |
|-----|------|------|
| 1 | SEQ_ENTRY | 进入追踪范围 |
| 2 | SEQ_EXIT | 离开追踪范围 |
| 3 | XFER_CALL | 调用了未被 instrument 的函数（addr=目标, site=调用者 PC） |
| 4 | XFER_RETURN | 从外部函数返回追踪范围（addr=返回目标） |

**写入条件**：SEQ_ENTRY/SEQ_EXIT 受 `qbditrace_config_t.record` 的 `QBDITRACE_REC_SEQEVENTS`
位控制（默认开启）。它们大约每次 taken 分支/循环回边触发一对，是 loop-heavy 代码里数量最多的
记录类型之一，但**没有任何 tenet pass 依赖其语义**——基本块与循环边界完全由 `cfg`/`loop` pass
从裸 PC 流 + 静态反汇编重建。因此 qbditrace 的 sampling 模式（`record = QBDITRACE_REC_SAMPLING`，
见下方“采样侦察 trace”）会关闭这两个事件以大幅缩减体积，且不影响 `cfg`/`loop`/`window_stats`
等 pass 的正确性。XFER_CALL/XFER_RETURN 不受此位影响，始终发射。

**tenet 使用**：
- XFER_CALL/RETURN 用于 CallStack 重建
- SEQ_ENTRY/SEQ_EXIT 目前仅在 TraceReader 解析层被消费，任何 pass 均不依赖其内容

---

## REC_SVC — 系统调用

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=4)                                                  │
│ u8  flags           ← `reserved[0]`；QBDITRACE_SVC_FL_*         │
│ u8  reserved[2]                                                │
│ u64 pc              ← svc 指令地址                             │
│ u64 syscall_no      ← x16 (Darwin) 或 x8 (Linux/Android)       │
│ u64 args[6]         ← x0-x5                                   │
└────────────────────────────────────────────────────────────────┘
Total: 72 字节 (`sizeof(qbditrace_svc_head_t)`，含对齐 padding)
```

`flags` 复用旧 `reserved[0]`，不改变 72B 布局：`SVC_FL_MACH_TRAP`、`SVC_FL_BINDER_IOC`、
`SVC_FL_MEM_OP`、`SVC_FL_FILE_OP`、`SVC_FL_NET_OP`、`SVC_FL_CRYPTO_OP` 分别标识 Mach trap、Binder ioctl
及内存/文件/网络/密码学相关系统调用。

---

## REC_OBJC — Objective-C 消息发送

v4–v7 使用 `qbditrace_objc_head_t`：80B 固定头，字段为 `kind/variant/reserved/pc/recv/sel/cls[48]`；
`cls` 是在线捕获的 NUL 终止接收者类名。

v8（`HF_CALL_META`）改用同为 **80B** 的 `qbditrace_objc_head_v8_t`：

```
kind | variant | sel_len | flags | reserved | pc | recv | sel | cls[48]
[selector_name: sel_len 字节内容 + NUL，随后补齐到 4B]
```

`selector_name` 由 tracer 在线调用 `sel_getName` 捕获；`sel_len` 不含末尾 NUL。`flags` 的 bit 0 为
`OBJC_FL_SEL_TRUNCATED`，bit 1 为 `OBJC_FL_SEL_READ_FAIL`；最长 255 字节。尾部仅在 v8 存在，
记录大小为 `80 + align4(sel_len + 1)`。

ObjC Variant：MSGSEND(0), MSGSEND_SUPER(1), MSGSEND_SUPER2(2), MSGSEND_STRET(3)。对于
MSGSEND_STRET：x0 为隐藏返回指针，x1 为 receiver，x2 为 selector；`recv` 存 x1，`sel` 存 x2。

**tenet 使用**：`cls` 直接提供类名，v8 selector payload 提供无需离线解引用的 selector 名；两者均可增强
CallStack 方法边界识别。

---

## REC_CODE — 指令原始字节

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=6)                                                  │
│ u8  size            ← 指令字节数（AArch64 = 4）               │
│ u8  reserved[2]                                                │
│ u64 pc              ← 运行时地址                               │
│ u8  bytes[size]     ← 原始机器码                               │
└────────────────────────────────────────────────────────────────┘
Total: 16 + size 字节 (`sizeof(qbditrace_code_head_t)` + size，含对齐 padding；AArch64 size=4 即 20 字节)
```

**语义**：每个 distinct PC 只记录一次（首次出现时写入）。
这使 tenet 无需外部 binary image 即可反汇编。

**tenet 使用**：
- CodeTable 从 CODE 记录构建 pc → opcode 映射
- 对 SMC（同一 PC 出现多个 CODE 记录）：按出现顺序记录多版本

---

## REC_CAPICALL — C/平台 API 调用记录

当 QBDI `EXEC_TRANSFER_CALL` 目标匹配 `capi_funcs[]` 中的已注册地址时发射。
携带被调用函数的语义标识（`api_id`）、调用点 PC、目标地址、参数寄存器（x0..x7），
以及可选的指针参数内联字符串捕获。

> **写入条件**：`qbditrace_config_t.record` 含 `QBDITRACE_REC_CAPI` **且**
> `enable_capi_intercept != 0` **且** `n_capi_funcs > 0`。

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=7)                                                  │
│ u8  api_id        ← v4–v7：`qbditrace_capi_id_t` 的低 8 位    │
│ u8  arg_count     ← args[] 中有效项数（0..8）                  │
│ u8  str_count     ← 紧随其后的字符串捕获条数（0..4）           │
│ u64 pc            ← 调用点 PC（位于被追踪范围内）              │
│ u64 target        ← 被调用函数的运行时地址                     │
│ u64 args[8]       ← x0..x7（仅前 arg_count 项有效）           │
├────────────────────────────────────────────────────────────────┤
│ 对每个字符串捕获（str_count 次）：                              │
│   u8  str_arg_idx ← 来自 args[] 的哪个索引（0..7）            │
│   u8  str_len     ← 字符串内容字节数（不含 NUL）              │
│   u8  str_flags   ← QBDITRACE_SF_* 位标志                     │
│   u8  _reserved                                                │
│   u8  str_data[str_len + 1]  ← NUL 终止，补齐到 4 字节对齐   │
└────────────────────────────────────────────────────────────────┘
Fixed header: sizeof(qbditrace_capicall_head_t) = 88 字节
Variable tail: str_count × (4 + str_len + 1 + pad)，最多 ≈ 1 KB
```

v8（`HF_CALL_META`）固定头改为 `qbditrace_capicall_head_v8_t`，仍为 **88B**：字段顺序为
`kind/arg_count/str_count/flags/api_id(uint16_t)/reserved/pc/target/args[8]`。可变字符串尾部与旧布局相同；
`api_id` 因此可完整保存 16 位 API ID，文件内不得混用两种布局。

**str_flags 位定义**：

| 位 | 宏 | 含义 |
|----|----|------|
| bit 0 | `SF_TRUNCATED` | 字符串超过 255 字节被截断 |
| bit 1 | `SF_BINARY` | 内容为原始字节（含不可打印字符） |
| bit 2 | `SF_SAFE_READ_FAIL` | safeRead 失败，str_len=0，捕获为空 |

> **版本差异**：v4–v7 的磁盘 `api_id` 为 `uint8_t`，所有 `api_id >= 256` 会截断；v8 的
> `qbditrace_capicall_head_v8_t.api_id` 为 `uint16_t`，可完整 round-trip。

**api_id 分组速览**（来自 `qbditrace_capi_id_t`）：

| 范围 | 分类 | 平台 |
|------|------|------|
| 0 | Unknown | — |
| 1–19 | 内存操作（memcpy/memmove/memset/…） | 通用 |
| 20–59 | 字符串操作（strlen/strcmp/strcpy/…） | 通用 |
| 60–79 | 堆分配（malloc/calloc/free/…） | 通用 |
| 80–99 | 文件 I/O（fopen/read/write/…） | 通用 |
| 100–129 | libc 级 Crypto（arc4random/getrandom） | 通用 |
| 130–199 | iOS/macOS 平台 API（CommonCrypto/Security.framework/CF） | [ios] |
| 200–279 | Android/Bionic 平台 API（BoringSSL/android_log/Binder） | [android] |
| 280–359 | JNI 函数（280–301 基础集 + 302–359 扩展，覆盖 JNINativeInterface_ 全 vtable 约 112 个 slot） | [jni] |
| 360–379 | pthread / 同步原语 | 通用 |
| 380–399 | 网络（socket/connect/send/recv/…） | 通用 |
| 400–419 | 编码（base64_encode/decode） | 通用 |
| 420–449 | 反调试/完整性（ptrace/sysctl/isatty/…） | 通用 |
| 450–469 | 扩展文件系统（mmap/mprotect/…） | 通用 |
| 470–599 | iOS/macOS 扩展（CCHmac*/CCCryptorCreate*/CFString*…） | [ios] |
| 600–699 | Android/Bionic 扩展（EVP_Encrypt*/HMAC_*/AES_*…） | [android] |
| 700–731 | JNI 扩展（GetIntField/NewObject/GetVersion/GetIntArrayRegion/…） | [jni] |

**关键 iOS crypto api_id**：

| api_id | 常量 | 函数签名 |
|--------|------|---------|
| 134 | `CAPI_CC_CRYPT` | `CCCrypt(op,alg,opt,key,kl,iv,pt,pl,ct,cl,ml)` |
| 135 | `CAPI_CC_HMAC` | `CCHmac(alg,key,kl,data,dl,mac)` |
| 136 | `CAPI_CC_DIGEST` | `CC_SHA256/MD5/…(data,len,out)` |
| 137 | `CAPI_CC_KEY_DERIVE_PBKDF` | `CCKeyDerivationPBKDF(…)` |
| 476 | `CAPI_CC_HMAC_INIT` | `CCHmacInit(ctx,alg,key,kl)` |
| 479 | `CAPI_CC_CRYPTOR_CREATE` | `CCCryptorCreate(op,alg,opt,key,kl,iv,ref)` |

**记录大小计算**：

```cpp
// capicall 记录大小：固定头 + 可变字符串尾
size_t capicall_record_size(const uint8_t* ptr) {
    const auto* h = (const qbditrace_capicall_head_t*)ptr;
    size_t sz = sizeof(qbditrace_capicall_head_t);
    const uint8_t* p = ptr + sz;
    for (uint8_t i = 0; i < h->str_count; ++i) {
        const auto* s = (const qbditrace_capicall_str_t*)p;
        // 4 字节 header + str_len + 1 NUL，补齐到 4 字节
        size_t entry = 4 + s->str_len + 1;
        entry = (entry + 3) & ~3u;  // round up to 4
        p += entry;
        sz += entry;
    }
    return sz;
}
```

**tenet 使用**：
- `SyscallInterceptCollector::on_capicall()` 处理此记录，优先级高于 Event XFER_CALL 启发式检测
- `from_capicall_record = true` 的 `InterceptedCall` 含有 `captured_strings` 内联字符串向量
- 已处理的 callee PC 被记录进 `capicall_seen_`，阻止后续重复的 Event 路径生成冗余记录

---

## REC_RETVAL — 返回事实（v8）

`HF_CALL_META` 下允许 `REC_RETVAL`（`qbditrace_retval_t`，固定 **64B**），用于自描述地关联
OBJC、CAPICALL 或 SVC 的实际返回状态：

| 字段 | 类型 | 说明 |
|------|------|------|
| `kind/source_kind/flags/reserved8` | 4 × u8 | `kind=8`；来源为 SVC/OBJC/CAPICALL |
| `aux_id/record_size` | 2 × u16 | 紧凑 variant/API 提示；记录总大小（v8 为 64B） |
| `source_id/site/target/resume/x0/x1` | 6 × u64 | 完整来源标识、调用点、目标、恢复地址及返回 x0/x1 |
| `nzcv/reserved32` | 2 × u32 | 返回时 NZCV 与保留字段 |

- `source_id` 保存完整来源标识，Darwin syscall selector 不截断为 32 位；`aux_id` 为紧凑的 variant/API 提示。
- `site` 是原调用点，`target` 是调用目标，`resume` 是恢复执行地址；`x0/x1/nzcv` 是返回时原始架构状态。
- `record_size` 支持将来扩展：v8 reader 应按该值跳过完整记录。`flags` 的 bit 0
  `QBDITRACE_RET_FL_ERRNO_VALID` 表示 producer 可证明 errno 属于此调用。
- 记录器对待返回的调用按 **LIFO** 栈管理：每个 call-site 先压入 pending call，返回时弹出栈顶并发射
  RETVAL；嵌套调用因此与最近、尚未完成的来源记录关联。

---

## REC_MEMIMG — 内存快照块（v9）

`HF_MEMIMG` 下，`qbditrace_configure()` 在写完文件头后立即对调用方指定的内存范围
（`qbditrace_config_t::snapshot_ranges[]`，默认关闭）做一次快照，以 REC_MEMIMG 记录写入。
**流契约：所有 MEMIMG 记录位于第一个 REC_INST 之前**，因此 reader 可用一次廉价的前缀扫描收集。

| 字段 | 类型 | 说明 |
|------|------|------|
| `kind/flags/record_size` | u8 + u8 + u16 | `kind=9`；`record_size = 24 + len`（自描述，可按值跳过整条记录） |
| `seq` | u32 | 块序号（快照内单调递增） |
| `addr` | u64 | `data[0]` 的运行时地址 |
| `len/reserved` | u32 × 2 | payload 字节数；保留字必须为 0 |
| `data[len]` | u8[] | 原始内存字节（无尾部对齐填充） |

- 固定头 24B（`qbditrace_memimg_t`），单块 payload ≤ `QBDITRACE_MEMIMG_CHUNK_MAX`（32 KiB）。
- 录制时按 4 KiB 页用容错读（`safeRead`）捕获：不可读页（guard page/未映射洞）在流中形成空洞，
  相邻可读页合并为大块；总量硬上限 256 MiB。`end <= start` 的无效范围被静默跳过。
- **设计意图**：指令的写/读日志只覆盖被追踪代码实际触碰的地址。trace 开始前由未插桩代码
  （解密壳、启动代码）写入的全局状态（.data/.bss 里的解密字符串、运行时表）若从未被读/写，
  对分析不可见；快照补的正是这一块。不要 dump rodata（与 tenet `--image` 回退重复）、heap/stack。

**tenet 使用**：
- `TraceReader::collect_memimg_regions()` 前缀扫描并合并相邻块为排序的连续区域。
- `MemoryModel` 将其作为**快照基底层**：读查询按 写日志 → 读日志 → 快照 的顺序解析，
  快照只填日志未覆盖的字节；`at_inst_id == 0` 时直接以快照作答（这正是 t=0 的状态）。
- 快照字节的 `MemReadResult.writer_id` 标记为哨兵 `MemoryModel::kSnapshotWriterId`
  （= UINT64_MAX，`is_snapshot_writer()` 判定）：它是 t=0 时刻的值，用于更晚时刻是**显式标注的
  近似**，而非静默近似。快照不计入 `active_pages()`/`was_accessed()`。
- `tenet --dump` 输出 MEMIMG 摘要（seq/addr/len），不 hexdump payload。

---

## Branch Hint 编码（HF_BRANCH_HINT）

当 `HF_BRANCH_HINT` (bit 9) 设置时，每条 REC_INST 的 `nzcv` 字节高 4 位编码分支类别：

| bits[7:4] | 宏 | 含义 |
|-----------|----|------|
| 0 | BRANCH_HINT_NONE | 普通指令 |
| 1 | BRANCH_HINT_CALL | BL / BLR (调用) |
| 2 | BRANCH_HINT_RET | RET / RETAA / RETAB (返回) |
| 4 | BRANCH_HINT_BRANCH | B / BR (无条件跳转) |

`nzcv` 低 4 位 (bits[3:0]) 仍为 N,Z,C,V 条件标志。

**tenet 使用**：`FunctionPass` 和 `CFGPass` 优先从 Branch Hint 识别调用/返回边界，跳过 Capstone 反汇编，大幅提升扫描吞吐量。

---

## 地址规范化

qbditrace 记录的是**运行时地址**（含 ASLR slide）。tenet 中两种地址表示：

```
static_address = runtime_address - module_slide
runtime_address = static_address + module_slide
```

内部存储和索引使用**运行时地址**（与 trace 一致），显示时可选转换为静态地址。

---

## 采样侦察 trace（QBDITRACE_REC_SAMPLING）

**动机**：做一次完整 trace 之前，先用一次代价小得多的"侦察"trace 摸清目标函数的执行情况
（有没有巨大的、明显与业务逻辑无关的循环——如 memset 式清零、CRC/校验和、反调试忙等延时），
再决定用 `--exclude-range` 排除哪些区域做正式的完整 trace。

**关键设计约束**：`record == 0` 在 ABI 层历史上被当作"调用方没设置该字段"（兼容旧结构体大小的
调用方），会被静默替换为 `QBDITRACE_REC_DEFAULT`（见 `qbditrace_configure` 内 ABI 兼容 shim）。
因此不能靠传 `record = 0` 得到"什么都不记录"的效果。为此新增了一个不参与任何记录内容判断的
哨兵位 `QBDITRACE_REC_SAMPLING`（`1u << 31`）：只要 `record` 非零就不会被替换为默认值，而这个
哨兵位本身不出现在任何 `cfg.record & QBDITRACE_REC_*` 的判断里，因此效果等价于"真正的 0"。

**采样模式产出的记录构成**：仅 `REC_INST`（裸 PC，无寄存器 diff/无内存访问）+ `REC_CODE`（去重
指令字节表）+ `REC_ANCHOR`（线程/PC 定位用，间隔可调大）+ `REC_THREAD`；`REC_EVENT` 的
SEQ_ENTRY/SEQ_EXIT 由 `QBDITRACE_REC_SEQEVENTS` 位控制，sampling 模式下默认关闭
（XFER_CALL/XFER_RETURN 不受影响，仍然发射，因为它们数量少且携带跨界调用信息）。

**为什么这样瘦身而不是"跳过部分指令采样"**：tenet 的 `cfg`/`loop`/`window_stats` 等 pass 都是
基于**完整、连续的 PC 执行序列**做静态反汇编 + 动态边计数重建基本块和循环的（见 `cfg_pass.cpp`
Phase 1-4），任何跳过指令的统计采样都会直接破坏边计数和循环回边识别的正确性。因此 sampling 模式
的思路是"保留完整 PC 流，只裁剪掉每条记录里不必要的载荷"，而不是抽样跳过指令——这样 `loop` pass
识别出的循环迭代次数和 `cfg` pass 统计的边 taken_count 仍然是精确值，不是估计值。

**实测收益**（20 万次迭代热循环 + 少量分支逻辑的合成用例）：完整记录 55 MB → sampling 关闭
REGDIFF/MEM/SEQEVENTS 后 26 MB → 再加 `enable_pc_delta`（v5，INST 头 16B→6B）后 9.6 MB，
体积降至约 17%，且 `cfg`/`loop` pass 在瘦身后的 trace 上精确复现了 199876~199877 次的循环边计数。

**使用方式**：见 `tools/qbditrace/qbditrace_runner.py --sampling`（一键应用
`record=QBDITRACE_REC_SAMPLING` + `enable_pc_delta=1` + 较大的 `anchor_interval`），配合
`tenet --suggest-excludes`（基于 `loop` pass 结果生成候选 `--exclude-range` 建议，见
`tools/tenet/src/batch_analysis.cpp` 的 `run_suggest_excludes`）或 `tenet --run-pass loop` 人工
检查循环明细。

---

## tenet 核心假设

| # | 假设 | 违反时处理 |
|---|------|-----------|
| 1 | Header 为 536 字节，magic = "QBDT" | 拒绝打开 |
| 2 | version >= 4 | < 4 拒绝；> 9 警告并尝试继续 |
| 3 | flags 包含 REG_DIFF（常规完整 trace） | 不强制：REG_DIFF/NZCV/MEM 均可关闭（见 `QBDITRACE_REC_SAMPLING`），此时 RegisterFile/MemoryModel 相关能力降级，但 `xref`/`cfg`/`loop`/`window_stats` 等只需 PC 流 + REC_CODE 的 pass 正常工作 |
| 4 | flags 包含 HAS_CODE | 不含则需要外部 image |
| 5 | 记录按写入顺序排列（时间单调递增） | 索引依赖此假设 |
| 6 | ANCHOR 间隔 ≤ 65536 条 INST | 超过则性能退化 |
| 7 | 每条记录大小可从头部字段确定 | 向前兼容跳过未知记录 |
| 8 | num_gpr = 34 (AArch64) | 其他值按 header 声明处理 |
| 9 | CAPICALL 记录（若存在）紧随对应 XFER_CALL Event 之前 | SyscallInterceptCollector 用 capicall_seen_ 去重 |
| 10 | `HF_CALL_META` 仅随 v8 出现，且 v8 必带该 flag | 其他组合拒绝；v8 可组合 PC_DELTA/HAS_FPR/OLD_VALUE |
| 11 | `HF_MEMIMG` 仅随 v9 出现，且 v9 必带该 flag；MEMIMG 记录全部位于首个 INST 之前 | 无 flag 的 v9 拒绝；前缀扫描遇到 INST 即停 |

---

## 记录大小计算

tenet 遍历 trace 时需要知道每条记录的大小以跳到下一条。**必须根据 flags 选择对应的头部结构**：

```cpp
size_t record_size(const uint8_t* ptr, const TraceFlags& flags, uint32_t num_gpr) {
    switch (ptr[0]) {
    case QBDITRACE_REC_INST: {
        size_t head_size;
        uint8_t n_regdiff, n_mem, n_fprdiff = 0;
        if (flags.has_fpr && flags.pc_delta) {
            // v7+v5: 8 字节头
            auto* h = (const qbditrace_inst_head_v7_v5_t*)ptr;
            head_size = sizeof(*h); n_regdiff = h->n_regdiff;
            n_fprdiff = h->n_fprdiff; n_mem = h->n_mem;
        } else if (flags.has_fpr) {
            // v7: 24 字节头
            auto* h = (const qbditrace_inst_head_v7_t*)ptr;
            head_size = sizeof(*h); n_regdiff = h->n_regdiff;
            n_fprdiff = h->n_fprdiff; n_mem = h->n_mem;
        } else if (flags.pc_delta) {
            // v5: 6 字节头
            auto* h = (const qbditrace_inst_head_v5_t*)ptr;
            head_size = sizeof(*h); n_regdiff = h->n_regdiff; n_mem = h->n_mem;
        } else {
            // v4: 16 字节头
            auto* h = (const qbditrace_inst_head_t*)ptr;
            head_size = sizeof(*h); n_regdiff = h->n_regdiff; n_mem = h->n_mem;
        }
        size_t memacc_size = flags.old_value
            ? sizeof(qbditrace_memacc_v6_t) : sizeof(qbditrace_memacc_t);
        return head_size
             + n_regdiff * sizeof(qbditrace_regdiff_t)
             + n_fprdiff * sizeof(qbditrace_fprdiff_t)
             + n_mem * memacc_size;
    }
    case QBDITRACE_REC_ANCHOR: {
        size_t fpr_bytes = flags.has_fpr ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
        return sizeof(qbditrace_anchor_head_t) + num_gpr * 8 + fpr_bytes;
    }
    case QBDITRACE_REC_THREAD:
        return sizeof(qbditrace_thread_head_t);
    case QBDITRACE_REC_EVENT:
        return sizeof(qbditrace_event_head_t);
    case QBDITRACE_REC_SVC:
        return sizeof(qbditrace_svc_head_t);
    case QBDITRACE_REC_OBJC:
        // v8: 80B 固定头 + align4(sel_len + NUL)；旧版固定 80B。
        return flags.call_meta
            ? sizeof(qbditrace_objc_head_v8_t)
              + align4(((const qbditrace_objc_head_v8_t*)ptr)->sel_len + 1)
            : sizeof(qbditrace_objc_head_t);
    case QBDITRACE_REC_CODE:
        return sizeof(qbditrace_code_head_t) + ptr[1]; // ptr[1] = size
    case QBDITRACE_REC_CAPICALL: {
        // v8 仍为 88B 固定头，但 api_id 位宽和字段顺序不同。
        const size_t head_size = flags.call_meta
            ? sizeof(qbditrace_capicall_head_v8_t)
            : sizeof(qbditrace_capicall_head_t);
        const uint8_t str_count = flags.call_meta
            ? ((const qbditrace_capicall_head_v8_t*)ptr)->str_count
            : ((const qbditrace_capicall_head_t*)ptr)->str_count;
        size_t sz = head_size;
        const uint8_t* sp = ptr + head_size;
        for (uint8_t i = 0; i < str_count; ++i) {
            const auto* s = (const qbditrace_capicall_str_t*)sp;
            size_t entry = 4 + s->str_len + 1;
            entry = (entry + 3) & ~3u;  // 4-byte aligned
            sp += entry;
            sz += entry;
        }
        return sz;
    }
    case QBDITRACE_REC_RETVAL:
        return ((const qbditrace_retval_t*)ptr)->record_size;
    default:
        return 0; // 未知记录，无法跳过
    }
}
```

---

## 流式压缩格式（HF_COMPRESSED）

当文件头 flags 包含 `HF_COMPRESSED` (bit 7) 时，文件布局如下：

```
┌──────────────────────────────────────────┐
│ File Header (536 bytes, 明文)             │  ← qbditrace_file_header_t
├──────────────────────────────────────────┤
│ Zstd Frame                               │  ← ZSTD_compressStream2 输出
│   (解压后与未压缩格式的记录流完全相同)       │
└──────────────────────────────────────────┘
```

文件头始终不压缩；压缩范围是文件头之后的所有字节，构成一个完整的 zstd frame（包含 content checksum）。

**写入端**：当前 qbditrace writer 不再产生此格式。本节保留用于解释和读取历史
`HF_COMPRESSED` trace。

**读取端（tenet）**：`TraceReader::open()` 检测到 `HF_COMPRESSED` 后，自动通过 `ZSTD_decompressStream` 流式解压到临时文件（同目录下 `.tenet-decomp-XXXXXX`，若失败回退 `/tmp`）。临时文件的 header 中 `HF_COMPRESSED` 标志已被清除，之后正常 mmap。`TraceReader::close()` 时自动删除临时文件。

---

## 分块压缩格式（HF_BLOCK_COMPRESSED）

当文件头 flags 包含 `HF_BLOCK_COMPRESSED` (bit 8) 时，使用分块压缩格式。与流式压缩的区别：每块是**独立的 zstd frame**，可以独立解压，支持 **O(1) 随机访问**。

**文件布局**（重复文件布局小节的内容，此处为详细字段说明）：

```
[536B file header]  ← 未压缩
[block 0: 独立 zstd frame，解压后 ≤ 1MB]
[block 1: 独立 zstd frame]
...
[block N-1]
[block index table: N × qbditrace_block_entry_t]
[block index footer: qbditrace_block_footer_t (16 bytes)]
```

**Block Entry（`qbditrace_block_entry_t`，24 字节）**：

```
u64  original_offset    ← 该块在解压后逻辑流中的起始偏移
u64  compressed_offset  ← 该块在物理文件中的起始偏移
u32  original_size      ← 解压后大小（≤ 1MB）
u32  compressed_size    ← 压缩后大小
```

**Block Index Footer（`qbditrace_block_footer_t`，16 字节）**：

```
u64  index_offset   ← block index table 在文件中的偏移（从文件头算起）
u32  block_count    ← 块的总数量
u32  magic          ← 0x51424249 ("QBBI")
```

**读取策略**：

1. 读取文件末尾 16 字节，验证 `magic == 0x51424249`。
2. 根据 `index_offset` 和 `block_count` 读取 block index table。
3. 二分搜索找到包含目标逻辑偏移的块，解压该块即可。

**写入端与默认参数**：这是当前 qbditrace 的默认压缩格式。`BackgroundWriter` 累积
1 MiB 原始记录（`QBDITRACE_DEFAULT_BLOCK_SIZE`），以 zstd level 1 + frame checksum
压成独立 frame；`qbditrace_stop()` 刷出最后一块并写索引表与 footer。

**tenet 使用**：`TraceReader` 在检测到 `HF_BLOCK_COMPRESSED` 后，将 index table 加载为 `std::vector<BlockEntry>`，随机访问时通过二分查找定位块，按需解压，无需预先解压整个文件。

---

## 版本兼容策略

```cpp
// 版本与 flags 处理逻辑
if (header.version < 4)
    return Error("Unsupported trace version {}, need >= 4", header.version);

// v5: PC_DELTA 模式
bool pc_delta_mode = (header.flags & HF_PC_DELTA) != 0;
// v6: OLD_VALUE 扩展（writer 已移除，仅支持读取旧 trace）
bool old_value_mode = (header.flags & HF_OLD_VALUE) != 0;
// v7: FPR 记录
bool has_fpr = (header.flags & HF_HAS_FPR) != 0;

bool call_meta_mode = (header.flags & HF_CALL_META) != 0;
if ((header.version == 8) != call_meta_mode)
    return Error("HF_CALL_META is required exactly for v8 traces");
if (header.version > 8)
    warn("Unknown trace version {}, attempting to continue", header.version);
```

| 版本 | 新增 Flag | INST 头大小 | ANCHOR 大小 | 备注 |
|------|-----------|------------|------------|------|
| v4 | — | 16B | 288B | 基线，qbditrace 默认产 v4 |
| v5 | PC_DELTA | **6B** | 288B | 约减少 60% 文件体积 |
| v6 | OLD_VALUE | 16B | 288B | memacc 扩展为 48B；writer 已移除 |
| v7 | HAS_FPR | 24B (或 8B 含 PC_DELTA) | **800B** | 新增 FPR diff 和快照 |
| v8 | CALL_META | 同 v4–v7 组合 | 同 v4–v7 组合 | OBJC 在线 selector、CAPICALL `api_id:uint16_t`、RETVAL |

对于未知 kind 的记录，tenet 的处理规则：

- 如果 `record_size()` 可以确定大小，跳过该记录继续
- 如果返回 0（无法确定大小），停止遍历并报错

---

## 未来增强方向（需 qbditrace 配合）

| 编号 | 增强 | 动机 | 状态 |
|------|------|------|------|
| E1 | Header 记录 anchor_interval | tenet 可预测 ANCHOR 位置 | 待实现 |
| E2 | 文件尾部全局索引表 | 避免 tenet 全文件扫描建索引（O(n)→O(1)） | 待实现 |
| E3 | 浮点/向量寄存器 | 密码学分析需要 NEON | ✅ **已实现**（v7 HF_HAS_FPR） |
| E4 | 内存映射信息 | mmap 区域感知 | 待实现（REC_MMAP） |
| E5 | 压缩 | 文件体积压缩 3-4x | ✅ **已实现**（当前 writer 使用 HF_BLOCK_COMPRESSED；HF_COMPRESSED 仅兼容历史读取） |
| E6 | inst_id 全局编号 | 当前无显式 ID，靠顺序计数 | 待实现 |
| E7 | 分块压缩 | O(1) 随机访问压缩 trace | ✅ **已实现**（HF_BLOCK_COMPRESSED） |
| E8 | 分支类别提示 | 零开销函数边界识别 | ✅ **已实现**（HF_BRANCH_HINT） |
| E9 | CAPICALL api_id 扩宽 | v8 已升级为 `uint16_t`，支持 Android/JNI 扩展 ID | ✅ **已实现**（v8 HF_CALL_META） |

**优先级**（待实现部分）：E2 > E1 > E6 > E4

E2（尾部全局索引表）对 tenet 性能影响最大——可将首次打开从 60s 降到 < 1s。
