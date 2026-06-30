# Trace Format 接口契约 (v2)

## 概述

本文档是 **tenet 分析器**与 **qbditrace 记录器**之间的接口契约。
tenet 依赖 `TraceFormat.h` (v4) 定义的格式读取 `.bin` trace 文件。

**权威来源**：`tools/qbditrace/TraceFormat.h`。本文档是该头文件的人类可读解释，
并标注 tenet 特有的处理策略和未来增强方向。如有冲突，以 `.h` 文件为准。

---

## 文件布局

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

所有数据均为 **小端序**（AArch64 native）。

---

## File Header — `qbditrace_file_header_t` (536 字节)

| 偏移 | 大小 | 字段 | 值/说明 |
|------|------|------|---------|
| 0x00 | 4 | magic | `0x51424454` ("QBDT") |
| 0x04 | 4 | version | 4 |
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

| Flag | 值 | 说明 |
|------|-----|------|
| HAS_MEM | bit 0 | 记录包含内存访问 |
| HAS_NZCV | bit 1 | INST 记录包含 NZCV |
| REG_DIFF | bit 2 | INST 使用 diff 模式（非全量快照） |
| HAS_CODE | bit 3 | 流中包含 REC_CODE 记录 |
| PC_DELTA | bit 4 | v5: INST 使用 pc_delta (int16) 代替绝对 PC |
| OLD_VALUE | bit 5 | v6: 内存写操作记录旧值（memacc 48B） |
| HAS_FPR | bit 6 | v7: ANCHOR/INST 包含 FPR (NEON v0-v31) |
| COMPRESSED | bit 7 | Header 后所有数据为 zstd 压缩流（见下方"压缩格式"节） |

**Target OS**：

| 值 | 枚举 | 说明 |
|------|------|------|
| 0 | UNKNOWN | 旧 trace（reserved 全零），tenet 会根据 module_name 路径启发式推断 |
| 1 | iOS | iOS / macOS (Darwin) |
| 2 | Android | Android (Linux kernel + Bionic) |
| 3 | Linux | Linux (glibc) |

qbditrace 在录制时通过编译期宏自动填写此字段。tenet 读取时会校验值是否在 0-3 范围，超过则回退为 Unknown。

**tenet 要求**：magic == 0x51424454, version >= 4, flags 必须包含 REG_DIFF | HAS_CODE。

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

**注意**：

- fp (frame pointer) = x29，索引 29，不是一个独立的额外寄存器
- wN 寄存器不单独索引，是 xN 的低 32 位
- **fpcr 不在 GPR 快照中**（如需，未来通过新记录类型扩展）
- 浮点/向量寄存器（q0-q31）当前版本不记录

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

> **磁盘布局说明**：所有记录以 C struct 自然对齐方式存储（writer 用 `memcpy(p, &struct, sizeof)`），
> 磁盘大小 = `sizeof(struct)`，**含对齐 padding**。下方各记录的 “Total” 均为 sizeof 口径，
> 与 `TraceFormat.h` 的 `static_assert` 一致。解析时必须用 `sizeof()` 推进，不能按字段裸和计算
> （例如 `qbditrace_inst_head_t` 逻辑字段 12 字节，但 sizeof = 16 字节，含 4 字节 padding）。

---

## REC_INST — 指令增量记录

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=0)                                                  │
│ u8  nzcv         ← 低 4 位 = N,Z,C,V（指令执行后）            │
│ u8  n_regdiff    ← 修改了几个 GPR                              │
│ u8  n_mem        ← 几次内存访问                                │
│ u64 pc           ← 指令的运行时地址                            │
├────────────────────────────────────────────────────────────────┤
│ n_regdiff × { u8 reg_index; u64 value; }  (各 16 字节)        │
├────────────────────────────────────────────────────────────────┤
│ n_mem × { u8 mem_type; u8 mem_flags; u16 size;                │
│           u64 addr; u64 value; u64 value_hi; }  (各 32 字节)  │
└────────────────────────────────────────────────────────────────┘
```

**字段解释**：

- `nzcv`：指令执行后的条件标志（如果 HAS_NZCV flag 未设则为 0）
- `reg_index`：修改的寄存器在 GPR 映射表中的索引
- `value`：指令执行**后**该寄存器的新值（旧值由 decoder 从运行状态推导）
- `mem_type`：bit0 = read, bit1 = write（对应 QBDI MemoryAccessType）
- `mem_flags`：bit0 = unknown_size, bit1 = minimum_size, bit2 = unknown_value
- `size`：访问大小（字节）
- `value`/`value_hi`：访问的数据。≤8B 时 `value` 即全部；9-16B 时低 8B 在 `value`，高字节在 `value_hi`

**记录大小**：16 + n_regdiff×16 + n_mem×32 字节（= `sizeof(qbditrace_inst_head_t)` + n_regdiff×`sizeof(qbditrace_regdiff_t)` + n_mem×`sizeof(qbditrace_memacc_t)`，含对齐 padding）。典型指令 ~30-60 字节。

---

## REC_ANCHOR — 完整寄存器快照

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=1)                                                  │
│ u8  reserved[3]                                                │
│ u64 pc              ← 快照时的 PC                              │
│ u64 regs[num_gpr]   ← 34 × 8 = 272 字节的完整 GPR 快照       │
└────────────────────────────────────────────────────────────────┘
Total: 16 + 272 = 288 字节 (`sizeof(qbditrace_anchor_head_t)` + num_gpr×8，含对齐 padding)
```

**语义**：在该 ANCHOR 之后的第一条 INST 执行**前**，CPU 的完整寄存器状态。

**频率**：qbditrace 默认每 4096 条 INST 记录一个 ANCHOR（可通过 `--anchor-interval` 配置）。
另外在 SEQ_ENTRY 事件后也会强制写入 ANCHOR。

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

标记后续记录属于哪个线程。tenet 当前假设单线程（忽略 THREAD 记录），未来扩展多线程支持。

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

**tenet 使用**：
- XFER_CALL/RETURN 用于 CallStack 重建
- SEQ_ENTRY 后期待一个 ANCHOR

---

## REC_SVC — 系统调用

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=4)                                                  │
│ u8  reserved[3]                                                │
│ u64 pc              ← svc 指令地址                             │
│ u64 syscall_no      ← x16 (Darwin) 或 x8 (Linux/Android)       │
│ u64 args[6]         ← x0-x5                                   │
└────────────────────────────────────────────────────────────────┘
Total: 72 字节 (`sizeof(qbditrace_svc_head_t)`，含对齐 padding)
```

---

## REC_OBJC — Objective-C 消息发送

```
┌────────────────────────────────────────────────────────────────┐
│ u8  kind (=5)                                                  │
│ u8  variant         ← qbditrace_objc_variant_t                │
│ u8  reserved[2]                                                │
│ u64 pc              ← 调用点 PC                                │
│ u64 recv            ← x0 (receiver)                           │
│ u64 sel             ← x1 (selector ptr)                       │
│ char cls[48]        ← 运行时类名（NUL 终止）                   │
└────────────────────────────────────────────────────────────────┘
Total: 80 字节 (`sizeof(qbditrace_objc_head_t)`，含对齐 padding)
```

ObjC Variant：MSGSEND(0), MSGSEND_SUPER(1), MSGSEND_SUPER2(2), MSGSEND_STRET(3)

**tenet 使用**：
- 字符串来源：cls 字段直接提供类名
- CallStack 增强：识别 ObjC 方法边界

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

## 地址规范化

qbditrace 记录的是**运行时地址**（含 ASLR slide）。tenet 中两种地址表示：

```
static_address = runtime_address - module_slide
runtime_address = static_address + module_slide
```

内部存储和索引使用**运行时地址**（与 trace 一致），显示时可选转换为静态地址。

---

## tenet 核心假设

| # | 假设 | 违反时处理 |
|---|------|-----------|
| 1 | Header 为 536 字节，magic = "QBDT" | 拒绝打开 |
| 2 | version = 4 | < 4 拒绝；> 4 跳过未知记录 |
| 3 | flags 包含 REG_DIFF | 不含则不支持（v1/v2 格式） |
| 4 | flags 包含 HAS_CODE | 不含则需要外部 image |
| 5 | 记录按写入顺序排列（时间单调递增） | 索引依赖此假设 |
| 6 | ANCHOR 间隔 ≤ 65536 条 INST | 超过则性能退化 |
| 7 | 每条记录大小可从头 4 字节确定 | 向前兼容跳过未知记录 |
| 8 | num_gpr = 34 (AArch64) | 其他值按 header 声明处理 |

---

## 记录大小计算

tenet 遍历 trace 时需要知道每条记录的大小以跳到下一条：

```cpp
size_t record_size(const uint8_t* ptr, uint32_t num_gpr) {
    switch (ptr[0]) {
    case QBDITRACE_REC_INST: {
        auto* h = (const qbditrace_inst_head_t*)ptr;
        return sizeof(qbditrace_inst_head_t)
             + h->n_regdiff * sizeof(qbditrace_regdiff_t)
             + h->n_mem * sizeof(qbditrace_memacc_t);
    }
    case QBDITRACE_REC_ANCHOR:
        return sizeof(qbditrace_anchor_head_t) + num_gpr * 8;
    case QBDITRACE_REC_THREAD:
        return sizeof(qbditrace_thread_head_t);
    case QBDITRACE_REC_EVENT:
        return sizeof(qbditrace_event_head_t);
    case QBDITRACE_REC_SVC:
        return sizeof(qbditrace_svc_head_t);
    case QBDITRACE_REC_OBJC:
        return sizeof(qbditrace_objc_head_t);
    case QBDITRACE_REC_CODE:
        return sizeof(qbditrace_code_head_t) + ptr[1]; // ptr[1] = size
    default:
        return 0; // 未知记录，无法跳过
    }
}
```

---

## 压缩格式（HF_COMPRESSED）

当文件头 flags 包含 `HF_COMPRESSED` (bit 7) 时，文件布局如下：

```
┌──────────────────────────────────────────┐
│ File Header (536 bytes, 明文)             │  ← qbditrace_file_header_t
├──────────────────────────────────────────┤
│ Zstd Frame                               │  ← ZSTD_compressStream2 输出
│   (解压后与未压缩格式的记录流完全相同)       │
└──────────────────────────────────────────┘
```

**设计要点**：

文件头始终不压缩，这样读取端可以先读 536 字节，检查 magic、version、flags 后再决定是否需要解压。压缩范围是文件头之后的所有字节，构成一个完整的 zstd frame（包含 content checksum）。

**写入端（qbditrace）实现**：qbditrace 在 `BackgroundWriter` 中使用 `ZSTD_compressStream2` 流式压缩。写入线程从 chunk 队列取出数据后，先压缩再写磁盘。压缩等级固定为 1（最快），预期压缩比 3-4x（trace 数据中有大量重复模式：连续 pc_delta=+4、相似 reg_index 等）。

**配置**：`qbditrace_config_t.disable_compress`（反转语义，0 = 压缩，默认值）。Frida 侧配置示例：

```javascript
// 默认已开启压缩，无需额外设置
cfg.disable_compress = 0;  // 压缩（默认）
cfg.disable_compress = 1;  // 不压缩
```

**读取端（tenet）**：`TraceReader::open()` 检测到 `HF_COMPRESSED` 后，自动通过 `ZSTD_decompressStream` 流式解压到临时文件（同目录下 `.tenet-decomp-XXXXXX`，若失败回退 `/tmp`）。临时文件的 header 中 `HF_COMPRESSED` 标志已被清除，之后正常 mmap。`TraceReader::close()` 时自动删除临时文件。

构建时需要 zstd 依赖（通过 FetchContent 自动拉取，与 qbditrace 共享 `_deps/` 缓存）。若 tenet 构建时无 zstd（`TENET_HAS_ZSTD=0`），打开压缩 trace 会返回错误。

---

## 未来增强方向（需 qbditrace 配合）

| 编号 | 增强 | 动机 | 建议实现 |
|------|------|------|----------|
| E1 | Header 记录 anchor_interval | tenet 可预测 ANCHOR 位置 | header reserved 区新增字段 |
| E2 | 文件尾部索引表 | 避免 tenet 全文件扫描建索引 | Footer: `(每N条inst的offset)[]` |
| E3 | 浮点/向量寄存器 | 密码学分析需要 NEON | 新记录类型 REC_FPREG + header flag |
| E4 | 内存映射信息 | mmap 区域感知 | 新记录类型 REC_MMAP |
| E5 | ~~分块压缩~~ ✅ 已实现 | 1.5GB → ~400MB | Zstd stream + HF_COMPRESSED flag (qbditrace 写端) |
| E6 | inst_id 全局编号 | 当前无显式 ID，靠顺序计数 | INST 记录中可选的 4B inst_id 字段 |

**优先级**：E2 > E5 > E1 > E6 > E3 > E4

E2（尾部索引表）对 tenet 性能影响最大——可将首次打开从 60s 降到 < 1s。
E5（压缩）对存储和传输最有价值。两者可组合。

---

## 版本兼容策略

```cpp
if (header.version < 4)
    return Error("Unsupported trace version {}, need >= 4", header.version);
if (header.version == 4)
    // 正常处理
if (header.version > 4)
    // 警告，跳过未知 record kind
    // 依赖 record_size() 能确定任何记录的大小
```

对于 version > 4 的 trace，tenet 遇到未知 kind 时：
- 如果 `record_size()` 返回 0（无法确定大小），停止遍历并报错
- 否则跳过该记录继续
