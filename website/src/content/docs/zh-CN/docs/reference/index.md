---
title: Trace 格式规范
sidebar:
  order: 1
---

二进制 Trace 格式是任何采集引擎与 Tenet 之间的契约。只要工具生成合规的 `.bin` 文件，Tenet 即可分析——QBDITrace 是官方实现，但不是唯一选择。

权威 C 定义位于 `dashcam/TraceFormat.h`。本文档为自定义采集器的实现者重新陈述该格式。

## 文件头

536 字节，在文件起始处写入一次。所有多字节整数均为小端序（AArch64 原生）。

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| 0x000 | 4 | `magic` | `0x51424454`（"QBDT"） |
| 0x004 | 4 | `version` | 4（基线）、5（PC-delta）、6（old-value）、7（FPR）、8（调用元数据） |
| 0x008 | 4 | `arch` | 架构标签：1 = AArch64, 2 = x86_64 |
| 0x00C | 4 | `num_gpr` | 锚点快照中的 GPR 数（AArch64: 34） |
| 0x010 | 8 | `module_base` | 被追踪模块的运行时基地址 |
| 0x018 | 8 | `module_slide` | ASLR slide（运行时 − 静态首选基址） |
| 0x020 | 8 | `trace_start` | 追踪范围运行时起始（含） |
| 0x028 | 8 | `trace_end` | 追踪范围运行时终止（不含） |
| 0x030 | 8 | `flags` | 头部标志（见下文） |
| 0x038 | 256 | `module_name` | NUL 终止的模块路径 |
| 0x138 | 4 | `target_os` | 0=未知, 1=iOS, 2=Android, 3=Linux |
| 0x13C | 220 | `reserved` | 填充至 536 字节 |

### 地址归一化

```
static_address = runtime_address − module_slide
```

Tenet 将所有运行时 PC 归一化回静态镜像，以便与 IDA/Ghidra 匹配。

## 头部标志

偏移 0x030 的 `flags` 字段控制记录布局与压缩。标志与版本标签正交：版本由改变磁盘布局的*最高*标志决定。

| 位 | 名称 | 效果 |
|----|------|------|
| 0 | `HF_HAS_MEM` | 记录可能包含内存访问 |
| 1 | `HF_HAS_NZCV` | INST 记录包含 NZCV 标志 |
| 2 | `HF_REG_DIFF` | INST 记录存储寄存器差值（非全量快照） |
| 3 | `HF_HAS_CODE` | 流中包含 `REC_CODE` 记录 |
| 4 | `HF_PC_DELTA` | **v5**：INST 头用 2 字节有符号 PC 差值替代 8 字节绝对 PC |
| 5 | `HF_OLD_VALUE` | **v6**：内存访问记录包含写前值（每条 48 B） |
| 6 | `HF_HAS_FPR` | **v7**：ANCHOR 包含 512 B FPR 快照；INST 包含 FPR 差值 |
| 7 | `HF_COMPRESSED` | 遗留格式：整个记录流为一个 zstd 帧（历史） |
| 8 | `HF_BLOCK_COMPRESSED` | 1 MiB zstd 分块 + 尾部索引，支持随机访问（默认） |
| 9 | `HF_BRANCH_HINT` | nzcv 高 4 位编码 CALL/RET/BRANCH 分类 |
| 10 | `HF_CALL_META` | **v8**：启用 v8 OBJC/CAPICALL 布局与 `REC_RETVAL`；可与 `HF_PC_DELTA` / `HF_HAS_FPR` 组合 |

## 版本演进

| 版本 | 门控标志 | 关键变化 |
|------|---------|---------|
| v4 | 基线 | INST 头 16 B, ANCHOR 288 B, 引入 REC_CODE |
| v5 | `HF_PC_DELTA` | INST 头缩至 6 B（int16 PC 差值）；解码器维护运行 PC |
| v6 | `HF_OLD_VALUE` | 内存访问记录增至 48 B（写前 old_value 字段）；**writer 已移除** |
| v7 | `HF_HAS_FPR` | ANCHOR 增加 512 B FPR 块（共 800 B）；INST 增加 FPR 差值段 |
| v8 | `HF_CALL_META` | 增加 `REC_RETVAL` 真实返回事实；OBJC 在线捕获 selector；CAPICALL `api_id` 扩为 `uint16_t`；可与 `HF_PC_DELTA` / `HF_HAS_FPR` 组合 |

不认识某个标志的读取器**必须**拒绝该文件。

## 记录类型

每条记录以单字节 `kind` 标签开头：

| Kind | 值 | 说明 |
|------|---|------|
| `REC_INST` | 0 | 逐指令寄存器/内存差值 |
| `REC_ANCHOR` | 1 | 全量寄存器快照（重建检查点） |
| `REC_THREAD` | 2 | 线程上下文标记 |
| `REC_EVENT` | 3 | VM 事件（序列入口/出口、跨区间转移） |
| `REC_SVC` | 4 | 系统调用位置 |
| `REC_OBJC` | 5 | ObjC msgSend 系列派发 |
| `REC_CODE` | 6 | 原始指令字节（每 PC 仅一次） |
| `REC_CAPICALL` | 7 | C/平台 API 调用，含语义参数捕获 |
| `REC_RETVAL` | 8 | v8 的 OBJC/CAPI/SVC 真实返回事实 |

### REC_INST（kind = 0）

最频繁的记录。只存储指令产生的*变化*。

**v4 布局**（`HF_PC_DELTA` 未设置）：

```
qbditrace_inst_head_t    16 字节
  kind        u8
  nzcv        u8    （低 4 位 = N/Z/C/V；高 4 位 = branch hint，当 HF_BRANCH_HINT 时）
  n_regdiff   u8
  n_mem       u8
  pc          u64   （运行时绝对 PC）
n_regdiff × regdiff_t    每条 16 字节
  reg_index   u8    （QBDI GPR 排序：0=x0 … 30=lr, 31=sp, 32=nzcv, 33=pc）
  [padding]   7 B
  value       u64   （指令执行后的值）
n_mem × memacc_t         每条 32 字节
  mem_type    u8    （bit0 = 读, bit1 = 写）
  mem_flags   u8    （bit0 = unknown_size, bit1 = minimum_size, bit2 = unknown_value）
  size        u16
  addr        u64
  value       u64   （低 8 字节）
  value_hi    u64   （9–16 字节 store 的高字节；否则为 0）
```

**v5 布局**（`HF_PC_DELTA` 设置）：除 `pc` 替换为 `pc_delta`（int16 LE）外完全相同。解码器维护 `running_pc += pc_delta`。若 `|delta| > 32767`，先发射 ANCHOR（用其绝对 pc 重置 running_pc），然后 delta = 0。头大小：6 字节。

**v7 布局**（`HF_HAS_FPR` 设置）：在 GPR 差值之后、内存访问之前，插入 FPR 差值段：

```
inst_head（v7 或 v7+v5 变体）
n_regdiff × regdiff_t
n_fprdiff × fprdiff_t     每条 24 字节
  fpr_index   u8    （0..31 = v0..v31）
  [padding]   7 B
  lo          u64   （bits 63:0）
  hi          u64   （bits 127:64）
n_mem × memacc_t
```

### REC_ANCHOR（kind = 1）

周期性全量寄存器检查点。解码器使用最近的锚点重建任意指令的状态。

**v4/v5/v6 布局：**

```
anchor_head_t             16 字节
  kind        u8
  [reserved]  3 B
  pc          u64   （绝对运行时 PC）
num_gpr × u64             272 字节（AArch64: 34 × 8 B）
```

总计：288 字节。

**v7 布局**（`HF_HAS_FPR` 设置）：GPR 块之后追加 512 字节 FPR 快照：

```
anchor_head_t + GPR block    288 字节
fpr_lo[32]                   256 字节  （v0..v31 的 bits 63:0）
fpr_hi[32]                   256 字节  （v0..v31 的 bits 127:64）
```

总计：800 字节。

### REC_THREAD（kind = 2）

```
thread_head_t   16 字节
  kind       u8
  [reserved] 3 B
  thread_id  u64
```

在每个线程流起始处发射。当前 Tenet 假设单线程 trace。

### REC_EVENT（kind = 3）

```
event_head_t    24 字节
  kind       u8
  event      u8    （1=SEQ_ENTRY, 2=SEQ_EXIT, 3=XFER_CALL, 4=XFER_RETURN）
  [reserved] 2 B
  addr       u64   （XFER_CALL: 目标地址; XFER_RETURN: 返回目标）
  site       u64   （XFER_CALL: 调用点 PC; 否则为 0）
```

### REC_SVC（kind = 4）

```
svc_head_t      72 字节
  kind        u8
  [reserved]  3 B
  pc          u64   （svc 指令地址）
  syscall_no  u64   （Darwin: x16; Linux/Android: x8）
  args[6]     6×u64 （x0..x5）
```

### REC_OBJC（kind = 5）

**v4-v7 遗留布局：**

```
objc_head_t     80 字节
  kind       u8
  variant    u8    （0=msgSend, 1=msgSendSuper, 2=msgSendSuper2, 3=msgSend_stret）
  [reserved] 2 B
  pc         u64   （调用点 PC）
  recv       u64   （x0: 接收者或 super 结构体指针）
  sel        u64   （x1: 选择子; *Super 变体用 x2）
  cls[48]          （NUL 终止的运行时类名; 不可用时为 ""）
```

**v8 布局**（`HF_CALL_META` 设置）：固定头仍为 80 字节，但加入 `sel_len` 和 `flags`；头后追加在线捕获的 selector（`sel_len` 个内容字节 + NUL，填充至 4 字节对齐）。`flags` 标记 selector 截断或读取失败。`HF_CALL_META` 是文件级布局契约，同一文件不会混用遗留与 v8 OBJC 布局。

### REC_CODE（kind = 6）

每 PC 一条原始指令字节。首次执行时发射，按 PC 去重。支持无外部镜像的离线反汇编。

```
code_head_t     16 字节
  kind       u8
  size       u8    （指令长度; AArch64 为 4）
  [reserved] 2 B
  pc         u64   （运行时地址）
  bytes[size]      （原始小端编码）
```

### REC_CAPICALL（kind = 7）

捕获已知 C/平台 API 函数的调用。固定 88 字节头 + 0–4 个变长内联字符串捕获。

**v4-v7 遗留布局：**

```
capicall_head_t     88 字节
  kind        u8
  api_id      u8    （capi_id 枚举的数值 ID）
  arg_count   u8    （args[] 有效项数, 0..8）
  str_count   u8    （后随的内联字符串捕获数, 0..4）
  pc          u64   （调用点 PC）
  target      u64   （被调用函数的运行时地址）
  args[8]     8×u64 （调用时 x0..x7）
```

**v8 布局**（`HF_CALL_META` 设置）：固定头仍为 88 字节，字段顺序调整并将 `api_id` 扩为 `uint16_t`，从而完整表示超过 255 的 API ID。该文件级标志要求文件内所有 CAPICALL 统一使用 v8 布局。

后随 `str_count` 个变长捕获（两种布局相同）：

```
capicall_str_t      4 字节
  str_arg_idx  u8   （该字符串来自哪个参数, 0..7）
  str_len      u8   （内容字节数，不含 NUL; 最大 255）
  str_flags    u8   （bit0=截断, bit1=二进制, bit2=safe-read 失败）
  [_reserved]  u8
str_data[str_len + 1]    （NUL 终止; 填充至 4 字节对齐）
```

### REC_RETVAL（kind = 8）

仅在 v8 `HF_CALL_META` 文件中出现。该 64 字节自描述记录把真实返回状态关联回 OBJC、CAPICALL 或 SVC 调用，包含来源 kind/ID、调用点、目标、恢复地址以及原始 `x0`、`x1`、`nzcv`；`record_size` 允许未来读取器安全跳过扩展字段。

## 压缩

### 分块压缩（`HF_BLOCK_COMPRESSED`）

所有新 trace 的默认方式。536 字节头部之后的数据被分为独立的 1 MiB zstd 帧。文件末尾的尾部索引支持 O(1) 随机访问。

**文件布局：**

```
[文件头: 536 B, 未压缩]
[block 0: zstd 帧]
[block 1: zstd 帧]
...
[block N: zstd 帧]
[块索引表: N × 24 B 条目]
[块尾部: 16 B]
```

**块索引条目**（每条 24 字节）：

| 字段 | 大小 | 说明 |
|------|------|------|
| `original_offset` | u64 | 逻辑（解压后）字节偏移（从记录起始） |
| `compressed_offset` | u64 | 压缩块的物理文件偏移 |
| `original_size` | u32 | 解压后字节数 |
| `compressed_size` | u32 | 磁盘上压缩字节数 |

**块尾部**（文件最后 16 字节）：

| 字段 | 大小 | 说明 |
|------|------|------|
| `index_offset` | u64 | 第一个索引条目的文件偏移 |
| `block_count` | u32 | 压缩块数量 |
| `magic` | u32 | `0x51424249`（"QBBI"） |

### 遗留流式压缩（`HF_COMPRESSED`）

历史格式：头部之后的整个记录流为单个 zstd 帧。无随机访问。`HF_COMPRESSED` 与 `HF_BLOCK_COMPRESSED` 互斥。

## Branch hint

当 `HF_BRANCH_HINT` 设置时，`REC_INST` 中 `nzcv` 字节的高 4 位编码指令的分支类别：

| 高 nibble | 值 | 含义 |
|-----------|---|------|
| `0b0000` | 0 | 普通指令（非分支） |
| `0b0001` | 1 | CALL（BL / BLR） |
| `0b0010` | 2 | RET（RET / RETAA / RETAB） |
| `0b0100` | 4 | BRANCH（B / BR — 非调用无条件跳转） |

此编码零额外字节，让解码器对 ~95–98% 指令跳过 pc_kind 查表。向后兼容：旧 trace 永远不会设置高 nibble，旧读取器不受影响。

## AArch64 寄存器索引

GPR 索引（用于 `regdiff_t.reg_index` 和锚点快照）：

| 索引 | 寄存器 |
|------|--------|
| 0–28 | x0–x28 |
| 29 | fp (x29) |
| 30 | lr (x30) |
| 31 | sp |
| 32 | nzcv |
| 33 | pc |

FPR 索引（用于 `fprdiff_t.fpr_index`）：

| 索引 | 寄存器 |
|------|--------|
| 0–31 | v0–v31（128 位 NEON） |

## 兼容性分层

Tenet 可打开任何 `QBDT` magic 且版本 ≥ 4 的 trace。缺失记录优雅降级——仅运行输入满足的 Pass。

### 最低可用 trace

要求：合法 `QBDT` magic、版本 ≥ 4、含 PC 的 `REC_INST` 记录、至少一个 `REC_ANCHOR`。

结果：基础指令列表与地址归一化。

### 推荐配置

增加：`HF_REG_DIFF`、`HF_HAS_NZCV`、`HF_HAS_MEM`、`HF_HAS_CODE`、`HF_BRANCH_HINT`、`REC_EVENT`。

结果：完整 CFG 恢复、函数边界检测、调用图、循环分析、寄存器重建、内存模型、污点分析。

### 平台增强

增加：`REC_SVC`、`REC_OBJC`、`REC_CAPICALL`；v8 还可增加 `HF_CALL_META` 与 `REC_RETVAL`。

结果：系统调用命名、ObjC 消息解析、C API 参数捕获与字符串检查；v8 可提供在线 selector 和真实返回事实。

### 向量增强

增加：`HF_HAS_FPR`（v7）。

结果：NEON/向量寄存器重建、密码学算法识别。

## 实现自定义采集器

QBDITrace 的常见替代包括 **Frida Stalker**（通过 `Stalker.follow` 发射 `REC_INST` + `REC_ANCHOR` + `REC_CODE`）、DynamoRIO、Pin 或 Unicorn 等自定义模拟器——关键在于遵守上文描述的二进制格式。

1. 写入 536 字节文件头，`magic = 0x51424454`、`version = 4`、设置相应 `flags`。
2. 周期性发射 `REC_ANCHOR` 记录（每 1024 条指令为推荐默认）。每个锚点必须包含完整 GPR 快照。
3. 对每条执行的指令，发射 `REC_INST` 记录，含 PC（绝对或差值）、NZCV、寄存器差值和内存访问。
4. 可选为每个首次执行的 PC 发射 `REC_CODE` 记录。
5. 使用分块压缩以支持高效随机访问：按 1 MiB 压缩并追加索引表与尾部。
6. 正确设置 `module_base` 和 `module_slide`，使 Tenet 能将运行时地址归一化回静态镜像。

### 最小示例（伪代码）

```c
// 写入头部
qbditrace_file_header_t hdr = {0};
hdr.magic        = 0x51424454;
hdr.version      = 4;
hdr.arch         = 1; // AArch64
hdr.num_gpr      = 34;
hdr.module_base  = runtime_base;
hdr.module_slide = slide;
hdr.trace_start  = range_start;
hdr.trace_end    = range_end;
hdr.flags        = QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_NZCV
                  | QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_CODE
                  | QBDITRACE_HF_BLOCK_COMPRESSED | QBDITRACE_HF_BRANCH_HINT;
strncpy(hdr.module_name, path, 255);
write(fd, &hdr, 536);

// 每条指令：
qbditrace_inst_head_t inst = {0};
inst.kind      = 0;
inst.nzcv      = current_nzcv;
inst.n_regdiff = count_written_regs;
inst.n_mem     = count_mem_accesses;
inst.pc        = runtime_pc;
write(fd, &inst, 16);
write(fd, reg_diffs, inst.n_regdiff * 16);
write(fd, mem_accesses, inst.n_mem * 32);

// 周期性：
qbditrace_anchor_head_t anchor = {0};
anchor.kind = 1;
anchor.pc   = runtime_pc;
write(fd, &anchor, 16);
write(fd, gpr_snapshot, num_gpr * 8);
```

## C API 参考

QBDITrace dylib 暴露稳定的 C ABI 用于编程式捕获：

```c
int  qbditrace_configure(const qbditrace_config_t *cfg);
int  qbditrace_run_call(uint64_t *ret_out, uint64_t fn,
                        uint32_t argc, const uint64_t *argv);
int  qbditrace_run_at(uint64_t *ret_out, uint64_t start_pc,
                      const uint64_t *gpr31, uint64_t sp, uint64_t lr);
void qbditrace_stop(void);

int         qbditrace_force_anchor(void);
const char *qbditrace_output_path(void);
int         qbditrace_dump_pcring(const char *path);
const qbditrace_stats_t *qbditrace_stats_page(void);
```

参见[捕获 > 参数与配置](/zh-CN/docs/capture/configuration/)了解封装这些调用的 Python loader。
