---
title: 内存、字符串与值搜索
sidebar:
  order: 4
---

Tenet 在选定时刻重建内存、发现字符串、捕获快照、搜索模式和值、测量熵并运行 YARA 规则。所有结果都与指令 ID 绑定。

## MemoryModel 时间语义

`MemoryModel` 把每条内存写入以 `[page_addr | page_offset | inst_id]` 编码存入 RocksDB。查询回答"某个时刻内存长什么样"：对每个字节回扫最近一次覆盖写。每个字节有独立的 `known` 标记 —— 从未被写入的字节显示为 `??`。

时间模型用**排他性** `at_inst_id`：查询查找满足 `inst_id < at_inst_id` 的写入（即"指令 N **之前**"的状态）。一个关键的不对称处理读写：

- **写 @ inst N**：以 `inst_id = N` 入库，`at_inst_id >= N+1` 时可见（新值在写**之后**才存在）。
- **读 @ inst N**：派生记录以 `inst_id = N-1` 入库，`at_inst_id >= N` 时可见。读不改变内存，被观察到的值在查询点（读指令自身）必须立即可见；否则 `memread` 在该指令当刻会与 `disasm` 直接读到的原始记录矛盾。

该语义由 `compute_trace_fingerprint()` 的 schema 版本号（当前 = 2）保护，版本不匹配会失效旧持久化索引以触发重建。

已记录的 read 可恢复由未插桩代码准备的数据（共享缓存、系统库）。完全未被观察的数据不可恢复——除非它被 configure 时的快照覆盖（见下）。

### configure 时快照基底层（v9）

如果 trace 录制时用了 `qbditrace --snapshot-range`（v9 `REC_MEMIMG` 记录），`MemoryModel` 会把这些快照块懒加载为**访问日志之下的基底层**。字节解析顺序：写日志 → 读日志 → 快照。快照只填补从未被任何指令触碰的字节——典型场景是 trace 开始前由未插桩代码（解密壳、启动代码）写入的全局状态（`.data`/`.bss` 中的解密字符串/密钥、运行时填充的表）。

快照字节的 `writer_inst_id` 为哨兵值 `kSnapshotWriterId`（`UINT64_MAX`，用 `is_snapshot_writer()` 判定）：它是 trace 起始时刻（`inst_id 0`）的值，用于更晚时刻是**显式标注的近似**，绝不静默。`at_inst_id == 0` 时快照直接作答。快照区域不算访问——不会出现在 `active_pages()` / `was_accessed()` 中。

## 时间感知内存读取

`memread` 在某时刻读取一块区域，未知字节显示为 `??`；每个报告的字节携带 `writer_inst_id`。`--mem-history` 列出与地址区间重叠的全部已记录写入（默认上限 500 条）。两者都不是 Pass —— 它们直接查询 `MemoryModel`。

```bash
./tenet [options] trace.bin --memread 0x16fdff200 32 50000
./tenet [options] trace.bin --mem-history 0x16fdff200 32
```

:::note[MCP 命名差异]
CLI 用 `--mem-history`，MCP 工具名为 `mem_write_history`。两者都查询 `MemoryModel::write_history()`，但输出形态不同：CLI 打印含 PC 的写入详情，MCP 返回分页的 writer 指令 ID。
:::

## 字符串

| Pass | 方法 | 适用场景 |
|---|---|---|
| `strings` | 每次写入后的时间一致快照 | 稳定字符串、ObjC selector、符号名、常量数据 |
| `memory_strings` | 调用点活跃指针重建 | 瞬时解密/解码字符串 |

### `strings` 的真实工作方式

`strings` **不是**“最终快照” Pass。它遍历 Trace 中每一条内存 **写入**（跳过 read——read 不会引入新字节内容），在该指令执行**之后**重建写入地址附近的一小段内存（查询时刻为 `inst_id + 1`），再扫描重建窗口中的 ASCII / UTF-16LE 串。因此同一条字符串的所有字节保证在时间上一致 —— 该 Pass 不可能把不同时刻的字缝合成一个假串。

因为在**每一个**写入事件上扫描，而不是只在最终状态扫描，`strings` 仍可捕获后来被覆盖的中间缓冲区内容——"每次写入的快照"比"最终快照"更准确。

去重：对同一地址的连续相同写入（自旋锁、引用计数、热计数器）复用上一次扫描结果，避免重复 RocksDB 探测。

```bash
./tenet [options] trace.bin --strings
```

### `memory_strings`

`MemoryStringPass` 先扫一遍 Trace 收集"调用点"指令（BL / BLR / SVC 和 REC ObjC 消息发送），然后对每个调用点：

1. 通过 `RegisterFile::state_before(site.inst_id)` 获取寄存器快照。
2. 把 **x0–x7** 与 **SP 相对栈**当作指针（`>= min_pointer_value`，默认 `0x100000000`）。
3. 对每个唯一指针调用 `read_region(ptr, scan_size, call_site_inst_id)` 并扫描可打印串。
4. **Deep probe**：被窗口边缘截断的命中（不是被 NUL 或非可打印字节结束）会触发 `deep_probe_string()` 沿真实写历史回溯，恢复完整内容。

结果源标记为 `RegPointer`（含 `source_reg` 0–7）、`StackLocal`（`source_reg` = 31）或 `DeepProbe`。

```bash
./tenet [options] trace.bin --memory-strings
./tenet [options] trace.bin --memory-strings --memory-strings-scan-size 512
./tenet [options] trace.bin --memory-strings --memory-strings-max-sites 2000
```

MCP：`memory_strings` tool。

## 内存快照

`memory_snapshot` 在显式 `inst_id` 处和/或每个函数调用点捕获内存区域。显式 ID 模式下，快照 **SP**（栈帧）+ **x0–x7** 中像指针的值；`snapshot_at_function_calls = true`（默认）下，收集 `function` Pass 发现的每个调用事件上的指针。捕获区域按插入顺序返回；`by_inst_id` 索引把每个 `inst_id` 映射到其快照。

区域大小由 `--memory-snapshot-size` 控制（默认 64）。CLI 只暴露显式 ID 与大小；`snapshot_at_function_calls` 是内部默认配置，没有对应的独立 CLI 标志。

```bash
./tenet [options] trace.bin --memory-snapshot 5000 --memory-snapshot-size 128
./tenet [options] trace.bin --memory-snapshot 5000 --memory-snapshot 6000 --memory-snapshot 7200
```

两阶段收集：Phase A 仅用 `RegisterFile::state_before`（~170 µs）收集 `(addr, inst_id)` 元组；Phase B 按页号排序，使连续读取命中线程本地页缓存，把 N 次随机 RocksDB 寻道转换为页排序顺序访问。总量受 `config_.max_snapshots` 约束。

MCP：`memory_snapshot` tool 接受显式 `inst_ids`；Tauri 前端：**Tools → Memory Snapshot…**

## 值与模式搜索

`mem_search` 在单个 Pass 中提供两种互补模式：

|模式|输入源|后端|
|---|---|---|
| 字节模式 | `--mem-search "DE AD ?? BE EF"` | 可用时使用 YARA Aho-Corasick；否则执行掩码线性扫描 |
| 精确值 | `--mem-search-value 0x9E3779B97F4A7C15`（可重复） | O(1) 哈希查找，对比 reg_diff、内存写入值，以及（配合 `--mem-search-immediates`）MOVZ/MOVK 字段 |

`--literal-search` 是 `--mem-search-value` 的弃用别名。

`--mem-search-range <start> <end>` 把两种模式都限制到 inst_id 窗口。`--run-pass mem_search` 是遗留简写，不配置模式/值 —— 请通过上述 CLI 参数或 Tauri 前端/MCP 提供参数。

```bash
./tenet [options] trace.bin --mem-search "48 8B ?? ?? 48 89"
./tenet [options] trace.bin --mem-search-value 0x67452301 --mem-search-value 0xEFCDAB89
./tenet [options] trace.bin --mem-search-value 0x9E3779B97F4A7C15 --mem-search-immediates
./tenet [options] trace.bin --mem-search "FF 25" --mem-search-range 10000 50000
```

MCP：`mem_search` tool 接受 `patterns`（可用 `??` 通配符）、`exact_values`、`range`、`search_reg_values`、`search_immediates`。

Tauri 前端：**Tools → Memory / Value Search…**

## 熵

`entropy` 在选定 `inst_id` 处测量内存区域的 Shannon 熵。每个块的结果喂入启发式分类器：

| 分类 | 条件 |
|---|---|
| Unknown | 已知字节 < 8 |
| Plaintext | 熵 < 4.0 |
| Compressed | 熵 6.0–7.5 |
| Encrypted | 熵 > 7.5 |
| KeyMaterial | 熵 4.0–6.0 且区域 ≤ 64 字节 |

:::caution[仅为启发式]
这些分类是统计信号，不是证明。压缩数据可能得分低于 7.5；小密钥调度可能高于 4.0。结论前务必用 `pattern` / `taint` / `loop_semantics` 证据交叉印证。
:::

CLI 的真实签名是 `--entropy <addr_hex> <size>`：第一个参数是十六进制内存地址，第二个参数是十进制字节数。用 `--entropy-at <inst_id>` 选择采样时刻；用 `--entropy-timeline` 在该区域的写历史点重采样并输出时间线。

Tauri 前端的 Entropy 面板同样提供地址、大小、采样时刻与时间线控制。MCP `entropy_analysis` 用于分页读取后端 `entropy` Pass 的结果块。

```bash
./tenet [options] trace.bin --entropy 0x16fdff200 4096
./tenet [options] trace.bin --entropy 0x16fdff200 4096 --entropy-at 5000
./tenet [options] trace.bin --entropy 0x16fdff200 4096 --entropy-timeline
```

MCP：`entropy_analysis` tool。

## YARA 内存扫描

`yara_mem_scan` 对重建后的堆 / 内存页、可选显式 inst_id 点、可选代码字节缓冲区运行 YARA 规则。仅在 `TENET_ENABLE_YARA=ON`（需要 `libyara`）时可用。在禁用 YARA 的构建中该 Pass 仍会**注册**（保证 `tools/list` 稳定），但调用它会返回清晰的编译期错误而非静默失败。

### 构建与规则查找

- 编译：`cmake .. -DTENET_ENABLE_YARA=ON`。
- 默认规则目录按顺序查找：`<exe_dir>/rules/`、`<exe_dir>/../rules/`、`<exe_dir>/../../rules/`，然后兼容性回退到 `<cwd>/rules` 与 `<cwd>/../rules`。
- 用 `--yara-rules <文件|目录>`（可重复）或 MCP `rules_dir` 添加自定义规则。

### 扫描选项

| 标志 | 用途 |
|---|---|
| `--yara-rules <file_or_dir>` | 额外规则文件或目录（可重复） |
| `--yara-min-entropy <N>` | 跳过 Shannon 熵 < N 的自动扫描页（默认 0 = 全扫描） |
| `--yara-scan-code` | 同时扫描重建的指令字节缓冲区（查找嵌入代码的常量） |

```bash
./tenet [options] trace.bin --yara-mem-scan
./tenet [options] trace.bin --yara-mem-scan --yara-rules custom.yar --yara-min-entropy 3.0
./tenet [options] trace.bin --yara-mem-scan --yara-scan-code
```

### 排查

- **"YaraMemScanPass: no .yar rule files found."** 编译器成功但未找到任何 `.yar` 文件。确认错误消息列出的规则查找目录；传递显式 `--yara-rules`。
- **"YaraMemScanPass: failed to initialize YARA compiler."** `libyara` 返回编译器错误。先用 `yarac` 检查规则语法。
- **"YARA support not compiled in"**（Tauri 前端或 MCP）。构建使用 `TENET_ENABLE_YARA=OFF`；需重编译启用 YARA。菜单项灰显而非隐藏，让用户知道该功能存在。

MCP：`yara_mem_scan` tool；Tauri 前端：**Tools → YARA Scan…**

## Tauri 前端与 MCP 速查

| 能力 | Tauri 前端入口 | MCP tool |
|---|---|---|
| 内存读取 | 右键地址 → "Open in Hex Dump" | `memread` |
| 写历史 | **Tools → Memory Write History…** | `mem_write_history` |
| 字符串 | Strings 面板 | `strings_scan` |
| 调用点字符串 | Strings 面板（第二标签） | `memory_strings` |
| 快照 | **Tools → Memory Snapshot…** | `memory_snapshot` |
| 模式 / 值搜索 | **Tools → Memory / Value Search…** | `mem_search` |
| 熵 | **Tools → Entropy…** 或 右键 → "Entropy Analysis…" | `entropy_analysis` |
| YARA 扫描 | **Tools → YARA Scan…** | `yara_mem_scan` |

## 证据与限制

- 所有内存结果依赖**已记录的写入与读取**。未访问页保持未知。
- 已记录的 read 可恢复未插桩代码准备的数据；完全未被观察的数据不可恢复，除非被 v9 `REC_MEMIMG` 快照覆盖（快照字节以 `kSnapshotWriterId` 哨兵标注，代表 trace 起始状态）。
- `strings` 捕获的是每次写入后的快照，不是单一最终状态 —— 早期写入的（后来被覆盖的）值仍可被发现。
- `memory_strings` 能发现 `strings` 因后期覆盖而遗漏的瞬时调用点参数。
- CLI 和 Tauri 前端都可指定精确地址与大小；CLI 另用 `--entropy-at` 选择时刻、`--entropy-timeline` 请求时间线。MCP `entropy_analysis` 分页返回后端 Pass 结果。
- YARA 扫描的是重建后的真实内存，不是近似；受可选构建开关保护，必须在规则 / 编译器层面排查。
