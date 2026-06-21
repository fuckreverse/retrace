# IO 层

> 职责：trace 文件的**零拷贝访问**与**持久化倒排索引**。是整个系统的只读数据底座。
> 源码：`src/io/`。权威格式：`tools/qbditrace/TraceFormat.h`（v4），格式契约见 [trace-format.md](trace-format.md)。

## 组件清单

| 文件 | 类 | 职责 |
|------|------|------|
| trace_reader.{h,cpp} | `TraceReader` | mmap 映射 + 零拷贝记录视图 + 顺序/随机访问 |
| index_builder.{h,cpp} | `TraceIndex` | RocksDB 多 CF 倒排索引（offset/anchor/mem/reg/code） |
| code_table.{h,cpp} | `CodeTable` + `ImageFallback` | PC→opcode 映射 + 二进制镜像缺码回填 |
| streaming_index.{h,cpp} | `StreamingIndex` | 实时 tail 增量索引（live trace） |
| rpc_server.{h,cpp} | `RpcServer` + `TenetRpcService` | JSON-RPC 2.0 over Unix socket |
| recent_files.{h,cpp} | `RecentFiles` | 最近打开文件列表（~/.config/tenet/recent.json） |

## TraceReader — 零拷贝读取

**设计**：整个文件 `mmap(MAP_PRIVATE)` 映射到虚拟地址空间，OS 管理页面换入。记录解析返回指向 mmap 区域的指针视图，绝不复制。只读映射 → 天然线程安全，多 Pass 并发读无锁。

**文件头**：`FileHeader`（536B）封装 magic/version/arch/num_gpr/module_base/slide/flags。`has_mem()/has_code()/reg_diff()/has_old_value()` 按 flags 位判断记录布局变体。

**记录视图**（零拷贝，全部指向 mmap）：
- `RecordView`：tagged union，`kind` + `file_offset` + `raw_ptr` + 预解析的 `resolved_pc`/`is_v5`/`is_v6` 标志。
- `InstView`：`pc`/`nzcv`/`reg_diff_count`/`mem_access_count` + `raw_diffs`/`raw_mems` 原始指针。`reg_diff(i)`/`mem_access(i)` 按结构体 stride 直接 reinterpret_cast。
- `AnchorView`：`gpr_values` 指向 mmap 中的 num_gpr 个 uint64。
- 还有 `CodeView`/`EventView`/`SvcView`/`ObjcView`/`ThreadView`，每个有 `byte_size()`。

**v4/v5/v6 兼容**（关键复杂度）：
- **v4**：INST 头含绝对 PC，内存访问 32B。
- **v5**（`HF_PC_DELTA`）：INST 头只存 `pc_delta`（相对上一条），绝对 PC 需 Iterator 在遍历时累加 `current_pc_` 并写回 `RecordView.resolved_pc`。**随机访问**必须用 `offset_of_with_pc()` 获取 seed_pc，再 `record_at(offset, seed_pc)`。
- **v6**（`HF_OLD_VALUE`）：内存访问 48B，含写前旧值（供 MemoryModel 精确回滚）。`has_old_value` 标志是否有效。

**访问方式**：
- 顺序遍历：`begin()/end()` 返回 `Iterator`，`operator++` 按 `byte_size()` 推进。v5 模式下自动维护 `current_pc_`。
- 随机访问：`record_at(offset)` 或 `record_at(offset, seed_pc)`。
- 原始字节：`data()/data_at(offset)` 给 IndexBuilder 用。

**madvise 策略**：建索引阶段 `MADV_SEQUENTIAL`（预读），建完切 `MADV_RANDOM`。

## TraceIndex — RocksDB 倒排索引

**为什么 RocksDB**：100M+ 条目倒排、持久化、范围查询、多 CF 隔离、内置压缩。LSM-tree 天生为海量 KV 优化。

**Column Family 设计**（`cf::` 命名空间）：

| CF | Key | Value | 用途 |
|----|-----|-------|------|
| `meta` | 字符串 | 字符串/整型 | trace_hash/inst_count/bookmarks/last_inst 等元信息 |
| `offset` | inst_id (u64 BE) | file_offset | **稀疏**主索引，每 N 条存一个（N 自适应 64-4096） |
| `anchor` | anchor 序号 | file_offset | anchor 定位 |
| `mem_write` | `[page(8)\|page_off(2)\|inst_id(8)]` BE | `[size(1)\|data]` | 内存写倒排（含跨页拆分） |
| `mem_read` | 同上 | 同上 | 内存读倒排（回填未追踪代码写入的值） |
| `reg_writes` | `(reg_idx<<48\|inst_id)` | 空 | 寄存器写倒排，O(log N) 找 last writer |
| `code_bytes` | runtime_pc (u64 BE) | opcode[4] | 代码字节，单遍构建免二次扫文件 |

**稀疏 offset 策略**：不存每条 inst_id（100M×16B=1.6GB），而是每 `sparse_interval_` 条存锚点。定位 inst_id=N：二分找 floor(N/interval) 的 offset，向前线性扫 ≤interval 条。`SPARSE_MIN=64`/`SPARSE_MAX=4096`，按 inst_count 自适应使索引 ≤65536 条。

**并行构建**：以 ANCHOR 记录边界做分片，多核并行扫，最后合并。`IndexStats.num_shards` 记录实际分片数。

**查询接口**：
- `offset_of(inst_id)` / `offset_of_with_pc(inst_id)` →（offset, seed_pc），后者 v5 必需。
- `nearest_anchor_before(inst_id)` → (anchor_idx, offset, inst_id)，给 RegisterFile 重建用。
- `find_last_writer_of(reg_idx, before_id)` → inst_id，用 REG_WRITES CF 的 `SeekForPrev`，O(log N)。无该 CF 时回退线性扫。
- `load_code_table(CodeTable&)` → 从 CODE_BYTES CF 装载，免扫文件。

**持久化与校验**：`open_or_build()` 先查缓存，按 `trace_hash`（sha256(header+首4KB)）校验有效性。`verify_integrity()` 跑 RocksDB `VerifyChecksum()` + hash 交叉校验。

**会话持久化**：bookmarks 和 last_inst 存在 `meta` CF，下次打开恢复光标。

## CodeTable + ImageFallback

**CodeTable**：`ankerl::unordered_dense::map<pc, opcode>` 存 trace 中出现的所有 PC 的 4 字节指令。从 `CODE_BYTES` CF 装载（或扫 REC_CODE 记录）。`opcode_at(pc)` 先查表，miss 则查 `ImageFallback`。

**ImageFallback**：加载原始 Mach-O/ELF，解析可执行段建 `(runtime_start, runtime_end, file_offset)` 映射。**解决 LDXR/STXR 缺码问题**——qbditrace 不对临界区发 REC_CODE（会破坏 ARM 独占预留），导致 ~10-20% PC 无代码。镜像回填从磁盘字节恢复，完整保留反汇编/CFG/污点分析。还提供 `read_bytes_at()`/`image_read_cstring()` 读二进制中的数据（selector 字符串等）。

## StreamingIndex — 实时增量索引

**用途**：边录制边分析。后台 tail 线程轮询文件增长，每 `batch_size` 条新记录触发增量索引 flush，通过 condition variable 通知等待的消费者。

**消费者 API**：`wait_for_inst(target_id, timeout_ms)` 阻塞直到至少 target_id 条指令已索引。`inst_count()` 原子读当前进度。`is_complete()` 在 STREAM_END 哨兵或空闲超时后置真。

**不依赖 qbditrace 配合**：也能 tail 静态文件（退化为后台索引器 + 进度）。`YaraRuleWatcher` 是附带工具，监听目录新 `.yar` 文件自动重载规则。

## RpcServer — JSON-RPC over Unix socket

**协议**：每条消息是换行结尾的 JSON 串。标准 JSON-RPC 2.0 请求/响应。单连接串行处理（内部 mutex 序列化并发客户端）。

**TenetRpcService** 自动装配标准方法：`ping/get_stats/get_reg/get_regs/read_mem/get_inst/get_range/get_xref/get_cfg/get_call_graph`。把 reader/index/regfile/memory/pm 引用注入即可 `start(socket_path)`。`--rpc` 启动后阻塞直到客户端断开。

## RecentFiles

最近打开列表，持久化到 `~/.config/tenet/recent.json`，最多 20 条。GUI 启动页用它。

## 性能与内存预算

| 组件 | 内存 | 磁盘 |
|------|------|------|
| mmap 映射 | 虚拟 1.5GB，RSS 由 OS 管 | — |
| RocksDB block cache | 256MB（可配） | — |
| RocksDB 数据 | — | 200-500MB（Zstd 压缩） |
| offset CF（稀疏） | — | ~6MB |
| mem_write CF | — | 100-300MB |
| reg_writes CF | — | ~30MB |
| CodeTable | ~40MB | — |

索引构建后持久化，后续打开同一 trace 直接加载（<1s）。

## 关键设计决策

1. **零拷贝贯穿到底**：从 mmap 到 Pass 消费，数据从不复制。InstView 的 `raw_diffs` 直接指向 mmap 字节。
2. **稀疏 + 倒排组合**：offset 稀疏（省 99% 空间），mem/reg 倒排（O(log N) 查询），code 全量但小。
3. **单遍构建**：索引构建扫一遍 trace 同时填 offset/anchor/mem_write/mem_read/reg_writes/code_bytes 六个 CF，无二次扫描。
4. **v5 PC 重建**：PC delta 模式省空间但牺牲随机访问——用 `offset_of_with_pc` + seed_pc 解决。
5. **ImageFallback 补全**：承认 trace 不完整（LDXR/STXR），用二进制镜像优雅降级而非报错。
