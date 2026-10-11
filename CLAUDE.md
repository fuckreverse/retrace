# Retrace — Dashcam 录制器 / Slowmo 分析器

## 项目概述

Retrace 是一个独立发布的逆向分析 monorepo，包含两个紧密协作的组件及其产品网站：

- **dashcam**（`dashcam/`）— 录制器：基于 QBDI 的高性能指令追踪器，编译为 dylib(iOS) 或 .so(Android)，通过 Frida 注入目标进程，录制 `.bin` trace 文件。（内部沿用 `qbditrace` 作为库名/产物名）
- **slowmo**（`slowmo/`）— 分析器：dashcam 的离线分析端，读取 `.bin` trace，提供 TUI 交互浏览、CLI 批量分析（污点、CFG、调用图、模式识别等），以及通过独立的 Tauri 桌面应用（`slowmo/web/`）提供图形化浏览体验。（可执行文件仍叫 `tenet`）
- **website**（`website/`）— Slowmo 的 Astro 静态官网与文档站；开发、构建和 Cloudflare Pages 发布约定见 `website/CLAUDE.md`。

两者通过 `dashcam/TraceFormat.h` 约定的二进制 trace 格式协作（dashcam 写、slowmo 读）；slowmo 不链接 QBDI。

## 与上游 QBDI 的关系

dashcam 深度依赖 [QBDI/QBDI](https://github.com/QBDI/QBDI)，但本仓库**不携带 QBDI 源码**：

- `patches/qbdi/` 存放对官方 QBDI 的最小 patch 系列（LSE 解码修复、`QBDI_LOG_FILE` 崩溃诊断、iOS 构建配置），`PIN` 钉住所基于的上游 commit
- `scripts/prepare-qbdi.sh` 克隆官方 QBDI → 应用 patch → 按平台构建静态库，缓存在 `third-party/qbdi/<platform>/`（gitignored）
- CI 中有 `qbdi-patches` job 校验 patch 系列对 pin 的上游 commit 仍然干净可用

## 构建

### ⚠️ 重要：禁止创建新 build 目录

dashcam 和 slowmo 均使用固定 build 目录。**严禁**随意 `mkdir build-xxx`——每次新建都会触发第三方依赖重新克隆编译（slowmo 需 30 分钟以上，dashcam 较轻量但仍需下载 zstd + Catch2）。

第三方源码缓存目录：

- slowmo：`slowmo/_deps/`（rocksdb、roaring、Catch2 等）
- dashcam：`dashcam/_deps/`（zstd、Catch2；可通过 `-DFETCHCONTENT_BASE_DIR` 指向 slowmo 的 `_deps/` 来复用）

**禁止删除 `_deps/` 目录。**

### 固定 build 目录

**slowmo：**

| 目录 | 用途 | cmake 命令 |
|------|------|-----------|
| `slowmo/build/` | **主力构建（默认 RelWithDebInfo）** | `cmake ..` |
| `slowmo/build-no-triton/` | 不带 Triton 的构建 | `cmake .. -DTENET_ENABLE_TRITON=OFF` |

**dashcam：**

| 目录 | 用途 | cmake 命令 |
|------|------|-----------|
| `dashcam/build/` | **Host 测试 + decoder** | `cmake .. -G Ninja -DQBDITRACE_BUILD_DYLIB=OFF` |
| `dashcam/build-ios/` | iOS dylib 交叉编译 | 见下方 iOS 构建说明 |
| `dashcam/build-android/` | Android .so 交叉编译 | 见下方 Android 构建说明 |

需要切换编译选项时，**在已有 build 目录里重新 cmake**，不要新建目录。

### 日常编译（增量构建）

```bash
# slowmo
cd slowmo/build
ninja -j$(nproc)          # RelWithDebInfo 增量编译仍是单文件粒度，通常秒级（改单个文件 ~3-4s）

# dashcam（host 测试）
cd dashcam/build
ninja -j$(nproc)
ctest --output-on-failure  # 运行全部单元测试
```

### 首次从零构建（或 build 目录被误删后）

**slowmo：**
```bash
cd slowmo
mkdir build && cd build
cmake ..                        # 默认 RelWithDebInfo，开发迭代用
ninja -j$(nproc)
```

**dashcam（host 测试 + decoder）：**
```bash
cd dashcam
mkdir build && cd build
# 复用 slowmo 的依赖缓存（推荐，避免重复下载 zstd/Catch2）：
cmake .. -G Ninja -DQBDITRACE_BUILD_DYLIB=OFF \
    -DFETCHCONTENT_BASE_DIR=$(pwd)/../../slowmo/_deps
ninja -j$(nproc)
ctest --output-on-failure
```

**dashcam（iOS dylib 交叉编译）：**
```bash
# 从仓库根目录执行
bash scripts/prepare-qbdi.sh ios      # 一次性：克隆+patch+构建 QBDI 静态库
bash dashcam/build-dashcam-ios.sh
```

**dashcam（Android .so 交叉编译）：**
```bash
# 需要先准备 patched QBDI for Android（NDK_PATH 需设置）
# 然后从仓库根目录执行
bash scripts/prepare-qbdi.sh android
bash dashcam/build-dashcam-android.sh
```

> 两者的 `_deps/*-src` 目录存在时，`FETCHCONTENT_UPDATES_DISCONNECTED=ON`
> 会跳过所有网络请求，直接复用已有源码。

### 关键 CMake 选项

**slowmo：**

- `CMAKE_BUILD_TYPE` — 三层构建策略：
  - **Debug**：`-O0 -g`，最快编译，最慢运行
  - **RelWithDebInfo**（默认）：`-O2 -g -DNDEBUG`，无 LTO/PGO/-mcpu；增量编译仍为单文件粒度（改一个 .cpp 只重编译它），运行性能约 Debug 的 2-3×
  - **Release**：`-O3` + ThinLTO + `-mcpu=apple-m1`；最慢编译（LTO re-link），最快运行（发布/性能剖析用）
- `TENET_ENABLE_TRITON=ON/OFF` — Triton 精确污点（默认 ON，需预装 libTriton；Windows 默认 OFF）
- `TENET_ENABLE_YARA=ON/OFF` — YARA 模式匹配（需系统 yara；Windows 默认 OFF）
- `TENET_ENABLE_WS=ON/OFF` — WebSocket 服务（uWebSockets + FlatBuffers；macOS/Linux 默认 ON，**Windows 默认 OFF**——Tauri 前端在 Windows 上暂时无法通过 WS 获取实时数据，是已知遗留问题）
- `TENET_BUILD_TESTS=ON/OFF` — 单元测试（测试 target 永久关闭 LTO，保证链接快）
- `TENET_ENABLE_TBB=ON/OFF` — Intel oneTBB 并行算法与任务调度（默认 ON；IndexBuilder `parallel_sort`、PassManager `task_group` DAG 调度、Scan Fusion 单遍广播）
- `FETCHCONTENT_BASE_DIR` — 第三方源码共享缓存目录（默认 `slowmo/_deps/`，**勿修改**）

**dashcam：**

- `QBDITRACE_BUILD_DYLIB=ON/OFF` — 构建 tracer dylib（需 QBDI 静态库，默认 ON）
- `QBDITRACE_BUILD_DECODER=ON/OFF` — 构建离线解码器（已弃用，功能由 `tenet --dump` 接替；该选项保留仅为兼容）
- `QBDITRACE_BUILD_TESTS=ON/OFF` — 构建单元测试（默认 ON）
- `QBDITRACE_BUILD_TESTS_INTEGRATION=ON/OFF` — macOS arm64 进程内集成测试，可选联合 slowmo 验证 pass 流水线（默认 OFF）
- `QBDITRACE_ENABLE_ZSTD=ON/OFF` — zstd 压缩支持（默认 ON）
- `FETCHCONTENT_BASE_DIR` — 第三方源码共享缓存目录（默认 `dashcam/_deps/`，推荐指向 `slowmo/_deps/` 复用）

> **注**：独立的 `trace_decode` 已移除，其功能由 `tenet --dump`（`tenet --dump text` / `tenet --dump jsonl`）接替。`tenet --dump` 支持 v4/v5/v7 全格式（含默认分块压缩）。

## Trace 格式契约

权威定义：`dashcam/TraceFormat.h`（支持 v4/v5/v7）。

- 文件头：536 字节，magic `0x51424454`（"QBDT"），小端序
- 记录类型：INST(0) / ANCHOR(1) / THREAD(2) / EVENT(3) / SVC(4) / OBJC(5) / CODE(6) / CAPICALL(7) / RETVAL(8) / MEMIMG(9)
- AArch64 GPR：34 个（x0-x28, fp, lr, sp, nzcv, pc）
- slowmo 打开条件：version ≥ 4；sampling 可不含 `REG_DIFF/HAS_MEM/HAS_NZCV`，缺 `HAS_CODE` 时依赖反汇编的分析需外部镜像或降级
- `target_os`：偏移 0x138，4 字节（占用 reserved 前 4 字节）；0=Unknown, 1=iOS, 2=Android, 3=Linux。旧 trace 为 0，slowmo 会根据 module_name 启发式推断。

**格式版本演进**（均由 header flags 控制，向下兼容）：

| version | Flag | 变化 |
|---------|------|------|
| v4 | 基线 | INST 头 16B，ANCHOR 288B |
| v5 | `HF_PC_DELTA` (bit 4) | INST 头缩至 6B（存 int16 pc_delta），约减少 60% 文件体积 |
| v6 | `HF_OLD_VALUE` (bit 5) | memacc 扩展至 48B（含写前值），**writer 已移除** |
| v7 | `HF_HAS_FPR` (bit 6) | INST 头含 n_fprdiff（GPR 24B/v5+v7 8B），ANCHOR 含 512B FPR 快照（共 800B） |
| v8 | `HF_CALL_META` (bit 10) | REC_RETVAL 返回事实 + OBJC 在线 selector + CAPI `api_id` 扩为 `uint16_t` |
| v9 | `HF_MEMIMG` (bit 11) | REC_MEMIMG 内存快照块（configure 时对指定范围快照，全部位于首个 INST 之前；MemoryModel 作为快照基底层，writer_id 哨兵 `kSnapshotWriterId` 标注近似） |

其他关键 flags：`HF_COMPRESSED`(bit 7)=历史单帧 zstd（当前 writer 不产生），`HF_BLOCK_COMPRESSED`(bit 8)=当前默认的 1 MiB 分块压缩+尾部索引，`HF_BRANCH_HINT`(bit 9)=nzcv 高 4 位编码 CALL/RET/BRANCH，`HF_MEMIMG`(bit 11)=v9 内存快照。

详细格式见 `slowmo/docs/trace-format.md`。

## slowmo 架构

```
Frontend (TUI/CLI/RPC/MCP/WS) ←→ Tauri 桌面应用（slowmo/web/，经 WS/MCP 连接后端进程）
        ↕
Pass Pipeline (XRef, Taint, CFG, String, Pattern, LoopSemantics, ...)
        ↕  PassManager 自动调度
Core (RegisterFile + MemoryModel + TritonBridge)
        ↕
IO (TraceReader mmap + RocksDB Index)
```

> `tenet` 可执行文件本身是纯后端（不含任何原生图形渲染代码），图形化体验由独立的 Tauri Web 前端（`slowmo/web/`）提供，通过 sidecar 拉起 `tenet --ws-port <port> ... --mcp-hub` 子进程，浏览器端仅经 WebSocket（FlatBuffers 二进制协议）与后端通信，MCP Hub 则供 AI 工具/IDAPython 等外部客户端接入，二者是并行能力而非主备关系。跨平台差异（socket/进程/内存映射/文件锁/路径）集中在 `slowmo/src/common/platform_*.h`。当前 tenet 后端目标支持 Windows/Linux/macOS（x86_64/arm64）；`--rpc` 已从 Unix socket 改为 TCP loopback（`--rpc [[host:]port]`，默认 `127.0.0.1:0`，端口 0 由 OS 自动分配）。

- **IO 层**：`TraceReader` mmap 零拷贝，`TraceIndex` RocksDB 持久化（首次约 60s，之后秒开）
- **Core 层**：`RegisterFile` 基于 ANCHOR 重建任意时刻寄存器状态；`MemoryModel` 追踪写历史；`TritonBridge` 提供指令语义
- **Pass 层**：每个分析是独立 Pass，声明依赖，PassManager 自动调度；新增分析只需实现一个 Pass 类

## dashcam C ABI

```c
// 核心 4 个
int  qbditrace_configure(const qbditrace_config_t *cfg);  // 必须先调用；cfg.struct_size = sizeof(cfg)
int  qbditrace_run_call(uint64_t *ret_out, uint64_t fn, uint32_t argc, const uint64_t *argv);  // argc <= 8
int  qbditrace_run_at(uint64_t *ret_out, uint64_t start_pc, const uint64_t *gpr31, uint64_t sp, uint64_t lr);  // gpr31 = x0..x28+fp
void qbditrace_stop(void);                                // 幂等，进程退出时隐式调用

// 辅助 4 个
int         qbditrace_force_anchor(void);                 // 强制下一条指令前写入 ANCHOR 快照
const char *qbditrace_output_path(void);                  // 当前 trace 文件路径
int         qbditrace_dump_pcring(const char *path);       // 导出最近 2048 条 PC 环形窗口（崩溃诊断）
const qbditrace_stats_t *qbditrace_stats_page(void);        // 实时只读统计页；Frida 默认每 500ms 轮询
```

**`qbditrace_config_t` 关键字段**（需先设 `struct_size = sizeof(qbditrace_config_t)`）：详见 `dashcam/QBDITrace.h`。

典型 Frida 流程（两种模式）：

- **Hook 模式**（被动）：`Module.load(dylib/.so)` → `qbditrace_configure(&cfg)` → `Interceptor.replace` hook 目标函数 → 等待 App 触发 → 回调内调用 `qbditrace_run_call` → `qbditrace_stop()`
- **Invoke 模式**（主动）：`Module.load(dylib/.so)` → `qbditrace_configure(&cfg)` → `materializeArgs()` 构造类型化参数 → 直接 `qbditrace_run_call(retOut, func, argc, argv)` → `qbditrace_stop()`

Python loader 通过 `--invoke --args "TYPE:VALUE" ...` 启用主动调用模式，支持的参数类型：`int`、`str`、`bytes`、`buf`（输出 buffer）、`nullptr`、`nsstr`/`nsdata`/`nsnum`（ObjC，iOS only）。

iOS 部署：`scp libqbditrace.dylib vphone:/var/jb/usr/lib/` + `ldid -S`
Android 部署：`adb push libqbditrace.so /data/local/tmp/`

## tenet CLI 常用命令

```bash
./tenet --tui trace.bin                    # TUI 模式（终端交互浏览）
./tenet --ws-port 9090 trace.bin           # 启动 WS 服务，供 Tauri 桌面应用连接做图形化浏览
./tenet --export-cfg func.dot trace.bin    # 导出 CFG（Graphviz DOT）
./tenet --taint 0 trace.bin                # 从 x0 正向污点
./tenet --backward-taint <inst_id> <reg>   # 反向污点
./tenet --call-graph cg.dot trace.bin      # 调用图
./tenet --pattern trace.bin                # 加密/反调试模式检测
./tenet --algorithm-summary trace.bin      # 算法自动识别
./tenet --objc trace.bin                   # ObjC 消息分析
./tenet --syscall-intercept trace.bin      # C API/系统调用拦截（CommonCrypto/BoringSSL/JNI；Darwin Mach trap/MIG）
./tenet --exclude-range 0x1001000 0x1002000 trace.bin  # 排除噪声区间（可重复，分析时过滤）
```

## 重要约定

- 所有地址使用**运行时地址**（含 ASLR slide）；静态地址 = runtime - slide
- Pass 名称用下划线小写：`xref`, `cfg`, `cfg_layout`, `taint`, `backward_taint` 等
- slowmo 当前假设单线程 trace（`THREAD` 记录被忽略）
- 核心数据结构在 `slowmo/src/common/` 下：`BinaryTrees.h`, `LinkedListPool.h`
- dashcam 的库名/产物名保持 `qbditrace`/`libqbditrace.*`，slowmo 的可执行文件名保持 `tenet`——**目录/仓库级品牌为 Retrace/dashcam/slowmo，二进制与 C ABI 不改名**（ABI 稳定性）

## QBDI patch 维护

- 改动 `patches/qbdi/` 下的 patch 时：基于 `PIN` 中的上游 commit 生成 diff（`git diff` 于官方源码 + patch 状态），更新 patch 文件与 `PIN`
- 上游 QBDI 更新后 rebase：新 pin → 重放系列 → 重新生成 patch → 更新 `PIN`；CI `qbdi-patches` job 会立即暴露失败
- 两个修复（LSE、`QBDI_LOG_FILE`）都适合提给上游，合入后逐步缩减系列

## 文档维护

每次代码变更后，检查 `slowmo/docs/` 是否需要同步更新（架构/接口/Pass 目录/格式契约等），需要则更新。文档是代码的高度压缩视图，**保持与实现一致**，不重复代码细节。

## 本仓库历史

本仓库由 QBDI fork（`tools/qbditrace` + `tools/tenet` + `website/`）经 `git filter-repo` 迁出，保留了全部提交历史（目录重映射：`tools/tenet` → `slowmo`，`tools/qbditrace` → `dashcam`）。历史 commit message 中出现的旧路径（`tools/tenet/...`、`tools/qbditrace/...`）指向迁移前布局。
