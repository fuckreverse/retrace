# Advanced Benchmark Suite

面向 **tenet 离线分析器**的高级测试集：真实加密算法 + 真实 OLLVM 混淆模式 + 综合逆向场景。

## 快速开始

```sh
# 前置条件：已构建 macOS arm64 QBDI 静态库
sh cmake/config/config-macOS-AARCH64.sh && ninja QBDI_static qbdi-llvm

# 一键运行全部 22 个 target
sh dashcam/benchmark/advanced/run_advanced.sh

# 只跑混淆组 + tenet 分析
sh dashcam/benchmark/advanced/run_advanced.sh --group B --tenet ./build/tenet
```

## 目录结构

```
advanced/
├── README.md              ← 本文档
├── advanced_targets.h     ← 22 个 target 统一注册表（分组 + tenet 能力注解）
├── crypto_targets.c       ← Group A: 真实加密算法实现
├── obfuscation_targets.c  ← Group B: OLLVM 混淆变体（同一 XTEA 的 5 种混淆版本）
├── scenario_targets.c     ← Group C+D: 综合场景 + 压力测试
├── advanced_harness.c     ← 通用 harness（编译 + 运行 + 正确性校验）
├── run_advanced.sh        ← 自动化脚本（build → trace → decode → tenet）
└── build_ollvm.sh         ← 可选：从源码编译 Pluto-Obfuscator
```

## Target 分组

### Group A — 真实加密算法（7 个）

| Target | 算法 | 特征 | 典型 trace |
|--------|------|------|-----------|
| `aes128_encrypt` | AES-128 ECB 单块 | 10 轮 SubBytes/MixColumns，S-Box 查表 | 188KB |
| `aes128_keyexp` | AES-128 密钥扩展 | 轮常数递推、S-Box 复用 | 103KB |
| `chacha20_block` | ChaCha20 单 block | 20 轮 quarter-round (a+=b; d^=a; d<<<16 ...) | 157KB |
| `sha256_compress` | SHA-256 压缩函数 | 64 步 Σ/σ/Ch/Maj + K 常量表 | 142KB |
| `hmac_sha256` | HMAC-SHA256 | 内外层 SHA-256 嵌套（key padding → hash → hash） | 531KB |
| `xtea64` | XTEA 64 轮 | 经典 Feistel 结构，delta=0x9E3779B9 | 24KB |
| `sm4_encrypt` | SM4 单块 | 32 轮、专用 S-Box、L 线性变换 | 117KB |

**tenet 验证点**：PatternPass 应识别 S-Box 查表模式和 ARX 结构；TaintPass 应追踪
key/input → output 的数据流依赖。

### Group B — OLLVM 混淆变体（5 个）

全部基于同一个 XTEA-64 算法，输出与 plain `xtea64` 完全一致（作为正确性基线）。

| Target | 混淆 Pass | 代码特征 | 典型 trace |
|--------|-----------|---------|-----------|
| `xtea_cff` | Control Flow Flattening | while(1)+switch dispatcher，state_var 驱动 | 643KB |
| `xtea_bcf` | Bogus Control Flow | 永不命中的 opaque predicate 分支 | 40KB |
| `xtea_sub` | Instruction Substitution (MBA) | `a+b` → `(a^b)+2*(a&b)` 等等价变换 | 74KB |
| `xtea_constenc` | Constant Encryption | 运行时解密 delta/magic，结果缓存 | 49KB |
| `xtea_allobf` | CFF + BCF + MBA + ConstEnc 全叠加 | 上述全部混淆组合 | 673KB |

**tenet 验证点**：CFGPass 应还原 CFF dispatcher 下的真实 CFG；PatternPass 应透过 MBA
识别底层 XOR/ADD；TaintPass 在混淆下仍应追踪到 key→output 依赖。

### Group C — 综合实战场景（6 个）

| Target | 场景 | 代码特征 | 典型 trace |
|--------|------|---------|-----------|
| `pbkdf2_sha256` | PBKDF2 密钥派生 (1000 轮) | 大量 HMAC 嵌套，深循环 | 51MB |
| `request_sign` | 请求签名流水线 | timestamp→HMAC→hex encode 多步 pipeline | 779KB |
| `antitamper_crc` | 反篡改 CRC32 | 代码段自校验（模拟） | 25KB |
| `mini_vm` | Mini-VM 解释器 | 8 条自定义 opcode 的 fetch-decode-execute 循环 | 132KB |
| `layered_crypto` | 层叠加密 | XOR → XTEA → S-Box → 逆序组合 | 56KB |
| `aes_cff_mba` | AES + CFF + MBA ("boss fight") | AES SubBytes 被 CFF 包裹 + MBA 替换 | 187KB |

**tenet 验证点**：FunctionPass/CallGraphPass 应还原调用层次；SlicePass 应能对
request_sign 的输出做后向切片追到 key；PatternPass 应在 mini_vm 中识别 dispatch loop。

### Group D — 边界压力（4 个）

| Target | 场景 | 代码特征 | 典型 trace |
|--------|------|---------|-----------|
| `branch_explosion` | 分支爆炸 | 16 级 if/else 嵌套，CFG 节点多 | 5KB |
| `aes_tablebased` | T-Table AES | 4 个 1KB 查找表 (Te0-Te3) | 54KB |
| `deep_callchain` | 深调用链 | 16 级嵌套函数调用 | 29KB |
| `decrypt_execute` | 解密-执行 | XOR 解密代码段 → 执行 → 重新加密 | 281KB |

**tenet 验证点**：SlicePass 的路径爆炸抗性；XRefPass 应识别 T-Table 交叉引用模式；
CallGraphPass 应正确构建深调用图。

## 编译注意事项

**关键限制**：target 源码必须使用以下编译选项：

```
-march=armv8-a+nosha3+nocrypto+noaes+nosha2 -fno-vectorize -fno-slp-vectorize
```

原因：即使指定 `-march=armv8-a`，编译器在高优化级别下可能自动使用 ARMv8.2-SHA3 的
NEON crypto 指令（如 `eor3.16b`）来向量化 S-Box 查表。这些指令超出 QBDI 内置 LLVM
反汇编器的支持范围，导致插桩时 QBDI 无限循环。

这不影响 harness 和 QBDITrace.cpp 本身的编译（它们不被插桩），只约束被 trace 的
target 代码。

## 自动化脚本选项

`run_advanced.sh` 支持的完整选项：

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `--seed <hex>` | 输入 seed | 0x1234567890ABCDEF |
| `--group <A\|B\|C\|D>` | 只运行指定分组 | 全部 |
| `--filter <name>` | 只运行名称匹配的 target | 全部 |
| `--output-dir <dir>` | trace 输出目录 | /tmp/qbditrace-advanced |
| `--tenet <path>` | tenet 二进制路径（启用分析） | 无 |
| `--tenet-passes <list>` | 逗号分隔的 tenet pass | all |
| `--decode-all` | 解码所有 trace（前 100 条指令） | summary |
| `--no-decode` | 跳过解码 | - |
| `--csv` | 以 CSV 格式输出结果 | - |
| `--verbose` | 详细输出 | - |
| `--clean` | 运行前清空输出目录 | - |

## tenet 集成

当提供 `--tenet` 参数时，脚本会对每个 trace 文件运行 tenet 分析并生成 JSON 报告：

```sh
sh run_advanced.sh --tenet ./build/tenet --tenet-passes pattern,cfg,taint
```

报告保存在 `<output-dir>/tenet_reports/<target>_report.json`，包含：

- `pattern.matches[]`：识别到的加密/混淆模式（类别 + 置信度 + 位置）
- `cfg.nodes / cfg.edges`：重建的 CFG 节点数和边数
- `taint.sources / taint.sinks`：污点源和汇
- 各 pass 的详细分析数据

每个 target 在 `advanced_targets.h` 中标注了它应当触发的 tenet 能力（`caps` 字段），
可用于自动化回归测试：验证 tenet 升级后是否仍能正确分析所有已知场景。

## 可选：Pluto-Obfuscator 真实编译

`build_ollvm.sh` 从源码编译 Pluto-Obfuscator（基于 LLVM 14.0.6），生成真正的 OLLVM
混淆二进制。这些二进制可与手工实现的混淆版本做对比分析。

```sh
sh dashcam/benchmark/advanced/build_ollvm.sh
# 编译约 30 分钟，生成 /tmp/pluto-obfuscator/bin/clang
# 随后对各 target 分别应用 CFF/BCF/SUB/ALL 编译
```

编译产物放在 `<output-dir>/ollvm_binaries/`，可直接用 qbditrace 或 run_advanced.sh
trace 后传给 tenet 分析。

## 设计哲学

1. **真实性**：加密算法使用完整标准实现（含 S-Box、轮常数），不是简化 demo
2. **可验证性**：所有混淆变体的输出必须与 plain 版本完全一致，作为正确性基线
3. **tenet 导向**：每个 target 显式标注期望触发的 tenet Pass 和预期分析结果
4. **自包含**：无外部依赖（除 QBDI 静态库和 capstone），单一脚本完成全流程
5. **渐进难度**：从 24KB 的简单 XTEA 到 51MB 的 PBKDF2，覆盖不同规模的分析挑战
