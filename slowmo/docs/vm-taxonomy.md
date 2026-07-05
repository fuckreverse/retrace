# VMP 形式分类与 VMAbstractPass 覆盖评估

本文档系统梳理所有可能的 VM-based protection (VMP) 形式，并评估当前 `VMAbstractPass` 对每种形式的支持情况。分类沿五个正交维度展开，实际 VMP 方案是这些维度的笛卡尔积组合。

## 一、架构模型（Operand Model）

### 1.1 栈机（Stack Machine）

操作数通过隐式操作数栈传递，指令不编码操作数位置。典型案例包括 JVM、CPython bytecode、.NET CIL、早期 Themida。指令编码短小（无需编码寄存器号），但同一操作需要更多指令（先 push 再 op）。

### 1.2 寄存器机（Register Machine）

操作数在 VM 寄存器文件中，指令显式编码寄存器索引。典型案例包括 Lua 5.x VM、Dalvik、阿里 SGAVMP。指令较长（需编码 2-3 个寄存器号），但指令数少。

### 1.3 累加器机（Accumulator Machine）

只有一个隐式累加器寄存器，一个操作数来自指令编码。典型案例包括一些轻量级混淆 VM 和早期 8-bit CPU 仿真。介于栈机和寄存器机之间。

### 1.4 混合架构（Hybrid）

同时有寄存器文件和操作数栈。典型案例包括某些 OLLVM-VM 变种，用栈传临时值、寄存器存长期状态。也有一些 VMP 用"栈帧"模拟寄存器——本质是栈机但操作数通过固定栈偏移寻址，行为上像寄存器机。

### 1.5 内存-内存机（Memory-to-Memory）

没有显式寄存器文件或栈，指令直接编码内存地址做源和目的。实际上和寄存器机区别不大，只是"寄存器"数量可以很大且不固定。

## 二、分发机制（Dispatch Mechanism）

### 2.1 While-Switch（集中式 switch-case）

经典形式：`while(1) { switch(*vpc++) { case 0: ...; case 1: ...; } }`。有明确的循环头和 switch 分发点。被 CFF 混淆后 switch 可能被拆散但逻辑不变。

### 2.2 Indirect Branch（间接跳转表）

`dispatch: opcode = *vpc++; goto handler_table[opcode];`。和 while-switch 的区别是用 `BR Xn`（computed goto）代替 switch 语句。编译器优化 switch 后经常退化成这种形式。

### 2.3 Call Table（间接调用表）

`dispatch: opcode = *vpc++; handler_table[opcode]();`。用 `BLR` 调用 handler，handler 通过 `RET` 返回 dispatcher。handler 是独立函数而非内联代码块。

### 2.4 Threaded Code（线索化 / 直接线程）

没有集中 dispatcher。每个 handler 末尾内联 fetch-next-and-jump 逻辑，直接跳到下一个 handler。典型案例包括 GCC computed goto 实现的解释器、CPython 3.x 启用 `THREADED_CODE` 后的版本。效率最高（省了回跳 dispatcher 的开销），但逆向最难（没有单一分发点）。

### 2.5 Token Threaded / Indirect Threaded

和 Threaded Code 类似，但字节码流里存的不是 handler 地址而是 token/index，每个 handler 末尾通过一个小查表跳转。介于 Threaded 和 Switch 之间。

### 2.6 Subroutine Threaded

字节码流里直接存的是 CALL handler 指令序列（不是数据而是代码）。即"字节码"本身就是一段原生 call 指令序列，不存在传统的 opcode 提取过程。

### 2.7 Trampoline / 中继蹦床

handler 执行后返回到一个小的"next"蹦床函数，蹦床负责取下一个 opcode 并跳转。和 while-switch 的区别是蹦床不包含 handler body（handler 在别处），和 threaded 的区别是有一个集中的返回点。

### 2.8 Coroutine / Yield-based

handler 通过 yield/resume 机制切换，可能基于 setjmp/longjmp 或 fiber。罕见但存在于某些高度定制的保护方案中。

### 2.9 Exception-based Dispatch

通过异常/信号（如 SIGTRAP、非法指令异常）触发 handler。在信号处理函数里做分发。反调试常见的形式（INT3 dispatch），也被一些 VMP 用于分发。

## 三、指令编码格式（Instruction Encoding）

### 3.1 定长指令（Fixed-Length）

所有指令宽度相同（如 4 字节/8 字节）。解码简单，vpc 步进固定。许多自定义 VMP 为简化实现采用定长编码。

### 3.2 变长指令（Variable-Length）

opcode 决定后续操作数长度。如 opcode 1 字节但操作数可能 0/1/2/4/8 字节不等。典型案例包括 x86 ISA、JVM bytecode。

### 3.3 前缀编码（Prefix-based）

有前缀字节修改后续指令的行为（如操作数宽度、寻址模式）。类似 x86 的 REX/VEX 前缀。

### 3.4 压缩编码（Huffman / Variable-bit）

指令不对齐字节边界，按位编码。极罕见但理论上存在。

### 3.5 VLIW / 打包格式

一条"宽指令"包含多个子操作（如同时编码一个 ALU 操作和一个 load）。罕见。

## 四、字节码混淆手段（Bytecode Obfuscation）

### 4.1 Opcode 加密 / 变换

opcode 经过 XOR/ADD/SUB/ROL/ROR/MBA 变换。每次执行可能用不同密钥（rolling key）。

### 4.2 多态 Opcode（Polymorphic / Metamorphic）

同一语义操作对应多个不同 opcode 值，或者每次保护时 opcode-to-handler 映射随机化。运行时映射表固定，但不同 build 的映射不同。

### 4.3 操作数加密

不仅 opcode，操作数（立即数、寄存器索引、跳转偏移）也被加密。

### 4.4 Handler 内联 / 克隆

同一语义的 handler 被克隆成多份放在不同地址，CFF 后它们的代码形态不同但语义相同。

### 4.5 虚假 Handler（Dead Handler）

存在从不被执行的 handler，干扰静态分析。

### 4.6 字节码自修改

运行时动态解密或修改后续字节码。handler 可能会改写待执行的字节码流。

### 4.7 Rolling State / 密钥链

用一个滚动状态（如前一条指令的哈希）参与下一条 opcode 的解密。decode 依赖执行历史，每条指令的解密密钥由上一条指令的结果推导而来。

## 五、其他结构特征

### 5.1 多层 VM（Nested VM）

VM 里面再套一层 VM。外层 VM 的某个 handler 是另一个 VM 的入口。

### 5.2 多入口 / 多 Dispatcher

一个二进制里有多个 VMP 实例，各自有独立的 dispatcher 和 handler 集合，保护不同的函数。

### 5.3 JIT 混合

VM 部分 opcode 在运行时被 JIT 编译为原生代码执行，不经过解释分发。

### 5.4 Context 结构变体

VM 上下文的承载方式各异：固定结构体（如阿里 SGAVMP 的 `vm_ctx`），栈帧偏移寻址，或者直接复用宿主寄存器（不分配额外内存）。

---

## VMAbstractPass 覆盖评估

### 架构模型

| 形式 | 状态 | 说明 |
|------|------|------|
| 栈机 | ✅ 支持 | `VMArchType::StackMachine`；`VMRegisterFileHint` 含 stack 配置（SP offset、depth、elem_size、direction） |
| 寄存器机 | ✅ 支持 | `VMArchType::RegisterMachine`；`VMRegisterFileHint` 含命名寄存器+偏移 |
| 混合架构 | ✅ 支持 | `is_mixed()` 明确支持同时有寄存器和栈 |
| 累加器机 | ⚠️ 可建模 | 用寄存器机建模（只定义一个寄存器即可），无功能缺口 |
| 内存-内存机 | ⚠️ 可建模 | 用 `VMContextHint` 的 fields 建模；若操作数地址动态计算（非固定偏移）则无法追踪 |

### 分发机制

| 形式 | 状态 | 说明 |
|------|------|------|
| While-Switch | ✅ 支持 | `DispatchType::WhileSwitch` |
| Indirect Branch | ✅ 支持 | `DispatchType::IndirectBranch`，BR Xn 识别 |
| Call Table | ✅ 支持 | `DispatchType::CallTable`，BLR Xn 识别 |
| Threaded Code | ✅ 支持 | `DispatchType::ThreadedCode`，专用 `ThreadedCollector` |
| Trampoline | ✅ 支持 | `DispatchType::Trampoline` |
| FetchOnly | ✅ 支持 | 专为重度 CFF 混淆设计，支持 PC anchor 和 Memory anchor |
| Token/Indirect Threaded | ⚠️ 近似 | 可用 `ThreadedCode` 建模（handler 末尾跳转），查表步骤需额外提示 |
| Subroutine Threaded | ❌ 不支持 | 字节码流是 CALL 指令序列，无 opcode 提取过程，与当前"读内存/读寄存器获取 opcode"的基本假设冲突 |
| Exception-based | ❌ 不支持 | 基于异常/信号分发，没有固定的分发点 PC，当前 collector 的 PC 命中切分逻辑无法处理 |
| Coroutine-based | ❌ 不支持 | yield/resume 控制流模式与 loop+branch 完全不同 |

### 指令编码

| 形式 | 状态 | 说明 |
|------|------|------|
| 定长指令 | ✅ 支持 | `opcode_size` 固定 |
| 变长指令（opcode 部分） | ✅ 支持 | `opcode_size` + `opcode_byte_offset` + `opcode_mask` 可提取 opcode 字段 |
| 变长指令（操作数部分） | ✅ 已支持 | `OperandFormatHint` 描述每个操作数字段的 byte_offset/size/mask/shift/deobf_steps，逐字段从字节码解码 |
| 前缀编码 | ❌ 不支持 | 无前缀概念；若前缀不影响 opcode 位置可 workaround，多字节前缀+opcode 组合无法正确处理 |
| 压缩/位编码 | ❌ 不支持 | 假设字节对齐 |
| VLIW | ❌ 不支持 | 假设一条指令对应一个 handler |

### 字节码混淆

| 形式 | 状态 | 说明 |
|------|------|------|
| 简单 opcode 变换 | ✅ 支持 | `deobfuscation_steps` 支持 15 种操作（sub/add/xor/and/or/lsr/lsl/mul/ror/bswap/neg/not/xor_rolling/add_rolling/sub_rolling） |
| Rolling key | ✅ 已支持 | `xor_rolling`/`add_rolling`/`sub_rolling` 有状态步骤 + `rolling_key_update` 规则（XorOpcode/AddOpcode/SubOpcode/HashOpcode） |
| 操作数加密 | ✅ 已支持 | `OperandFormatHint::OperandFieldDesc` 每个字段可配独立 `deobfuscation_steps` 管线 |
| 多态 opcode | ⚠️ 部分 | `handler_names` 允许多 handler PC 映射同一标签，但 opcode 值到语义的 N:1 映射无显式建模 |
| Handler 克隆 | ⚠️ 部分 | 克隆体入口 PC 不同会被当作不同 handler；需手动通过 `handler_names` 标注同义 |
| 虚假 handler | ✅ 不受影响 | 未执行的 handler 不出现在 trace 中 |
| 字节码自修改 | ⚠️ 自然兼容 | trace 时间点的内存读会捕获修改后的值，但分析假设未显式处理 |
| Rolling state | ✅ 已支持 | 同 Rolling key |

### 其他结构

| 形式 | 状态 | 说明 |
|------|------|------|
| 多 dispatcher | ✅ 支持 | 可对同一 trace 多次运行 pass，用不同 hints |
| 嵌套 VM | ⚠️ 有限 | 可多次运行 pass，但 inst_id 范围内假设单一 VM 实例，嵌套边界可能混淆 |
| JIT 混合 | ❌ 不支持 | JIT 生成的代码不在已知 handler PC 集合中，会被忽略或误归类 |
| 宿主寄存器作 VM 寄存器 | ✅ 已支持 | `VMRegisterFileHint::VMReg::from_host_reg` 直接从 AArch64 宿主寄存器文件读取 VM 寄存器值，绕过 MemoryModel |

---

## 关键缺口优先级排序

### P1 — ✅ 已解决

**Rolling key 解密**：`OpcodeDeobfStep::Op` 新增 `xor_rolling`/`add_rolling`/`sub_rolling` 有状态步骤，`OpcodeFormatHint::rolling_key_update` 控制密钥更新规则（XorOpcode/AddOpcode/SubOpcode/HashOpcode）。每个 rolling 步骤的 `imm` 字段作为初始密钥种子，跨 VM 步骤自动演进。

**宿主寄存器作 VM 寄存器**：`VMRegisterFileHint::VMReg::from_host_reg` 字段，当设为 0-28 时直接从 AArch64 宿主寄存器文件（`RegisterFile::state_before`）读取 VM 寄存器值，绕过 MemoryModel。不需要 rf_base_reg 也能工作。

**操作数解码**：`VMConfig::OperandFormatHint` 含 `OperandFieldDesc` 列表，每个字段描述 byte_offset/size/mask/shift 和独立的 deobfuscation_steps 管线。解码结果存入 `VMStep::operands`（`VMOperand` 列表）。

### P2 — 偶尔出现

**多态 opcode 语义映射**：增加 opcode-to-semantic-id 的 N:1 映射表，补充 `handler_names` 只作用于 PC 的局限。

**嵌套 VM 支持**：支持层级化的 inst_id 范围划分和递归分析，需要 pass 能感知"当前分析的 VM 层级"。

### P3 — 极罕见

**Exception-based dispatch**、**Subroutine threaded**、**Coroutine-based**——这些在移动端 VMP 实战中极为罕见，优先级最低。

---

## 实战覆盖率估算

真实世界中 95% 以上的移动端 VMP（阿里 SGAVMP/LiteVM、VMProtect、Themida、OLLVM-VM、O-MVLL VM、Pluto VM 等）都落在 **while-switch / indirect-branch / threaded** + **寄存器机或栈机** + **定长或简单变长** 的组合空间内，当前 VMAbstractPass 对这些主流组合均能处理。原有的三个 P1 缺口（rolling key 解密、宿主寄存器快照、操作数解码）已全部补齐，剩余缺口（exception-based dispatch、subroutine threaded、coroutine-based）在移动端实战中极为罕见。
