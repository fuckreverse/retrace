---
title: 虚拟机与代码虚拟化
sidebar:
  order: 8
---

VMP 风格保护把原生逻辑翻译成自定义字节码，再由 dispatcher 和 handlers 在运行时解释执行。Tenet 的 `vm_abstract` 将 **IDA/Ghidra 提供的静态结构**与 Trace 中的真实执行连接起来，恢复 VM 步骤、opcode、上下文、虚拟寄存器和 handler 热度。

:::caution[必须先提供静态 hint]
`vm_abstract` 完全由 hint 驱动，不会扫描 Trace 猜测“像 VM 的循环”。只运行 `--vm-abstract` 会被拒绝。请先在 IDA/Ghidra 中定位 dispatcher、稳定 anchor 或 handler，再将结果交给 Tenet。
:::

## 它能回答什么

| 问题 | Tenet 提供的证据 |
|---|---|
| 每条 VM 指令对应哪段原生执行？ | VM step 的 `inst_id_start` / `inst_id_end` |
| 哪些 handlers 最常执行？ | handler 频率、body PC 和 opcode 集合 |
| 当前 VM-PC、context 与寄存器是什么？ | 每步的 VM-PC、context 字段、寄存器/栈快照 |
| opcode 是否经过编码？ | 位域提取、固定变换、rolling key 去混淆 |
| 某个虚拟寄存器从哪里来？ | `vm_reg_timeline` 与 `vm_backward_slice` |

它不会自动恢复完整 VM ISA、枚举未执行 handler、生成原生代码或重新编译字节码。输出是后续 handler 语义分析和去虚拟化的动态证据层。

## 最小工作流

### 1. 在静态工具中定位 anchor

寻找每条 VM 指令**恰好执行一次**的位置：

- while/switch dispatcher 的循环头；
- direct-threaded VM 中各 handler 的 fetch/dispatch PC 集合；
- 每步都写一次的 VM-PC 或 instruction-counter 内存字段。

### 2. 运行分析

只知道 dispatcher 时，可以先用行内 hint：

```bash
./tenet trace.bin --vm-abstract \
  --vm-dispatcher 0x100005000 \
  --vm-indirect-br 0x100005014
```

已知多个 handler 时可重复使用 `--vm-handler`。复杂 VM 推荐使用 JSON：

```bash
./tenet trace.bin --vm-abstract --vm-hints vm-hints.json
```

如有独立的字节码 decoder 定义，可追加 `--vm-decoder decoder.json`。

### 3. 在 VM Workspace 中检查结果

GUI 顶部的 **VM Hints** 入口支持拖放或选择 JSON。运行后打开 **VM Workspace**：

- **VM Handlers**：频率、标签与原生 PC；
- **VM Steps**：opcode、VM-PC、标签及对应原生指令区间；
- **Bytecode/Stats**：字节码范围与执行统计；
- **VM Registers / Stack**：虚拟寄存器或操作数栈快照；
- **VM Memory / Ctx**：context 字段值。

启用 **Linked** 后，选择 VM step 会同步跳转到原生指令时间线。

## Hints JSON

下面是寄存器机的基础示例：

```json
{
  "dispatcher_pc": "0x100005000",
  "indirect_branch_pc": "0x100005014",
  "handler_entry_pcs": [
    "0x100006000",
    "0x100007000",
    "0x100008000"
  ],
  "handler_names": {
    "0x100006000": "ADD",
    "0x100007000": "XOR",
    "0x100008000": "LOAD"
  },
  "dispatch_type": "WhileSwitch",
  "ctx_base_reg": "x21",
  "ctx_fields": [
    { "name": "ip", "offset": 0, "size": 8 },
    { "name": "sp", "offset": 8, "size": 8, "is_pointer": true }
  ],
  "rf_base_reg": "x20",
  "vm_registers": [
    { "name": "pc", "offset": 0, "size": 8 },
    { "name": "R0", "offset": 32, "size": 8 },
    { "name": "R1", "offset": 40, "size": 8 }
  ],
  "opcode_size": 4,
  "opcode_mask": "0xFF",
  "opcode_shift": 0
}
```

`vm_registers` 中名为 `pc` 或 `ip` 的字段会被用作 VM-PC。`rf_base_reg` 未设置时，寄存器文件读取会使用 `ctx_base_reg`。

## 三种 anchor 模式

| 模式 | JSON 字段 | 适用结构 |
|---|---|---|
| 单 PC | `dispatcher_pc` | 中央 while/switch、间接分支或 trampoline dispatcher |
| PC 集合 | `anchor_pcs` | handler 内联 fetch/dispatch 的 direct-threaded VM |
| 内存写 | `mem_anchor_addr` + `mem_anchor_size` | 控制流被 CFF 打散，但 VM-PC/context 字段仍每步写一次 |

PC anchor 必须每条 VM 指令恰好命中一次；命中缺失或重复都会造成错误切分，Pass 无法自动证明 anchor 是否满足这个约束。

Direct-threaded VM 可以给出多个稳定位置：

```json
{
  "anchor_pcs": [
    "0x100006034",
    "0x100007034",
    "0x100008034"
  ],
  "dispatch_type": "ThreadedCode",
  "handler_entry_pcs": [
    "0x100006000",
    "0x100007000",
    "0x100008000"
  ]
}
```

重度 CFF 场景可改用内存写：

```json
{
  "dispatch_type": "FetchOnly",
  "mem_anchor_addr": "0x13B3444F0",
  "mem_anchor_size": 4,
  "handler_entry_pcs": ["0x100006000", "0x100007000"],
  "opcode_from_reg": "x0"
}
```

`opcode_from_reg` 表示 opcode 已在 host 寄存器中解码，Tenet 不再从 VM-PC 指向的内存读取。

## 地址约定

- `dispatcher_pc`、`indirect_branch_pc`、`handler_entry_pcs` 和 `anchor_pcs` 使用 **IDA/Ghidra 显示地址**；Tenet 根据 Trace 的 `module_slide` 重定位。
- AArch64 Mach-O 默认按 IDA image base `0x100000000` 解释。
- `mem_anchor_addr` 是例外：它必须是 Trace 中观察到的**运行时内存地址**，不会重基。

不要混用静态 PC、运行时 PC 和文件偏移。如果 hinted PC 没有执行记录，先确认 hint 来自同一版本二进制且落在录制范围内。

## Opcode、操作数和虚拟状态

默认模式从 VM-PC 指向的内存读取 `opcode_size` 字节，然后应用 `opcode_byte_offset`、`opcode_mask` 和 `opcode_shift`。还可声明去混淆与操作数字段：

```json
{
  "opcode_size": 2,
  "opcode_byte_offset": 1,
  "opcode_mask": "0xFF00",
  "opcode_shift": 8,
  "opcode_deobf_steps": [
    { "op": "xor", "imm": "0xE0" },
    { "op": "sub", "imm": "0x0F" },
    { "op": "xor_rolling", "imm": "0xDEAD" }
  ],
  "rolling_key_update": "xor_opcode",
  "instruction_size": 4,
  "operand_fields": [
    { "name": "dst", "byte_offset": 2, "size": 1, "mask": "0x1F", "shift": 0 },
    { "name": "src", "byte_offset": 3, "size": 1 }
  ]
}
```

支持固定算术/位运算、rotate、byte-swap、取反以及 rolling-key 变换。若字节码来自未被 Trace 观察到的只读映射，opcode 会保持 unknown；此时应改用 `opcode_from_reg`，或确保录制覆盖字节码的生成/写入。

虚拟状态也可以直接映射到 host 寄存器：

```json
{
  "vm_registers": [
    { "name": "pc", "from_host_reg": "x19" },
    { "name": "sp", "from_host_reg": "x20" },
    { "name": "R0", "from_host_reg": "x21" }
  ]
}
```

这适用于把 VM 状态常驻在 AArch64 callee-saved 寄存器中的轻量解释器。

## MCP 深入查询

先用 `vm_abstract` 加载相同 hints，再使用：

- `vm_summary`：dispatcher、架构和 handler 热度概览；
- `vm_steps_query`：按 label、opcode、VM-PC 或寄存器变化过滤步骤；
- `vm_reg_timeline`：追踪一个虚拟寄存器的值变化；
- `vm_backward_slice`：从指定 step 的虚拟寄存器反查 producer。

MCP 返回的 PC 使用当前 `image_base` 重基后的显示地址；默认与 AArch64 Mach-O 的 IDA 地址一致。

## 结果解释与限制

主要结果包括 dispatcher 类型、迭代数、架构分类、handler 执行次数、VM steps、VM-PC、context、虚拟寄存器、操作数和推断的字节码范围。

- 结果只覆盖当前 Trace 实际执行的路径；未执行 handler 不会出现。
- handler 标签来自 hints，不是 Tenet 自动证明的语义。
- Sampling、缺失 GPR diff 或内存访问会降低状态恢复精度。
- `vm_abstract` 提供结构和动态状态，不等于完整去虚拟化。

## 排查

### `requires at least one static-analysis hint`

传入 `--vm-hints`、`--vm-dispatcher` 或至少一个 `--vm-handler`。不存在无 hint 自动检测模式。

### Hinted PC 从未执行

确认地址来自当前版本二进制、使用 IDA/Ghidra 显示地址、位于 qbditrace 追踪范围内，并且当前输入确实执行了该 VM 路径。

### Anchor 命中不足或步骤数异常

至少需要三个 anchor 命中。步骤过少通常表示漏命中，过多通常表示每步命中多次。对 direct-threaded 或 CFF 结构改用 `anchor_pcs` 或 `mem_anchor_addr`。

### VM-PC 有值但 opcode 全部 unknown

字节码内存可能没有被 Trace 观察到。定位承载已解码 opcode 的 host 寄存器并使用 `opcode_from_reg`，或扩大录制范围覆盖字节码写入。
