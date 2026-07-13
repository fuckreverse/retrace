---
title: Virtual machines and code virtualization
sidebar:
  order: 8
---

VMP-style protections translate native logic into custom bytecode interpreted at runtime by a dispatcher and handlers. Tenet's `vm_abstract` connects **static structure supplied by IDA/Ghidra** with observed execution to recover VM steps, opcodes, context, virtual registers, and handler hotness.

:::caution[Static hints are required]
`vm_abstract` is entirely hint-driven. It does not scan a trace for “VM-like loops,” and running only `--vm-abstract` is rejected. Locate a dispatcher, stable anchor, or handlers in IDA/Ghidra before handing them to Tenet.
:::

## Questions it can answer

| Question | Evidence from Tenet |
|---|---|
| Which native execution implements each VM instruction? | The VM step's `inst_id_start` / `inst_id_end` |
| Which handlers execute most often? | Handler frequency, body PCs, and opcode sets |
| What are the current VM-PC, context, and registers? | Per-step VM-PC, context fields, register/stack snapshots |
| Is the opcode encoded? | Bit-field extraction, fixed transforms, and rolling-key deobfuscation |
| Where did a virtual register value come from? | `vm_reg_timeline` and `vm_backward_slice` |

It does not automatically recover a complete VM ISA, enumerate handlers that never executed, generate native code, or recompile bytecode. Its output is the dynamic evidence layer for handler-semantic analysis and devirtualization.

## Minimal workflow

### 1. Find an anchor in a static tool

Look for a location that executes **exactly once per VM instruction**:

- the loop header of a while/switch dispatcher;
- a set of fetch/dispatch PCs embedded in direct-threaded handlers;
- a VM-PC or instruction-counter memory field written once per step.

### 2. Run the analysis

If only the dispatcher is known, start with inline hints:

```bash
./tenet trace.bin --vm-abstract \
  --vm-dispatcher 0x100005000 \
  --vm-indirect-br 0x100005014
```

Use `--vm-handler` repeatedly when several handler entries are known. For non-trivial VMs, prefer JSON:

```bash
./tenet trace.bin --vm-abstract --vm-hints vm-hints.json
```

If you have a separate bytecode decoder definition, append `--vm-decoder decoder.json`.

### 3. Inspect the VM Workspace

The GUI's **VM Hints** entry accepts a dropped or selected JSON file. After the pass runs, open **VM Workspace**:

- **VM Handlers**: frequencies, labels, and native PCs;
- **VM Steps**: opcodes, VM-PCs, labels, and native instruction ranges;
- **Bytecode/Stats**: bytecode range and execution statistics;
- **VM Registers / Stack**: virtual register or operand-stack snapshots;
- **VM Memory / Ctx**: context field values.

With **Linked** enabled, selecting a VM step navigates the native instruction timeline to the same execution range.

## Hints JSON

This is a basic register-machine example:

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

A field named `pc` or `ip` in `vm_registers` is treated as the VM-PC. If `rf_base_reg` is omitted, register-file reads use `ctx_base_reg`.

## Three anchor modes

| Mode | JSON field | Suitable structure |
|---|---|---|
| Single PC | `dispatcher_pc` | Central while/switch, indirect-branch, or trampoline dispatcher |
| PC set | `anchor_pcs` | Direct-threaded VM with fetch/dispatch embedded in handlers |
| Memory write | `mem_anchor_addr` + `mem_anchor_size` | CFF-disrupted control flow whose VM-PC/context field is still written once per step |

A PC anchor must hit exactly once per VM instruction. Missing or duplicate hits produce incorrect segmentation, and the pass cannot prove that an anchor satisfies this constraint.

A direct-threaded VM can supply several stable locations:

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

For heavily flattened control flow, use a memory-write anchor:

```json
{
  "dispatch_type": "FetchOnly",
  "mem_anchor_addr": "0x13B3444F0",
  "mem_anchor_size": 4,
  "handler_entry_pcs": ["0x100006000", "0x100007000"],
  "opcode_from_reg": "x0"
}
```

`opcode_from_reg` means that a host register already contains the decoded opcode, so Tenet does not read it from memory at the VM-PC.

## Address conventions

- `dispatcher_pc`, `indirect_branch_pc`, `handler_entry_pcs`, and `anchor_pcs` use **IDA/Ghidra displayed addresses**. Tenet relocates them with the trace's `module_slide`.
- AArch64 Mach-O defaults to IDA image base `0x100000000`.
- `mem_anchor_addr` is the exception: it must be the **runtime memory address** observed in the trace and is not rebased.

Do not mix static PCs, runtime PCs, and file offsets. If a hinted PC has no execution records, verify that it belongs to the same binary version and lies within the captured range.

## Opcodes, operands, and virtual state

By default, Tenet reads `opcode_size` bytes from memory at the VM-PC, then applies `opcode_byte_offset`, `opcode_mask`, and `opcode_shift`. Deobfuscation and operand fields can also be declared:

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

Fixed arithmetic/bitwise operations, rotates, byte swaps, complements, and rolling-key transforms are supported. If the bytecode comes from a read-only mapping never observed by the trace, opcodes remain unknown. Use `opcode_from_reg`, or capture the bytecode generation/write path.

Virtual state may also map directly to host registers:

```json
{
  "vm_registers": [
    { "name": "pc", "from_host_reg": "x19" },
    { "name": "sp", "from_host_reg": "x20" },
    { "name": "R0", "from_host_reg": "x21" }
  ]
}
```

This suits lightweight interpreters that keep VM state in AArch64 callee-saved registers.

## Deeper MCP queries

Run `vm_abstract` with the same hints, then use:

- `vm_summary` for dispatcher, architecture, and handler-hotness overview;
- `vm_steps_query` to filter by label, opcode, VM-PC, or register changes;
- `vm_reg_timeline` to track value changes for one virtual register;
- `vm_backward_slice` to find producers for a virtual register at a step.

MCP PC values use the currently selected `image_base`; by default they match IDA addresses for AArch64 Mach-O.

## Interpreting results and limitations

The main results include dispatcher type and iteration count, architecture classification, handler execution counts, VM steps, VM-PC, context, virtual registers, operands, and an inferred bytecode range.

- Results cover only the path executed by this trace; unexecuted handlers are absent.
- Handler labels come from hints and are not automatically proven semantics.
- Sampling or missing GPR diffs/memory accesses reduces state-reconstruction precision.
- `vm_abstract` provides structure and dynamic state; it is not complete devirtualization.

## Troubleshooting

### `requires at least one static-analysis hint`

Pass `--vm-hints`, `--vm-dispatcher`, or at least one `--vm-handler`. There is no hint-free detection mode.

### A hinted PC never executed

Confirm that the address comes from the current binary, uses the IDA/Ghidra displayed address, lies inside the qbditrace range, and is reached by the current input.

### Too few anchor hits or an implausible step count

At least three anchor hits are required. Too few steps usually indicate missed hits; too many usually indicate multiple hits per VM instruction. Use `anchor_pcs` or `mem_anchor_addr` for direct-threaded or flattened designs.

### VM-PC is valid but every opcode is unknown

The trace may not know the bytecode memory. Locate the host register carrying the decoded opcode and use `opcode_from_reg`, or expand capture to include bytecode writes.
