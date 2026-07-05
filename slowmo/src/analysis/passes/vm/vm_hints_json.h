#pragma once

// vm_hints_json.h — Shared JSON hints-file loader for VMAbstractPass.
//
// VM dispatcher auto-detection is unreliable on real traces (see the caveat
// in vm_abstract_pass.h), so both the CLI (--vm-hints <file>) and the GUI
// ("Load Hints" in the VM Workspace) require the caller to supply static
// analysis hints obtained from IDA/Ghidra before running vm_abstract. This
// header defines the shared JSON schema + loader used by both frontends.
//
// ── Address convention (MUST match the MCP `vm_abstract` tool) ─────────────
//
// All PC-valued fields (dispatcher_pc, indirect_branch_pc, handler_entry_pcs,
// threaded_dispatch_pcs, bytecode_base, opcode_mask-adjacent addresses,
// handler_asm_map keys, handler_names keys) are interpreted as **IDA-displayed
// addresses** (i.e. `image_base + static_offset`, IDA's default image_base
// for AArch64 Mach-O is 0x100000000) — the exact same convention the MCP
// `vm_abstract` tool / `set_image_base` use for every other PC-taking MCP
// tool. This loader converts them to runtime addresses via:
//
//     runtime_pc = displayed_pc - image_base + module_slide
//
// so that a hints file authored by copying addresses straight out of IDA
// works identically whether it's fed through the MCP tool's `hints_file`
// arg, the GUI's "Load Hints" drop zone, or `--vm-hints` on the CLI.
// (Earlier versions of this loader treated the JSON as raw runtime
// addresses with no rebase — that silently diverged from the MCP tool and
// produced "hinted PC was never executed" for anyone reusing an MCP-style
// hints file in the GUI/CLI.)
//
// `mem_anchor_addr` is the one exception: it is documented (see
// DispatcherHint::mem_anchor_addr) as already being a runtime address
// (typically computed at hint-authoring time from an observed heap
// pointer), so it is passed through unchanged — same as the MCP tool.
//
// JSON schema (all fields optional):
//
//   {
//     "dispatcher_pc": "0x...", "indirect_branch_pc": "0x...",
//     "handler_entry_pcs": ["0x...", ...],
//     "dispatch_type": "WhileSwitch|IndirectBranch|CallTable|ThreadedCode|Trampoline",
//     "threaded_dispatch_pcs": ["0x...", ...],
//     "vm_pc_reg": "x19", "bytecode_base": "0x...",
//     "opcode_size": 1, "opcode_byte_offset": 0, "opcode_mask": "0x...",
//     "opcode_shift": 0, "opcode_from_reg": "x0",
//     "opcode_deobf_steps": [{"op": "xor", "imm": "0xE0"}, ...],
//     "ctx_base_reg": "x21",
//     "ctx_fields": [{"name": "ip", "offset": 0, "size": 8, "is_pointer": false}, ...],
//     "vm_registers": [{"name": "R0", "offset": 0, "size": 8}, ...],
//     "rf_base_reg": "x20",
//     "vm_stack_sp_offset": 16, "vm_stack_depth": 8, "vm_stack_elem_size": 8,
//     "vm_stack_direction": "descending|ascending",
//     "handler_asm_map": {"0x...": ["asm line", ...] or [{"pc":"0x...","text":"..."}]},
//     "handler_names": {"0x...": "ADD", ...}
//   }

#include "analysis/passes/vm/vm_abstract_pass.h"

#include <cstdint>
#include <string>

namespace tenet {

/// IDA's default image base for AArch64 Mach-O binaries. Matches
/// TenetMcpService::image_base_'s default — see the address-convention
/// comment above.
inline constexpr uint64_t kDefaultIdaImageBase = 0x100000000ULL;

/// Loads static-analysis hints from a JSON file at `path` into `cfg`.
/// Existing fields already set in `cfg` are left untouched unless the JSON
/// file also specifies them (in which case the file's value wins — callers
/// that want "inline args override file" semantics should apply inline
/// overrides to `cfg` AFTER calling this function).
///
/// All PC-valued fields are read as IDA-displayed addresses and converted
/// to runtime addresses via `displayed_pc - image_base + module_slide`
/// (see the address-convention comment above). Callers running against a
/// real trace should pass `image_base = kDefaultIdaImageBase` (IDA's
/// default) and `module_slide` from `TraceReader::header().module_slide` so
/// the conversion lines up with this trace's ASLR slide — this is what the
/// GUI and CLI frontends do, matching the MCP `vm_abstract` tool's default.
///
/// Defaults to `image_base = 0, module_slide = 0` (no-op passthrough) for
/// backward compatibility with callers/tests that construct a VMConfig from
/// hand-written raw addresses with no rebase involved.
///
/// Returns true on success. On failure (file not found / invalid JSON),
/// prints an error to stderr and returns false; `cfg` may be partially
/// modified in that case.
bool load_vm_hints_from_json(const std::string& path, VMConfig& cfg,
                             uint64_t module_slide = 0,
                             uint64_t image_base = 0);

}  // namespace tenet
