#pragma once

// vm_hints_json.h — Shared JSON hints-file loader for VMAbstractPass.
//
// VM dispatcher auto-detection is unreliable on real traces (see the caveat
// in vm_abstract_pass.h), so both the CLI (--vm-hints <file>) and the GUI
// ("Load Hints" in the VM Workspace) require the caller to supply static
// analysis hints obtained from IDA/Ghidra before running vm_abstract. This
// header defines the shared JSON schema + loader used by both frontends
// (the MCP tool has its own inline arg + hints_file merge logic in
// io/mcp/mcp_tools_analysis.cpp, using the same field names).
//
// JSON schema (all fields optional; addresses are raw runtime hex strings,
// no ASLR rebase — same convention as the --vm-dispatcher/--vm-handler CLI
// flags):
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

#include <string>

namespace tenet {

/// Loads static-analysis hints from a JSON file at `path` into `cfg`.
/// Existing fields already set in `cfg` are left untouched unless the JSON
/// file also specifies them (in which case the file's value wins — callers
/// that want "inline args override file" semantics should apply inline
/// overrides to `cfg` AFTER calling this function).
///
/// Returns true on success. On failure (file not found / invalid JSON),
/// prints an error to stderr and returns false; `cfg` may be partially
/// modified in that case.
bool load_vm_hints_from_json(const std::string& path, VMConfig& cfg);

}  // namespace tenet
