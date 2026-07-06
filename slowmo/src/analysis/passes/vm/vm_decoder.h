#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// VM Bytecode Decoder — Loadable disassembler for VM instruction traces.
//
// Consumes a VMAbstractResult (from vm_abstract pass) and renders each
// VMStep's opcode word into human-readable assembly text. Decoders are
// loaded from JSON descriptor files, making it trivial to add support for
// new VM ISAs without touching C++ code.
//
// Design:
//   The decoder is a post-processing layer, NOT part of the vm_abstract
//   pass itself.  VMAbstractPass extracts structural data (step sequence,
//   raw opcode values, operand fields, register snapshots); the decoder
//   turns those numeric values into formatted text.
//
// JSON Schema overview (see vm_decoder.cpp / docs for full spec):
//
//   {
//     "name": "bncode_v1",
//     "word_size": 4,             // instruction width in bytes (4 = 32-bit)
//     "registers": {"prefix":"R", "count":32},
//     "routing": [                // ordered multi-level mask+compare rules
//       { "mask":"0xFFE0003F", "match":"0x37", "op":"XOR",
//         "format":"{dst}, {src1}, {src2}",
//         "extract": { "dst":  [...bit-field ops...],
//                      "src1": [...], "src2": [...] } },
//       ...
//     ],
//     "default_op": "UNK"
//   }
//
// Bit-field extraction mini-language (the "extract" arrays):
//   Each named operand is decoded by a pipeline of micro-ops applied
//   to the 32/64-bit instruction word:
//     {"op":"lsr", "imm":4}          — shift right by 4
//     {"op":"and", "imm":"0xC"}      — mask with 0xC
//     {"op":"or_into","accum":true}   — OR result into accumulator
//     {"op":"lsr_and","lsr":11,"and":"0x3"} — combined shift+mask
//     {"op":"sext","width":16}       — sign-extend from N bits
//
//   This can express both simple UBFX-style field extraction AND the
//   scattered bit-field gathering used by e.g. bnCode VMP (where a 5-bit
//   register index is assembled from 3 non-contiguous bit groups via
//   shift+mask+OR).
// ═══════════════════════════════════════════════════════════════════════════

#include "analysis/passes/vm/vm_abstract_pass.h"  // VMStep, VMAbstractResult

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tenet {

// ─── Decoded instruction ─────────────────────────────────────────────────

/// A single decoded VM instruction with mnemonic + formatted assembly text.
struct VMDecodedInsn {
    std::string mnemonic;         // e.g. "XOR", "LDR", "B_REL26"
    std::string asm_text;         // e.g. "XOR R3, R1, R2"
    bool        valid = false;    // false if decoding failed
};

// ─── Abstract decoder interface ──────────────────────────────────────────

/// Base class for VM bytecode decoders.
///
/// Implementations consume VMStep data (opcode_value, operands, vm_regs)
/// and produce human-readable disassembly.
class VMBytecodeDecoder {
public:
    virtual ~VMBytecodeDecoder() = default;

    /// Decoder name (from the JSON descriptor), e.g. "bncode_v1".
    virtual std::string_view name() const = 0;

    /// Decode a single VM step into assembly text.
    /// Returns a VMDecodedInsn with valid=true on success.
    virtual VMDecodedInsn decode(const VMStep& step,
                                  const VMAbstractResult& ctx) const = 0;

    /// Batch-decode all steps. Default implementation calls decode() in a
    /// loop; subclasses may override for efficiency.
    virtual std::vector<VMDecodedInsn>
    decode_all(const std::vector<VMStep>& steps,
               const VMAbstractResult& ctx) const;
};

// ─── JSON-driven decoder ─────────────────────────────────────────────────

/// Loads a decoder from a JSON descriptor file.
///
/// Returns nullptr on parse failure (errors printed to stderr).
std::unique_ptr<VMBytecodeDecoder> load_decoder_from_json(const std::string& path);

}  // namespace tenet
