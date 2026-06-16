#pragma once

#include "common/types.h"
#include "io/code_table.h"

#include <capstone/capstone.h>
#include <array>
#include <string>
#include <string_view>
#include <cstdint>

namespace tenet {

/// Decoded instruction information.
/// Uses fixed-size arrays to eliminate all heap allocations in the decode path.
struct DecodedInst {
    uint64_t pc = 0;
    uint32_t opcode = 0;
    char mnemonic[12]{};      // fixed buffer, zero-terminated (AArch64 mnemonics ≤ 10 chars)
    char op_str[64]{};        // fixed buffer, zero-terminated (operands rarely exceed 60)
    uint8_t size = 0;

    // Register access info (fixed-size arrays, no heap allocation)
    std::array<uint8_t, 8> regs_read{};
    std::array<uint8_t, 8> regs_written{};
    uint8_t regs_read_count = 0;
    uint8_t regs_written_count = 0;

    // Convenience accessors returning string_view (no allocation)
    std::string_view mnemonic_sv() const { return std::string_view(mnemonic); }
    std::string_view op_str_sv() const { return std::string_view(op_str); }
};

/// Wraps Capstone for AArch64 disassembly with a decode cache.
class InstructionDecoder {
public:
    InstructionDecoder();
    ~InstructionDecoder();

    // Non-copyable
    InstructionDecoder(const InstructionDecoder&) = delete;
    InstructionDecoder& operator=(const InstructionDecoder&) = delete;

    /// Initialize Capstone. Returns false on failure.
    bool init();

    /// Decode a single instruction at the given PC with the given opcode bytes.
    /// Returns nullopt if Capstone fails to decode.
    std::optional<DecodedInst> decode(uint64_t pc, uint32_t opcode);

    /// Decode using the CodeTable (convenience wrapper).
    std::optional<DecodedInst> decode(uint64_t pc, const CodeTable& code_table);

    /// Format an instruction as a string: "addr: mnemonic operands"
    std::string format(uint64_t pc, uint32_t opcode);

private:
    csh handle_ = 0;
    bool initialized_ = false;
    LRUCache<uint64_t, DecodedInst> cache_{16384};
};

}  // namespace tenet
