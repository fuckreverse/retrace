#pragma once

#include <cstdint>
#include <string>

namespace tenet {

/// Display model for one instruction row (shared between TUI and GUI).
struct InstructionRow {
    uint64_t inst_id;
    uint64_t pc;
    uint64_t static_pc;
    std::string disasm;       // full "mnemonic operands" string
    std::string mnemonic;     // just the mnemonic (for syntax highlighting)
    std::string operands;     // just the operands (for syntax highlighting)
    uint8_t nzcv;
    uint8_t reg_diff_count;
    uint8_t mem_access_count;
    bool has_bookmark = false;
};

}  // namespace tenet
