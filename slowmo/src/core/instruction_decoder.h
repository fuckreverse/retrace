#pragma once

#include "common/types.h"
#include "io/code_table.h"

#include <capstone/capstone.h>
#include <array>
#include <shared_mutex>
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

/// Wraps Capstone for AArch64 disassembly with a per-thread decode cache.
///
/// Key optimization: cache by **opcode** instead of PC.
/// AArch64 is a fixed-length instruction set (4 bytes), so the opcode word
/// fully determines the disassembly result (mnemonic, operands, register
/// access sets).  Different PCs executing the same opcode share one cache
/// entry, yielding far higher hit rates than a PC-indexed cache.
///
/// Thread safety: each thread gets its own Capstone handle (thread_local),
/// eliminating the global mutex that was the bottleneck under concurrent
/// decode workloads.  The opcode cache is protected by a shared_mutex
/// (reader-writer lock) so multiple passes can call decode() concurrently
/// from different threads under run_all(N) parallelism.
class InstructionDecoder {
public:
    InstructionDecoder();
    ~InstructionDecoder();

    // Non-copyable
    InstructionDecoder(const InstructionDecoder&) = delete;
    InstructionDecoder& operator=(const InstructionDecoder&) = delete;

    /// Initialize the thread-local Capstone handle. Returns false on failure.
    bool init();

    /// Decode a single instruction at the given PC with the given opcode bytes.
    /// Returns nullopt if Capstone fails to decode.
    std::optional<DecodedInst> decode(uint64_t pc, uint32_t opcode);

    /// Decode using the CodeTable (convenience wrapper).
    std::optional<DecodedInst> decode(uint64_t pc, const CodeTable& code_table);

    /// Format an instruction as a string: "addr: mnemonic operands"
    std::string format(uint64_t pc, uint32_t opcode);

private:
    /// Per-thread Capstone handle (lazily initialized).
    /// No mutex needed — each thread has its own copy.
    static csh& tls_handle();

    /// Opcode-keyed decode cache, protected by a reader-writer lock.
    /// AArch64 has ~2K distinct encodings, so 4096 slots is generous.
    /// The shared_mutex allows multiple concurrent readers (cache hits)
    /// while serializing writers (cache misses that insert new entries).
    LRUCache<uint32_t, DecodedInst> opcode_cache_{4096};
    mutable std::shared_mutex opcode_cache_mtx_;

    bool initialized_ = false;
};

}  // namespace tenet
