#pragma once

#include "common/types.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>

namespace tenet {

// ─── Triton semantic query results ────────────────────────────────────────

/// Describes one register slice read/written by an instruction.
struct RegAccess {
    uint8_t reg_id;     // Index in GPR array (0-33)
    bool is_read;
    bool is_written;
};

/// Describes one memory access with symbolic address/value info.
struct MemAccess {
    uint64_t address;
    uint8_t size;       // bytes
    bool is_read;
    bool is_written;
    bool address_is_symbolic;   // address depends on runtime value
};

/// Full semantic info for one instruction.
struct InstructionSemantics {
    uint64_t pc;
    uint32_t opcode;

    std::vector<RegAccess> reg_accesses;
    std::vector<MemAccess> mem_accesses;

    bool is_branch;
    bool is_conditional;
    bool is_call;
    bool is_return;

    /// Simplified symbolic expression string (for taint/slice display)
    std::string expression;
};

// ─── TritonBridge interface ───────────────────────────────────────────────

/// Abstract interface to a semantic oracle.
/// Default implementation is a stub; real Triton linkage is optional.
class TritonBridge {
public:
    virtual ~TritonBridge() = default;

    /// Query semantics for a single instruction given its bytes and PC.
    virtual Result<InstructionSemantics> query_semantics(
        uint64_t pc, const uint8_t* code, size_t code_size) = 0;

    /// Batch query: semantics for a sequence of instructions.
    /// Default implementation calls query_semantics in a loop.
    virtual std::vector<Result<InstructionSemantics>> query_batch(
        const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& instructions);

    /// Set concrete register state for context-sensitive analysis.
    virtual void set_register_context(const RegState& state) = 0;

    /// Set concrete memory bytes for context-sensitive analysis.
    virtual void set_memory_context(uint64_t addr, const uint8_t* data, size_t size) = 0;

    /// Reset internal state (for pooling/reuse).
    virtual void reset() = 0;

    /// Check if Triton is actually available (linked).
    virtual bool is_available() const = 0;
};

// ─── Extended interface for taint-aware Triton usage ──────────────────────

/// Extended interface providing direct Triton taint engine access.
/// Only available when TENET_HAS_TRITON is defined.
class TritonBridgeTaint : public TritonBridge {
public:
    virtual ~TritonBridgeTaint() = default;

    /// Taint a register by GPR index.
    virtual bool taint_register(uint8_t gpr_idx) = 0;

    /// Untaint a register by GPR index.
    virtual bool untaint_register(uint8_t gpr_idx) = 0;

    /// Check if a register is tainted.
    virtual bool is_register_tainted(uint8_t gpr_idx) const = 0;

    /// Taint a memory range.
    virtual bool taint_memory(uint64_t addr, size_t size) = 0;

    /// Check if memory is tainted.
    virtual bool is_memory_tainted(uint64_t addr, size_t size = 1) const = 0;

    /// Process a single instruction, advancing taint state.
    virtual bool process_instruction(uint64_t pc, const uint8_t* code, size_t code_size) = 0;

    /// Get all currently tainted GPR indices.
    virtual std::vector<uint8_t> get_tainted_gprs() const = 0;

    /// Get the current taint state as a bitmask.
    /// Bit N set means GPR N is tainted.  Zero heap allocation — the
    /// preferred API for hot loops (callers can do bitwise diff instead
    /// of O(T²) nested scans).
    virtual uint64_t get_tainted_gpr_mask() const = 0;
};

// ─── Stub implementation ──────────────────────────────────────────────────

/// Stub that always returns "not available" errors.
/// Used when Triton is not linked.
class TritonBridgeStub final : public TritonBridge {
public:
    Result<InstructionSemantics> query_semantics(
        uint64_t pc, const uint8_t* code, size_t code_size) override;

    void set_register_context(const RegState& state) override;
    void set_memory_context(uint64_t addr, const uint8_t* data, size_t size) override;
    void reset() override;
    bool is_available() const override;
};

// ─── Factory ──────────────────────────────────────────────────────────────

/// Create the best available TritonBridge.
/// Returns real implementation if Triton is linked, otherwise returns stub.
/// When Triton is available, the returned pointer can be dynamic_cast to TritonBridgeTaint*.
std::unique_ptr<TritonBridge> create_triton_bridge();

// ─── Context pool ─────────────────────────────────────────────────────────

/// Pool of TritonBridge instances for concurrent use.
class TritonPool {
public:
    explicit TritonPool(size_t pool_size = 4);
    ~TritonPool();

    /// Borrow a bridge from the pool. Returns nullptr if pool exhausted.
    class BorrowedBridge {
    public:
        BorrowedBridge(TritonPool& pool, std::unique_ptr<TritonBridge> bridge)
            : pool_(pool), bridge_(std::move(bridge)) {}
        ~BorrowedBridge() { pool_.return_bridge(std::move(bridge_)); }

        BorrowedBridge(const BorrowedBridge&) = delete;
        BorrowedBridge& operator=(const BorrowedBridge&) = delete;
        BorrowedBridge(BorrowedBridge&&) = default;
        BorrowedBridge& operator=(BorrowedBridge&&) = delete;

        TritonBridge& operator*() { return *bridge_; }
        TritonBridge* operator->() { return bridge_.get(); }
        TritonBridge* get() { return bridge_.get(); }

    private:
        TritonPool& pool_;
        std::unique_ptr<TritonBridge> bridge_;
    };

    std::optional<BorrowedBridge> borrow();
    bool is_available() const;

private:
    void return_bridge(std::unique_ptr<TritonBridge> bridge);

    std::vector<std::unique_ptr<TritonBridge>> pool_;
    mutable std::mutex mutex_;
};

}  // namespace tenet
