#include "core/triton_bridge.h"
#include <mutex>
#include <shared_mutex>

#ifdef TENET_HAS_TRITON
#include <triton/context.hpp>
#include <triton/archEnums.hpp>
#include <triton/instruction.hpp>
#endif

namespace tenet {

// ─── TritonBridge default batch implementation ────────────────────────────

std::vector<Result<InstructionSemantics>> TritonBridge::query_batch(
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& instructions) {
    std::vector<Result<InstructionSemantics>> results;
    results.reserve(instructions.size());
    for (auto& [pc, code] : instructions) {
        results.push_back(query_semantics(pc, code.data(), code.size()));
    }
    return results;
}

// ─── Stub implementation ──────────────────────────────────────────────────

Result<InstructionSemantics> TritonBridgeStub::query_semantics(
    uint64_t /*pc*/, const uint8_t* /*code*/, size_t /*code_size*/) {
    return Error(ErrorCode::CapstoneError, "Triton not linked");
}

void TritonBridgeStub::set_register_context(const RegState& /*state*/) {
    // no-op
}

void TritonBridgeStub::set_memory_context(uint64_t /*addr*/, const uint8_t* /*data*/, size_t /*size*/) {
    // no-op
}

void TritonBridgeStub::reset() {
    // no-op
}

bool TritonBridgeStub::is_available() const {
    return false;
}

// ─── Real Triton implementation ───────────────────────────────────────────

#ifdef TENET_HAS_TRITON

namespace {

/// Maps tenet GPR index (0-33) to Triton AArch64 register enum.
triton::arch::register_e gpr_index_to_triton(uint8_t idx) {
    using namespace triton::arch;
    // x0-x28
    if (idx <= 28) {
        return static_cast<register_e>(
            static_cast<int>(register_e::ID_REG_AARCH64_X0) + idx);
    }
    switch (idx) {
        case 29: return register_e::ID_REG_AARCH64_X29;  // FP
        case 30: return register_e::ID_REG_AARCH64_X30;  // LR
        case 31: return register_e::ID_REG_AARCH64_SP;   // SP
        case 32: return register_e::ID_REG_AARCH64_SPSR; // NZCV (closest available)
        case 33: return register_e::ID_REG_AARCH64_PC;   // PC
        default: return register_e::ID_REG_INVALID;
    }
}

/// Maps Triton AArch64 register to tenet GPR index (0-33), or 0xFF if not a GPR.
uint8_t triton_reg_to_gpr_index(triton::arch::register_e reg) {
    using namespace triton::arch;
    auto id = static_cast<int>(reg);
    auto x0 = static_cast<int>(register_e::ID_REG_AARCH64_X0);
    auto x28 = static_cast<int>(register_e::ID_REG_AARCH64_X28);

    if (id >= x0 && id <= x28) {
        return static_cast<uint8_t>(id - x0);
    }
    if (reg == register_e::ID_REG_AARCH64_X29) return 29;
    if (reg == register_e::ID_REG_AARCH64_X30) return 30;
    if (reg == register_e::ID_REG_AARCH64_SP)  return 31;
    if (reg == register_e::ID_REG_AARCH64_SPSR) return 32;
    if (reg == register_e::ID_REG_AARCH64_PC)  return 33;
    return 0xFF;  // not a GPR we track
}

/// Thread-safe shared semantic cache across TritonPool instances.
/// Keyed by opcode word (AArch64 fixed 4-byte instructions produce
/// identical register/memory access sets regardless of PC).
class SharedSemCache {
public:
    std::optional<InstructionSemantics> lookup(uint32_t opcode) const {
        std::shared_lock<std::shared_mutex> lk(mutex_);
        auto it = cache_.find(opcode);
        if (it != cache_.end()) return it->second;
        return std::nullopt;
    }

    void insert(uint32_t opcode, const InstructionSemantics& sem) {
        std::unique_lock<std::shared_mutex> lk(mutex_);
        cache_.emplace(opcode, sem);
    }

private:
    mutable std::shared_mutex mutex_;
    ankerl::unordered_dense::map<uint32_t, InstructionSemantics> cache_;
};

}  // anonymous namespace

class TritonBridgeImpl final : public TritonBridgeTaint {
public:
    explicit TritonBridgeImpl(std::shared_ptr<SharedSemCache> shared_cache = nullptr)
        : shared_cache_(std::move(shared_cache)) {
        // Taint context: used by process_instruction / taint_register etc.
        ctx_.setArchitecture(triton::arch::architecture_e::ARCH_AARCH64);
        // Disable symbolic execution (we only need concrete semantics + taint)
        ctx_.setMode(triton::modes::mode_e::ONLY_ON_TAINTED, true);

        // Semantics context: a separate lightweight context used ONLY for
        // query_semantics(). It never accumulates taint state, so we don't
        // need ONLY_ON_TAINTED — plain concrete mode is fine and cheaper.
        // This isolation prevents query_semantics() calls from corrupting the
        // running taint engine state.
        sem_ctx_.setArchitecture(triton::arch::architecture_e::ARCH_AARCH64);
    }

    Result<InstructionSemantics> query_semantics(
        uint64_t pc, const uint8_t* code, size_t code_size) override {

        // ── Opcode cache: AArch64 is fixed 4-byte instructions, so the opcode
        // word fully determines register read/write sets (what backward_taint
        // needs). We key by opcode_word, not PC, so the cache works across
        // repeated executions of the same instruction at the same or different
        // addresses.
        uint32_t opcode_word = (code_size >= 4)
            ? *reinterpret_cast<const uint32_t*>(code) : 0;

        // Check shared cache first (lock-free read path via shared_mutex)
        if (shared_cache_) {
            auto cached = shared_cache_->lookup(opcode_word);
            if (cached) {
                cached->pc = pc;
                return *cached;
            }
        }

        // Check local cache (no lock needed, single-threaded per instance)
        auto it = sem_cache_.find(opcode_word);
        if (it != sem_cache_.end()) {
            InstructionSemantics cached = it->second;
            cached.pc = pc;
            return cached;
        }

        triton::arch::Instruction inst;
        inst.setOpcode(code, static_cast<triton::uint32>(code_size));
        inst.setAddress(pc);

        auto exception = sem_ctx_.processing(inst);
        if (exception != triton::arch::exception_e::NO_FAULT) {
            return Error(ErrorCode::CapstoneError,
                "Triton processing failed for instruction at " + std::to_string(pc));
        }

        InstructionSemantics sem;
        sem.pc = pc;
        sem.opcode = opcode_word;

        // Extract read registers
        for (auto& [reg, ast_node] : inst.getReadRegisters()) {
            uint8_t idx = triton_reg_to_gpr_index(reg.getId());
            if (idx != 0xFF) {
                sem.reg_accesses.push_back({idx, true, false});
            }
        }

        // Extract written registers
        for (auto& [reg, ast_node] : inst.getWrittenRegisters()) {
            uint8_t idx = triton_reg_to_gpr_index(reg.getId());
            if (idx != 0xFF) {
                // Check if also read
                bool already_read = false;
                for (auto& ra : sem.reg_accesses) {
                    if (ra.reg_id == idx && ra.is_read) {
                        ra.is_written = true;
                        already_read = true;
                        break;
                    }
                }
                if (!already_read) {
                    sem.reg_accesses.push_back({idx, false, true});
                }
            }
        }

        // Extract memory loads
        for (auto& [mem_access, ast_node] : inst.getLoadAccess()) {
            MemAccess ma;
            ma.address = mem_access.getAddress();
            ma.size = static_cast<uint8_t>(mem_access.getSize());
            ma.is_read = true;
            ma.is_written = false;
            ma.address_is_symbolic = false;  // concrete mode
            sem.mem_accesses.push_back(ma);
        }

        // Extract memory stores
        for (auto& [mem_access, ast_node] : inst.getStoreAccess()) {
            MemAccess ma;
            ma.address = mem_access.getAddress();
            ma.size = static_cast<uint8_t>(mem_access.getSize());
            ma.is_read = false;
            ma.is_written = true;
            ma.address_is_symbolic = false;
            sem.mem_accesses.push_back(ma);
        }

        sem.is_branch = inst.isBranch();
        sem.is_conditional = inst.isConditionTaken();
        sem.is_call = false;  // Triton doesn't expose is_call directly; detect via BL/BLR
        sem.is_return = false;

        // Detect call/return from disassembly mnemonic
        auto disasm = inst.getDisassembly();
        if (disasm.find("bl") == 0 || disasm.find("blr") == 0) {
            sem.is_call = true;
        } else if (disasm.find("ret") == 0) {
            sem.is_return = true;
        }

        sem.expression = disasm;

        // Store in local cache (fast, no lock)
        sem_cache_.emplace(opcode_word, sem);
        // Propagate to shared cache (thread-safe, visible to other pool instances)
        if (shared_cache_) {
            shared_cache_->insert(opcode_word, sem);
        }

        return sem;
    }

    void set_register_context(const RegState& state) override {
        for (uint8_t i = 0; i < AARCH64_GPR_COUNT; i++) {
            auto triton_reg = gpr_index_to_triton(i);
            if (triton_reg != triton::arch::register_e::ID_REG_INVALID) {
                const auto& reg = ctx_.getRegister(triton_reg);
                ctx_.setConcreteRegisterValue(reg, state.gpr[i]);
            }
        }
    }

    void set_memory_context(uint64_t addr, const uint8_t* data, size_t size) override {
        for (size_t i = 0; i < size; i++) {
            ctx_.setConcreteMemoryValue(addr + i, data[i]);
        }
    }

    void reset() override {
        ctx_.reset();
        ctx_.setArchitecture(triton::arch::architecture_e::ARCH_AARCH64);
        ctx_.setMode(triton::modes::mode_e::ONLY_ON_TAINTED, true);
    }

    bool is_available() const override {
        return true;
    }

    // ─── Taint engine access (direct Triton taint API) ──────────────────

    /// Taint a register in Triton's taint engine.
    bool taint_register(uint8_t gpr_idx) override {
        auto triton_reg = gpr_index_to_triton(gpr_idx);
        if (triton_reg == triton::arch::register_e::ID_REG_INVALID) return false;
        const auto& reg = ctx_.getRegister(triton_reg);
        return ctx_.taintRegister(reg);
    }

    /// Untaint a register.
    bool untaint_register(uint8_t gpr_idx) override {
        auto triton_reg = gpr_index_to_triton(gpr_idx);
        if (triton_reg == triton::arch::register_e::ID_REG_INVALID) return false;
        const auto& reg = ctx_.getRegister(triton_reg);
        return ctx_.untaintRegister(reg);
    }

    /// Check if a register is tainted.
    bool is_register_tainted(uint8_t gpr_idx) const override {
        auto triton_reg = gpr_index_to_triton(gpr_idx);
        if (triton_reg == triton::arch::register_e::ID_REG_INVALID) return false;
        const auto& reg = ctx_.getRegister(triton_reg);
        return ctx_.isRegisterTainted(reg);
    }

    /// Taint a memory range.
    bool taint_memory(uint64_t addr, size_t size) override {
        bool any = false;
        for (size_t i = 0; i < size; i++) {
            any |= ctx_.taintMemory(addr + i);
        }
        return any;
    }

    /// Check if a memory address is tainted.
    bool is_memory_tainted(uint64_t addr, size_t size) const override {
        return ctx_.isMemoryTainted(addr, static_cast<triton::uint32>(size));
    }

    /// Process a single instruction (advancing taint state).
    /// Returns true if instruction processed successfully.
    bool process_instruction(uint64_t pc, const uint8_t* code, size_t code_size) override {
        triton::arch::Instruction inst;
        inst.setOpcode(code, static_cast<triton::uint32>(code_size));
        inst.setAddress(pc);
        auto exception = ctx_.processing(inst);
        return (exception == triton::arch::exception_e::NO_FAULT);
    }

    /// Get all tainted GPR indices after processing.
    std::vector<uint8_t> get_tainted_gprs() const override {
        std::vector<uint8_t> result;
        for (uint8_t i = 0; i < AARCH64_GPR_COUNT; i++) {
            if (is_register_tainted(i)) {
                result.push_back(i);
            }
        }
        return result;
    }

    /// Zero-allocation bitmask version — preferred for hot loops.
    uint64_t get_tainted_gpr_mask() const override {
        uint64_t mask = 0;
        for (uint8_t i = 0; i < AARCH64_GPR_COUNT; i++) {
            if (is_register_tainted(i)) {
                mask |= (1ULL << i);
            }
        }
        return mask;
    }

    /// Direct access to the Triton context (advanced use).
    triton::Context& raw_context() { return ctx_; }

private:
    triton::Context ctx_;       // Taint engine context (stateful across instructions)
    triton::Context sem_ctx_;   // Semantics-only context (stateless, used by query_semantics)

    // Per-instance local cache (fast, no synchronization needed)
    ankerl::unordered_dense::map<uint32_t, InstructionSemantics> sem_cache_;

    // Shared cache across all pool instances (thread-safe via shared_mutex)
    std::shared_ptr<SharedSemCache> shared_cache_;
};

#endif  // TENET_HAS_TRITON

// ─── Factory ──────────────────────────────────────────────────────────────

std::unique_ptr<TritonBridge> create_triton_bridge() {
#ifdef TENET_HAS_TRITON
    return std::make_unique<TritonBridgeImpl>();
#else
    return std::make_unique<TritonBridgeStub>();
#endif
}

// ─── TritonPool implementation ────────────────────────────────────────────

TritonPool::TritonPool(size_t pool_size) {
    pool_.reserve(pool_size);
#ifdef TENET_HAS_TRITON
    auto shared_cache = std::make_shared<SharedSemCache>();
    for (size_t i = 0; i < pool_size; i++) {
        pool_.push_back(std::make_unique<TritonBridgeImpl>(shared_cache));
    }
#else
    for (size_t i = 0; i < pool_size; i++) {
        pool_.push_back(create_triton_bridge());
    }
#endif
}

TritonPool::~TritonPool() = default;

std::optional<TritonPool::BorrowedBridge> TritonPool::borrow() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) return std::nullopt;
    auto bridge = std::move(pool_.back());
    pool_.pop_back();
    bridge->reset();
    return BorrowedBridge(*this, std::move(bridge));
}

void TritonPool::return_bridge(std::unique_ptr<TritonBridge> bridge) {
    std::lock_guard<std::mutex> lock(mutex_);
    pool_.push_back(std::move(bridge));
}

bool TritonPool::is_available() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) return false;
    return pool_.front()->is_available();
}

}  // namespace tenet
