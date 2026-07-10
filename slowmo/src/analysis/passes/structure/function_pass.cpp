#include "analysis/passes/structure/function_pass.h"
#include "analysis/trace_collector.h"
#include "infra/scan_orchestrator.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"

#include <ankerl/unordered_dense.h>
#include <fmt/core.h>
#include <algorithm>
#include <numeric>
#include <string_view>

#include "common/byte_codec.h"

namespace tenet {

// ─── FunctionResult serialization helpers ────────────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic             = 0x46554E43 ("FUNC")
//   u32  version           = 1
//   u64  num_call_events
//   for each CallEvent (48 bytes):
//     u64  call_inst_id
//     u64  return_inst_id
//     u64  call_site_pc
//     u64  target_pc
//     u64  depth
//     u8   is_tail_call
//     u8   pad[7]
//   u64  num_functions
//   for each FunctionInfo:
//     u64  entry_pc
//     u64  total_calls
//     u64  total_instructions
//     u32  name_len
//     u8[] name_bytes[name_len]
//     u64  num_call_event_indices
//     u64[] call_event_indices[num_call_event_indices]

namespace {

static constexpr uint32_t FUNC_BLOB_MAGIC   = 0x46554E43u;  // "FUNC"
static constexpr uint32_t FUNC_BLOB_VERSION = 1u;

std::string function_serialize(const FunctionResult& res) {
    // ── Compute total size ─────────────────────────────────────────────────
    size_t total = 4 + 4 + 8;  // header + num_call_events
    total += res.call_events.size() * 48;  // each CallEvent is 48 bytes

    total += 8;  // num_functions
    for (const auto& [entry_pc, fi] : res.functions) {
        total += 8 + 8 + 8;                    // entry_pc, total_calls, total_instructions
        total += 4 + fi.name.size();           // name_len + name
        total += 8 + fi.call_event_indices.size() * 8;  // num_indices + indices
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u8  = [&](uint8_t  v) { std::memcpy(p, &v, 1); p += 1; };
    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };

    write_u32(FUNC_BLOB_MAGIC);
    write_u32(FUNC_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.call_events.size()));

    for (const auto& evt : res.call_events) {
        write_u64(evt.call_inst_id);
        write_u64(evt.return_inst_id);
        write_u64(evt.call_site_pc);
        write_u64(evt.target_pc);
        write_u64(evt.depth);
        write_u8(evt.is_tail_call ? 1u : 0u);
        // 7 bytes padding
        p += 7;
    }

    write_u64(static_cast<uint64_t>(res.functions.size()));
    for (const auto& [entry_pc, fi] : res.functions) {
        write_u64(fi.entry_pc);
        write_u64(fi.total_calls);
        write_u64(fi.total_instructions);
        write_u32(static_cast<uint32_t>(fi.name.size()));
        std::memcpy(p, fi.name.data(), fi.name.size());
        p += fi.name.size();
        write_u64(static_cast<uint64_t>(fi.call_event_indices.size()));
        for (size_t idx : fi.call_event_indices) {
            write_u64(static_cast<uint64_t>(idx));
        }
    }

    return buf;
}

bool function_deserialize(const std::string& blob, FunctionResult& out,
                          bool full_mode = false) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != FUNC_BLOB_MAGIC)   return false;
    if (r.u32() != FUNC_BLOB_VERSION) return false;

    uint64_t n_events = r.u64();
    // In default mode: apply the same cap as during live analysis so loading a
    // legacy blob (written before the cap was in place) does not exhaust memory.
    // In full_mode: load everything.
    static constexpr size_t kMaxCallEvents = 20'000'000;
    const uint64_t load_events = full_mode
        ? n_events
        : std::min(n_events, (uint64_t)kMaxCallEvents);
    out.call_events.reserve(static_cast<size_t>(load_events));

    for (uint64_t i = 0; i < n_events; i++) {
        CallEvent evt;
        evt.call_inst_id   = r.u64();
        evt.return_inst_id = r.u64();
        evt.call_site_pc   = r.u64();
        evt.target_pc      = r.u64();
        evt.depth          = r.u64();
        evt.is_tail_call   = r.u8() != 0;
        r.skip(7);  // skip padding
        if (!r.ok()) return false;
        // Only store events within the cap; consume the bytes regardless.
        if (i < load_events) {
            out.call_events.push_back(evt);
        }
    }

    uint64_t n_funcs = r.u64();
    if (!r.ok()) return false;
    out.functions.reserve(static_cast<size_t>(n_funcs));

    for (uint64_t i = 0; i < n_funcs; i++) {
        FunctionInfo fi;
        fi.entry_pc            = r.u64();
        fi.total_calls         = r.u64();
        fi.total_instructions  = r.u64();
        if (!r.str(fi.name)) return false;
        uint64_t n_idx = r.u64();
        if (!r.ok()) return false;
        // In default mode: apply the same cap as end() so deserialized data
        // doesn't exceed the in-memory limit even with legacy blobs.
        // In full_mode: load all indices (filtered only for validity).
        static constexpr size_t kMaxCallEventIndices = 1000;
        const uint64_t load_idx = full_mode
            ? n_idx
            : std::min(n_idx, (uint64_t)kMaxCallEventIndices);
        fi.call_event_indices.reserve(static_cast<size_t>(load_idx));
        // How many valid call_event_indices to keep (capped and within bounds)
        size_t loaded_idx_count = 0;
        for (uint64_t j = 0; j < n_idx; j++) {
            uint64_t idx_val = r.u64();  // must consume all bytes
            // Filter: only include indices that are within the loaded
            // call_events array.  This handles legacy blobs that were written
            // before the cap existed.
            if (loaded_idx_count < load_idx &&
                idx_val < out.call_events.size()) {
                fi.call_event_indices.push_back(static_cast<size_t>(idx_val));
                ++loaded_idx_count;
            }
        }
        if (!r.ok()) return false;
        out.functions.emplace(fi.entry_pc, std::move(fi));
    }

    // Rebuild lookup maps (call_site_map_ / return_site_map_)
    for (size_t idx = 0; idx < out.call_events.size(); idx++) {
        const auto& evt = out.call_events[idx];
        out.call_site_map_[evt.call_inst_id] = idx;
        if (evt.return_inst_id != 0) {
            out.return_site_map_[evt.return_inst_id] = idx;
        }
    }

    return true;
}

// ─── Known non-returning functions (common in iOS/macOS AArch64 binaries) ──

static constexpr std::string_view kNonReturningSymbols[] = {
    "exit", "_exit", "abort", "__abort",
    "__cxa_throw", "__cxa_rethrow", "objc_exception_throw",
    "longjmp", "_longjmp", "siglongjmp",
    "pthread_exit", "__pthread_exit",
    "__assert_rtn", "__assert_fail",
    "__stack_chk_fail", "__fortify_fail",
    "swift_unexpectedError", "swift_fatalError",
};

/// Check if a symbol name is a known non-returning function.
static bool is_non_returning(std::string_view name) {
    for (auto sv : kNonReturningSymbols) {
        if (sv == name) return true;
    }
    return false;
}

// ─── AArch64 opcode classification via bit patterns ───────────────────────

struct OpcodeClass {
    bool is_call             : 1;  // BL / BLR / BLRAA/BLRAB/BLRAAZ/BLRABZ
    bool is_ret              : 1;  // RET
    bool is_unconditional_jump : 1; // B / BR
};

inline OpcodeClass classify_opcode(uint32_t op) {
    OpcodeClass c{false, false, false};

    // BL (direct call, imm26): bits[31:26] = 100101
    if ((op & 0xFC000000u) == 0x94000000u) {
        c.is_call = true;
        return c;
    }

    // B (unconditional direct branch): bits[31:26] = 000101
    if ((op & 0xFC000000u) == 0x14000000u) {
        c.is_unconditional_jump = true;
        return c;
    }

    // Remaining candidates all have bits[31:25] = 1101011 (0x6B << 25)
    if ((op & 0xFE000000u) != 0xD6000000u) return c;

    // BLR (indirect call)
    if ((op & 0xFFFFFC1Fu) == 0xD63F0000u) {
        c.is_call = true;
        return c;
    }

    // RET
    if ((op & 0xFFFFFC1Fu) == 0xD65F0000u) {
        c.is_ret = true;
        return c;
    }

    // BR (unconditional indirect branch)
    if ((op & 0xFFFFFC1Fu) == 0xD61F0000u) {
        c.is_unconditional_jump = true;
        return c;
    }

    // BLRAA / BLRAB / BLRAAZ / BLRABZ (PAC-authenticated BLR)
    if ((op & 0xFEFFF800u) == 0xD63F0800u) {
        c.is_call = true;
        return c;
    }

    return c;
}

}  // anonymous namespace

// ─── FunctionResult methods ───────────────────────────────────────────────

void FunctionResult::build_call_index() const {
    if (call_index_built_) return;
    sorted_call_indices_.resize(call_events.size());
    std::iota(sorted_call_indices_.begin(), sorted_call_indices_.end(), 0);
    std::sort(sorted_call_indices_.begin(), sorted_call_indices_.end(),
              [this](size_t a, size_t b) {
                  return call_events[a].call_inst_id < call_events[b].call_inst_id;
              });
    call_index_built_ = true;
}

std::vector<const CallEvent*> FunctionResult::call_stack_at(uint64_t inst_id) const {
    build_call_index();

    auto bound = std::upper_bound(
        sorted_call_indices_.begin(), sorted_call_indices_.end(), inst_id,
        [this](uint64_t id, size_t idx) {
            return id < call_events[idx].call_inst_id;
        });

    std::vector<const CallEvent*> stack;
    for (auto it = sorted_call_indices_.begin(); it != bound; ++it) {
        const auto& evt = call_events[*it];
        if (evt.return_inst_id == 0 || evt.return_inst_id >= inst_id) {
            stack.push_back(&evt);
        }
    }
    std::sort(stack.begin(), stack.end(),
              [](const CallEvent* a, const CallEvent* b) {
                  return a->depth < b->depth;
              });
    return stack;
}

void FunctionResult::build_depth_table() {
    depth_table_.clear();
    if (call_events.empty()) return;

    depth_table_.reserve(call_events.size() * 2);

    uint64_t sim_depth = 0;
    for (const auto& evt : call_events) {
        sim_depth = evt.depth + 1;
        depth_table_.push_back({evt.call_inst_id, sim_depth});

        if (evt.return_inst_id != 0) {
            depth_table_.push_back({evt.return_inst_id, evt.depth});
        }
    }

    std::sort(depth_table_.begin(), depth_table_.end(),
              [](const DepthEntry& a, const DepthEntry& b) {
                  return a.inst_id < b.inst_id;
              });
}

uint64_t FunctionResult::depth_at(uint64_t inst_id) const {
    if (depth_table_.empty()) {
        uint64_t depth = 0;
        for (const auto& evt : call_events) {
            if (evt.call_inst_id > inst_id) break;
            if (evt.call_inst_id <= inst_id) depth = evt.depth + 1;
            if (evt.return_inst_id != 0 && evt.return_inst_id <= inst_id)
                depth = evt.depth;
        }
        return depth;
    }

    auto it = std::upper_bound(depth_table_.begin(), depth_table_.end(), inst_id,
                               [](uint64_t id, const DepthEntry& e) {
                                   return id < e.inst_id;
                               });
    if (it == depth_table_.begin()) return 0;
    --it;
    return it->depth;
}

const FunctionInfo* FunctionResult::function_at(uint64_t inst_id) const {
    build_call_index();

    auto bound = std::upper_bound(
        sorted_call_indices_.begin(), sorted_call_indices_.end(), inst_id,
        [this](uint64_t id, size_t idx) {
            return id < call_events[idx].call_inst_id;
        });

    const CallEvent* innermost = nullptr;
    for (auto it = bound; it != sorted_call_indices_.begin(); ) {
        --it;
        const auto& evt = call_events[*it];
        if (evt.return_inst_id == 0 || evt.return_inst_id >= inst_id) {
            if (!innermost || evt.depth > innermost->depth) {
                innermost = &evt;
            }
        }
    }

    if (!innermost) return nullptr;
    auto it = functions.find(innermost->target_pc);
    if (it == functions.end()) return nullptr;
    return &it->second;
}

// ─── FunctionCollector implementation ─────────────────────────────────────
//
// Two-phase design for performance:
//
//   Phase 1  (on_inst / on_anchor):
//     For each INST record the hot-path does a single binary search on
//     pc_kind_sorted_ (a sorted flat array — more cache-friendly than a hash
//     map for sparse branch-PC sets).  If the PC is not a branch-class
//     instruction AND phase1_need_next_ is false, on_inst returns immediately
//     with zero allocations.
//
//     When a branch-class PC is seen, a compact BranchEvent is appended to
//     branch_events_ and phase1_need_next_ is set.  The next on_inst call
//     writes the successor's PC into the preceding BranchEvent's target_pc
//     field — no deferred target resolution needed in Phase 2.
//
//     branch_events_ ends up with ~2-5% of total instruction count entries.
//
//   Phase 2  (end()):
//     The call/return state machine runs over the tiny branch_events_ array.
//     No trace data is accessed.  Function table construction, tail-call
//     detection, name generation, and depth table build all happen here.
//
// Performance impact (1M-instruction trace, RelWithDebInfo):
//   - Phase 1 scan: ~2-3× fewer hash map operations (binary search on flat
//     array is cache-friendlier than open-addressing hash map for sparse sets)
//   - Phase 2 state machine: processes ~20-50K events instead of 1M+ — the
//     per-event work is essentially free compared to the scan
//   - No fmt::format in the hot path (names deferred to end())
//   - Tail-call detection: known_entries built once, updated incrementally
//     instead of being rebuilt from scratch each iteration

FunctionCollector::FunctionCollector(CodeTable& code_table,
                                     uint64_t module_slide,
                                     uint32_t num_gpr,
                                     bool has_branch_hint,
                                     bool full_mode)
    : code_table_(code_table)
    , module_slide_(module_slide)
    , num_gpr_(num_gpr)
    , has_branch_hint_(has_branch_hint)
    , full_mode_(full_mode)
{}

// ── Phase-1 helper: binary-search lookup in sorted flat array ────────────

inline uint8_t FunctionCollector::lookup_pc_kind(uint64_t pc) const {
    // Binary search on sorted pc_kind_sorted_ array.
    // More cache-friendly than hash map for sparse PC sets because:
    //  1. The array is contiguous — prefetcher can stream it
    //  2. No hash collision resolution / open addressing
    //  3. Typical trace has 5-50K unique branch PCs; log2(50K) ≈ 16 comparisons
    auto it = std::lower_bound(pc_kind_sorted_.begin(), pc_kind_sorted_.end(), pc,
                               [](const PcKindEntry& e, uint64_t v) { return e.pc < v; });
    if (it == pc_kind_sorted_.end() || it->pc != pc) return 0;
    return it->kind;
}

bool FunctionCollector::begin(uint64_t /*start_inst_id*/, uint64_t /*end_inst_id*/) {
    // ── Reset all state ───────────────────────────────────────────────────
    result_ = FunctionResult{};
    call_stack_.clear();
    tail_candidates_.clear();
    ret_pc_refcount_.clear();
    branch_events_.clear();
    phase1_sp_             = 0;
    phase1_sp_valid_       = false;
    phase1_need_next_      = false;
    p2_prev_was_ret_       = false;
    p2_prev_ret_inst_id_   = 0;
    p2_prev_was_branch_    = false;
    p2_prev_jump_inst_id_  = 0;
    p2_prev_jump_pc_       = 0;
    p2_prev_jump_sp_       = 0;
    p2_prev_jump_sp_known_ = false;
    non_local_unwinds_     = 0;
    tail_calls_detected_   = 0;

    // ── Build PC classification table as sorted flat array ───────────────
    // Replaces ankerl::unordered_dense::map<uint64_t, uint8_t>:
    //   - Binary search on a contiguous sorted array has much better cache
    //     behaviour than open-addressing hash map for sparse PC sets.
    //   - We iterate code_table_ directly to avoid all_entries() which builds
    //     an extra sorted copy; we sort once here.
    pc_kind_sorted_.clear();
    pc_kind_sorted_.reserve(code_table_.size());

    for (const auto& [pc, opcode] : code_table_) {
        auto c = classify_opcode(opcode);
        if (c.is_call || c.is_ret || c.is_unconditional_jump) {
            uint8_t bits = 0;
            if (c.is_call)               bits |= KIND_CALL;
            if (c.is_ret)                bits |= KIND_RET;
            if (c.is_unconditional_jump) bits |= KIND_BRANCH;
            pc_kind_sorted_.push_back({pc, bits});
        }
    }
    std::sort(pc_kind_sorted_.begin(), pc_kind_sorted_.end(),
              [](const PcKindEntry& a, const PcKindEntry& b) { return a.pc < b.pc; });

    // Pre-size branch_events_ — heuristic: branch instructions are ~10-20% of
    // unique PCs; their execution count is ~2-5% of total instructions.
    // In default (capped) mode: cap at 4M entries (~192 MB) to avoid
    // over-committing on huge traces.  In full_mode the cap is lifted.
    const size_t raw_reserve = std::max(pc_kind_sorted_.size() * 8, size_t(4096));
    static constexpr size_t kMaxBranchReserve = 4 * 1024 * 1024;  // 4M entries
    branch_events_.reserve(
        full_mode_ ? raw_reserve
                   : std::min(raw_reserve, kMaxBranchReserve));

    return true;
}

// ── Phase 1: on_anchor ───────────────────────────────────────────────────

void FunctionCollector::on_anchor(uint64_t /*inst_id*/, const AnchorView& anchor) {
    // Update running SP from the full register snapshot.
    static constexpr uint32_t IDX_SP = 31;
    if (num_gpr_ > IDX_SP) {
        phase1_sp_       = anchor.gpr_values[IDX_SP];
        phase1_sp_valid_ = true;
    }
}

// ── Phase 1: on_inst ─────────────────────────────────────────────────────

void FunctionCollector::on_inst(uint64_t inst_id, const InstView& inst) {
    static constexpr uint32_t IDX_SP = 31;

    const uint64_t pc = inst.pc;

    // ── Resolve target_pc for the preceding CALL/BRANCH event ────────────
    // The very first thing we do is check phase1_need_next_: if set, the
    // current instruction's PC is the target of the last BranchEvent.
    // We write it directly into that event's target_pc field.
    // This MUST be done before the early-exit check so that even if the
    // successor is an ordinary instruction (kind == 0), we still capture it.
    if (phase1_need_next_) {
        phase1_need_next_ = false;
        if (!branch_events_.empty()) {
            branch_events_.back().target_pc = pc;
        }
        // Fall through: this instruction might itself be a branch-class PC.
    }

    // ── Fast gate: classify instruction ──────────────────────────────────────
    // When HF_BRANCH_HINT is set (new traces from qbditrace), the branch class
    // is encoded in bits[7:4] of the nzcv byte by the tracer at recording time.
    // branch_hint() is a single bit-shift with no memory access (sub-ns) and
    // handles ~95-98% of instructions by immediately returning 0 (ordinary).
    //
    // QBDITRACE_BRANCH_HINT_* values map directly to KIND_* constants:
    //   HINT_CALL(1) = KIND_CALL(1), HINT_RET(2) = KIND_RET(2),
    //   HINT_BRANCH(4) = KIND_BRANCH(4)  —  same bit values, no translation.
    //
    // For old traces (no HF_BRANCH_HINT) we fall back to the binary-search table
    // lookup on pc_kind_sorted_, which is still cache-friendly for sparse sets.
    uint8_t kind;
    if (has_branch_hint_) {
        // O(1) path: read pre-computed hint directly from nzcv high nibble.
        kind = inst.branch_hint();
        if (kind == 0) return;  // Fast return for ordinary instructions (~95%)
    } else {
        // O(log N) fallback for old traces without HF_BRANCH_HINT.
        kind = lookup_pc_kind(pc);
        if (kind == 0) return;
    }

    // ── Extract SP from register diffs ────────────────────────────────────
    // Only done for branch-class instructions (ordinary instructions are
    // skipped above, so SP tracking stays cheap).
    for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
        const auto diff = inst.reg_diff(d);
        if (diff.index == IDX_SP) {
            phase1_sp_       = diff.value;
            phase1_sp_valid_ = true;
            break;
        }
    }

    // ── Emit a BranchEvent ────────────────────────────────────────────────
    BranchEvent ev;
    ev.inst_id   = inst_id;
    ev.pc        = pc;
    ev.kind      = kind;
    ev.sp_valid  = phase1_sp_valid_;
    ev.sp        = phase1_sp_;
    ev.target_pc = 0;  // filled on next on_inst (phase1_need_next_)
    branch_events_.push_back(ev);

    // Arm need_next_ so the next on_inst resolves the target PC.
    phase1_need_next_ = true;
}

// ── Phase 2: call/return state machine helpers ───────────────────────────

void FunctionCollector::handle_deferred_ret(uint64_t ret_dest_pc, uint64_t ret_inst_id) {
    if (call_stack_.empty()) return;

    // Helper: fill return_inst_id only when the frame was actually recorded
    // (call_event_idx != SIZE_MAX).  Frames above the cap are sentinel-only.
    auto fill_return = [&](const StackFrame& frame) {
        if (frame.call_event_idx != SIZE_MAX) {
            result_.call_events[frame.call_event_idx].return_inst_id = ret_inst_id;
            result_.return_site_map_[ret_inst_id] = frame.call_event_idx;
        }
    };

    if (call_stack_.back().return_pc == ret_dest_pc) {
        // Fast path: top of stack matches (most common case).
        auto& top = call_stack_.back();
        fill_return(top);
        auto rc_it = ret_pc_refcount_.find(top.return_pc);
        if (rc_it != ret_pc_refcount_.end()) {
            if (--rc_it->second == 0) ret_pc_refcount_.erase(rc_it);
        }
        call_stack_.pop_back();
    } else {
        // O(1) existence check before linear search.
        auto rc_it = ret_pc_refcount_.find(ret_dest_pc);
        if (rc_it != ret_pc_refcount_.end()) {
            for (int i = static_cast<int>(call_stack_.size()) - 1; i >= 0; --i) {
                if (call_stack_[i].return_pc == ret_dest_pc) {
                    // Non-local unwind: pop all frames above i.
                    for (int j = static_cast<int>(call_stack_.size()) - 1; j > i; --j) {
                        auto& frame = call_stack_[j];
                        fill_return(frame);
                        auto rc2 = ret_pc_refcount_.find(frame.return_pc);
                        if (rc2 != ret_pc_refcount_.end()) {
                            if (--rc2->second == 0) ret_pc_refcount_.erase(rc2);
                        }
                        call_stack_.pop_back();
                        non_local_unwinds_++;
                    }
                    // Pop frame i itself.
                    fill_return(call_stack_[i]);
                    auto rc3 = ret_pc_refcount_.find(call_stack_[i].return_pc);
                    if (rc3 != ret_pc_refcount_.end()) {
                        if (--rc3->second == 0) ret_pc_refcount_.erase(rc3);
                    }
                    call_stack_.erase(call_stack_.begin() + i);
                    break;
                }
            }
        } else {
            // Destination not in stack — fallback: pop top frame.
            auto& top = call_stack_.back();
            fill_return(top);
            auto rc2 = ret_pc_refcount_.find(top.return_pc);
            if (rc2 != ret_pc_refcount_.end()) {
                if (--rc2->second == 0) ret_pc_refcount_.erase(rc2);
            }
            call_stack_.pop_back();
        }
    }
}

void FunctionCollector::handle_branch_event(const BranchEvent& ev) {
    // ── Flush deferred RET ────────────────────────────────────────────────
    // A RET records its successor's PC (= the return destination) only when
    // we see the next event.  ev.pc is that successor PC.
    if (p2_prev_was_ret_) {
        p2_prev_was_ret_ = false;
        handle_deferred_ret(ev.pc, p2_prev_ret_inst_id_);
    }

    // ── Flush deferred unconditional branch ───────────────────────────────
    // A B/BR records its successor PC (= jump target) when the next event fires.
    if (p2_prev_was_branch_) {
        tail_candidates_.push_back({
            p2_prev_jump_inst_id_,
            p2_prev_jump_pc_,
            ev.pc,           // jump target = first PC after the branch
            p2_prev_jump_sp_,
            p2_prev_jump_sp_known_
        });
        p2_prev_was_branch_ = false;
    }

    // ── Dispatch on kind ──────────────────────────────────────────────────
    const bool is_call   = (ev.kind & KIND_CALL)   != 0;
    const bool is_ret    = (ev.kind & KIND_RET)    != 0;
    const bool is_branch = (ev.kind & KIND_BRANCH) != 0;

    if (is_call) {
        // target_pc was resolved in Phase 1 and stored in ev.target_pc.
        const uint64_t tgt = ev.target_pc;

        // ── Cap call_events to avoid unbounded memory on huge traces ─────
        // In default (capped) mode: on a 1.3B-instruction trace call_events
        // can exceed 30M entries (1.5 GB+).  Beyond kMaxCallEvents we still
        // track call_stack_ (needed for correct RET pairing) and function
        // stats (total_calls / total_instructions), but we skip appending to
        // call_events / call_site_map_ / call_event_indices.
        // In full_mode all events are recorded without truncation.
        static constexpr size_t kMaxCallEvents = 20'000'000;  // 20M ≈ 960 MB
        const bool record_event = full_mode_
            ? true
            : (result_.call_events.size() < kMaxCallEvents);

        size_t idx = SIZE_MAX;  // sentinel: not recorded
        if (record_event) {
            CallEvent cevt;
            cevt.call_inst_id   = ev.inst_id;
            cevt.return_inst_id = 0;
            cevt.call_site_pc   = ev.pc;
            cevt.target_pc      = tgt;
            cevt.depth          = call_stack_.size();
            cevt.is_tail_call   = false;

            idx = result_.call_events.size();
            result_.call_site_map_[ev.inst_id] = idx;
            result_.call_events.push_back(cevt);
        }

        const uint64_t ret_pc = ev.pc + 4;
        // Always push a stack frame so RET matching stays correct even when
        // we stopped recording events.  Use SIZE_MAX as a sentinel index.
        call_stack_.push_back({idx, ret_pc, ev.sp_valid ? ev.sp : 0});
        // Use try_emplace to avoid a double hash lookup: insert-or-increment
        // in a single operation instead of operator[] (find + insert) + ++.
        ++ret_pc_refcount_.try_emplace(ret_pc, 0u).first->second;

        // Register the target function immediately (deferred name).
        if (tgt != 0) {
            // try_emplace avoids default-constructing FunctionInfo when the
            // key already exists (saves one redundant zero-init + heap alloc
            // for the name/call_event_indices vectors on every repeated call).
            auto [it, inserted] = result_.functions.try_emplace(tgt);
            auto& func = it->second;
            if (inserted) {
                func.entry_pc = tgt;
                // name is left empty; generated in batch at end()
            }
            func.total_calls++;
            // Only record the index if within the cap.
            if (record_event) {
                func.call_event_indices.push_back(idx);
            }
        }

    } else if (is_ret) {
        p2_prev_was_ret_     = true;
        p2_prev_ret_inst_id_ = ev.inst_id;

    } else if (is_branch) {
        p2_prev_was_branch_    = true;
        p2_prev_jump_inst_id_  = ev.inst_id;
        p2_prev_jump_pc_       = ev.pc;
        p2_prev_jump_sp_       = ev.sp;
        p2_prev_jump_sp_known_ = ev.sp_valid;
    }
}

// ── Phase 2: run the state machine over the compact event stream ─────────

void FunctionCollector::run_state_machine() {
    for (const auto& ev : branch_events_) {
        handle_branch_event(ev);
    }
}

// ── end(): Phase 2 entry point ───────────────────────────────────────────

void FunctionCollector::end() {
    // ── Phase 2 pre-allocation ────────────────────────────────────────────
    // branch_events_ is fully built by now.  Roughly half its entries are
    // CALL events (the others are RET / unconditional BRANCH).  Reserve the
    // output containers up-front so that run_state_machine() never triggers
    // a vector/map reallocation, eliminating the memmove traffic that showed
    // up as the #1 hot spot in sampling (383 memmove samples in 10 s).
    if (!branch_events_.empty()) {
        // In default mode: cap the call_events reserve at kMaxCallEvents so we
        // don't commit gigabytes up front on huge traces before the state machine
        // starts dropping events.  In full_mode the reserve is uncapped.
        static constexpr size_t kMaxCallEventsReserve = 20'000'000;
        const size_t raw_call_est = branch_events_.size() / 2 + 64;
        const size_t call_est = full_mode_
            ? raw_call_est
            : std::min(raw_call_est, kMaxCallEventsReserve);
        result_.call_events.reserve(call_est);
        result_.call_site_map_.reserve(call_est);
        result_.return_site_map_.reserve(call_est);
        // call_stack_ depth is bounded by the call-tree depth; reserve a
        // generous upper bound to avoid any realloc during the scan.
        call_stack_.reserve(std::min(call_est, size_t(4096)));
        // tail_candidates_ mirrors unconditional-branch events.
        tail_candidates_.reserve(branch_events_.size() / 4 + 64);
        // ret_pc_refcount_ tracks unique return-PC values on the live stack.
        ret_pc_refcount_.reserve(std::min(call_est, size_t(4096)));
    }

    // ── Phase 2: state machine over branch_events_ ────────────────────────
    // branch_events_ holds ~2-5% of total instruction count.
    // Report progress through the state machine in ~5% increments.
    if ((progress_fn_ || cancel_fn_) && !branch_events_.empty()) {
        const size_t total = branch_events_.size();
        const size_t report_interval = std::max(total / 20, size_t(1));
        size_t processed = 0;
        for (const auto& ev : branch_events_) {
            if (is_cancelled()) return;
            handle_branch_event(ev);
            ++processed;
            if (progress_fn_ && processed % report_interval == 0) {
                progress_fn_(static_cast<float>(processed) / static_cast<float>(total));
            }
        }
        if (progress_fn_) progress_fn_(1.0f);
    } else {
        run_state_machine();
    }

    // ── Handle trailing deferred RET ─────────────────────────────────────
    if (p2_prev_was_ret_ && !call_stack_.empty()) {
        auto& top = call_stack_.back();
        // Guard against sentinel frames (call_event_idx == SIZE_MAX) that
        // were pushed when the kMaxCallEvents cap was reached.
        if (top.call_event_idx != SIZE_MAX) {
            result_.call_events[top.call_event_idx].return_inst_id = p2_prev_ret_inst_id_;
            result_.return_site_map_[p2_prev_ret_inst_id_] = top.call_event_idx;
        }
        call_stack_.pop_back();
    }

    // ── Tail-call detection (angr's two-stage heuristic) ─────────────────
    // Optimised: build known_entries ONCE from BL/BLR-discovered functions,
    // then update it incrementally when new functions are found via tail calls.
    // The original code rebuilt the set from scratch every iteration.
    constexpr int kMaxIterations = 4;
    const size_t n_cands = tail_candidates_.size();
    std::vector<bool> resolved(n_cands, false);

    ankerl::unordered_dense::set<uint64_t> known_entries;
    known_entries.reserve(result_.functions.size() * 2);
    for (const auto& [entry_pc, _] : result_.functions) {
        known_entries.insert(entry_pc);
    }

    for (int iteration = 0; iteration < kMaxIterations; ++iteration) {
        if (is_cancelled()) return;
        uint64_t new_this_round = 0;

        for (size_t ci = 0; ci < n_cands; ++ci) {
            if (resolved[ci]) continue;
            const auto& cand = tail_candidates_[ci];

            const bool target_is_known_entry = (known_entries.count(cand.target_pc) > 0);

            if (!target_is_known_entry) {
                const int64_t distance = static_cast<int64_t>(cand.target_pc) -
                                         static_cast<int64_t>(cand.jump_pc);
                if (std::abs(distance) < 4096) {
                    resolved[ci] = true;
                    continue;
                }
                if (!cand.sp_known) continue;
            }

            const bool accept = target_is_known_entry || cand.sp_known;
            if (!accept) continue;

            CallEvent evt;
            evt.call_inst_id   = cand.inst_id;
            evt.return_inst_id = 0;
            evt.call_site_pc   = cand.jump_pc;
            evt.target_pc      = cand.target_pc;
            evt.depth          = 0;
            evt.is_tail_call   = true;

            const size_t evt_idx = result_.call_events.size();
            result_.call_site_map_[cand.inst_id] = evt_idx;
            result_.call_events.push_back(evt);

            auto [fit, finserted] = result_.functions.try_emplace(cand.target_pc);
            auto& func = fit->second;
            if (finserted) {
                func.entry_pc = cand.target_pc;
                // name left empty — generated in batch below
                // Incremental update — no full set rebuild needed.
                known_entries.insert(cand.target_pc);
            }
            func.total_calls++;
            func.call_event_indices.push_back(evt_idx);

            tail_calls_detected_++;
            new_this_round++;
            resolved[ci] = true;
        }

        if (new_this_round == 0) break;
    }

    if (is_cancelled()) return;

    // ── Truncate call_event_indices to a bounded size (default mode only) ───
    // On large traces a single hot function can accumulate millions of call
    // event indices (one per invocation).  The UI only ever shows the first
    // ~10 for navigation; keeping millions wastes hundreds of MB of RAM.
    // Cap at kMaxCallEventIndices — well above any UI need but low enough to
    // bound memory: 1000 × 8 bytes × N functions ≪ N × total_calls × 8 bytes.
    // In full_mode the truncation is skipped so every call event remains
    // reachable through call_event_indices for complete per-call navigation.
    if (!full_mode_) {
        static constexpr size_t kMaxCallEventIndices = 1000;
        for (auto& [entry_pc, func] : result_.functions) {
            if (func.call_event_indices.size() > kMaxCallEventIndices) {
                func.call_event_indices.resize(kMaxCallEventIndices);
                func.call_event_indices.shrink_to_fit();
            }
        }
    }

    // ── Generate deferred function names ──────────────────────────────────
    // Batching fmt::format calls here avoids per-call heap allocation in
    // the hot scan path.
    for (auto& [entry_pc, func] : result_.functions) {
        if (func.name.empty()) {
            func.name = fmt::format("sub_{:x}", entry_pc - module_slide_);
        }
    }

    // ── Calculate total_instructions per function ─────────────────────────
    for (auto& [entry_pc, func] : result_.functions) {
        uint64_t total_insts = 0;
        for (auto idx : func.call_event_indices) {
            const auto& cevt = result_.call_events[idx];
            if (cevt.return_inst_id > cevt.call_inst_id) {
                total_insts += cevt.return_inst_id - cevt.call_inst_id;
            }
        }
        func.total_instructions = total_insts;
    }

    // Build depth table for fast O(log N) depth_at() queries.
    result_.build_depth_table();

    // ── Release temporary Phase-1/2 structures ────────────────────────────
    // On large traces (e.g. 1.3B instructions) these can reach several GB:
    //   branch_events_  : ~2-5% of total insts × 48 bytes = up to 3 GB
    //   tail_candidates_: proportional to unconditional branches
    //   call_stack_     : proportional to max call depth × frames in flight
    //   ret_pc_refcount_: proportional to unique return PCs
    // All are Phase-1/2 scratch — neither FunctionResult nor the caller needs
    // them after end() returns.  Swap-with-empty is the only reliable way to
    // free the underlying heap block (clear() leaves capacity intact).
    { std::vector<BranchEvent>       tmp; tmp.swap(branch_events_); }
    { std::vector<TailCallCandidate> tmp; tmp.swap(tail_candidates_); }
    { std::vector<StackFrame>        tmp; tmp.swap(call_stack_); }
    {
        ankerl::unordered_dense::map<uint64_t, uint32_t> tmp;
        tmp.swap(ret_pc_refcount_);
    }
    // pc_kind_sorted_ is also no longer needed after Phase 2.
    { std::vector<PcKindEntry> tmp; tmp.swap(pc_kind_sorted_); }
}

// ─── FunctionPass::declare_scan ──────────────────────────────────────────────

void FunctionPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& code_table = ctx.code_table();
    const auto& hdr  = ctx.reader().header();

    collector_ = std::make_unique<FunctionCollector>(
        code_table, hdr.module_slide, hdr.num_gpr,
        hdr.has_branch_hint(), config_.full_mode);

    // Set progress/cancel callbacks BEFORE registering with orchestrator,
    // so FunctionCollector::end() (Phase 2 state machine) has them available
    // during execute_scan() — which calls end() before run() is invoked.
    // Phase 2 progress: map collector's [0,1] → [kPhase1End, kPhase2End]
    constexpr float kPhase1End = 0.70f;
    constexpr float kPhase2End = 0.85f;
    collector_->set_progress_fn([&ctx, kPhase1End, kPhase2End](float p2_pct) {
        ctx.progress(kPhase1End + p2_pct * (kPhase2End - kPhase1End),
                     "Function analysis: building call graph...");
    });
    collector_->set_cancel_fn([&ctx]() { return ctx.cancelled(); });

    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}

// ─── FunctionPass::run — now delegates to FunctionCollector ───────────────

PassResult FunctionPass::run(PassContext& ctx) {
    auto& index      = ctx.index();
    const auto& range = ctx.range();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("function", blob)) {
            FunctionResult cached;
            if (function_deserialize(blob, cached, config_.full_mode)) {
                cached.build_depth_table();
                // Release the blob string now that we have the deserialized data.
                // On a large trace this blob can be hundreds of MB.
                { std::string tmp; tmp.swap(blob); }
                // Compact all containers so the loaded result is as lean as a
                // freshly-computed one (avoids the 2× over-reservation that
                // vector::reserve() can leave behind).
                cached.call_events.shrink_to_fit();
                cached.depth_table_.shrink_to_fit();
                cached.sorted_call_indices_.shrink_to_fit();
                cached.call_site_map_.rehash(0);
                cached.return_site_map_.rehash(0);
                collector_.reset();  // not needed, free memory
                ctx.progress(1.0f, fmt::format(
                    "Functions: {} unique, {} call events (from cache)",
                    cached.functions.size(), cached.call_events.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    // ── Progress budget allocation (based on profiling) ──────────────────
    // Phase 1 (trace scan):         0% → 70%  (done by ScanOrchestrator)
    // Phase 2 (state machine):     70% → 85%  (driven by collector progress_fn)
    // Post-processing (tail/names): 85% → 90%
    // Serialize + save_blob:        90% → 100%
    constexpr float kPhase1End   = 0.70f;
    constexpr float kPhase2End   = 0.85f;
    constexpr float kPostEnd     = 0.90f;

    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    ctx.progress(kPhase1End, "Function analysis: finalising...");

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    ctx.progress(kPostEnd, "Function analysis: post-processing...");
    auto result = collector_->take_result();

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    // ── Compact result containers to exactly-fit sizes ────────────────────
    // After construction, vectors may hold up to 2× their logical size worth
    // of capacity (from reserve() heuristics + geometric growth).  On a 1.3B-
    // instruction trace, call_events alone can be 600MB+ over-reserved.
    // shrink_to_fit() reclaims the unused half of each allocation.
    result.call_events.shrink_to_fit();
    result.depth_table_.shrink_to_fit();
    result.sorted_call_indices_.shrink_to_fit();
    result.call_site_map_.rehash(0);    // unordered_dense: shrink to min load
    result.return_site_map_.rehash(0);

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        ctx.progress(kPostEnd, "Function analysis: serialising...");
        std::string blob = function_serialize(result);
        if (!blob.empty()) {
            if (ctx.cancelled()) {
                return PassResult::failed("cancelled by user");
            }
            ctx.progress(0.95f, "Function analysis: writing cache...");
            index.save_pass_blob("function", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format(
        "Functions: {} unique, {} call events, {} tail calls, {} non-local unwinds",
        result.functions.size(),
        result.call_events.size(),
        collector_->tail_calls_detected(),
        collector_->non_local_unwinds()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
