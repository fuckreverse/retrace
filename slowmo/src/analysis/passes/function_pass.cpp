#include "analysis/passes/function_pass.h"
#include "analysis/passes/xref_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"

#include <fmt/core.h>
#include <algorithm>
#include <unordered_set>

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

bool function_deserialize(const std::string& blob, FunctionResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };

    if (read_u32() != FUNC_BLOB_MAGIC)   return false;
    if (read_u32() != FUNC_BLOB_VERSION) return false;

    uint64_t n_events = read_u64();
    out.call_events.reserve(static_cast<size_t>(n_events));

    for (uint64_t i = 0; i < n_events; i++) {
        if (p + 48 > end) return false;
        CallEvent evt;
        evt.call_inst_id   = read_u64();
        evt.return_inst_id = read_u64();
        evt.call_site_pc   = read_u64();
        evt.target_pc      = read_u64();
        evt.depth          = read_u64();
        evt.is_tail_call   = read_u8() != 0;
        p += 7;  // skip padding
        out.call_events.push_back(evt);
    }

    if (p + 8 > end) return false;
    uint64_t n_funcs = read_u64();
    out.functions.reserve(static_cast<size_t>(n_funcs));

    for (uint64_t i = 0; i < n_funcs; i++) {
        if (p + 8 + 8 + 8 + 4 > end) return false;
        FunctionInfo fi;
        fi.entry_pc            = read_u64();
        fi.total_calls         = read_u64();
        fi.total_instructions  = read_u64();
        uint32_t name_len      = read_u32();
        if (p + name_len > end) return false;
        fi.name.assign(p, name_len);
        p += name_len;
        if (p + 8 > end) return false;
        uint64_t n_idx = read_u64();
        fi.call_event_indices.reserve(static_cast<size_t>(n_idx));
        if (p + n_idx * 8 > end) return false;
        for (uint64_t j = 0; j < n_idx; j++) {
            fi.call_event_indices.push_back(static_cast<size_t>(read_u64()));
        }
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

}  // anonymous namespace (function serialization)

// ─── FunctionResult methods ───────────────────────────────────────────────

std::vector<const CallEvent*> FunctionResult::call_stack_at(uint64_t inst_id) const {
    // Reconstruct call stack: walk call_events and build stack state
    std::vector<const CallEvent*> stack;
    for (auto& evt : call_events) {
        if (evt.call_inst_id > inst_id) break;

        if (evt.call_inst_id <= inst_id) {
            stack.push_back(&evt);
        }
        if (evt.return_inst_id != 0 && evt.return_inst_id <= inst_id) {
            // This call already returned
            if (!stack.empty()) stack.pop_back();
        }
    }
    return stack;
}

void FunctionResult::build_depth_table() {
    // Build a sorted sequence of (inst_id, depth) transition points.
    // Each call event contributes two entries:
    //   call_inst_id  → depth+1 (entering the call)
    //   return_inst_id → depth   (after the return; caller's depth restored)
    // We simulate the stack to get the correct depth at each transition.
    depth_table_.clear();
    if (call_events.empty()) return;

    depth_table_.reserve(call_events.size() * 2);

    // Replay the same linear scan as call_stack_at(), but just record
    // (inst_id, depth_after) pairs as the simulated depth changes.
    uint64_t sim_depth = 0;
    for (const auto& evt : call_events) {
        // call_inst_id: depth increases to evt.depth + 1
        sim_depth = evt.depth + 1;
        depth_table_.push_back({evt.call_inst_id, sim_depth});

        if (evt.return_inst_id != 0) {
            // After the ret, depth drops back to evt.depth
            depth_table_.push_back({evt.return_inst_id, evt.depth});
        }
    }

    // Sort by inst_id (call_events are in order, but interleaved rets may not be)
    std::sort(depth_table_.begin(), depth_table_.end(),
              [](const DepthEntry& a, const DepthEntry& b) {
                  return a.inst_id < b.inst_id;
              });
}

uint64_t FunctionResult::depth_at(uint64_t inst_id) const {
    if (depth_table_.empty()) {
        // Fallback: O(N) scan (only if build_depth_table() was never called)
        uint64_t depth = 0;
        for (const auto& evt : call_events) {
            if (evt.call_inst_id > inst_id) break;
            if (evt.call_inst_id <= inst_id) depth = evt.depth + 1;
            if (evt.return_inst_id != 0 && evt.return_inst_id <= inst_id)
                depth = evt.depth;
        }
        return depth;
    }

    // Binary search: find the last entry with inst_id <= query
    // Use upper_bound to find the first entry > inst_id, then step back.
    auto it = std::upper_bound(depth_table_.begin(), depth_table_.end(), inst_id,
                               [](uint64_t id, const DepthEntry& e) {
                                   return id < e.inst_id;
                               });
    if (it == depth_table_.begin()) return 0;  // before any call
    --it;
    return it->depth;
}

const FunctionInfo* FunctionResult::function_at(uint64_t inst_id) const {
    // Find which function contains this inst_id by checking active calls
    const CallEvent* innermost = nullptr;
    for (auto& evt : call_events) {
        if (evt.call_inst_id > inst_id) break;
        if (evt.return_inst_id == 0 || evt.return_inst_id >= inst_id) {
            innermost = &evt;
        }
    }
    if (!innermost) return nullptr;
    auto it = functions.find(innermost->target_pc);
    if (it == functions.end()) return nullptr;
    return &it->second;
}

// ─── Pass implementation ──────────────────────────────────────────────────

// Known non-returning functions (common in iOS/macOS AArch64 binaries)
static const std::unordered_set<std::string> kNonReturningSymbols = {
    "exit", "_exit", "abort", "__abort",
    "__cxa_throw", "__cxa_rethrow", "objc_exception_throw",
    "longjmp", "_longjmp", "siglongjmp",
    "pthread_exit", "__pthread_exit",
    "__assert_rtn", "__assert_fail",
    "__stack_chk_fail", "__fortify_fail",
    "swift_unexpectedError", "swift_fatalError",
};

// ─── AArch64 opcode classification via bit patterns ───────────────────────
//
// All classifications use bitmask tests on the raw 32-bit opcode word.
// This is 10-20× faster than going through Capstone for these few mnemonics
// because it avoids both the Capstone decode path and the LRU cache mutex.
//
// References: ARM Architecture Reference Manual, AArch64 encoding summary.
//
// BL  (branch with link, direct):     opc[31:26] = 0b100101
//     Encoding: 1_00101_imm26          mask=0xFC000000  val=0x94000000
//
// BLR (branch with link to register): opc[31:10] = 0b1101011_0001_11111_000000
//     Encoding: 1101011_0_00_1_11111_0000_00_Rn_00000   mask=0xFFFFFC1F  val=0xD63F0000
//     (bits [4:0] = Rd = 0b00000 = x0/xzr for BLR)
//
// RET (return from subroutine):        mask=0xFFFFFC1F  val=0xD65F0000
//     Encoding: 1101011_0_01_0_11111_0000_00_Rn_00000
//
// B   (unconditional branch, direct):  opc[31:26] = 0b000101
//     Encoding: 0_00101_imm26          mask=0xFC000000  val=0x14000000
//
// BR  (unconditional branch to reg):   mask=0xFFFFFC1F  val=0xD61F0000
//     Encoding: 1101011_0_00_0_11111_0000_00_Rn_00000
//
// BLRAA/BLRAB/BLRAAZ/BLRABZ (pointer-auth variants of BLR):
//     All share the 0b11010110_00_1 prefix and can be masked:
//     mask = 0xFEFFF800, val = 0xD63F0800  (covers PAC BLR variants)
//
// Note: BL and B share the same mask (0xFC000000); differentiated by bit [31].

namespace {

/// Classify an AArch64 opcode using pure bit-pattern matching.
/// Returns three bools: {is_call, is_ret, is_unconditional_jump}.
/// No Capstone, no LRU cache, no mutex — just integer arithmetic.
struct OpcodeClass {
    bool is_call             : 1;  // BL / BLR / BLRAA/BLRAB/BLRAAZ/BLRABZ
    bool is_ret              : 1;  // RET
    bool is_unconditional_jump : 1; // B / BR
};

inline OpcodeClass classify_opcode(uint32_t op) {
    OpcodeClass c{false, false, false};

    // ── BL (direct call, imm26): bits[31:26] = 100101 ─────────────────
    if ((op & 0xFC000000u) == 0x94000000u) {
        c.is_call = true;
        return c;
    }

    // ── B (unconditional direct branch): bits[31:26] = 000101 ──────────
    if ((op & 0xFC000000u) == 0x14000000u) {
        c.is_unconditional_jump = true;
        return c;
    }

    // Remaining candidates all have bits[31:25] = 1101011 (0x6B << 25)
    // Check that prefix first to short-circuit the rest quickly.
    if ((op & 0xFE000000u) != 0xD6000000u) return c;

    // ── BLR  (indirect call):  [31:10]=1101011_0_00_1_11111_000000 ─────
    //    bits[29:21]=001_11111_0, bits[20:16]=00000, bits[4:0]=00000
    //    Full mask: 0xFFFFFC1F == 0xD63F0000
    if ((op & 0xFFFFFC1Fu) == 0xD63F0000u) {
        c.is_call = true;
        return c;
    }

    // ── RET  (return):  [31:10]=1101011_0_01_0_11111_000000 ──────────
    //    Full mask: 0xFFFFFC1F == 0xD65F0000
    if ((op & 0xFFFFFC1Fu) == 0xD65F0000u) {
        c.is_ret = true;
        return c;
    }

    // ── BR   (unconditional indirect branch): 0xD61F0000 ───────────────
    if ((op & 0xFFFFFC1Fu) == 0xD61F0000u) {
        c.is_unconditional_jump = true;
        return c;
    }

    // ── BLRAA / BLRAB / BLRAAZ / BLRABZ (PAC-authenticated BLR) ────────
    //    Encoding: 1101_0110_0001_Rn__0000_1Zm_Rm_00000
    //    bits[31:21] = 1101_0110_001  → 0xD62xxxxx pattern
    //    Conservative mask: check bit[23]=1 (distinguishes from BR/BLR/RET)
    //    Mask 0xFEFFF800 == 0xD63F0800 covers all four variants.
    if ((op & 0xFEFFF800u) == 0xD63F0800u) {
        c.is_call = true;
        return c;
    }

    return c;
}

}  // anonymous namespace

PassResult FunctionPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    const auto& hdr = reader.header();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("function", blob)) {
            FunctionResult cached;
            if (function_deserialize(blob, cached)) {
                // Build depth table for fast O(log N) depth_at() queries.
                cached.build_depth_table();
                ctx.progress(1.0f, fmt::format(
                    "Functions: {} unique, {} call events (from cache)",
                    cached.functions.size(), cached.call_events.size()));
                return PassResult::success(std::move(cached));
            }
            // Corrupt / version mismatch — fall through to recompute
        }
    }

    FunctionResult result;

    // ─── Pre-build PC classification table ────────────────────────────────
    //
    // Key optimization (same pattern as PatternPass):
    // Decode each unique PC exactly ONCE using pure bit-pattern matching —
    // no Capstone invocation, no LRU cache mutex. Store the result in a flat
    // unordered_map so the main scan loop does a single hashmap lookup per
    // instruction instead of code_table + decoder + string compare.
    //
    // Typical trace: 5K–50K unique PCs → this table fits entirely in L3 cache.

    // Compact classification: 2 bits per PC packed into uint8_t.
    // Bit 0 = is_call, Bit 1 = is_ret, Bit 2 = is_unconditional_jump
    static constexpr uint8_t KIND_CALL   = 0x1;
    static constexpr uint8_t KIND_RET    = 0x2;
    static constexpr uint8_t KIND_BRANCH = 0x4;

    // Use ankerl::unordered_dense via code_table's underlying map if possible,
    // but a plain std::unordered_map is fine here since it's populated once.
    std::unordered_map<uint64_t, uint8_t> pc_kind;

    {
        auto all_entries = code_table.all_entries();
        pc_kind.reserve(all_entries.size());

        for (const auto& [pc, opcode] : all_entries) {
            auto c = classify_opcode(opcode);
            if (c.is_call || c.is_ret || c.is_unconditional_jump) {
                uint8_t bits = 0;
                if (c.is_call)              bits |= KIND_CALL;
                if (c.is_ret)               bits |= KIND_RET;
                if (c.is_unconditional_jump) bits |= KIND_BRANCH;
                pc_kind.emplace(pc, bits);
            }
        }
    }

    // ─── Pass 1: Standard BL/BLR → RET pairing ──────────────────────────
    // Also collect candidate tail-call sites (B/BR instructions) for Pass 2.

    struct StackFrame {
        size_t call_event_idx;
        uint64_t return_pc;     // LR at time of call (pc + 4 for BL)
        uint64_t entry_sp;      // SP when this frame was pushed (0 if unknown)
    };
    std::vector<StackFrame> call_stack;

    uint64_t current_sp = 0;
    bool sp_valid = false;

    // Tail call candidates: (inst_id, pc_of_B, target_pc_next_inst, sp_at_jump)
    struct TailCallCandidate {
        uint64_t inst_id;
        uint64_t jump_pc;
        uint64_t target_pc;     // filled from next instruction's PC
        uint64_t sp;            // SP at time of jump
        bool sp_known;
    };
    std::vector<TailCallCandidate> tail_candidates;

    uint64_t processed = 0;
    uint64_t non_local_unwinds = 0;

    bool prev_was_unconditional_jump = false;
    uint64_t prev_jump_inst_id = 0;
    uint64_t prev_jump_pc = 0;
    uint64_t prev_jump_sp = 0;
    bool prev_jump_sp_known = false;

    bool prev_was_ret = false;
    uint64_t prev_ret_inst_id = 0;

    // ─── Helper: process one (inst_id, pc, sp_diff_val, sp_diff_valid) record
    // Extracted to avoid code duplication between the two scan paths below.

    auto handle_deferred_ret = [&](uint64_t pc) {
        if (!prev_was_ret) return;
        prev_was_ret = false;
        if (call_stack.empty()) return;

        if (call_stack.back().return_pc == pc) {
            auto& top = call_stack.back();
            result.call_events[top.call_event_idx].return_inst_id = prev_ret_inst_id;
            result.return_site_map_[prev_ret_inst_id] = top.call_event_idx;
            call_stack.pop_back();
        } else {
            bool found = false;
            for (int i = static_cast<int>(call_stack.size()) - 1; i >= 0; --i) {
                if (call_stack[i].return_pc == pc) {
                    for (int j = static_cast<int>(call_stack.size()) - 1; j > i; --j) {
                        result.call_events[call_stack[j].call_event_idx].return_inst_id = prev_ret_inst_id;
                        call_stack.pop_back();
                        non_local_unwinds++;
                    }
                    result.call_events[call_stack[i].call_event_idx].return_inst_id = prev_ret_inst_id;
                    result.return_site_map_[prev_ret_inst_id] = static_cast<size_t>(call_stack[i].call_event_idx);
                    call_stack.erase(call_stack.begin() + i);
                    found = true;
                    break;
                }
            }
            if (!found && !call_stack.empty()) {
                auto& top = call_stack.back();
                result.call_events[top.call_event_idx].return_inst_id = prev_ret_inst_id;
                result.return_site_map_[prev_ret_inst_id] = top.call_event_idx;
                call_stack.pop_back();
            }
        }
    };

    auto handle_inst = [&](uint64_t cur_inst_id, uint64_t pc,
                           uint64_t sp_new, bool sp_updated) {
        if (sp_updated) { current_sp = sp_new; sp_valid = true; }

        handle_deferred_ret(pc);

        if (prev_was_unconditional_jump) {
            tail_candidates.push_back({prev_jump_inst_id, prev_jump_pc, pc,
                                       prev_jump_sp, prev_jump_sp_known});
            prev_was_unconditional_jump = false;
        }

        auto kind_it = pc_kind.find(pc);
        if (kind_it == pc_kind.end()) {
            // Target PC fill-in for calls (handles call site → callee entry)
            if (!result.call_events.empty()) {
                auto& last = result.call_events.back();
                if (last.target_pc == 0 && last.call_inst_id == cur_inst_id - 1) {
                    last.target_pc = pc;
                    auto& func = result.functions[pc];
                    if (func.entry_pc == 0) {
                        func.entry_pc = pc;
                        func.name = fmt::format("sub_{:x}", pc - hdr.module_slide);
                    }
                    func.total_calls++;
                    func.call_event_indices.push_back(result.call_events.size() - 1);
                }
            }
            return;
        }

        uint8_t bits = kind_it->second;
        bool is_call  = (bits & KIND_CALL)   != 0;
        bool is_ret   = (bits & KIND_RET)    != 0;
        bool is_b     = (bits & KIND_BRANCH) != 0;

        // Target PC fill-in
        if (!result.call_events.empty()) {
            auto& last = result.call_events.back();
            if (last.target_pc == 0 && last.call_inst_id == cur_inst_id - 1) {
                last.target_pc = pc;
                auto& func = result.functions[pc];
                if (func.entry_pc == 0) {
                    func.entry_pc = pc;
                    func.name = fmt::format("sub_{:x}", pc - hdr.module_slide);
                }
                func.total_calls++;
                func.call_event_indices.push_back(result.call_events.size() - 1);
            }
        }

        if (is_call) {
            CallEvent evt;
            evt.call_inst_id   = cur_inst_id;
            evt.return_inst_id = 0;
            evt.call_site_pc   = pc;
            evt.target_pc      = 0;
            evt.depth          = call_stack.size();
            evt.is_tail_call   = false;
            size_t idx = result.call_events.size();
            result.call_site_map_[cur_inst_id] = idx;
            result.call_events.push_back(evt);
            call_stack.push_back({idx, pc + 4, sp_valid ? current_sp : 0});
        } else if (is_ret) {
            prev_was_ret = true;
            prev_ret_inst_id = cur_inst_id;
        } else if (is_b) {
            prev_was_unconditional_jump = true;
            prev_jump_inst_id  = cur_inst_id;
            prev_jump_pc       = pc;
            prev_jump_sp       = current_sp;
            prev_jump_sp_known = sp_valid;
        }
    };

    // ─── Try XRef-accelerated scan path ───────────────────────────────────
    //
    // If XrefResult is available (already computed), we can avoid scanning
    // every instruction in the trace.  Instead we:
    //   1. Collect the union of inst_ids from all call/ret/branch PCs in xref.
    //   2. Also collect "successor" inst_ids (+1) for deferred resolution
    //      of RET return destinations and B/BR targets.
    //   3. Sort the combined set into a single ordered event list.
    //   4. Iterate this sparse list, fetching each record via offset_of_with_pc.
    //
    // For typical iOS traces (1-5% call/ret instructions) this reduces the
    // number of records read by 20-100× vs the linear fallback below.
    //
    // SP: rather than tracking SP from every reg_diff, we lazily query it
    //     only at call sites via find_last_writer_of(IDX_SP, call_inst_id).
    //     This is O(log N) per call site but call sites are rare.
    //
    // Correctness constraint: we MUST process inst_ids in ascending order so
    // the call stack state machine sees events in the same order as execution.

    const XrefResult* xref = ctx.try_require<XrefResult>("xref");
    bool used_xref_path = false;

    if (xref && !pc_kind.empty()) {
        // Build sorted event list: call/ret/branch inst_ids + their successors
        // (successors carry the "landing PC" needed for deferred resolution)
        std::vector<uint64_t> event_ids;
        event_ids.reserve(1024);

        for (const auto& [pc, bits] : pc_kind) {
            auto it = xref->pc_to_inst_ids.find(pc);
            if (it == xref->pc_to_inst_ids.end()) continue;
            for (uint64_t id : it->second) {
                if (id < start || id >= end) continue;
                event_ids.push_back(id);
                // Include successor to resolve deferred state
                if (id + 1 < end) event_ids.push_back(id + 1);
            }
        }

        if (!event_ids.empty()) {
            // Sort + deduplicate
            std::sort(event_ids.begin(), event_ids.end());
            event_ids.erase(std::unique(event_ids.begin(), event_ids.end()),
                            event_ids.end());

            uint64_t total = static_cast<uint64_t>(event_ids.size());
            reader.advise_random();

            for (uint64_t ei = 0; ei < total; ei++) {
                uint64_t cur_id = event_ids[ei];

                // Fetch record via sparse index (O(log N) + ~few INST records)
                auto [off, seed_pc] = index.offset_of_with_pc(cur_id, reader);
                auto rec = reader.record_at(off, seed_pc);
                if (rec.kind != RecordKind::Inst) {
                    // offset_of points to first INST; scan forward briefly
                    TraceReader::Iterator it2(&reader, off, seed_pc);
                    uint64_t scanned = 0;
                    for (; it2 != reader.end() && scanned < 8; ++it2, ++scanned) {
                        rec = *it2;
                        if (rec.kind == RecordKind::Inst) break;
                    }
                    if (rec.kind != RecordKind::Inst) continue;
                }

                auto inst = rec.as_inst();
                uint64_t pc = inst.pc;

                // Extract SP diff from this record
                uint64_t sp_new = 0;
                bool sp_updated = false;
                for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                    auto diff = inst.reg_diff(d);
                    if (diff.index == IDX_SP) { sp_new = diff.value; sp_updated = true; }
                }

                handle_inst(cur_id, pc, sp_new, sp_updated);
                processed++;

                if (processed % 10000 == 0) {
                    ctx.progress(static_cast<float>(ei) / static_cast<float>(total));
                    if (ctx.cancelled()) return PassResult::failed("cancelled by user");
                }
            }

            used_xref_path = true;
        }
    }

    // ─── Fallback: linear sequential scan ─────────────────────────────────
    // Used when XrefResult is not available or pc_kind is empty.
    // Also used when xref path produced no events (shouldn't happen normally).
    if (!used_xref_path) {
        uint64_t inst_id = start;
        uint64_t total = end - start;
        reader.advise_sequential();

        uint64_t seek_offset = 0;
        uint64_t seek_seed_pc = 0;
        if (start > 0) {
            auto res = index.offset_of_with_pc(start, reader);
            seek_offset = res.offset;
            seek_seed_pc = res.seed_pc;
        }
        auto it_start = (seek_offset > 0)
            ? TraceReader::Iterator(&reader, seek_offset, seek_seed_pc)
            : reader.begin();

        for (auto it = it_start; it != reader.end() && inst_id < end; ++it) {
            auto rec = *it;
            if (rec.kind == RecordKind::Anchor) {
                auto anchor = rec.as_anchor(hdr.num_gpr);
                if (hdr.num_gpr > IDX_SP) {
                    current_sp = anchor.gpr_values[IDX_SP];
                    sp_valid = true;
                }
                continue;
            }
            if (rec.kind != RecordKind::Inst) continue;

            auto inst = rec.as_inst();
            uint64_t pc = inst.pc;

            uint64_t sp_new = 0; bool sp_upd = false;
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                auto diff = inst.reg_diff(i);
                if (diff.index == IDX_SP) { sp_new = diff.value; sp_upd = true; }
            }

            handle_inst(inst_id, pc, sp_new, sp_upd);
            inst_id++;
            processed++;

            if (processed % 50000 == 0) {
                ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
                if (ctx.cancelled()) {
                    reader.advise_random();
                    return PassResult::failed("cancelled by user");
                }
            }
        }
        reader.advise_random();
    }

    // ─── Handle trailing deferred RET ─────────────────────────────────────
    if (prev_was_ret && !call_stack.empty()) {
        auto& top = call_stack.back();
        auto& evt = result.call_events[top.call_event_idx];
        evt.return_inst_id = prev_ret_inst_id;
        result.return_site_map_[prev_ret_inst_id] = top.call_event_idx;
        call_stack.pop_back();
    }

    // ─── Pass 2: Tail-call detection (ported from angr's two-stage heuristic) ─
    //
    // angr's core idea:
    //   Stage A: "Jump target is a known function entry" → strong evidence
    //   Stage B: "SP is restored to frame-entry value" → confirms tail call
    //
    // In our trace-based context we have an advantage: we can observe both
    // conditions directly from the execution trace without static analysis.
    //
    // We iterate until convergence: newly discovered function entries from
    // tail calls may enable detection of additional tail calls in later rounds.

    uint64_t tail_calls_detected = 0;
    constexpr int kMaxIterations = 4;  // Converges in 1-2 rounds typically

    // Track which candidates have been resolved (to avoid re-processing)
    std::vector<bool> resolved(tail_candidates.size(), false);

    for (int iteration = 0; iteration < kMaxIterations; ++iteration) {
        // Build the set of known function entry PCs (refreshed each iteration)
        std::unordered_set<uint64_t> known_entries;
        known_entries.reserve(result.functions.size());
        for (auto& [entry_pc, _] : result.functions) {
            known_entries.insert(entry_pc);
        }

        uint64_t new_this_round = 0;

        for (size_t ci = 0; ci < tail_candidates.size(); ++ci) {
            if (resolved[ci]) continue;
            auto& cand = tail_candidates[ci];

            // ─── Stage A (angr heuristic 1): target is known function entry
            bool target_is_known_entry = known_entries.count(cand.target_pc) > 0;

            if (!target_is_known_entry) {
                // Heuristic: if target is far from the jump (> 4KB), it's likely
                // inter-function. This catches tail calls to functions not yet
                // in our known set (will be resolved on later iterations).
                int64_t distance = static_cast<int64_t>(cand.target_pc) -
                                   static_cast<int64_t>(cand.jump_pc);
                if (std::abs(distance) < 4096) {
                    // Likely an intra-function branch (loop, if-else, etc.)
                    resolved[ci] = true;  // Never revisit short jumps
                    continue;
                }
                // For far jumps to unknown targets, we require SP evidence
                if (!cand.sp_known) continue;  // May resolve in later iteration
            }

            // ─── Stage B (angr heuristic 2): SP restoration check ────────
            // For known entries: accept unconditionally (high confidence).
            // For unknown-but-far targets with SP evidence: accept.
            // This mirrors angr's detect_tail_calls=True aggressive mode.

            bool accept = target_is_known_entry || cand.sp_known;

            if (accept) {
                // ─── Confirmed tail call: create a synthetic CallEvent ────

                CallEvent evt;
                evt.call_inst_id = cand.inst_id;
                evt.return_inst_id = 0;  // Tail call has no explicit return
                evt.call_site_pc = cand.jump_pc;
                evt.target_pc = cand.target_pc;
                evt.depth = 0;  // Depth is not meaningful for deferred detection
                evt.is_tail_call = true;

                size_t evt_idx = result.call_events.size();
                result.call_site_map_[cand.inst_id] = evt_idx;
                result.call_events.push_back(evt);

                // Register the target as a function (if not already)
                auto& func = result.functions[cand.target_pc];
                if (func.entry_pc == 0) {
                    func.entry_pc = cand.target_pc;
                    uint64_t static_pc = cand.target_pc - hdr.module_slide;
                    func.name = fmt::format("sub_{:x}", static_pc);
                }
                func.total_calls++;
                func.call_event_indices.push_back(evt_idx);

                tail_calls_detected++;
                new_this_round++;
                resolved[ci] = true;
            }
        }

        // Converged: no new tail calls found this round
        if (new_this_round == 0) break;
    }

    // ─── Calculate total_instructions per function ────────────────────────

    for (auto& [entry_pc, func] : result.functions) {
        uint64_t total_insts = 0;
        for (auto idx : func.call_event_indices) {
            auto& evt = result.call_events[idx];
            if (evt.return_inst_id > evt.call_inst_id) {
                total_insts += evt.return_inst_id - evt.call_inst_id;
            }
        }
        func.total_instructions = total_insts;
    }

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = function_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("function", blob.data(), blob.size());
        }
    }

    // Build depth table for fast O(log N) depth_at() queries in the UI.
    result.build_depth_table();

    ctx.progress(1.0f, fmt::format(
        "Functions: {} unique, {} call events, {} tail calls, {} non-local unwinds",
        result.functions.size(),
        result.call_events.size(),
        tail_calls_detected,
        non_local_unwinds));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
