#include "analysis/passes/function_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"

#include <ankerl/unordered_dense.h>
#include <fmt/core.h>
#include <algorithm>
#include <numeric>
#include <string_view>

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

FunctionCollector::FunctionCollector(CodeTable& code_table,
                                     uint64_t module_slide,
                                     uint32_t num_gpr)
    : code_table_(code_table)
    , module_slide_(module_slide)
    , num_gpr_(num_gpr)
{}

bool FunctionCollector::begin(uint64_t /*start_inst_id*/, uint64_t /*end_inst_id*/) {
    // Reset all state
    result_ = FunctionResult{};
    call_stack_.clear();
    tail_candidates_.clear();
    ret_pc_refcount_.clear();
    current_sp_ = 0;
    sp_valid_ = false;
    prev_was_unconditional_jump_ = false;
    prev_jump_inst_id_ = 0;
    prev_jump_pc_ = 0;
    prev_jump_sp_ = 0;
    prev_jump_sp_known_ = false;
    prev_was_ret_ = false;
    prev_ret_inst_id_ = 0;
    need_next_ = false;
    non_local_unwinds_ = 0;
    tail_calls_detected_ = 0;

    // ── Pre-build PC classification table from code_table ──
    pc_kind_.clear();
    auto all_entries = code_table_.all_entries();
    pc_kind_.reserve(all_entries.size());

    for (const auto& [pc, opcode] : all_entries) {
        auto c = classify_opcode(opcode);
        if (c.is_call || c.is_ret || c.is_unconditional_jump) {
            uint8_t bits = 0;
            if (c.is_call)              bits |= KIND_CALL;
            if (c.is_ret)               bits |= KIND_RET;
            if (c.is_unconditional_jump) bits |= KIND_BRANCH;
            pc_kind_.emplace(pc, bits);
        }
    }

    return true;
}

void FunctionCollector::handle_deferred_ret(uint64_t pc) {
    if (!prev_was_ret_) return;
    prev_was_ret_ = false;
    if (call_stack_.empty()) return;

    if (call_stack_.back().return_pc == pc) {
        // Fast path: top of stack matches (most common case).
        auto& top = call_stack_.back();
        result_.call_events[top.call_event_idx].return_inst_id = prev_ret_inst_id_;
        result_.return_site_map_[prev_ret_inst_id_] = top.call_event_idx;
        // Decrement refcount for this return_pc before popping.
        auto rc_it = ret_pc_refcount_.find(top.return_pc);
        if (rc_it != ret_pc_refcount_.end()) {
            if (--rc_it->second == 0) ret_pc_refcount_.erase(rc_it);
        }
        call_stack_.pop_back();
    } else {
        // O(1) check: is this return_pc anywhere in the stack?
        auto rc_it = ret_pc_refcount_.find(pc);
        if (rc_it != ret_pc_refcount_.end()) {
            // Found — linear search from top to locate exact position.
            for (int i = static_cast<int>(call_stack_.size()) - 1; i >= 0; --i) {
                if (call_stack_[i].return_pc == pc) {
                    // Non-local unwind: pop all frames above i.
                    for (int j = static_cast<int>(call_stack_.size()) - 1; j > i; --j) {
                        auto& frame = call_stack_[j];
                        result_.call_events[frame.call_event_idx].return_inst_id = prev_ret_inst_id_;
                        // Decrement refcount for popped frame.
                        auto rc2 = ret_pc_refcount_.find(frame.return_pc);
                        if (rc2 != ret_pc_refcount_.end()) {
                            if (--rc2->second == 0) ret_pc_refcount_.erase(rc2);
                        }
                        call_stack_.pop_back();
                        non_local_unwinds_++;
                    }
                    // Now pop frame i itself.
                    result_.call_events[call_stack_[i].call_event_idx].return_inst_id = prev_ret_inst_id_;
                    result_.return_site_map_[prev_ret_inst_id_] = static_cast<size_t>(call_stack_[i].call_event_idx);
                    // Decrement refcount for this frame.
                    auto rc3 = ret_pc_refcount_.find(call_stack_[i].return_pc);
                    if (rc3 != ret_pc_refcount_.end()) {
                        if (--rc3->second == 0) ret_pc_refcount_.erase(rc3);
                    }
                    call_stack_.erase(call_stack_.begin() + i);
                    break;
                }
            }
        } else {
            // return_pc not in stack at all — fallback: pop top frame.
            auto& top = call_stack_.back();
            result_.call_events[top.call_event_idx].return_inst_id = prev_ret_inst_id_;
            result_.return_site_map_[prev_ret_inst_id_] = top.call_event_idx;
            // Decrement refcount for popped frame.
            auto rc2 = ret_pc_refcount_.find(top.return_pc);
            if (rc2 != ret_pc_refcount_.end()) {
                if (--rc2->second == 0) ret_pc_refcount_.erase(rc2);
            }
            call_stack_.pop_back();
        }
    }
}

void FunctionCollector::try_fill_call_target(uint64_t cur_inst_id, uint64_t pc) {
    if (result_.call_events.empty()) return;
    auto& last = result_.call_events.back();
    if (last.target_pc == 0 && last.call_inst_id == cur_inst_id - 1) {
        last.target_pc = pc;
        auto& func = result_.functions[pc];
        if (func.entry_pc == 0) {
            func.entry_pc = pc;
            func.name = fmt::format("sub_{:x}", pc - module_slide_);
        }
        func.total_calls++;
        func.call_event_indices.push_back(result_.call_events.size() - 1);
    }
}

void FunctionCollector::handle_inst_inner(uint64_t cur_inst_id, uint64_t pc,
                                           uint64_t sp_new, bool sp_updated) {
    if (sp_updated) { current_sp_ = sp_new; sp_valid_ = true; }

    handle_deferred_ret(pc);

    if (prev_was_unconditional_jump_) {
        tail_candidates_.push_back({prev_jump_inst_id_, prev_jump_pc_, pc,
                                    prev_jump_sp_, prev_jump_sp_known_});
        prev_was_unconditional_jump_ = false;
    }

    try_fill_call_target(cur_inst_id, pc);

    auto kind_it = pc_kind_.find(pc);
    if (kind_it == pc_kind_.end()) return;

    uint8_t bits = kind_it->second;
    bool is_call  = (bits & KIND_CALL)   != 0;
    bool is_ret   = (bits & KIND_RET)    != 0;
    bool is_b     = (bits & KIND_BRANCH) != 0;

    if (is_call) {
        CallEvent evt;
        evt.call_inst_id   = cur_inst_id;
        evt.return_inst_id = 0;
        evt.call_site_pc   = pc;
        evt.target_pc      = 0;
        evt.depth          = call_stack_.size();
        evt.is_tail_call   = false;
        size_t idx = result_.call_events.size();
        result_.call_site_map_[cur_inst_id] = idx;
        result_.call_events.push_back(evt);
        uint64_t ret_pc = pc + 4;
        call_stack_.push_back({idx, ret_pc, sp_valid_ ? current_sp_ : 0});
        ret_pc_refcount_[ret_pc]++;
    } else if (is_ret) {
        prev_was_ret_ = true;
        prev_ret_inst_id_ = cur_inst_id;
    } else if (is_b) {
        prev_was_unconditional_jump_ = true;
        prev_jump_inst_id_  = cur_inst_id;
        prev_jump_pc_       = pc;
        prev_jump_sp_       = current_sp_;
        prev_jump_sp_known_ = sp_valid_;
    }
}

void FunctionCollector::on_anchor(uint64_t /*inst_id*/, const AnchorView& anchor) {
    if (num_gpr_ > IDX_SP) {
        current_sp_ = anchor.gpr_values[IDX_SP];
        sp_valid_ = true;
    }
}

void FunctionCollector::on_inst(uint64_t inst_id, const InstView& inst) {
    uint64_t pc = inst.pc;

    // Check if this instruction is relevant:
    // 1. It's a call/ret/branch (in pc_kind_), OR
    // 2. It immediately follows one (need_next_ flag).
    bool is_interesting = (pc_kind_.find(pc) != pc_kind_.end());
    if (is_interesting || need_next_) {
        // Extract SP from register diffs
        uint64_t sp_new = 0;
        bool sp_updated = false;
        for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
            auto diff = inst.reg_diff(d);
            if (diff.index == IDX_SP) {
                sp_new = diff.value;
                sp_updated = true;
                break;
            }
        }

        handle_inst_inner(inst_id, pc, sp_new, sp_updated);
        need_next_ = is_interesting;
    } else {
        need_next_ = false;
    }
}

void FunctionCollector::end() {
    // ── Handle trailing deferred RET ──
    if (prev_was_ret_ && !call_stack_.empty()) {
        auto& top = call_stack_.back();
        auto& evt = result_.call_events[top.call_event_idx];
        evt.return_inst_id = prev_ret_inst_id_;
        result_.return_site_map_[prev_ret_inst_id_] = top.call_event_idx;
        call_stack_.pop_back();
    }

    // ── Pass 2: Tail-call detection (angr's two-stage heuristic) ──
    constexpr int kMaxIterations = 4;
    std::vector<bool> resolved(tail_candidates_.size(), false);

    for (int iteration = 0; iteration < kMaxIterations; ++iteration) {
        ankerl::unordered_dense::set<uint64_t> known_entries;
        known_entries.reserve(result_.functions.size());
        for (auto& [entry_pc, _] : result_.functions) {
            known_entries.insert(entry_pc);
        }

        uint64_t new_this_round = 0;

        for (size_t ci = 0; ci < tail_candidates_.size(); ++ci) {
            if (resolved[ci]) continue;
            auto& cand = tail_candidates_[ci];

            bool target_is_known_entry = known_entries.count(cand.target_pc) > 0;

            if (!target_is_known_entry) {
                int64_t distance = static_cast<int64_t>(cand.target_pc) -
                                   static_cast<int64_t>(cand.jump_pc);
                if (std::abs(distance) < 4096) {
                    resolved[ci] = true;
                    continue;
                }
                if (!cand.sp_known) continue;
            }

            bool accept = target_is_known_entry || cand.sp_known;

            if (accept) {
                CallEvent evt;
                evt.call_inst_id = cand.inst_id;
                evt.return_inst_id = 0;
                evt.call_site_pc = cand.jump_pc;
                evt.target_pc = cand.target_pc;
                evt.depth = 0;
                evt.is_tail_call = true;

                size_t evt_idx = result_.call_events.size();
                result_.call_site_map_[cand.inst_id] = evt_idx;
                result_.call_events.push_back(evt);

                auto& func = result_.functions[cand.target_pc];
                if (func.entry_pc == 0) {
                    func.entry_pc = cand.target_pc;
                    uint64_t static_pc = cand.target_pc - module_slide_;
                    func.name = fmt::format("sub_{:x}", static_pc);
                }
                func.total_calls++;
                func.call_event_indices.push_back(evt_idx);

                tail_calls_detected_++;
                new_this_round++;
                resolved[ci] = true;
            }
        }

        if (new_this_round == 0) break;
    }

    // ── Calculate total_instructions per function ──
    for (auto& [entry_pc, func] : result_.functions) {
        uint64_t total_insts = 0;
        for (auto idx : func.call_event_indices) {
            auto& evt = result_.call_events[idx];
            if (evt.return_inst_id > evt.call_inst_id) {
                total_insts += evt.return_inst_id - evt.call_inst_id;
            }
        }
        func.total_instructions = total_insts;
    }

    // Build depth table for fast O(log N) depth_at() queries.
    result_.build_depth_table();
}

// ─── FunctionPass::run — now delegates to FunctionCollector ───────────────

PassResult FunctionPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    const auto& hdr = reader.header();
    const auto& range = ctx.range();

    uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("function", blob)) {
            FunctionResult cached;
            if (function_deserialize(blob, cached)) {
                cached.build_depth_table();
                ctx.progress(1.0f, fmt::format(
                    "Functions: {} unique, {} call events (from cache)",
                    cached.functions.size(), cached.call_events.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    ctx.progress(0.0f, "Function analysis: scanning trace...");

    FunctionCollector collector(code_table, hdr.module_slide, hdr.num_gpr);

    // Use shared scan engine if available; otherwise create a local one.
    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run();
    } else {
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress([&](uint64_t processed, uint64_t total) {
            if (total > 0) {
                ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
            }
        });
        local_engine.set_cancel_check([&]() { return ctx.cancelled(); });
        local_engine.set_cancel_token(&ctx.global_cancel_flag());
        local_engine.add_collector(&collector);
        local_engine.run();
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto result = collector.take_result();

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = function_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("function", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format(
        "Functions: {} unique, {} call events, {} tail calls, {} non-local unwinds",
        result.functions.size(),
        result.call_events.size(),
        collector.tail_calls_detected(),
        collector.non_local_unwinds()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
