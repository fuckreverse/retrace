#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/xref_pass.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "core/instruction_decoder.h"
#include "core/register_file.h"

#include <fmt/core.h>
#include <algorithm>
#include <cstring>

namespace tenet {

// ─── LoopSemanticsResult serialization helpers ────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x4C534D4E ("LSMN")
//   u32  version = 1
//   u64  num_loop_semantics
//   for each LoopSemanticInfo:
//     u64  header_pc
//     u64  iteration_count
//     u8   kind
//     f32  confidence
//     u32  desc_len; u8[] description
//     u64  body_instruction_count
//     u8   has_sbox_pattern
//     u8   has_xor_mix
//     u8   has_shift_rotate
//     u8   has_addition_chain
//     u8   has_modular_arithmetic
//     u64  sample_iter_start
//     u64  sample_iter_end
//     u64  num_active_regs; u8[] active_regs
//     u64  num_invariant_regs; u8[] invariant_regs

namespace {

static constexpr uint32_t LSMN_BLOB_MAGIC   = 0x4C534D4Eu;  // "LSMN"
static constexpr uint32_t LSMN_BLOB_VERSION = 1u;

std::string loop_semantics_serialize(const LoopSemanticsResult& res) {
    size_t total = 4 + 4 + 8;  // magic, version, num_loop_semantics
    for (const auto& li : res.loop_semantics) {
        total += 8 + 8 + 1 + 4;  // header_pc, iter_count, kind, confidence
        total += 4 + li.description.size();  // desc
        total += 8;  // body_instruction_count
        total += 5;  // 5 bool flags
        total += 8 + 8;  // sample_iter_start/end
        total += 8 + li.active_regs.size();
        total += 8 + li.invariant_regs.size();
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u8  = [&](uint8_t  v) { std::memcpy(p, &v, 1); p += 1; };
    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_f32 = [&](float    v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };

    write_u32(LSMN_BLOB_MAGIC);
    write_u32(LSMN_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.loop_semantics.size()));

    for (const auto& li : res.loop_semantics) {
        write_u64(li.header_pc);
        write_u64(li.iteration_count);
        write_u8(static_cast<uint8_t>(li.kind));
        write_f32(li.confidence);
        write_u32(static_cast<uint32_t>(li.description.size()));
        std::memcpy(p, li.description.data(), li.description.size());
        p += li.description.size();
        write_u64(li.body_instruction_count);
        write_u8(li.has_sbox_pattern ? 1u : 0u);
        write_u8(li.has_xor_mix ? 1u : 0u);
        write_u8(li.has_shift_rotate ? 1u : 0u);
        write_u8(li.has_addition_chain ? 1u : 0u);
        write_u8(li.has_modular_arithmetic ? 1u : 0u);
        write_u64(li.sample_iter_start);
        write_u64(li.sample_iter_end);
        write_u64(static_cast<uint64_t>(li.active_regs.size()));
        for (uint8_t r : li.active_regs) write_u8(r);
        write_u64(static_cast<uint64_t>(li.invariant_regs.size()));
        for (uint8_t r : li.invariant_regs) write_u8(r);
    }

    return buf;
}

bool loop_semantics_deserialize(const std::string& blob, LoopSemanticsResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_f32 = [&]() -> float    { float    v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };

    if (read_u32() != LSMN_BLOB_MAGIC)   return false;
    if (read_u32() != LSMN_BLOB_VERSION) return false;

    uint64_t n = read_u64();
    out.loop_semantics.reserve(static_cast<size_t>(n));

    for (uint64_t i = 0; i < n; i++) {
        if (p + 8 + 8 + 1 + 4 > end) return false;
        LoopSemanticInfo li;
        li.header_pc      = read_u64();
        li.iteration_count = read_u64();
        li.kind           = static_cast<LoopKind>(read_u8());
        li.confidence     = read_f32();
        if (p + 4 > end) return false;
        uint32_t desc_len = read_u32();
        if (p + desc_len > end) return false;
        li.description.assign(p, desc_len);
        p += desc_len;
        if (p + 8 + 5 + 8 + 8 > end) return false;
        li.body_instruction_count  = read_u64();
        li.has_sbox_pattern        = read_u8() != 0;
        li.has_xor_mix             = read_u8() != 0;
        li.has_shift_rotate        = read_u8() != 0;
        li.has_addition_chain      = read_u8() != 0;
        li.has_modular_arithmetic  = read_u8() != 0;
        li.sample_iter_start       = read_u64();
        li.sample_iter_end         = read_u64();
        if (p + 8 > end) return false;
        uint64_t n_act = read_u64();
        if (p + n_act > end) return false;
        li.active_regs.resize(static_cast<size_t>(n_act));
        for (uint64_t j = 0; j < n_act; j++) li.active_regs[j] = read_u8();
        if (p + 8 > end) return false;
        uint64_t n_inv = read_u64();
        if (p + n_inv > end) return false;
        li.invariant_regs.resize(static_cast<size_t>(n_inv));
        for (uint64_t j = 0; j < n_inv; j++) li.invariant_regs[j] = read_u8();
        out.loop_semantics.push_back(std::move(li));
    }

    return true;
}

}  // anonymous namespace (loop_semantics serialization)

namespace {  // ─── Helpers ──────────────────────────────────────────────────────────────

/// Number of iterations to sample for register state comparison.
constexpr uint32_t MAX_SAMPLE_ITERATIONS = 3;

/// Well-known crypto iteration counts that boost confidence.
constexpr bool is_crypto_iteration_count(uint64_t count) {
    // AES=10/12/14, DES/Blowfish=16, ChaCha20=20, SHA-256=64, etc.
    return count == 4 || count == 8 || count == 10 || count == 12 ||
           count == 14 || count == 16 || count == 20 || count == 32 ||
           count == 48 || count == 64 || count == 80;
}

/// Check if a mnemonic represents an XOR operation.
inline bool is_xor_mnemonic(std::string_view mn) {
    return mn == "eor" || mn == "eors";
}

/// Check if a mnemonic represents a shift/rotate operation.
inline bool is_shift_rotate_mnemonic(std::string_view mn) {
    return mn == "lsl" || mn == "lsr" || mn == "asr" || mn == "ror" ||
           mn == "lsls" || mn == "lsrs" || mn == "asrs" || mn == "rors" ||
           mn == "eon" || mn == "extr";
}

/// Check if a mnemonic represents an ADD/SUB operation (for addition chains).
inline bool is_add_sub_mnemonic(std::string_view mn) {
    return mn == "add" || mn == "adds" || mn == "sub" || mn == "subs" ||
           mn == "adc" || mn == "adcs" || mn == "sbc" || mn == "sbcs";
}

/// Check if a mnemonic represents modular arithmetic (mul/div).
inline bool is_modular_mnemonic(std::string_view mn) {
    return mn == "mul" || mn == "madd" || mn == "msub" || mn == "smull" ||
           mn == "umull" || mn == "udiv" || mn == "sdiv" || mn == "umulh" ||
           mn == "smulh";
}

/// Check if a mnemonic is a load that could be a table lookup.
inline bool is_load_mnemonic(std::string_view mn) {
    return mn == "ldr" || mn == "ldrb" || mn == "ldrh" || mn == "ldrsb" ||
           mn == "ldrsh" || mn == "ldrsw" || mn == "ldrw";
}

/// Describes the operational features found in a loop body.
struct BodyFeatures {
    uint32_t xor_count = 0;
    uint32_t shift_rotate_count = 0;
    uint32_t add_sub_count = 0;
    uint32_t modular_count = 0;
    uint32_t load_with_reg_offset_count = 0;  // potential S-box lookups
    uint32_t total_instructions = 0;
};

/// Analyze the instruction body of a loop to extract features.
BodyFeatures analyze_body_instructions(
    const std::vector<uint64_t>& body_pcs,
    InstructionDecoder& decoder,
    CodeTable& code_table)
{
    BodyFeatures features;
    features.total_instructions = static_cast<uint32_t>(body_pcs.size());

    for (uint64_t pc : body_pcs) {
        auto decoded = decoder.decode(pc, code_table);
        if (!decoded) continue;

        std::string_view mn = decoded->mnemonic_sv();

        if (is_xor_mnemonic(mn)) {
            features.xor_count++;
        }
        if (is_shift_rotate_mnemonic(mn)) {
            features.shift_rotate_count++;
        }
        if (is_add_sub_mnemonic(mn)) {
            features.add_sub_count++;
        }
        if (is_modular_mnemonic(mn)) {
            features.modular_count++;
        }

        // Detect potential S-box pattern: LDR with a register used as index.
        // In AArch64, table lookups typically use "ldr Xn, [Xbase, Xoff, lsl #3]"
        // or similar addressing modes with a register offset. We heuristically
        // detect this by checking if the load reads 2+ registers (base + offset).
        if (is_load_mnemonic(mn) && decoded->regs_read_count >= 2) {
            features.load_with_reg_offset_count++;
        }
    }

    return features;
}

/// Classify a loop based on its features and iteration count.
void classify_loop(LoopSemanticInfo& info, const BodyFeatures& features,
                   bool has_counter_register)
{
    // Set feature flags
    info.has_xor_mix = features.xor_count > 0;
    info.has_shift_rotate = features.shift_rotate_count > 0;
    info.has_addition_chain = features.add_sub_count >= 3;
    info.has_modular_arithmetic = features.modular_count > 0;
    info.has_sbox_pattern = features.load_with_reg_offset_count >= 2;

    uint64_t iters = info.iteration_count;

    // ── SPN Round: XOR + S-box + typical round counts (AES-like) ─────
    if (info.has_xor_mix && info.has_sbox_pattern &&
        (iters == 8 || iters == 10 || iters == 12 || iters == 14 ||
         iters == 16 || iters == 32)) {
        info.kind = LoopKind::SPNRound;
        info.confidence = 0.8f;
        if (is_crypto_iteration_count(iters)) info.confidence = 0.85f;
        info.description = fmt::format("{}-round SPN cipher (AES-like)", iters);
        return;
    }

    // ── Feistel Round: XOR + shifts/rotates + 16/32/64 iterations ────
    if (info.has_xor_mix && info.has_shift_rotate &&
        (iters == 16 || iters == 32 || iters == 48 || iters == 64)) {
        info.kind = LoopKind::FeistelRound;
        info.confidence = 0.7f;
        if (iters == 16) info.confidence = 0.75f;  // DES-like
        info.description = fmt::format("{}-round Feistel cipher", iters);
        return;
    }

    // ── ARX Round: XOR + addition chains + shifts/rotates ────────────
    if (info.has_xor_mix && info.has_addition_chain && info.has_shift_rotate) {
        info.kind = LoopKind::ARXRound;
        info.confidence = 0.7f;
        if (iters == 20) info.confidence = 0.8f;  // ChaCha20-like
        info.description = fmt::format("{}-round ARX cipher (ChaCha/Salsa-like)", iters);
        return;
    }

    // ── Shift/Rotate dominant: primarily bitwise operations ──────────
    if (info.has_shift_rotate && features.shift_rotate_count >= features.total_instructions / 4 &&
        !info.has_xor_mix && !info.has_sbox_pattern) {
        info.kind = LoopKind::ShiftRotate;
        info.confidence = 0.5f;
        info.description = fmt::format("Shift/rotate loop ({} iterations)", iters);
        return;
    }

    // ── Accumulator: addition-heavy loop (hash/checksum) ─────────────
    if (info.has_addition_chain && !info.has_xor_mix && !info.has_sbox_pattern &&
        features.add_sub_count >= features.total_instructions / 3) {
        info.kind = LoopKind::Accumulator;
        info.confidence = 0.5f;
        info.description = fmt::format("Accumulator loop ({} iterations)", iters);
        return;
    }

    // ── Memcpy-like: mostly loads and stores, few arithmetic ops ─────
    if (features.load_with_reg_offset_count >= features.total_instructions / 3 &&
        features.xor_count == 0 && features.shift_rotate_count == 0 &&
        features.modular_count == 0) {
        info.kind = LoopKind::MemcpyLike;
        info.confidence = 0.6f;
        info.description = fmt::format("Memory copy/set loop ({} iterations)", iters);
        return;
    }

    // ── Counter loop: only one register changes (simple counter) ─────
    if (has_counter_register && info.active_regs.size() <= 2) {
        info.kind = LoopKind::CounterLoop;
        info.confidence = 0.6f;
        info.description = fmt::format("Simple counter loop ({} iterations)", iters);
        return;
    }

    // ── Fallback: unknown but with crypto hint if XOR present ────────
    if (info.has_xor_mix && is_crypto_iteration_count(iters)) {
        info.kind = LoopKind::Unknown;
        info.confidence = 0.3f;
        info.description = fmt::format("Unclassified loop with crypto-like features "
                                       "({} iterations)", iters);
        return;
    }

    // ── Default ──────────────────────────────────────────────────────
    info.kind = LoopKind::Unknown;
    info.confidence = 0.0f;
    info.description = fmt::format("Unclassified loop ({} iterations)", iters);
}

}  // anonymous namespace

// ─── LoopSemanticsPass::run ───────────────────────────────────────────────

PassResult LoopSemanticsPass::run(PassContext& ctx) {
    // ── Fast path: load from persisted cache ──────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob;
        if (ctx.index().load_pass_blob("loop_semantics", blob)) {
            LoopSemanticsResult cached;
            if (loop_semantics_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Loop semantics: {} loops classified (from cache)",
                    cached.loop_semantics.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    // ── Step 1: Get dependencies ──────────────────────────────────────────
    const auto& loop_result = ctx.require<LoopResult>("loop");
    const auto& xref        = ctx.require<XrefResult>("xref");

    if (loop_result.loops.empty()) {
        ctx.progress(1.0f, "Loop semantics: no loops to analyze");
        return PassResult::success(LoopSemanticsResult{});
    }

    auto& regfile    = ctx.regfile();
    auto& decoder    = ctx.decoder();
    auto& code_table = ctx.code_table();

    LoopSemanticsResult result;

    // Count analyzable loops (iteration_count >= 2)
    size_t analyzable = 0;
    for (const auto& loop : loop_result.loops) {
        if (loop.iteration_count >= 2) analyzable++;
    }

    if (analyzable == 0) {
        ctx.progress(1.0f, "Loop semantics: no loops with sufficient iterations");
        return PassResult::success(std::move(result));
    }

    ctx.progress(0.0f, fmt::format("Loop semantics: analyzing {} loops...", analyzable));

    const auto& range = ctx.range();

    // ── Step 1b: Pre-warm RegisterFile for all header inst_ids ───────────
    //
    // LoopSemanticsPass calls regfile.state_before() for up to
    // MAX_SAMPLE_ITERATIONS sample points per loop.  Each call with a cold
    // cache triggers an ANCHOR → INST replay chain (potentially hundreds of
    // sequential record reads).
    //
    // By first scanning all header_inst_ids and calling warm_range() over the
    // contiguous spans they cover, we warm the entire relevant range in a
    // single forward sequential pass through the trace — the most cache-friendly
    // access pattern possible.  Subsequent state_before() calls become O(1)
    // cache hits.
    //
    // Implementation:
    //   1. Collect the first MAX_SAMPLE_ITERATIONS header inst_ids per loop
    //      into a flat sorted list.
    //   2. Walk the sorted list and coalesce adjacent spans (gap ≤ 2 × anchor
    //      interval, estimated at 1000 instructions).  Call warm_range() for
    //      each coalesced span.  This avoids redundant warm_range calls when
    //      many loops cluster in the same region of the trace.

    {
        constexpr uint64_t ANCHOR_INTERVAL_EST = 1000;  // conservative estimate
        constexpr uint64_t COALESCE_GAP = ANCHOR_INTERVAL_EST * 2;

        // Gather candidate inst_ids (same logic as the main loop below)
        std::vector<uint64_t> warm_ids;
        warm_ids.reserve(analyzable * MAX_SAMPLE_ITERATIONS);

        for (const auto& loop : loop_result.loops) {
            if (loop.iteration_count < 2) continue;
            if (!xref.has_pc(loop.header_pc)) continue;
            size_t collected = 0;
            for (uint64_t iid : xref.inst_ids_at(loop.header_pc)) {
                if (iid < range.start_inst_id) continue;
                if (range.end_inst_id != UINT64_MAX && iid >= range.end_inst_id) break;
                warm_ids.push_back(iid);
                if (++collected >= MAX_SAMPLE_ITERATIONS) break;
            }
        }

        if (!warm_ids.empty()) {
            if (ctx.cancelled()) return PassResult::failed("Cancelled");

            std::sort(warm_ids.begin(), warm_ids.end());
            warm_ids.erase(std::unique(warm_ids.begin(), warm_ids.end()), warm_ids.end());

            // Coalesce into contiguous spans and warm each span
            uint64_t span_start = warm_ids[0];
            uint64_t span_end   = warm_ids[0] + 1;

            auto flush_warm = [&](uint64_t s, uint64_t e) {
                // Expand the span to cover the full anchor→sample window
                // (warm_range internally samples at `stride` intervals; using
                //  the default stride=0 lets RegisterFile choose optimally).
                regfile.warm_range(s, e, 0, nullptr);
            };

            for (size_t i = 1; i < warm_ids.size(); ++i) {
                if (ctx.cancelled()) return PassResult::failed("Cancelled");
                if (warm_ids[i] - span_end <= COALESCE_GAP) {
                    span_end = warm_ids[i] + 1;
                } else {
                    flush_warm(span_start, span_end);
                    span_start = warm_ids[i];
                    span_end   = warm_ids[i] + 1;
                }
            }
            flush_warm(span_start, span_end);
        }
    }

    size_t processed = 0;

    // ── Step 2: Analyze each loop ────────────────────────────────────────
    for (const auto& loop : loop_result.loops) {
        if (ctx.cancelled()) return PassResult::failed("Cancelled");

        if (loop.iteration_count < 2) continue;

        LoopSemanticInfo info;
        info.header_pc             = loop.header_pc;
        info.iteration_count       = loop.iteration_count;
        info.body_instruction_count = static_cast<uint64_t>(loop.body_pcs.size());

        // ── Step 2a: Find iteration boundaries via Xref bitmap ────────────
        //
        // Previous approach: O(loops × scan_window) random trace accesses.
        //   For 100 loops with a 1 M instruction window → ~100 M random reads.
        //
        // New approach: O(K) where K = min(iterations, MAX_SAMPLE_ITERATIONS).
        //   XrefPass already built a PC → Roaring64Map(inst_id) index in a
        //   single sequential pass.  We just iterate the bitmap for header_pc
        //   and take the first few inst_ids that fall within the analysis range.
        //   A Roaring64Map iterator over run-encoded sequential ids is ~O(1)
        //   per element, and no random file access is required at all.

        std::vector<uint64_t> header_inst_ids;
        header_inst_ids.reserve(MAX_SAMPLE_ITERATIONS + 1);

        for (uint64_t iid : xref.inst_ids_at(loop.header_pc)) {
            // Respect the analysis range
            if (iid < range.start_inst_id) continue;
            if (range.end_inst_id != UINT64_MAX && iid >= range.end_inst_id) break;
            header_inst_ids.push_back(iid);
            if (header_inst_ids.size() > MAX_SAMPLE_ITERATIONS) break;
        }

        if (header_inst_ids.size() < 2) {
            // Not enough iterations found — still record the loop
            info.kind        = LoopKind::Unknown;
            info.confidence  = 0.0f;
            info.description = fmt::format("Loop at {:#x} (insufficient iteration samples)",
                                           loop.header_pc);
            result.loop_semantics.push_back(std::move(info));
            processed++;
            ctx.progress(static_cast<float>(processed) / static_cast<float>(analyzable) * 0.9f);
            continue;
        }

        // Record iteration boundary for sampling info
        info.sample_iter_start = header_inst_ids[0];
        info.sample_iter_end   = header_inst_ids[1];

        // ── Step 2b: Compare register states across iterations ────────────
        // For each header hit, get the register state before execution.
        // Then determine which registers change vs. stay constant.

        uint32_t num_iters_sampled = static_cast<uint32_t>(
            std::min(header_inst_ids.size(), static_cast<size_t>(MAX_SAMPLE_ITERATIONS)));

        // Collect register snapshots at each iteration boundary
        std::vector<RegState> iter_states;
        iter_states.reserve(num_iters_sampled);

        for (uint32_t i = 0; i < num_iters_sampled; ++i) {
            iter_states.push_back(regfile.state_before(header_inst_ids[i]));
        }

        // Compare registers: active (changes in any pair) vs invariant (never changes)
        // We check GPR[0] through GPR[30] (skip SP/NZCV/PC which always change).
        constexpr uint8_t GPR_COMPARE_COUNT = 31; // x0-x30

        bool has_counter_register = false;

        for (uint8_t r = 0; r < GPR_COMPARE_COUNT; ++r) {
            bool changed = false;
            bool is_counter = true;

            for (uint32_t i = 1; i < num_iters_sampled; ++i) {
                if (iter_states[i].gpr[r] != iter_states[0].gpr[r]) {
                    changed = true;
                }
                // Check counter pattern: each iteration increments/decrements by 1
                if (i >= 1) {
                    int64_t diff = static_cast<int64_t>(iter_states[i].gpr[r]) -
                                   static_cast<int64_t>(iter_states[i - 1].gpr[r]);
                    if (diff != 1 && diff != -1) {
                        is_counter = false;
                    }
                }
            }

            if (changed) {
                info.active_regs.push_back(r);
                if (is_counter) has_counter_register = true;
            } else {
                info.invariant_regs.push_back(r);
            }
        }

        // ── Step 2c: Analyze loop body instructions ───────────────────────
        BodyFeatures features = analyze_body_instructions(
            loop.body_pcs, decoder, code_table);

        // ── Step 2d: Classify the loop ────────────────────────────────────
        classify_loop(info, features, has_counter_register);

        result.loop_semantics.push_back(std::move(info));
        processed++;
        ctx.progress(static_cast<float>(processed) / static_cast<float>(analyzable) * 0.9f);
    }

    ctx.progress(1.0f, fmt::format("Loop semantics: classified {} loops ({} crypto-related)",
                                   result.loop_semantics.size(),
                                   result.crypto_loops().size()));

    // ── Persist result for future sessions ───────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob = loop_semantics_serialize(result);
        if (!blob.empty()) {
            ctx.index().save_pass_blob("loop_semantics", blob.data(), blob.size());
        }
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet
