#include "analysis/passes/crypto/loop_semantics_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/structure/xref_pass.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "core/instruction_decoder.h"
#include "core/register_file.h"
#include "common/aarch64_classify.h"
#include "common/byte_codec.h"

#include <fmt/core.h>
#include <algorithm>
#include <array>
#include <cstring>

namespace tenet {

// ─── LoopSemanticsResult serialization helpers ────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x4C534D4E ("LSMN")
//   u32  version = 2
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
//     u8   sbox_pattern_data_dependent   (added in v2)
//     u64  sample_iter_start
//     u64  sample_iter_end
//     u64  num_active_regs; u8[] active_regs
//     u64  num_invariant_regs; u8[] invariant_regs
//
// NOTE: v1 blobs are intentionally rejected (not upgraded in place) by
// loop_semantics_deserialize()'s magic/version check below — classify_loop()
// changed its confidence/threshold logic alongside this field, so a stale v1
// cache would silently mix new-format flags with old-format confidence
// scores. Version bump forces a one-time recompute instead.

namespace {

static constexpr uint32_t LSMN_BLOB_MAGIC   = 0x4C534D4Eu;  // "LSMN"
static constexpr uint32_t LSMN_BLOB_VERSION = 2u;

std::string loop_semantics_serialize(const LoopSemanticsResult& res) {
    ByteWriter w;

    w.u32(LSMN_BLOB_MAGIC);
    w.u32(LSMN_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.loop_semantics.size()));

    for (const auto& li : res.loop_semantics) {
        w.u64(li.header_pc);
        w.u64(li.iteration_count);
        w.u8(static_cast<uint8_t>(li.kind));
        w.f32(li.confidence);
        w.str(li.description);
        w.u64(li.body_instruction_count);
        w.u8(li.has_sbox_pattern ? 1u : 0u);
        w.u8(li.has_xor_mix ? 1u : 0u);
        w.u8(li.has_shift_rotate ? 1u : 0u);
        w.u8(li.has_addition_chain ? 1u : 0u);
        w.u8(li.has_modular_arithmetic ? 1u : 0u);
        w.u8(li.sbox_pattern_data_dependent ? 1u : 0u);
        w.u64(li.sample_iter_start);
        w.u64(li.sample_iter_end);
        w.u64(static_cast<uint64_t>(li.active_regs.size()));
        for (uint8_t r : li.active_regs) w.u8(r);
        w.u64(static_cast<uint64_t>(li.invariant_regs.size()));
        for (uint8_t r : li.invariant_regs) w.u8(r);
    }

    return std::move(w).take();
}

bool loop_semantics_deserialize(const std::string& blob, LoopSemanticsResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != LSMN_BLOB_MAGIC)   return false;
    if (r.u32() != LSMN_BLOB_VERSION) return false;

    uint64_t n = r.u64();
    out.loop_semantics.reserve(static_cast<size_t>(n));

    for (uint64_t i = 0; i < n; i++) {
        LoopSemanticInfo li;
        li.header_pc      = r.u64();
        li.iteration_count = r.u64();
        li.kind           = static_cast<LoopKind>(r.u8());
        li.confidence     = r.f32();
        if (!r.str(li.description)) return false;
        li.body_instruction_count  = r.u64();
        li.has_sbox_pattern        = r.u8() != 0;
        li.has_xor_mix             = r.u8() != 0;
        li.has_shift_rotate        = r.u8() != 0;
        li.has_addition_chain      = r.u8() != 0;
        li.has_modular_arithmetic  = r.u8() != 0;
        li.sbox_pattern_data_dependent = r.u8() != 0;
        li.sample_iter_start       = r.u64();
        li.sample_iter_end         = r.u64();
        uint64_t n_act = r.u64();
        li.active_regs.resize(static_cast<size_t>(n_act));
        for (uint64_t j = 0; j < n_act; j++) li.active_regs[j] = r.u8();
        uint64_t n_inv = r.u64();
        li.invariant_regs.resize(static_cast<size_t>(n_inv));
        for (uint64_t j = 0; j < n_inv; j++) li.invariant_regs[j] = r.u8();
        out.loop_semantics.push_back(std::move(li));
    }

    return r.ok();
}

}  // anonymous namespace (loop_semantics serialization)

namespace {  // ─── Helpers ──────────────────────────────────────────────────────────────

/// Number of iterations to sample for register state comparison.
///
/// Previously 3. Raised to 5 because 3 samples (2 comparison pairs) gives the
/// counter-register/active-vs-invariant heuristics very little room to
/// absorb noise: a single atypical pair (e.g. a key-schedule warm-up step,
/// a conditionally-taken instruction on just one of the sampled iterations,
/// or a loop that peels its first iteration) is enough to flip the verdict
/// for an otherwise-clear pattern. 5 samples (4 pairs) with the
/// majority-vote counter check below (see COUNTER_PATTERN_MIN_AGREEMENT and
/// its use in the active/invariant register classification loop) tolerates
/// one such outlier pair while still being cheap: state_before() calls are
/// served by the eager dense checkpoint array (built at init_infra()), so
/// the incremental cost of 2 extra samples per loop is a handful of
/// additional O(K) checkpoint replays, not additional random trace I/O.
constexpr uint32_t MAX_SAMPLE_ITERATIONS = 5;

/// Minimum fraction of consecutive sample pairs that must show a ±1 step for
/// a register to still be considered a "simple counter" (CounterLoop/ARX
/// increment detection). Requiring 100% agreement made the check brittle
/// against a single noisy pair among the sampled iterations (see
/// MAX_SAMPLE_ITERATIONS above); a supermajority still rejects registers
/// that aren't behaving like counters at all while tolerating one outlier
/// once enough samples are available.
constexpr float COUNTER_PATTERN_MIN_AGREEMENT = 0.6f;

/// Well-known crypto iteration counts that boost confidence.
///
/// NOTE: this is intentionally a *fuzzy* match (±1) rather than an exact
/// set-membership test. `iteration_count` is derived from the number of
/// times a back-edge was *taken* in the observed trace window, which is
/// off-by-one from the textbook round count depending on how the loop's
/// exit test is shaped (e.g. a "do { ... } while (--n)" loop reports N-1
/// taken back-edges for N rounds) and can also be truncated by the
/// analysis range or unrolled/peeled iterations at the loop's boundary.
/// Requiring an exact match made the classifier reject legitimate crypto
/// loops over a single off-by-one instruction-count difference; a ±1
/// tolerance absorbs that without meaningfully increasing the false-positive
/// rate (adjacent integers are not crypto-round counts either).
constexpr bool is_crypto_iteration_count(uint64_t count) {
    // AES=10/12/14, DES/Blowfish=16, ChaCha20=20, SHA-256=64, etc.
    constexpr uint64_t kKnownCounts[] = {4, 8, 10, 12, 14, 16, 20, 32, 48, 64, 80};
    for (uint64_t known : kKnownCounts) {
        uint64_t diff = (count > known) ? (count - known) : (known - count);
        if (diff <= 1) return true;
    }
    return false;
}

/// Returns true if `count` is within ±1 of `target` (see is_crypto_iteration_count
/// for why exact matches are too brittle against real traces).
constexpr bool iteration_count_near(uint64_t count, uint64_t target) {
    uint64_t diff = (count > target) ? (count - target) : (target - count);
    return diff <= 1;
}

/// Returns true if `count` is within ±1 of any value in `targets`.
template <size_t N>
constexpr bool iteration_count_near_any(uint64_t count, const uint64_t (&targets)[N]) {
    for (uint64_t t : targets) {
        if (iteration_count_near(count, t)) return true;
    }
    return false;
}

// Mnemonic-based classification helpers (is_xor_mnemonic etc.) were
// removed: analyze_body_instructions now uses aarch64::OpcodeInfo pure bit
// classification (no Capstone, no string comparison) for counting, and only
// falls back to Capstone for loads + mixing-ops that need regs_read/
// regs_written detail.

/// Describes the operational features found in a loop body.
struct BodyFeatures {
    uint32_t xor_count = 0;
    uint32_t shift_rotate_count = 0;
    uint32_t add_sub_count = 0;
    uint32_t modular_count = 0;
    uint32_t load_with_reg_offset_count = 0;  // potential S-box lookups (any reg-offset load)

    /// Subset of `load_with_reg_offset_count` where the *index* register was
    /// itself produced by a mixing operation (XOR/shift-rotate/add-sub/mul)
    /// earlier in the same body — i.e. the load address actually depends on
    /// data computed by this round, not just on an incidental base+offset
    /// addressing mode. This is a much stronger S-box signal than "some
    /// register-offset load exists somewhere in the body": a real table
    /// lookup's index is derived from the round's input/state, whereas
    /// `load_with_reg_offset_count` alone is also triggered by ordinary
    /// array/struct-field access with no data-dependent indexing at all.
    uint32_t data_dependent_load_count = 0;

    uint32_t total_instructions = 0;
};

/// Analyze the instruction body of a loop to extract features.
///
/// In addition to simple per-mnemonic tallies, this performs a lightweight
/// forward data-flow pass over the body: any register written by a
/// mixing instruction (XOR/shift-rotate/add-sub/mul) is recorded as
/// "mixed", and a later load's offset/index register(s) being in that set
/// is what actually promotes a plain register-offset load to a validated
/// S-box/table-lookup signal (see `data_dependent_load_count` above).
///
/// This is intentionally a same-body, single-pass, no-loop-back-edge model
/// (it does not track values across iterations) — good enough to reject the
/// common false positive of "some load somewhere uses two registers" while
/// staying O(body size) with no extra trace access.
BodyFeatures analyze_body_instructions(
    const std::vector<uint64_t>& body_pcs,
    InstructionDecoder& decoder,
    CodeTable& code_table)
{
    BodyFeatures features;
    features.total_instructions = static_cast<uint32_t>(body_pcs.size());

    // Registers written by a mixing instruction (XOR/shift-rotate/add-sub/mul)
    // seen so far in this forward pass over the body.
    std::array<bool, 32> mixed_reg{};

    for (uint64_t pc : body_pcs) {
        auto opcode_opt = code_table.opcode_at(pc);
        if (!opcode_opt) continue;

        // ── Pure bit classification — no Capstone, no string comparison ──
        auto info = aarch64::OpcodeInfo::classify(*opcode_opt);
        bool is_mix_op = false;

        if (info.is_eor) {
            features.xor_count++;
            is_mix_op = true;
        }
        if (info.is_shift_rotate) {
            features.shift_rotate_count++;
            is_mix_op = true;
        }
        if (info.is_add_sub) {
            features.add_sub_count++;
            is_mix_op = true;
        }
        if (info.is_modular) {
            features.modular_count++;
            is_mix_op = true;
        }

        // ── Capstone fallback: only for loads (need regs_read for S-box
        // detection) and mixing ops (need regs_written for data-flow tracking).
        // This avoids decoding the majority of body instructions (MOV, CMP,
        // branches, etc.) which neither load nor mix.
        if (info.is_load || is_mix_op) {
            auto decoded = decoder.decode(pc, *opcode_opt);
            if (!decoded) continue;

            // Detect potential S-box pattern: LDR with a register used as index.
            if (info.is_load && decoded->regs_read_count >= 2) {
                features.load_with_reg_offset_count++;

                // Strengthen: is any of the read registers (candidate index)
                // one that a mixing instruction produced earlier in this body?
                for (uint8_t i = 0; i < decoded->regs_read_count; ++i) {
                    uint8_t r = decoded->regs_read[i];
                    if (r < mixed_reg.size() && mixed_reg[r]) {
                        features.data_dependent_load_count++;
                        break;
                    }
                }
            }

            if (is_mix_op) {
                for (uint8_t i = 0; i < decoded->regs_written_count; ++i) {
                    uint8_t r = decoded->regs_written[i];
                    if (r < mixed_reg.size()) mixed_reg[r] = true;
                }
            }
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
    info.sbox_pattern_data_dependent = features.data_dependent_load_count >= 1;

    uint64_t iters = info.iteration_count;

    // ── SPN Round: XOR + S-box + typical round counts (AES-like) ─────
    // Iteration-count membership uses a ±1 tolerance (see
    // is_crypto_iteration_count) because `iters` is a back-edge-taken count
    // sampled from the trace, not the textbook round count.
    static constexpr uint64_t kSpnCounts[] = {8, 10, 12, 14, 16, 32};
    if (info.has_xor_mix && info.has_sbox_pattern &&
        iteration_count_near_any(iters, kSpnCounts)) {
        info.kind = LoopKind::SPNRound;
        // Base confidence is now gated by whether the S-box load's index was
        // actually verified to be data-dependent on a mixing op in this same
        // body (see sbox_pattern_data_dependent) rather than merely "some
        // load reads 2+ registers" — the latter is also true for ordinary
        // struct/array access that has nothing to do with a table lookup.
        info.confidence = info.sbox_pattern_data_dependent ? 0.8f : 0.55f;
        if (is_crypto_iteration_count(iters)) info.confidence += 0.05f;
        info.description = info.sbox_pattern_data_dependent
            ? fmt::format("{}-round SPN cipher (AES-like, verified S-box index dependency)", iters)
            : fmt::format("{}-round SPN cipher (AES-like, unverified table-lookup heuristic)", iters);
        return;
    }

    // ── Feistel Round: XOR + shifts/rotates + 16/32/64 iterations ────
    static constexpr uint64_t kFeistelCounts[] = {16, 32, 48, 64};
    if (info.has_xor_mix && info.has_shift_rotate &&
        iteration_count_near_any(iters, kFeistelCounts)) {
        info.kind = LoopKind::FeistelRound;
        info.confidence = 0.7f;
        if (iteration_count_near(iters, 16)) info.confidence = 0.75f;  // DES-like
        info.description = fmt::format("{}-round Feistel cipher", iters);
        return;
    }

    // ── ARX Round: XOR + addition chains + shifts/rotates ────────────
    if (info.has_xor_mix && info.has_addition_chain && info.has_shift_rotate) {
        info.kind = LoopKind::ARXRound;
        info.confidence = 0.7f;
        if (iteration_count_near(iters, 20)) info.confidence = 0.8f;  // ChaCha20-like
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

    // Checkpoints are built eagerly at init_infra() — no per-range warm needed.

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

        // Collect GPR[0..30] snapshots at each iteration boundary via the
        // shared sample_gprs() primitive (also used by TraceFoldPass).
        auto iter_gprs = regfile.sample_gprs(
            header_inst_ids.data(), num_iters_sampled);

        // Compare registers: active (changes in any pair) vs invariant (never changes)
        // We check GPR[0] through GPR[30] (skip SP/NZCV/PC which always change).
        constexpr uint8_t GPR_COMPARE_COUNT = 31; // x0-x30

        bool has_counter_register = false;

        for (uint8_t r = 0; r < GPR_COMPARE_COUNT; ++r) {
            bool changed = false;
            uint32_t step_pairs = 0;       // consecutive sample pairs observed
            uint32_t step_pairs_pm1 = 0;   // ... of which had a ±1 step

            for (uint32_t i = 1; i < num_iters_sampled; ++i) {
                if (iter_gprs[i][r] != iter_gprs[0][r]) {
                    changed = true;
                }
                // Check counter pattern: does this iteration step by ±1 from
                // the previous one? We tally agreement across all sampled
                // pairs rather than requiring unanimous agreement (see
                // COUNTER_PATTERN_MIN_AGREEMENT) so that a single noisy pair
                // — e.g. a key-schedule warm-up step or a conditionally
                // taken instruction on one sampled iteration — doesn't flip
                // an otherwise-clear counter pattern to "not a counter".
                int64_t diff = static_cast<int64_t>(iter_gprs[i][r]) -
                               static_cast<int64_t>(iter_gprs[i - 1][r]);
                step_pairs++;
                if (diff == 1 || diff == -1) step_pairs_pm1++;
            }

            bool is_counter = step_pairs > 0 &&
                (static_cast<float>(step_pairs_pm1) / static_cast<float>(step_pairs))
                    >= COUNTER_PATTERN_MIN_AGREEMENT;

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
