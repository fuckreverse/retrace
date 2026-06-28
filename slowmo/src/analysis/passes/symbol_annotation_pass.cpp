#include "analysis/passes/symbol_annotation_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/constant_materialization_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <cstring>

namespace tenet {

// ─── AnnotationResult serialization helpers ───────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x414E4E54 ("ANNT")
//   u32  version = 1
//   u64  num_by_pc
//   for each by_pc entry:
//     u64  pc
//     u32  num_annotations
//     for each Annotation:
//       u8   kind
//       f32  priority
//       u32  label_len; u8[] label
//       u32  detail_len; u8[] detail
//   u64  num_by_inst_id
//   for each by_inst_id entry: (same layout as by_pc but keyed by inst_id)

namespace {

static constexpr uint32_t ANNT_BLOB_MAGIC   = 0x414E4E54u;  // "ANNT"
static constexpr uint32_t ANNT_BLOB_VERSION = 1u;

// Helper: compute serialized size for one Annotation vector
static size_t ann_vec_size(const std::vector<Annotation>& anns) {
    size_t sz = 4;  // num_annotations
    for (const auto& a : anns) {
        sz += 1 + 4;           // kind, priority
        sz += 4 + a.label.size();
        sz += 4 + a.detail.size();
    }
    return sz;
}

static void serialize_ann_vec(char*& p, const std::vector<Annotation>& anns) {
    auto write_u8  = [&](uint8_t  v) { std::memcpy(p, &v, 1); p += 1; };
    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_f32 = [&](float    v) { std::memcpy(p, &v, 4); p += 4; };

    write_u32(static_cast<uint32_t>(anns.size()));
    for (const auto& a : anns) {
        write_u8(static_cast<uint8_t>(a.kind));
        write_f32(a.priority);
        write_u32(static_cast<uint32_t>(a.label.size()));
        std::memcpy(p, a.label.data(), a.label.size()); p += a.label.size();
        write_u32(static_cast<uint32_t>(a.detail.size()));
        std::memcpy(p, a.detail.data(), a.detail.size()); p += a.detail.size();
    }
}

static bool deserialize_ann_vec(const char*& p, const char* end,
                                 std::vector<Annotation>& out) {
    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_f32 = [&]() -> float    { float    v; std::memcpy(&v, p, 4); p += 4; return v; };

    if (p + 4 > end) return false;
    uint32_t n = read_u32();
    out.reserve(n);
    for (uint32_t i = 0; i < n; i++) {
        if (p + 1 + 4 > end) return false;
        Annotation a;
        a.kind     = static_cast<Annotation::Kind>(read_u8());
        a.priority = read_f32();
        if (p + 4 > end) return false;
        uint32_t llen = read_u32();
        if (p + llen > end) return false;
        a.label.assign(p, llen); p += llen;
        if (p + 4 > end) return false;
        uint32_t dlen = read_u32();
        if (p + dlen > end) return false;
        a.detail.assign(p, dlen); p += dlen;
        out.push_back(std::move(a));
    }
    return true;
}

std::string annotation_serialize(const AnnotationResult& res) {
    // Compute total size
    size_t total = 4 + 4 + 8;  // magic, version, num_by_pc
    for (const auto& [pc, anns] : res.by_pc) {
        total += 8 + ann_vec_size(anns);  // key + annotations
    }
    total += 8;  // num_by_inst_id
    for (const auto& [id, anns] : res.by_inst_id) {
        total += 8 + ann_vec_size(anns);
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };

    write_u32(ANNT_BLOB_MAGIC);
    write_u32(ANNT_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.by_pc.size()));
    for (const auto& [pc, anns] : res.by_pc) {
        write_u64(pc);
        serialize_ann_vec(p, anns);
    }
    write_u64(static_cast<uint64_t>(res.by_inst_id.size()));
    for (const auto& [id, anns] : res.by_inst_id) {
        write_u64(id);
        serialize_ann_vec(p, anns);
    }

    return buf;
}

bool annotation_deserialize(const std::string& blob, AnnotationResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };

    if (read_u32() != ANNT_BLOB_MAGIC)   return false;
    if (read_u32() != ANNT_BLOB_VERSION) return false;

    uint64_t n_pc = read_u64();
    for (uint64_t i = 0; i < n_pc; i++) {
        if (p + 8 > end) return false;
        uint64_t key = read_u64();
        if (!deserialize_ann_vec(p, end, out.by_pc[key])) return false;
    }

    if (p + 8 > end) return false;
    uint64_t n_id = read_u64();
    for (uint64_t i = 0; i < n_id; i++) {
        if (p + 8 > end) return false;
        uint64_t key = read_u64();
        if (!deserialize_ann_vec(p, end, out.by_inst_id[key])) return false;
    }

    return true;
}

}  // anonymous namespace (symbol_annotation serialization)

// ─── AnnotationResult methods ─────────────────────────────────────────────

std::string AnnotationResult::format_pc(uint64_t pc) const {
    auto it = by_pc.find(pc);
    if (it == by_pc.end() || it->second.empty()) {
        return fmt::format("0x{:x}", pc);
    }

    const auto& annotations = it->second;

    // Find the function annotation (if any) for base name
    std::string base_name;
    std::string context_info;

    for (const auto& ann : annotations) {
        if (ann.kind == Annotation::Kind::Function && base_name.empty()) {
            base_name = ann.label;
        } else if (context_info.empty() && !ann.label.empty()) {
            context_info = ann.label;
        }
    }

    if (base_name.empty()) {
        base_name = fmt::format("0x{:x}", pc);
    }

    if (context_info.empty()) {
        return base_name;
    }

    return fmt::format("{} [{}]", base_name, context_info);
}

// ─── Pass implementation ──────────────────────────────────────────────────

PassResult SymbolAnnotationPass::run(PassContext& ctx) {
    // ── Fast path: load from persisted cache ──────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob;
        if (ctx.index().load_pass_blob("symbol_annotation", blob)) {
            AnnotationResult cached;
            if (annotation_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Symbol annotation: {} PCs, {} inst_ids (from cache)",
                    cached.by_pc.size(), cached.by_inst_id.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    AnnotationResult result;

    ctx.progress(0.0f, "Collecting annotations from passes");

    // Each dependency is soft — check if it succeeded before using it.
    // Use require_raw() which doesn't throw on failure.

    // 1. Function annotations
    {
        const auto& func_result = ctx.require_raw("function");
        if (func_result.ok()) {
            collect_functions(func_result, result);
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.25f, "Collected function annotations");

    // 2. Loop annotations
    {
        const auto& loop_result = ctx.require_raw("loop");
        if (loop_result.ok()) {
            collect_loops(loop_result, result);
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.50f, "Collected loop annotations");

    // 3. Constant materialization annotations
    {
        const auto& const_result = ctx.require_raw("constant_materialization");
        if (const_result.ok()) {
            collect_constants(const_result, result);
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.75f, "Collected constant annotations");

    // 4. Pattern annotations
    {
        const auto& pat_result = ctx.require_raw("pattern");
        if (pat_result.ok()) {
            collect_patterns(pat_result, result);
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    // 5. Sort all annotation vectors by priority descending
    sort_annotations(result);

    // ── Persist result for future sessions ───────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob = annotation_serialize(result);
        if (!blob.empty()) {
            ctx.index().save_pass_blob("symbol_annotation", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("Symbol annotation: {} PCs, {} inst_ids",
                                    result.by_pc.size(), result.by_inst_id.size()));

    return PassResult::success(std::move(result));
}

// ─── Collection helpers ───────────────────────────────────────────────────

void SymbolAnnotationPass::collect_functions(const PassResult& raw_result,
                                             AnnotationResult& out) {
    const auto& func = raw_result.get<FunctionResult>();

    for (const auto& [entry_pc, info] : func.functions) {
        Annotation ann;
        ann.kind = Annotation::Kind::Function;
        ann.label = info.name;
        ann.detail = fmt::format("Function {} — {} calls, {} instructions total",
                                 info.name, info.total_calls, info.total_instructions);
        ann.priority = 10.0f;  // Functions are high priority for labeling

        out.by_pc[entry_pc].push_back(std::move(ann));
    }

    // Also annotate call sites with callee info
    for (const auto& evt : func.call_events) {
        auto func_it = func.functions.find(evt.target_pc);
        if (func_it == func.functions.end()) continue;

        Annotation ann;
        ann.kind = Annotation::Kind::Function;
        ann.label = fmt::format("call {}", func_it->second.name);
        ann.detail = fmt::format("Call to {} at depth {}",
                                 func_it->second.name, evt.depth);
        ann.priority = 8.0f;

        out.by_inst_id[evt.call_inst_id].push_back(std::move(ann));
    }
}

void SymbolAnnotationPass::collect_loops(const PassResult& raw_result,
                                         AnnotationResult& out) {
    const auto& loops = raw_result.get<LoopResult>();

    for (size_t i = 0; i < loops.loops.size(); ++i) {
        const auto& loop = loops.loops[i];

        Annotation ann;
        ann.kind = Annotation::Kind::Loop;
        ann.label = fmt::format("loop@0x{:x}", loop.header_pc);
        ann.detail = fmt::format("Loop header — {} iterations, nesting depth {}",
                                 loop.iteration_count, loop.nesting_depth);
        ann.priority = 6.0f;

        out.by_pc[loop.header_pc].push_back(std::move(ann));

        // Also annotate the back-edge PC
        if (loop.back_edge_pc != 0) {
            Annotation back_ann;
            back_ann.kind = Annotation::Kind::Loop;
            back_ann.label = fmt::format("back-edge→0x{:x}", loop.header_pc);
            back_ann.detail = fmt::format("Back-edge to loop header at 0x{:x}",
                                          loop.header_pc);
            back_ann.priority = 4.0f;

            out.by_pc[loop.back_edge_pc].push_back(std::move(back_ann));
        }
    }
}

void SymbolAnnotationPass::collect_constants(const PassResult& raw_result,
                                             AnnotationResult& out) {
    const auto& consts = raw_result.get<ConstantMaterializationResult>();

    for (const auto& mc : consts.constants) {
        // Only annotate identified (known) constants with high priority;
        // unidentified constants get a lower priority annotation.
        if (mc.known_match) {
            Annotation ann;
            ann.kind = Annotation::Kind::Constant;
            ann.label = mc.known_match->name;
            ann.detail = fmt::format("{} constant: {} = 0x{:x}",
                                     mc.known_match->algorithm,
                                     mc.known_match->name,
                                     mc.value);
            ann.priority = 9.0f;  // Known crypto constants are very important

            // Annotate by PC (first instruction of the sequence)
            out.by_pc[mc.pc_first].push_back(ann);

            // Annotate each inst_id in the range
            for (uint64_t id = mc.first_inst_id; id <= mc.last_inst_id; ++id) {
                out.by_inst_id[id].push_back(ann);
            }
        } else {
            // Unidentified materialized constant — lower priority
            Annotation ann;
            ann.kind = Annotation::Kind::Constant;
            ann.label = fmt::format("0x{:x}", mc.value);
            ann.detail = fmt::format("Materialized constant 0x{:x} in x{} ({} parts)",
                                     mc.value, mc.dst_reg, mc.num_parts);
            ann.priority = 2.0f;

            out.by_pc[mc.pc_first].push_back(std::move(ann));
            out.by_inst_id[mc.first_inst_id].push_back(Annotation{
                Annotation::Kind::Constant,
                fmt::format("0x{:x}", mc.value),
                ann.detail,
                2.0f
            });
        }
    }
}

void SymbolAnnotationPass::collect_patterns(const PassResult& raw_result,
                                            AnnotationResult& out) {
    const auto& patterns = raw_result.get<PatternResult>();

    for (const auto& match : patterns.matches) {
        Annotation ann;
        ann.kind = Annotation::Kind::Pattern;
        ann.label = match.pattern_name;
        ann.detail = match.description.empty()
            ? fmt::format("Pattern: {}", match.pattern_name)
            : match.description;

        // Assign priority based on confidence
        switch (match.confidence) {
            case PatternConfidence::High:   ann.priority = 9.0f; break;
            case PatternConfidence::Medium: ann.priority = 7.0f; break;
            case PatternConfidence::Low:    ann.priority = 4.0f; break;
        }

        // Annotate anchor PC
        if (match.anchor_pc != 0) {
            out.by_pc[match.anchor_pc].push_back(ann);
        }

        // Annotate inst_id range
        if (match.start_inst_id != 0 && match.end_inst_id != 0) {
            // For large ranges, only annotate the start to avoid excessive memory use
            out.by_inst_id[match.start_inst_id].push_back(ann);

            if (match.end_inst_id != match.start_inst_id) {
                Annotation end_ann;
                end_ann.kind = Annotation::Kind::Pattern;
                end_ann.label = fmt::format("{} (end)", match.pattern_name);
                end_ann.detail = ann.detail;
                end_ann.priority = ann.priority - 1.0f;

                out.by_inst_id[match.end_inst_id].push_back(std::move(end_ann));
            }
        }
    }
}

void SymbolAnnotationPass::sort_annotations(AnnotationResult& out) {
    auto sort_fn = [](const Annotation& a, const Annotation& b) {
        return a.priority > b.priority;  // Descending
    };

    for (auto& [pc, vec] : out.by_pc) {
        std::sort(vec.begin(), vec.end(), sort_fn);
    }

    for (auto& [id, vec] : out.by_inst_id) {
        std::sort(vec.begin(), vec.end(), sort_fn);
    }
}

}  // namespace tenet
