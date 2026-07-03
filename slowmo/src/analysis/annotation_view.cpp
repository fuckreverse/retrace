#include "analysis/annotation_view.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/pattern_pass.h"  // also defines ConstantMaterializationResult

#include <fmt/core.h>
#include <algorithm>

namespace tenet {

namespace {

void collect_functions(const FunctionResult& func, AnnotationView& out) {
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

void collect_loops(const LoopResult& loops, AnnotationView& out) {
    for (const auto& loop : loops.loops) {
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

void collect_constants(const ConstantMaterializationResult& consts, AnnotationView& out) {
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

            // Annotate each inst_id in the range. Guard against pathologically
            // long ranges (e.g. a misclassified constant spanning the whole
            // trace) so a single bad entry can't blow up memory/time here.
            constexpr uint64_t kMaxAnnotatedSpan = 4096;
            uint64_t span_end = mc.last_inst_id;
            if (span_end > mc.first_inst_id + kMaxAnnotatedSpan) {
                span_end = mc.first_inst_id + kMaxAnnotatedSpan;
            }
            for (uint64_t id = mc.first_inst_id; id <= span_end; ++id) {
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

            out.by_pc[mc.pc_first].push_back(ann);
            out.by_inst_id[mc.first_inst_id].push_back(std::move(ann));
        }
    }
}

void collect_patterns(const PatternResult& patterns, AnnotationView& out) {
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

void sort_annotations(AnnotationView& out) {
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

}  // namespace

std::string AnnotationView::format_pc(uint64_t pc) const {
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

AnnotationView build_annotation_view(const FunctionResult* function_result,
                                      const LoopResult* loop_result,
                                      const ConstantMaterializationResult* constant_result,
                                      const PatternResult* pattern_result) {
    AnnotationView view;

    if (function_result) collect_functions(*function_result, view);
    if (loop_result) collect_loops(*loop_result, view);
    if (constant_result) collect_constants(*constant_result, view);
    if (pattern_result) collect_patterns(*pattern_result, view);

    sort_annotations(view);
    return view;
}

}  // namespace tenet
