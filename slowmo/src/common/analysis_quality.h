#pragma once

#include <cstdint>
#include <string>
#include <nlohmann/json.hpp>

namespace tenet {

// Coverage describes visited instructions, not an assurance of exact value,
// bit/lane-level or implicit-control-flow semantics. Indexed skips are not
// silently counted as decoded instructions.
struct AnalysisQuality {
    std::string engine = "unknown";
    uint64_t instructions_examined = 0;
    uint64_t missing_code = 0;
    uint64_t undecoded_instructions = 0;
    uint64_t unsupported_register_instructions = 0;
    uint64_t unresolved_control_joins = 0;
    bool truncated = false;
    bool thread_context_not_isolated = false;
    std::string termination_reason;

    bool has_gaps() const {
        return missing_code || undecoded_instructions || unsupported_register_instructions ||
               truncated || thread_context_not_isolated || unresolved_control_joins;
    }

    nlohmann::json to_json() const {
        return {{"engine", engine}, {"coverage_scope", "visited_instructions"},
                {"dependency_precision", "conservative_register_level"},
                {"instructions_examined", instructions_examined}, {"missing_code", missing_code},
                {"undecoded_instructions", undecoded_instructions},
                {"unsupported_register_instructions", unsupported_register_instructions},
                {"thread_context_not_isolated", thread_context_not_isolated},
                {"unresolved_control_joins", unresolved_control_joins},
                {"truncated", truncated}, {"termination_reason", termination_reason},
                {"has_gaps", has_gaps()}};
    }

    static AnalysisQuality from_json(const nlohmann::json& j) {
        AnalysisQuality q;
        j.at("engine").get_to(q.engine);
        j.at("instructions_examined").get_to(q.instructions_examined);
        j.at("missing_code").get_to(q.missing_code);
        j.at("undecoded_instructions").get_to(q.undecoded_instructions);
        j.at("unsupported_register_instructions").get_to(q.unsupported_register_instructions);
        j.at("thread_context_not_isolated").get_to(q.thread_context_not_isolated);
        q.unresolved_control_joins = j.value("unresolved_control_joins", uint64_t(0));
        j.at("truncated").get_to(q.truncated);
        j.at("termination_reason").get_to(q.termination_reason);
        return q;
    }
};

} // namespace tenet
