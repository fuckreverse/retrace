#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <optional>
#include <mutex>

#include <nlohmann/json.hpp>

namespace tenet {

// ─── Hypothesis Ledger ────────────────────────────────────────────────────
//
// State machine for managing analysis hypotheses (anti-hallucination).
//   proposed → active → concluded | abandoned
//
// Anti-hallucination rules:
//   - Cannot conclude without verified evidence
//   - Conflicting hypotheses cannot both be concluded
//   - Evidence must reference real trace data

enum class HypothesisStatus { Proposed, Active, Concluded, Abandoned };

struct HypothesisEvidence {
    std::string description;
    std::string source_tool;
    std::optional<uint64_t> inst_id;
    nlohmann::json data;
    bool verified = false;
    double timestamp = 0.0;
};

struct Hypothesis {
    std::string id;
    std::string statement;
    std::string category;
    HypothesisStatus status = HypothesisStatus::Proposed;
    std::vector<HypothesisEvidence> evidence_for;
    std::vector<HypothesisEvidence> evidence_against;
    std::optional<std::string> conclusion;
    double confidence = 0.0;
    double created_at = 0.0;
    double updated_at = 0.0;
    std::vector<std::string> conflicts_with;
    bool reviewed = false;
};

class HypothesisLedger {
public:
    HypothesisLedger() = default;

    nlohmann::json add(const std::string& statement,
                       const std::string& category = "general",
                       const std::vector<std::string>& conflicts_with = {});
    nlohmann::json activate(const std::string& hid);
    nlohmann::json add_evidence(const std::string& hid,
                                const std::string& description,
                                const std::string& source_tool,
                                std::optional<uint64_t> inst_id = std::nullopt,
                                const nlohmann::json& data = nullptr,
                                bool supports = true,
                                bool verified = false);
    nlohmann::json conclude(const std::string& hid, const std::string& conclusion);
    nlohmann::json abandon(const std::string& hid, const std::string& reason);
    nlohmann::json list_all(const std::string& status_filter = "") const;
    nlohmann::json get(const std::string& hid) const;
    nlohmann::json mark_reviewed(const std::string& hid);

private:
    double compute_confidence(const Hypothesis& h) const;
    static const char* status_str(HypothesisStatus s);

    mutable std::mutex mutex_;  // protects all mutable state below
    std::unordered_map<std::string, Hypothesis> hypotheses_;
    int next_id_ = 1;
    std::unordered_map<std::string, std::vector<std::string>> conflict_graph_;
};

}  // namespace tenet
