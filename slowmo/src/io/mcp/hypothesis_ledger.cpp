#include "hypothesis_ledger.h"

#include <fmt/core.h>

#include <algorithm>
#include <cmath>
#include <ctime>

using json = nlohmann::json;

namespace tenet {

// ═══════════════════════════════════════════════════════════════════════════
// HypothesisLedger implementation
// ═══════════════════════════════════════════════════════════════════════════

static double now_timestamp() {
    return static_cast<double>(std::time(nullptr));
}

const char* HypothesisLedger::status_str(HypothesisStatus s) {
    switch (s) {
        case HypothesisStatus::Proposed:  return "proposed";
        case HypothesisStatus::Active:    return "active";
        case HypothesisStatus::Concluded: return "concluded";
        case HypothesisStatus::Abandoned: return "abandoned";
    }
    return "unknown";
}

json HypothesisLedger::add(const std::string& statement,
                            const std::string& category,
                            const std::vector<std::string>& conflicts_with) {
    std::string hid = fmt::format("H{:03d}", next_id_++);
    Hypothesis h;
    h.id = hid;
    h.statement = statement;
    h.category = category;
    h.status = HypothesisStatus::Proposed;
    h.conflicts_with = conflicts_with;
    h.created_at = now_timestamp();
    h.updated_at = h.created_at;

    hypotheses_[hid] = std::move(h);

    // Register conflicts bidirectionally
    for (const auto& cid : conflicts_with) {
        auto it = hypotheses_.find(cid);
        if (it != hypotheses_.end()) {
            it->second.conflicts_with.push_back(hid);
        }
        conflict_graph_[hid].push_back(cid);
        conflict_graph_[cid].push_back(hid);
    }

    return {{"id", hid}, {"status", "proposed"}, {"statement", statement}};
}

json HypothesisLedger::activate(const std::string& hid) {
    auto it = hypotheses_.find(hid);
    if (it == hypotheses_.end())
        return {{"error", "Hypothesis " + hid + " not found"}};
    auto& h = it->second;
    if (h.status != HypothesisStatus::Proposed)
        return {{"error", "Can only activate PROPOSED hypotheses (current: " +
                          std::string(status_str(h.status)) + ")"}};
    h.status = HypothesisStatus::Active;
    h.updated_at = now_timestamp();
    return {{"id", hid}, {"status", "active"}};
}

json HypothesisLedger::add_evidence(const std::string& hid,
                                     const std::string& description,
                                     const std::string& source_tool,
                                     std::optional<uint64_t> inst_id,
                                     const json& data,
                                     bool supports,
                                     bool verified) {
    auto it = hypotheses_.find(hid);
    if (it == hypotheses_.end())
        return {{"error", "Hypothesis " + hid + " not found"}};
    auto& h = it->second;
    if (h.status != HypothesisStatus::Proposed && h.status != HypothesisStatus::Active)
        return {{"error", "Cannot add evidence to " + std::string(status_str(h.status)) + " hypothesis"}};

    // Auto-activate if still proposed
    if (h.status == HypothesisStatus::Proposed)
        h.status = HypothesisStatus::Active;

    HypothesisEvidence ev;
    ev.description = description;
    ev.source_tool = source_tool;
    ev.inst_id = inst_id;
    ev.data = data.is_null() ? json::object() : data;
    ev.verified = verified;
    ev.timestamp = now_timestamp();

    if (supports)
        h.evidence_for.push_back(std::move(ev));
    else
        h.evidence_against.push_back(std::move(ev));

    h.updated_at = now_timestamp();
    h.confidence = compute_confidence(h);

    return {{"id", hid},
            {"evidence_count", h.evidence_for.size() + h.evidence_against.size()},
            {"confidence", h.confidence},
            {"verified", verified}};
}

json HypothesisLedger::conclude(const std::string& hid, const std::string& conclusion) {
    auto it = hypotheses_.find(hid);
    if (it == hypotheses_.end())
        return {{"error", "Hypothesis " + hid + " not found"}};
    auto& h = it->second;
    if (h.status != HypothesisStatus::Active)
        return {{"error", "Can only conclude ACTIVE hypotheses (current: " +
                          std::string(status_str(h.status)) + ")"}};

    // Anti-hallucination: need verified evidence
    int verified_count = 0;
    for (const auto& e : h.evidence_for)
        if (e.verified) verified_count++;
    if (verified_count == 0) {
        return {{"error", "Cannot conclude without verified evidence. "
                          "Use verify_evidence tool first, then add_evidence with verified=true."},
                {"evidence_for_count", h.evidence_for.size()},
                {"verified_count", 0},
                {"hint", "Call verify_evidence to validate your observations, then re-add as verified"}};
    }

    // Conflict check
    for (const auto& cid : h.conflicts_with) {
        auto cit = hypotheses_.find(cid);
        if (cit != hypotheses_.end() && cit->second.status == HypothesisStatus::Concluded) {
            return {{"error", "Conflict: " + cid + " is already concluded. "
                              "Cannot conclude contradicting hypothesis."},
                    {"conflicting_hypothesis", cid},
                    {"conflict_statement", cit->second.statement}};
        }
    }

    h.status = HypothesisStatus::Concluded;
    h.conclusion = conclusion;
    h.updated_at = now_timestamp();

    return {{"id", hid},
            {"status", "concluded"},
            {"conclusion", conclusion},
            {"confidence", h.confidence},
            {"evidence_count", h.evidence_for.size()}};
}

json HypothesisLedger::abandon(const std::string& hid, const std::string& reason) {
    auto it = hypotheses_.find(hid);
    if (it == hypotheses_.end())
        return {{"error", "Hypothesis " + hid + " not found"}};
    auto& h = it->second;
    if (h.status == HypothesisStatus::Concluded)
        return {{"error", "Cannot abandon a concluded hypothesis. Use reopen first."}};

    h.status = HypothesisStatus::Abandoned;
    h.conclusion = "ABANDONED: " + reason;
    h.updated_at = now_timestamp();
    return {{"id", hid}, {"status", "abandoned"}, {"reason", reason}};
}

json HypothesisLedger::list_all(const std::string& status_filter) const {
    json results = json::array();
    int count_proposed = 0, count_active = 0, count_concluded = 0, count_abandoned = 0;

    for (const auto& [id, h] : hypotheses_) {
        switch (h.status) {
            case HypothesisStatus::Proposed:  count_proposed++;  break;
            case HypothesisStatus::Active:    count_active++;    break;
            case HypothesisStatus::Concluded: count_concluded++; break;
            case HypothesisStatus::Abandoned: count_abandoned++; break;
        }
        if (!status_filter.empty() && status_str(h.status) != status_filter)
            continue;

        int verified_evidence = 0;
        for (const auto& e : h.evidence_for)
            if (e.verified) verified_evidence++;

        results.push_back({
            {"id", h.id},
            {"statement", h.statement},
            {"category", h.category},
            {"status", status_str(h.status)},
            {"confidence", h.confidence},
            {"evidence_for", h.evidence_for.size()},
            {"evidence_against", h.evidence_against.size()},
            {"verified_evidence", verified_evidence},
            {"conflicts_with", h.conflicts_with},
            {"reviewed", h.reviewed}
        });
    }

    size_t total = hypotheses_.size();
    return {{"hypotheses", std::move(results)},
            {"total", total},
            {"by_status", {
                {"proposed",  count_proposed},
                {"active",    count_active},
                {"concluded", count_concluded},
                {"abandoned", count_abandoned}
            }}};
}

json HypothesisLedger::get(const std::string& hid) const {
    auto it = hypotheses_.find(hid);
    if (it == hypotheses_.end())
        return {{"error", "Hypothesis " + hid + " not found"}};
    const auto& h = it->second;

    json ev_for = json::array();
    for (const auto& e : h.evidence_for) {
        json ej = {
            {"description", e.description},
            {"source_tool", e.source_tool},
            {"verified", e.verified},
            {"timestamp", e.timestamp}
        };
        if (e.inst_id.has_value()) ej["inst_id"] = e.inst_id.value();
        ev_for.push_back(std::move(ej));
    }

    json ev_against = json::array();
    for (const auto& e : h.evidence_against) {
        json ej = {
            {"description", e.description},
            {"source_tool", e.source_tool},
            {"verified", e.verified},
            {"timestamp", e.timestamp}
        };
        if (e.inst_id.has_value()) ej["inst_id"] = e.inst_id.value();
        ev_against.push_back(std::move(ej));
    }

    json result = {
        {"id", h.id},
        {"statement", h.statement},
        {"category", h.category},
        {"status", status_str(h.status)},
        {"confidence", h.confidence},
        {"conflicts_with", h.conflicts_with},
        {"reviewed", h.reviewed},
        {"created_at", h.created_at},
        {"updated_at", h.updated_at},
        {"evidence_for", std::move(ev_for)},
        {"evidence_against", std::move(ev_against)}
    };
    if (h.conclusion.has_value()) result["conclusion"] = h.conclusion.value();
    return result;
}

json HypothesisLedger::mark_reviewed(const std::string& hid) {
    auto it = hypotheses_.find(hid);
    if (it == hypotheses_.end())
        return {{"error", "Hypothesis " + hid + " not found"}};
    auto& h = it->second;
    if (h.status != HypothesisStatus::Concluded &&
        h.status != HypothesisStatus::Abandoned)
        return {{"error", "Cannot mark_reviewed: hypothesis " + hid +
                           " is still " + status_str(h.status) +
                           " (must be concluded or abandoned)"}};
    h.reviewed = true;
    h.updated_at = now_timestamp();
    return {{"id", hid}, {"reviewed", true}};
}

double HypothesisLedger::compute_confidence(const Hypothesis& h) const {
    if (h.evidence_for.empty() && h.evidence_against.empty())
        return 0.0;

    int verified_for = 0, unverified_for = 0;
    for (const auto& e : h.evidence_for) {
        if (e.verified) verified_for++;
        else unverified_for++;
    }
    int against = static_cast<int>(h.evidence_against.size());

    // Verified evidence counts 3x, unverified 1x, against -2x
    double score = verified_for * 3.0 + unverified_for * 1.0 - against * 2.0;
    double max_possible = (verified_for + unverified_for) * 3.0 + 1.0;

    double conf = std::max(0.0, std::min(1.0, score / max_possible));
    return std::round(conf * 1000.0) / 1000.0;
}

}  // namespace tenet
