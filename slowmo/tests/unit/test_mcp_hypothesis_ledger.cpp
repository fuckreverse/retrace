/*
 * test_mcp_hypothesis_ledger.cpp -- Unit tests for tenet::HypothesisLedger
 *
 * Verifies the state machine lifecycle: Proposed -> Active -> Concluded/Abandoned,
 * conflict detection, evidence management, confidence scoring, and anti-hallucination
 * guards (e.g. cannot conclude without verified evidence).
 *
 * Pure unit tests -- no trace data needed.
 */
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include "io/mcp/hypothesis_ledger.h"

using namespace tenet;
using json = nlohmann::json;

// ═════════════════════════════════════════════════════════════════════════════
// Basic lifecycle
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: add creates a proposed hypothesis", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto result = ledger.add("x0 contains an AES key");

    REQUIRE(result.contains("id"));
    REQUIRE(result["id"].get<std::string>() == "H001");
    REQUIRE(result["status"] == "proposed");
    REQUIRE(result["statement"] == "x0 contains an AES key");
}

TEST_CASE("HypothesisLedger: sequential IDs", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r1 = ledger.add("first");
    auto r2 = ledger.add("second");
    auto r3 = ledger.add("third");

    REQUIRE(r1["id"] == "H001");
    REQUIRE(r2["id"] == "H002");
    REQUIRE(r3["id"] == "H003");
}

TEST_CASE("HypothesisLedger: activate transitions proposed -> active", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis A");
    std::string hid = r["id"];

    auto act = ledger.activate(hid);
    REQUIRE(act["status"] == "active");

    // Verify via get
    auto detail = ledger.get(hid);
    REQUIRE(detail["status"] == "active");
}

TEST_CASE("HypothesisLedger: cannot activate non-proposed hypothesis", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];

    ledger.activate(hid);
    // Try activating again (already active)
    auto act2 = ledger.activate(hid);
    REQUIRE(act2.contains("error"));
}

TEST_CASE("HypothesisLedger: activate nonexistent ID returns error", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto result = ledger.activate("H999");
    REQUIRE(result.contains("error"));
}

// ═════════════════════════════════════════════════════════════════════════════
// Evidence
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: add_evidence auto-activates proposed hypothesis",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];

    // Should be proposed; adding evidence auto-activates
    auto ev = ledger.add_evidence(hid, "x0 = 0xDEAD at inst 42", "get_regs",
                                   42, json{{"x0", "0xDEAD"}}, true, false);
    REQUIRE_FALSE(ev.contains("error"));
    REQUIRE(ev["evidence_count"] == 1);

    auto detail = ledger.get(hid);
    REQUIRE(detail["status"] == "active");
}

TEST_CASE("HypothesisLedger: supporting and contradicting evidence", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];

    // Supporting evidence
    ledger.add_evidence(hid, "supports", "disasm", std::nullopt, nullptr, true, false);
    // Contradicting evidence
    ledger.add_evidence(hid, "contradicts", "memread", std::nullopt, nullptr, false, false);

    auto detail = ledger.get(hid);
    REQUIRE(detail["evidence_for"].size() == 1);
    REQUIRE(detail["evidence_against"].size() == 1);
}

TEST_CASE("HypothesisLedger: cannot add evidence to concluded hypothesis",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];
    ledger.activate(hid);
    // Add verified evidence so conclude works
    ledger.add_evidence(hid, "verified data", "get_regs", 0, nullptr, true, true);
    ledger.conclude(hid, "confirmed");

    auto ev = ledger.add_evidence(hid, "late evidence", "memread");
    REQUIRE(ev.contains("error"));
}

TEST_CASE("HypothesisLedger: cannot add evidence to abandoned hypothesis",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];
    ledger.abandon(hid, "disproved");

    auto ev = ledger.add_evidence(hid, "late evidence", "memread");
    REQUIRE(ev.contains("error"));
}

// ═════════════════════════════════════════════════════════════════════════════
// Conclude -- anti-hallucination guards
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: conclude requires verified evidence",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];
    ledger.activate(hid);

    SECTION("no evidence at all") {
        auto res = ledger.conclude(hid, "conclusion");
        REQUIRE(res.contains("error"));
        REQUIRE(res["verified_count"] == 0);
    }

    SECTION("unverified evidence only") {
        ledger.add_evidence(hid, "unverified claim", "disasm", 10, nullptr, true, false);
        auto res = ledger.conclude(hid, "conclusion");
        REQUIRE(res.contains("error"));
        // evidence_for_count should be 1, verified_count should be 0
        REQUIRE(res["evidence_for_count"] == 1);
        REQUIRE(res["verified_count"] == 0);
    }

    SECTION("with verified evidence succeeds") {
        ledger.add_evidence(hid, "verified claim", "get_regs", 10, nullptr, true, true);
        auto res = ledger.conclude(hid, "it is AES-128");
        REQUIRE_FALSE(res.contains("error"));
        REQUIRE(res["status"] == "concluded");
        REQUIRE(res["conclusion"] == "it is AES-128");
    }
}

TEST_CASE("HypothesisLedger: can only conclude active hypothesis",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];

    // Still proposed -- cannot conclude
    auto res = ledger.conclude(hid, "nope");
    REQUIRE(res.contains("error"));
}

// ═════════════════════════════════════════════════════════════════════════════
// Conflict detection
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: conflict prevents concluding both",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r1 = ledger.add("It is AES-128", "crypto_algorithm");
    auto r2 = ledger.add("It is ChaCha20", "crypto_algorithm", {r1["id"]});
    std::string h1 = r1["id"];
    std::string h2 = r2["id"];

    // Conclude H1
    ledger.activate(h1);
    ledger.add_evidence(h1, "AES S-box found", "constants_scan", 100, nullptr, true, true);
    auto c1 = ledger.conclude(h1, "Confirmed AES-128");
    REQUIRE_FALSE(c1.contains("error"));

    // Try to conclude H2 -- should fail due to conflict
    ledger.activate(h2);
    ledger.add_evidence(h2, "quarter round", "loop_semantics", 200, nullptr, true, true);
    auto c2 = ledger.conclude(h2, "Confirmed ChaCha20");
    REQUIRE(c2.contains("error"));
    REQUIRE(c2.contains("conflicting_hypothesis"));
    REQUIRE(c2["conflicting_hypothesis"] == h1);
}

TEST_CASE("HypothesisLedger: bidirectional conflict registration",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r1 = ledger.add("A");
    auto r2 = ledger.add("B", "general", {r1["id"]});

    // Check H1 also knows about H2
    auto detail1 = ledger.get(r1["id"]);
    auto conflicts = detail1["conflicts_with"];
    bool found = false;
    for (const auto& c : conflicts) {
        if (c.get<std::string>() == r2["id"].get<std::string>()) found = true;
    }
    REQUIRE(found);
}

// ═════════════════════════════════════════════════════════════════════════════
// Abandon
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: abandon sets status and reason", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("bad hypothesis");
    std::string hid = r["id"];

    auto res = ledger.abandon(hid, "evidence disproved it");
    REQUIRE(res["status"] == "abandoned");
    REQUIRE(res["reason"] == "evidence disproved it");

    auto detail = ledger.get(hid);
    REQUIRE(detail["status"] == "abandoned");
    REQUIRE(detail["conclusion"].get<std::string>().find("ABANDONED") != std::string::npos);
}

TEST_CASE("HypothesisLedger: cannot abandon concluded hypothesis",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];
    ledger.activate(hid);
    ledger.add_evidence(hid, "proof", "get_regs", 0, nullptr, true, true);
    ledger.conclude(hid, "done");

    auto res = ledger.abandon(hid, "too late");
    REQUIRE(res.contains("error"));
}

// ═════════════════════════════════════════════════════════════════════════════
// List and filter
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: list_all returns all hypotheses", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    ledger.add("H1");
    ledger.add("H2");
    ledger.add("H3");

    auto list = ledger.list_all();
    REQUIRE(list["total"] == 3);
    REQUIRE(list["hypotheses"].size() == 3);
    REQUIRE(list["by_status"]["proposed"] == 3);
}

TEST_CASE("HypothesisLedger: list_all filters by status", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r1 = ledger.add("stay proposed");
    auto r2 = ledger.add("will activate");
    ledger.activate(r2["id"]);

    auto proposed = ledger.list_all("proposed");
    REQUIRE(proposed["hypotheses"].size() == 1);
    REQUIRE(proposed["hypotheses"][0]["id"] == r1["id"]);

    auto active = ledger.list_all("active");
    REQUIRE(active["hypotheses"].size() == 1);
    REQUIRE(active["hypotheses"][0]["id"] == r2["id"]);
}

// ═════════════════════════════════════════════════════════════════════════════
// Confidence scoring
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: confidence increases with verified evidence",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];

    // No evidence: confidence = 0
    auto detail0 = ledger.get(hid);
    REQUIRE(detail0["confidence"].get<double>() == 0.0);

    // Unverified evidence: some confidence
    auto ev1 = ledger.add_evidence(hid, "unverified", "disasm", 0, nullptr, true, false);
    double conf1 = ev1["confidence"].get<double>();
    REQUIRE(conf1 > 0.0);

    // Verified evidence: higher confidence
    auto ev2 = ledger.add_evidence(hid, "verified", "get_regs", 1, nullptr, true, true);
    double conf2 = ev2["confidence"].get<double>();
    REQUIRE(conf2 > conf1);
}

TEST_CASE("HypothesisLedger: contradicting evidence lowers confidence",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];

    ledger.add_evidence(hid, "supports", "disasm", 0, nullptr, true, true);
    auto ev_for = ledger.get(hid);
    double conf_before = ev_for["confidence"].get<double>();

    ledger.add_evidence(hid, "contradicts", "memread", 1, nullptr, false, false);
    auto ev_against = ledger.get(hid);
    double conf_after = ev_against["confidence"].get<double>();

    REQUIRE(conf_after < conf_before);
}

// ═════════════════════════════════════════════════════════════════════════════
// Get and mark_reviewed
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: get returns full details", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("detailed hypothesis", "crypto_algorithm");
    std::string hid = r["id"];
    ledger.activate(hid);
    ledger.add_evidence(hid, "evidence A", "taint_forward", 42,
                         json{{"tainted_regs", json::array({"x0", "x1"})}}, true, true);

    auto detail = ledger.get(hid);
    REQUIRE(detail["id"] == hid);
    REQUIRE(detail["statement"] == "detailed hypothesis");
    REQUIRE(detail["category"] == "crypto_algorithm");
    REQUIRE(detail["status"] == "active");
    REQUIRE(detail["evidence_for"].size() == 1);
    REQUIRE(detail["evidence_for"][0]["source_tool"] == "taint_forward");
    REQUIRE(detail["evidence_for"][0]["inst_id"] == 42);
    REQUIRE(detail["evidence_for"][0]["verified"] == true);
    REQUIRE(detail["reviewed"] == false);
}

TEST_CASE("HypothesisLedger: get nonexistent ID returns error", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto result = ledger.get("H999");
    REQUIRE(result.contains("error"));
}

TEST_CASE("HypothesisLedger: mark_reviewed rejects active hypothesis", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];

    // Active hypothesis cannot be reviewed
    auto res = ledger.mark_reviewed(hid);
    REQUIRE(res.contains("error"));
}

TEST_CASE("HypothesisLedger: mark_reviewed sets reviewed flag on concluded", "[unit][mcp][ledger]") {
    HypothesisLedger ledger;
    auto r = ledger.add("hypothesis");
    std::string hid = r["id"];
    ledger.activate(hid);
    ledger.add_evidence(hid, "evidence", "tool", std::nullopt, nullptr, true, true);
    ledger.conclude(hid, "confirmed");

    auto res = ledger.mark_reviewed(hid);
    REQUIRE(res["reviewed"] == true);

    auto detail = ledger.get(hid);
    REQUIRE(detail["reviewed"] == true);
}

// ═════════════════════════════════════════════════════════════════════════════
// Full workflow: propose -> activate -> evidence -> verify -> conclude
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HypothesisLedger: complete anti-hallucination workflow",
          "[unit][mcp][ledger]") {
    HypothesisLedger ledger;

    // Step 1: Propose
    auto h = ledger.add("Function at 0x1000 is AES-128 encryption",
                         "crypto_algorithm");
    std::string hid = h["id"];

    // Step 2: Activate
    ledger.activate(hid);

    // Step 3: Add unverified evidence (from tool observation)
    ledger.add_evidence(hid, "S-box constant 0x637C777B found at inst 100",
                         "constants_scan", 100,
                         json{{"constant", "0x637C777B"}}, true, false);

    // Step 4: Cannot conclude yet (no verified evidence)
    auto premature = ledger.conclude(hid, "It's AES");
    REQUIRE(premature.contains("error"));

    // Step 5: Mark evidence as verified (after verify_evidence check)
    ledger.add_evidence(hid, "S-box confirmed via verify_evidence",
                         "verify_evidence", 100,
                         json{{"check_type", "memory"}, {"valid", true}}, true, true);

    // Step 6: Now conclude succeeds
    auto concluded = ledger.conclude(hid, "Confirmed AES-128 encryption");
    REQUIRE_FALSE(concluded.contains("error"));
    REQUIRE(concluded["status"] == "concluded");

    // Step 7: Mark as reviewed
    ledger.mark_reviewed(hid);
    auto final_state = ledger.get(hid);
    REQUIRE(final_state["status"] == "concluded");
    REQUIRE(final_state["reviewed"] == true);
    REQUIRE(final_state["conclusion"] == "Confirmed AES-128 encryption");
}
