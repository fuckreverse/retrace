/*
 * test_mcp_tools_ai.cpp -- Unit tests for verify_evidence and batch_query tools
 *
 * Uses a synthetic trace (via trace_fixture.h) and constructs a TenetMcpService
 * to exercise the tool handlers through the public call_tool() API.
 *
 * Covers:
 *   - verify_evidence: register, memory, and instruction checks (pass/fail)
 *   - batch_query: multi-tool batching, error isolation, limit enforcement
 *   - hypothesis tools via MCP service: end-to-end workflow through call_tool()
 */
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstring>
#include <thread>

#include "fixtures/trace_fixture.h"
#include "io/mcp/mcp_server.h"
#include "io/mcp/mcp_helpers.h"

using namespace tenet;
using namespace tenet::test;
using json = nlohmann::json;

// ─── Fixture: build a trace with known register values, memory writes,
//     and identifiable instructions ──────────────────────────────────────

struct McpTestEnv {
    std::unique_ptr<TraceEnv> env;
    std::unique_ptr<PassManager> pm;
    std::unique_ptr<TenetMcpService> mcp;
};

static McpTestEnv make_mcp_env() {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);

        // inst 0: x0 = 0xDEADBEEF (movz x0, #0xBEEF)
        tw.emit(ms, 0x1000, enc::movz(0, 0xBEEF),
                {{0, 0xDEADBEEFULL}, {33, tw.rt(0x1004)}}, {});

        // inst 1: x1 = 0x42 (movz x1, #0x42)
        tw.emit(ms, 0x1004, enc::movz(1, 0x42),
                {{1, 0x42ULL}, {33, tw.rt(0x1008)}}, {});

        // inst 2: store x0 to [sp], producing a memory write
        //   memory write: 8 bytes at sp (0x7F000000) = 0xDEADBEEF
        tw.emit(ms, 0x1008, enc::str_imm(0, 31, 0),
                {{33, tw.rt(0x100C)}},
                {{2 /* WRITE */, 8, 0x7F000000ULL, 0xDEADBEEFULL}});

        // inst 3: nop
        tw.emit(ms, 0x100C, enc::nop(),
                {{33, tw.rt(0x1010)}}, {});

        tw.emit_anchor(ms);
    }, "mcp_ai_test");

    McpTestEnv result;
    result.env = std::move(env);
    result.pm = make_pm(*result.env);
    result.mcp = std::make_unique<TenetMcpService>(
        *result.env->reader, *result.env->index,
        *result.env->regfile, *result.env->memory,
        result.pm.get(),
        &result.env->code_table, &result.env->decoder);
    return result;
}

// ═════════════════════════════════════════════════════════════════════════════
// verify_evidence: register checks
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("verify_evidence: register check passes with correct value",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "register"}, {"inst_id", 1}, {"register", "x0"},
             {"expected_value", "0xDEADBEEF"}}
        })}
    });

    REQUIRE(result["all_valid"] == true);
    REQUIRE(result["checks_passed"] == 1);
    REQUIRE(result["results"][0]["valid"] == true);
}

TEST_CASE("verify_evidence: register check fails with wrong value",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "register"}, {"inst_id", 1}, {"register", "x0"},
             {"expected_value", "0xCAFEBABE"}}
        })}
    });

    REQUIRE(result["all_valid"] == false);
    REQUIRE(result["checks_passed"] == 0);
    REQUIRE(result["results"][0]["valid"] == false);
    REQUIRE(result["results"][0].contains("reason"));
}

TEST_CASE("verify_evidence: register check with unknown register name",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "register"}, {"inst_id", 0}, {"register", "q0"},
             {"expected_value", "0x0"}}
        })}
    });

    REQUIRE(result["all_valid"] == false);
    REQUIRE(result["results"][0]["valid"] == false);
    REQUIRE(result["results"][0]["reason"].get<std::string>().find("Unknown register") !=
            std::string::npos);
}

TEST_CASE("verify_evidence: register check with unparseable hex value",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "register"}, {"inst_id", 0}, {"register", "x0"},
             {"expected_value", "not_hex"}}
        })}
    });

    REQUIRE(result["all_valid"] == false);
    REQUIRE(result["results"][0]["valid"] == false);
}

// ═════════════════════════════════════════════════════════════════════════════
// verify_evidence: memory checks
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("verify_evidence: memory check passes with correct bytes",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    // After inst 2 (str x0, [sp]), memory at 0x7F000000 should contain
    // little-endian 0xDEADBEEF = ef be ad de ...
    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "memory"}, {"inst_id", 3},
             {"address", "0x7F000000"}, {"expected_bytes", "efbeadde"}}
        })}
    });

    REQUIRE(result["checks_passed"] == 1);
    REQUIRE(result["results"][0]["valid"] == true);
}

TEST_CASE("verify_evidence: memory check fails with wrong bytes",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "memory"}, {"inst_id", 3},
             {"address", "0x7F000000"}, {"expected_bytes", "00000000"}}
        })}
    });

    REQUIRE(result["all_valid"] == false);
    REQUIRE(result["results"][0]["valid"] == false);
}

// ═════════════════════════════════════════════════════════════════════════════
// verify_evidence: instruction checks
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("verify_evidence: instruction PC check passes",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

// inst 0 is at static 0x1000, runtime = 0x1000 + slide(0x4000) = 0x5000
// rebased with default image_base=0x100000000: 0x1000 + 0x100000000 = 0x100001000
auto result = ctx.mcp->call_tool("verify_evidence", {
{"checks", json::array({
{{"type", "instruction"}, {"inst_id", 0},
{"expected_pc", "0x100001000"}}
        })}
    });

    REQUIRE(result["all_valid"] == true);
    REQUIRE(result["results"][0]["valid"] == true);
}

TEST_CASE("verify_evidence: instruction PC check fails with wrong PC",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "instruction"}, {"inst_id", 0},
             {"expected_pc", "0x9999"}}
        })}
    });

    REQUIRE(result["all_valid"] == false);
    REQUIRE(result["results"][0]["valid"] == false);
}

TEST_CASE("verify_evidence: instruction mnemonic check (movz)",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    // inst 0 should be "movz" (or "mov" -- capstone may normalize it)
    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "instruction"}, {"inst_id", 0},
             {"expected_mnemonic", "mov"}}
        })}
    });

    REQUIRE(result["results"][0]["valid"] == true);
}

TEST_CASE("verify_evidence: instruction mnemonic check fails",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    // inst 3 is a nop, not "str"
    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "instruction"}, {"inst_id", 3},
             {"expected_mnemonic", "str"}}
        })}
    });

    REQUIRE(result["results"][0]["valid"] == false);
}

// ═════════════════════════════════════════════════════════════════════════════
// verify_evidence: multiple checks in one call
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("verify_evidence: multiple checks, mixed pass/fail",
          "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            // Check 0: passes (correct register value)
            {{"type", "register"}, {"inst_id", 1}, {"register", "x0"},
             {"expected_value", "0xDEADBEEF"}},
            // Check 1: fails (wrong register value)
            {{"type", "register"}, {"inst_id", 1}, {"register", "x1"},
             {"expected_value", "0xFFFF"}},
            // Check 2: passes (correct PC, rebased: 0x100001000)
            {{"type", "instruction"}, {"inst_id", 0},
             {"expected_pc", "0x100001000"}}
        })}
    });

    REQUIRE(result["all_valid"] == false);
    REQUIRE(result["checks_passed"] == 2);
    REQUIRE(result["checks_total"] == 3);
    REQUIRE(result["results"][0]["valid"] == true);
    REQUIRE(result["results"][1]["valid"] == false);
    REQUIRE(result["results"][2]["valid"] == true);
}

TEST_CASE("verify_evidence: unknown check type", "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("verify_evidence", {
        {"checks", json::array({
            {{"type", "magic_8_ball"}, {"inst_id", 0}}
        })}
    });

    REQUIRE(result["all_valid"] == false);
    REQUIRE(result["results"][0]["valid"] == false);
}

TEST_CASE("verify_evidence: empty checks array throws", "[unit][mcp][verify_evidence]") {
    auto ctx = make_mcp_env();
    REQUIRE_THROWS(ctx.mcp->call_tool("verify_evidence", {{"checks", json::array()}}));
}

// ═════════════════════════════════════════════════════════════════════════════
// batch_query
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("batch_query: single query works", "[unit][mcp][batch_query]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("batch_query", {
        {"queries", json::array({
            {{"tool", "trace_info"}, {"params", json::object()}}
        })}
    });

    REQUIRE(result["batch_size"] == 1);
    REQUIRE(result["errors"] == 0);
    REQUIRE(result["results"][0].contains("result"));
    REQUIRE(result["results"][0]["tool"] == "trace_info");
}

TEST_CASE("batch_query: multiple heterogeneous queries", "[unit][mcp][batch_query]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("batch_query", {
        {"queries", json::array({
            {{"tool", "trace_info"}, {"params", json::object()}},
            {{"tool", "get_regs"}, {"params", {{"inst_id", 0}}}}
        })}
    });

    REQUIRE(result["batch_size"] == 2);
    REQUIRE(result["errors"] == 0);
    // Both should have results, not errors
    for (int i = 0; i < 2; i++) {
        REQUIRE(result["results"][i].contains("result"));
        REQUIRE_FALSE(result["results"][i].contains("error"));
    }
}

TEST_CASE("batch_query: unknown tool name returns error without crashing others",
          "[unit][mcp][batch_query]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("batch_query", {
        {"queries", json::array({
            {{"tool", "trace_info"}, {"params", json::object()}},
            {{"tool", "nonexistent_tool"}, {"params", json::object()}},
            {{"tool", "trace_info"}, {"params", json::object()}}
        })}
    });

    REQUIRE(result["batch_size"] == 3);
    REQUIRE(result["errors"] == 1);
    // First and third succeed
    REQUIRE(result["results"][0].contains("result"));
    REQUIRE(result["results"][2].contains("result"));
    // Second fails with error
    REQUIRE(result["results"][1].contains("error"));
    REQUIRE(result["results"][1]["error"].get<std::string>().find("Unknown tool") !=
            std::string::npos);
}

TEST_CASE("batch_query: tool exception is caught and isolated",
          "[unit][mcp][batch_query]") {
    auto ctx = make_mcp_env();

    // verify_evidence with empty checks throws
    auto result = ctx.mcp->call_tool("batch_query", {
        {"queries", json::array({
            {{"tool", "trace_info"}, {"params", json::object()}},
            {{"tool", "verify_evidence"}, {"params", {{"checks", json::array()}}}},
            {{"tool", "trace_info"}, {"params", json::object()}}
        })}
    });

    REQUIRE(result["errors"] == 1);
    // First and third still succeed
    REQUIRE(result["results"][0].contains("result"));
    REQUIRE(result["results"][2].contains("result"));
    // Second has error
    REQUIRE(result["results"][1].contains("error"));
}

TEST_CASE("batch_query: empty queries throws", "[unit][mcp][batch_query]") {
    auto ctx = make_mcp_env();
    REQUIRE_THROWS(ctx.mcp->call_tool("batch_query",
                   {{"queries", json::array()}}));
}

TEST_CASE("batch_query: over 20 queries throws", "[unit][mcp][batch_query]") {
    auto ctx = make_mcp_env();

    json queries = json::array();
    for (int i = 0; i < 21; i++) {
        queries.push_back({{"tool", "trace_info"}, {"params", json::object()}});
    }
    REQUIRE_THROWS(ctx.mcp->call_tool("batch_query", {{"queries", queries}}));
}

// ═════════════════════════════════════════════════════════════════════════════
// batch_query: nested batch is NOT supported (batch_query calling batch_query)
// but should not crash -- it would just run
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("batch_query: can call hypothesis tools", "[unit][mcp][batch_query]") {
    auto ctx = make_mcp_env();

    auto result = ctx.mcp->call_tool("batch_query", {
        {"queries", json::array({
            {{"tool", "hypothesis_add"},
             {"params", {{"statement", "test hypothesis"}}}},
            {{"tool", "hypothesis_list"},
             {"params", json::object()}}
        })}
    });

    REQUIRE(result["errors"] == 0);
    // hypothesis_add should return an ID
    auto add_result = result["results"][0]["result"];
    REQUIRE(add_result.contains("id"));
    // hypothesis_list should show total >= 1
    auto list_result = result["results"][1]["result"];
    REQUIRE(list_result["total"].get<int>() >= 1);
}

// ═════════════════════════════════════════════════════════════════════════════
// Hypothesis tools via MCP service (end-to-end through call_tool)
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("MCP hypothesis tools: full workflow via call_tool",
          "[unit][mcp][hypothesis]") {
    auto ctx = make_mcp_env();

    // Add (auto-activates)
    auto h = ctx.mcp->call_tool("hypothesis_add", {
        {"statement", "Function encrypts with AES"},
        {"category", "crypto_algorithm"}
    });
    REQUIRE(h.contains("id"));
    REQUIRE(h["status"] == "active");
    std::string hid = h["id"];

    // Add evidence (unverified)
    ctx.mcp->call_tool("hypothesis_evidence", {
        {"id", hid}, {"description", "S-box match"},
        {"source_tool", "constants_scan"}, {"inst_id", 0},
        {"supports", true}, {"verified", false}
    });

    // Cannot conclude without verified evidence
    auto premature = ctx.mcp->call_tool("hypothesis_conclude", {
        {"id", hid}, {"conclusion", "It's AES"}
    });
    REQUIRE(premature.contains("error"));

    // Add verified evidence
    ctx.mcp->call_tool("hypothesis_evidence", {
        {"id", hid}, {"description", "verified via verify_evidence"},
        {"source_tool", "verify_evidence"}, {"inst_id", 0},
        {"supports", true}, {"verified", true}
    });

    // Conclude
    auto concluded = ctx.mcp->call_tool("hypothesis_conclude", {
        {"id", hid}, {"conclusion", "Confirmed AES-128"}
    });
    REQUIRE(concluded["status"] == "concluded");

    // Get full details
    auto detail = ctx.mcp->call_tool("hypothesis_get", {{"id", hid}});
    REQUIRE(detail["status"] == "concluded");
    REQUIRE(detail["conclusion"] == "Confirmed AES-128");
    REQUIRE(detail["evidence_for"].size() == 2);
    REQUIRE(detail["reviewed"] == false);

    // Mark reviewed
    auto rev = ctx.mcp->call_tool("hypothesis_mark_reviewed", {{"id", hid}});
    REQUIRE(rev["reviewed"] == true);

    // Verify reviewed flag persisted
    auto after_rev = ctx.mcp->call_tool("hypothesis_get", {{"id", hid}});
    REQUIRE(after_rev["reviewed"] == true);
}

TEST_CASE("MCP hypothesis tools: abandon workflow", "[unit][mcp][hypothesis]") {
    auto ctx = make_mcp_env();

    auto h = ctx.mcp->call_tool("hypothesis_add", {
        {"statement", "Uses RC4 stream cipher"}
    });
    std::string hid = h["id"];

    auto res = ctx.mcp->call_tool("hypothesis_abandon", {
        {"id", hid}, {"reason", "No evidence of key scheduling"}
    });
    REQUIRE(res["status"] == "abandoned");

    auto list = ctx.mcp->call_tool("hypothesis_list", {{"status", "abandoned"}});
    REQUIRE(list["hypotheses"].size() == 1);
}

TEST_CASE("MCP hypothesis tools: conflict via call_tool",
          "[unit][mcp][hypothesis]") {
    auto ctx = make_mcp_env();

    // hypothesis_add auto-activates
    auto h1 = ctx.mcp->call_tool("hypothesis_add", {
        {"statement", "AES encryption"},
        {"category", "crypto_algorithm"}
    });
    auto h2 = ctx.mcp->call_tool("hypothesis_add", {
        {"statement", "ChaCha20 encryption"},
        {"category", "crypto_algorithm"},
        {"conflicts_with", json::array({h1["id"]})}
    });

    // Conclude h1 (already active from add)
    ctx.mcp->call_tool("hypothesis_evidence", {
        {"id", h1["id"]}, {"description", "verified"}, {"source_tool", "test"},
        {"supports", true}, {"verified", true}
    });
    ctx.mcp->call_tool("hypothesis_conclude", {
        {"id", h1["id"]}, {"conclusion", "AES confirmed"}
    });

    // Try to conclude h2 (also already active from add) -- should fail
    ctx.mcp->call_tool("hypothesis_evidence", {
        {"id", h2["id"]}, {"description", "verified"}, {"source_tool", "test"},
        {"supports", true}, {"verified", true}
    });
    auto c2 = ctx.mcp->call_tool("hypothesis_conclude", {
        {"id", h2["id"]}, {"conclusion", "ChaCha20 confirmed"}
    });
    REQUIRE(c2.contains("error"));
    REQUIRE(c2.contains("conflicting_hypothesis"));
}

// ═════════════════════════════════════════════════════════════════════════════
// hypothesis_mark_reviewed edge cases
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("MCP hypothesis_mark_reviewed: cannot review non-concluded",
          "[unit][mcp][hypothesis]") {
    auto ctx = make_mcp_env();

    auto h = ctx.mcp->call_tool("hypothesis_add", {
        {"statement", "Uses Blowfish cipher"}
    });
    std::string hid = h["id"];

    // Active hypothesis cannot be marked reviewed
    auto res = ctx.mcp->call_tool("hypothesis_mark_reviewed", {{"id", hid}});
    REQUIRE(res.contains("error"));
}

TEST_CASE("MCP hypothesis_mark_reviewed: idempotent on concluded",
          "[unit][mcp][hypothesis]") {
    auto ctx = make_mcp_env();

    auto h = ctx.mcp->call_tool("hypothesis_add", {
        {"statement", "Uses DES encryption"}
    });
    std::string hid = h["id"];

    // Add verified evidence then conclude
    ctx.mcp->call_tool("hypothesis_evidence", {
        {"id", hid}, {"description", "DES key schedule detected"},
        {"source_tool", "pattern_detect"}, {"supports", true}, {"verified", true}
    });
    ctx.mcp->call_tool("hypothesis_conclude", {
        {"id", hid}, {"conclusion", "DES confirmed"}
    });

    // First review
    auto r1 = ctx.mcp->call_tool("hypothesis_mark_reviewed", {{"id", hid}});
    REQUIRE(r1["reviewed"] == true);

    // Second review is idempotent
    auto r2 = ctx.mcp->call_tool("hypothesis_mark_reviewed", {{"id", hid}});
    REQUIRE(r2["reviewed"] == true);
}

TEST_CASE("MCP hypothesis_mark_reviewed: works on abandoned hypothesis",
          "[unit][mcp][hypothesis]") {
    auto ctx = make_mcp_env();

    auto h = ctx.mcp->call_tool("hypothesis_add", {
        {"statement", "Uses Twofish cipher"}
    });
    std::string hid = h["id"];

    ctx.mcp->call_tool("hypothesis_abandon", {
        {"id", hid}, {"reason", "No supporting evidence found"}
    });

    // Abandoned hypothesis should also be reviewable
    auto res = ctx.mcp->call_tool("hypothesis_mark_reviewed", {{"id", hid}});
    REQUIRE(res["reviewed"] == true);
}

// ═════════════════════════════════════════════════════════════════════════════
// mem_search: hex_pattern / text wildcard-mask regression tests
// ═════════════════════════════════════════════════════════════════════════════
//
// Regression coverage for a bug where the mem_search MCP tool's hex_pattern/
// text parsing inverted MemSearchConfig::Pattern's mask semantics: concrete
// bytes were marked as wildcards (0xFF, i.e. "ignored") and "??" placeholders
// were marked as requiring an exact 0x00 byte — the opposite of
// MemSearchPass::match_at()'s contract (0xFF = wildcard, 0x00 = exact match).
// This made hex_pattern/text searches match almost nothing meaningful.
//
// The fixture's `mem_search_env` writes the 8 bytes "DEADBEEF" (ASCII) to
// memory at inst 2, which we use as ground truth for both hex_pattern and
// text lookups below.

static McpTestEnv make_mem_search_env() {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);

        // Write the ASCII bytes "DEADBEEF" (0x46454542444145 44 little-endian
        // as a 64-bit value) to memory — used as ground truth for both
        // hex_pattern and text search below.
        uint64_t ascii_deadbeef = 0;
        const char* s = "DEADBEEF";
        std::memcpy(&ascii_deadbeef, s, 8);
        tw.emit(ms, 0x1000, enc::str_imm(0, 31, 0),
                {{33, tw.rt(0x1004)}},
                {{2 /* WRITE */, 8, 0x7F000000ULL, ascii_deadbeef}});

        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "mcp_mem_search_test");

    McpTestEnv result;
    result.env = std::move(env);
    result.pm = make_pm(*result.env);
    result.mcp = std::make_unique<TenetMcpService>(
        *result.env->reader, *result.env->index,
        *result.env->regfile, *result.env->memory,
        result.pm.get(),
        &result.env->code_table, &result.env->decoder);
    return result;
}

// `mem_search` (like other pass-backed MCP tools) is non-blocking:
// require_pass<T>() kicks off the pass on a detached background thread and
// throws PassNotReady on the first call. Poll call_tool() until the pass
// actually completes and returns its result, to avoid racing the background
// thread's access to the PassManager/pass objects (which are torn down when
// the TEST_CASE's `ctx` goes out of scope).
static json call_mem_search_blocking(McpTestEnv& ctx, const json& args,
                                      int max_attempts = 200) {
    for (int i = 0; i < max_attempts; i++) {
        try {
            return ctx.mcp->call_tool("mem_search", args);
        } catch (const PassNotReady&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    FAIL("mem_search pass did not complete in time");
    return {};
}

TEST_CASE("mem_search: hex_pattern with concrete bytes finds an exact match",
          "[unit][mcp][mem_search]") {
    auto ctx = make_mem_search_env();
    // "DEADBEEF" in ASCII is 44 45 41 44 42 45 45 46 (little-endian layout
    // in memory matches the string's byte order for str_imm here).
    auto res = call_mem_search_blocking(
        ctx, {{"hex_pattern", "44 45 41 44 42 45 45 46"}});
    REQUIRE(res["total_matches"].get<size_t>() >= 1);
    REQUIRE_FALSE(res["hits"].empty());
}

TEST_CASE("mem_search: hex_pattern with wildcard placeholder still matches",
          "[unit][mcp][mem_search]") {
    auto ctx = make_mem_search_env();
    // Wildcard out the middle two bytes; the concrete bytes around them must
    // still be required to match exactly.
    auto res = call_mem_search_blocking(
        ctx, {{"hex_pattern", "44 45 ?? ?? 42 45 45 46"}});
    REQUIRE(res["total_matches"].get<size_t>() >= 1);
}

TEST_CASE("mem_search: hex_pattern rejects a non-matching concrete byte",
          "[unit][mcp][mem_search]") {
    auto ctx = make_mem_search_env();
    // Corrupt one concrete byte (44 -> 00); if concrete bytes were being
    // treated as wildcards (the historical bug), this would still match.
    auto res = call_mem_search_blocking(
        ctx, {{"hex_pattern", "00 45 41 44 42 45 45 46"}});
    REQUIRE(res["total_matches"].get<size_t>() == 0);
}

TEST_CASE("mem_search: text search finds an exact ASCII match",
          "[unit][mcp][mem_search]") {
    auto ctx = make_mem_search_env();
    auto res = call_mem_search_blocking(ctx, {{"text", "DEADBEEF"}});
    REQUIRE(res["total_matches"].get<size_t>() >= 1);
}

TEST_CASE("mem_search: text search rejects a non-matching string",
          "[unit][mcp][mem_search]") {
    auto ctx = make_mem_search_env();
    // If `text` bytes were being treated as wildcards (the historical bug),
    // any 8-character string would spuriously "match" the write.
    auto res = call_mem_search_blocking(ctx, {{"text", "ZZZZZZZZ"}});
    REQUIRE(res["total_matches"].get<size_t>() == 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// Tool registration count
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("MCP service registers expected number of tools",
          "[unit][mcp][registration]") {
    auto ctx = make_mcp_env();
    // Should have 47 tools total
    REQUIRE(ctx.mcp->tool_count() >= 40);
}
