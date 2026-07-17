#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"
#include "io/mcp/mcp_server.h"
#include "service/tenet_service.h"

using namespace Catch::Matchers;
using namespace tenet;
using namespace tenet::test;
using json = nlohmann::json;

namespace {

struct CoreMcpEnv {
    std::unique_ptr<TraceEnv> env;
    std::unique_ptr<TenetService> service;
    std::unique_ptr<TenetMcpService> mcp;
};

CoreMcpEnv make_core_env() {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();

        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);

        tw.emit(ms, 0x1000, enc::movz(0, 1),
                {{0, 1ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1),
                {{0, 2ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::nop(),
                {{33, tw.rt(0x100C)}}, {});

        tw.emit_anchor(ms);
    }, "mcp_core_tool_test");

    REQUIRE(env != nullptr);

    auto service = std::make_unique<TenetService>(
        *env->reader, *env->index, env->code_table, env->decoder,
        *env->regfile, *env->memory);

    auto mcp = std::make_unique<TenetMcpService>(*service);

    CoreMcpEnv out;
    out.env = std::move(env);
    out.service = std::move(service);
    out.mcp = std::move(mcp);
    return out;
}

}  // namespace

TEST_CASE("mcp core: get_cursor returns current inst and rebased pc",
          "[unit][mcp][core]") {
    auto ctx = make_core_env();

    ctx.service->navigate_to(1);

    auto result = ctx.mcp->call_tool("get_cursor");
    REQUIRE(result.at("inst_id") == 1);
    REQUIRE(result.at("pc") == "0x100001004");
}

TEST_CASE("mcp core: navigate clamps through TenetService and returns actual cursor",
          "[unit][mcp][core]") {
    auto ctx = make_core_env();

    auto result = ctx.mcp->call_tool("navigate", {{"inst_id", 999}});

    REQUIRE(result.at("inst_id") == 2);
    REQUIRE(result.at("pc") == "0x100001008");
    REQUIRE(ctx.service->current_inst() == 2);
}

TEST_CASE("mcp core: get_cursor and navigate report unavailable in raw-backend mode",
          "[unit][mcp][core]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();

        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "mcp_core_tool_raw");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    TenetMcpService mcp(*env->reader, *env->index, *env->regfile,
                        *env->memory, pm.get(),
                        &env->code_table, &env->decoder);

    REQUIRE_THROWS_WITH(mcp.call_tool("get_cursor"),
                        ContainsSubstring("get_cursor unavailable"));
    REQUIRE_THROWS_WITH(mcp.call_tool("navigate", {{"inst_id", 0}}),
                        ContainsSubstring("navigate unavailable"));
}

TEST_CASE("mcp core: search_pc nearest_inst_id uses backend nearest lookup",
          "[unit][mcp][core]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();

        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);

        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});   // inst 0
        tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});   // inst 1
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});   // inst 2
        tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});   // inst 3
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});   // inst 4
        tw.emit(ms, 0x4000, enc::nop(), {{33, tw.rt(0x4004)}}, {});   // inst 5
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});   // inst 6

        tw.emit_anchor(ms);
    }, "mcp_core_search_pc_nearest");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    REQUIRE(pm != nullptr);

    TenetMcpService mcp(*env->reader, *env->index, *env->regfile,
                        *env->memory, pm.get(),
                        &env->code_table, &env->decoder);
    REQUIRE(mcp.tool_count() > 0);

    register_pass_by_name(*pm, "xref");
    const auto xref_result = pm->require_shared("xref");
    REQUIRE(xref_result != nullptr);
    REQUIRE(xref_result->ok());
    const auto& xref = xref_result->get<XrefResult>();
    const uint64_t runtime_pc = rt_pc(0x1000);
    REQUIRE(xref.execution_count(runtime_pc) == 4);
    REQUIRE(xref.inst_ids_at(runtime_pc) == std::vector<uint64_t>{0, 2, 4, 6});
    REQUIRE(xref.nearest_inst_id_at(runtime_pc, 0) == 0);
    REQUIRE(xref.nearest_inst_id_at(runtime_pc, 3) == 2);
    REQUIRE(xref.nearest_inst_id_at(runtime_pc, 4) == 4);
    REQUIRE(xref.nearest_inst_id_at(runtime_pc, 99) == 6);

    auto before = mcp.call_tool("search_pc", {{"pc", "0x100001000"}, {"nearest_to_inst_id", 0}});
    REQUIRE(before.at("exec_count") == 4);
    REQUIRE(before.contains("nearest_inst_id"));
    REQUIRE(before.at("nearest_inst_id").is_number_unsigned());
    REQUIRE(before.at("nearest_inst_id").get<uint64_t>() == 0);
    REQUIRE(before.at("inst_ids").get<std::vector<uint64_t>>() == std::vector<uint64_t>{0, 2, 4, 6});

    auto between = mcp.call_tool("search_pc", {{"pc", "0x100001000"}, {"nearest_to_inst_id", 3}});
    REQUIRE(between.at("nearest_inst_id") == 2);  // tie prefers earlier execution

    auto exact = mcp.call_tool("search_pc", {{"pc", "0x100001000"}, {"nearest_to_inst_id", 4}});
    REQUIRE(exact.at("nearest_inst_id") == 4);

    auto after = mcp.call_tool("search_pc", {{"pc", "0x100001000"}, {"nearest_to_inst_id", 99}});
    REQUIRE(after.at("nearest_inst_id") == 6);

    auto paged = mcp.call_tool("search_pc", {
        {"pc", "0x100001000"},
        {"offset", 1},
        {"limit", 2},
        {"nearest_to_inst_id", 5}
    });
    REQUIRE(paged.at("inst_ids").get<std::vector<uint64_t>>() == std::vector<uint64_t>{2, 4});
    REQUIRE(paged.at("returned") == 2);
    REQUIRE(paged.at("has_more") == true);
    REQUIRE(paged.at("next_offset") == 3);
    REQUIRE(paged.at("nearest_inst_id") == 4);
}
