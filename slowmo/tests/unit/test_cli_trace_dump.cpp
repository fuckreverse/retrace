#include <catch2/catch_test_macros.hpp>

#include "cli/trace_dump.h"
#include "cli_options.h"
#include "fixtures/trace_fixture.h"

#include <sstream>

using namespace tenet;
using namespace tenet::test;

TEST_CASE("parse_args parses dump options", "[unit][cli][dump]") {
    const char* argv[] = {
        "tenet",
        "--dump", "jsonl",
        "--limit", "3",
        "--no-regs",
        "--no-mem",
        "sample.trace",
    };

    auto opts = parse_args(static_cast<int>(sizeof(argv) / sizeof(argv[0])),
                           const_cast<char**>(argv));

    REQUIRE(opts.parse_status == 0);
    REQUIRE(opts.opt_dump);
    REQUIRE(opts.dump_options.format == DumpFormat::Jsonl);
    REQUIRE(opts.dump_options.limit == 3);
    REQUIRE_FALSE(opts.dump_options.include_regs);
    REQUIRE_FALSE(opts.dump_options.include_mem);
    REQUIRE(opts.trace_path == "sample.trace");
}

TEST_CASE("dump_trace text includes core sections", "[unit][cli][dump]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 1024;
        tw.write_header_v7();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        tw.emit_thread(7);
        tw.emit_event(QBDITRACE_EV_XFER_CALL, tw.rt(0x2000), tw.rt(0x1000));
        tw.emit_svc(tw.rt(0x1000), 0x80, 0x11, 0x22);
        tw.emit_objc(tw.rt(0x1000), 0x1234, 0x5678, "DemoCls");
        tw.emit_capicall(QBDITRACE_CAPI_MEMCPY, tw.rt(0x1000), tw.rt(0x3000),
                         {0x1, 0x2, 0x3}, {{0, 0, "abc"}});

        tw.emit_v7(ms, 0x1000, enc::str_imm(0, 31, 0),
                   {{0, 0xAA}, {33, tw.rt(0x1004)}},
                   {{1, 8, 0x16F000000ULL, 0xAA}},
                   {{1, 0x1111, 0x2222}},
                   0x3);
    }, "dump_text");

    REQUIRE(env != nullptr);

    std::ostringstream os;
    DumpOptions options;
    options.format = DumpFormat::Text;

    auto result = dump_trace(*env->reader, options, os);
    REQUIRE(result.has_value());

    const auto s = os.str();
    REQUIRE(s.find("header") != std::string::npos);
    REQUIRE(s.find("INST") != std::string::npos);
    REQUIRE(s.find("fpr_diffs") != std::string::npos);
    REQUIRE(s.find("mem") != std::string::npos);
    REQUIRE(s.find("THREAD") != std::string::npos);
    REQUIRE(s.find("EVENT") != std::string::npos);
    REQUIRE(s.find("SVC") != std::string::npos);
    REQUIRE(s.find("OBJC") != std::string::npos);
    REQUIRE(s.find("CAPICALL") != std::string::npos);
}

TEST_CASE("dump_trace jsonl limit and no-regs/no-mem", "[unit][cli][dump]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 1024;
        tw.write_header_v7();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        tw.emit_v7(ms, 0x1000, enc::str_imm(0, 31, 0),
                   {{0, 0x10}, {33, tw.rt(0x1004)}},
                   {{1, 8, 0x16F000000ULL, 0x10}},
                   {{0, 1, 2}},
                   0x1);
        tw.emit_v7(ms, 0x1004, enc::str_imm(0, 31, 8),
                   {{0, 0x11}, {33, tw.rt(0x1008)}},
                   {{1, 8, 0x16F000008ULL, 0x11}},
                   {{1, 3, 4}},
                   0x2);
    }, "dump_jsonl_limit");

    REQUIRE(env != nullptr);

    std::ostringstream os;
    DumpOptions options;
    options.format = DumpFormat::Jsonl;
    options.limit = 1;
    options.include_regs = false;
    options.include_mem = false;

    auto result = dump_trace(*env->reader, options, os);
    REQUIRE(result.has_value());
    REQUIRE(result->inst_records == 1);

    const auto s = os.str();
    REQUIRE(s.find("\"type\":\"header\"") != std::string::npos);

    const auto inst_pos = s.find("\"type\":\"inst\"");
    REQUIRE(inst_pos != std::string::npos);

    const auto second_inst_pos = s.find("\"type\":\"inst\"", inst_pos + 1);
    REQUIRE(second_inst_pos == std::string::npos);

    REQUIRE(s.find("gpr_diffs") == std::string::npos);
    REQUIRE(s.find("fpr_diffs") == std::string::npos);
    REQUIRE(s.find("mem_accesses") == std::string::npos);
}
