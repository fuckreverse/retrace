#include <catch2/catch_test_macros.hpp>

#include "analysis/passes/platform/objc_pass.h"
#include "analysis/passes/platform/syscall_intercept_pass.h"
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
        tw.emit_objc(tw.rt(0x1004), 0x4321, 0x8765, "");
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
    REQUIRE(s.find("SVC name=unknown raw_syscall_no=128") != std::string::npos);
    REQUIRE(s.find("return=unknown (legacy)") != std::string::npos);
    REQUIRE(s.find("class=unknown class_resolution=unknown") != std::string::npos);
    REQUIRE(s.find("selector_source=hex selector_resolution=unresolved return=unknown (legacy)") != std::string::npos);
    REQUIRE(s.find("CAPICALL name=memcpy api_id=1") != std::string::npos);
    REQUIRE(s.find("CAPICALL name=memcpy api_id=1 pc=") != std::string::npos);
    REQUIRE(s.find("RETVAL") == std::string::npos);
}

TEST_CASE("dump_trace labels ObjC stret return as raw", "[unit][cli][dump][v8]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header_v8();
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND_STRET, tw.rt(0x2200),
                        0x1234, 0x5678, "", "buildValue");
        tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND_STRET,
                       tw.rt(0x2200), 0x9000, tw.rt(0x2204),
                       0xDEADBEEF, 0, 0, 0, 0,
                       QBDITRACE_OBJC_MSGSEND_STRET);
    }, "dump_v8_objc_stret");
    REQUIRE(env != nullptr);

    std::ostringstream os;
    DumpOptions options;
    options.format = DumpFormat::Text;
    REQUIRE(dump_trace(*env->reader, options, os).has_value());

    const auto output = os.str();
    CHECK(output.find("class=unknown class_resolution=unknown") != std::string::npos);
    CHECK(output.find("selector=buildValue selector_source=inline selector_resolution=resolved return=stret_raw") != std::string::npos);
    CHECK(output.find("return=unknown (legacy)") == std::string::npos);
    CHECK(output.find("RETVAL source_kind=objc source_id=3") != std::string::npos);
    CHECK(output.find("x0=0x00000000DEADBEEF") != std::string::npos);
}

TEST_CASE("v8 call metadata crosses reader passes and trace dump",
          "[unit][cli][dump][v8]") {
    constexpr uint64_t objc_return = 0xA0B0C0D0E0F00123ULL;
    constexpr uint64_t capi_return = 0x1122334455667788ULL;
    constexpr uint64_t svc_return = static_cast<uint64_t>(-5LL);
    constexpr uint64_t objc_site = 0x5000;
    constexpr uint64_t capi_site = 0x5004;
    constexpr uint64_t svc_site = 0x5008;

    auto env = make_env([](TraceWriter& tw) {
        tw.write_header_v8();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x0FF0, enc::nop(), {{33, tw.rt(0x0FF4)}}, {});

        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(objc_site),
                        0x1234, 0x5678, "DemoCls", "computeValue:");
        tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                       tw.rt(objc_site), 0x9000, tw.rt(objc_site + 4),
                       objc_return, 0, 0, 0, 0,
                       QBDITRACE_OBJC_MSGSEND);

        tw.emit_capicall_v8(600, tw.rt(capi_site), tw.rt(0x3000),
                            {1, 2, 3, 4, 5}, {{1, 0, "payload"}});
        tw.emit_retval(QBDITRACE_REC_CAPICALL, 600, tw.rt(capi_site),
                       tw.rt(0x3000), tw.rt(capi_site + 4),
                       capi_return, 0x99, 0x40000000, 0, 0, 600);

        tw.emit_svc(tw.rt(svc_site), 64, 7, 0xBEEF,
                    QBDITRACE_SVC_FL_MEM_OP | QBDITRACE_SVC_FL_FILE_OP);
        tw.emit_retval(QBDITRACE_REC_SVC, 64, tw.rt(svc_site), 0,
                       tw.rt(svc_site + 4), svc_return, 0x55, 0,
                       11, 5, 64, true);
        tw.emit(ms, 0x0FF4, enc::nop(), {{33, tw.rt(0x0FF8)}}, {});
    }, "dump_v8_complete_calls");
    REQUIRE(env != nullptr);

    SECTION("TraceReader preserves every source identity and real return") {
        bool saw_objc = false;
        bool saw_capi = false;
        bool saw_svc = false;
        for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
            const auto rec = *it;
            if (rec.kind != RecordKind::Retval) continue;
            const auto rv = rec.as_retval();
            if (rv.source_kind == QBDITRACE_REC_OBJC) {
                saw_objc = true;
                CHECK(rv.source_id == QBDITRACE_OBJC_MSGSEND);
                CHECK(rv.x0 == objc_return);
            } else if (rv.source_kind == QBDITRACE_REC_CAPICALL) {
                saw_capi = true;
                CHECK(rv.source_id == 600);
                CHECK(rv.x0 == capi_return);
            } else if (rv.source_kind == QBDITRACE_REC_SVC) {
                saw_svc = true;
                CHECK(rv.source_id == 64);
                CHECK(rv.x0 == svc_return);
            }
        }
        CHECK(saw_objc);
        CHECK(saw_capi);
        CHECK(saw_svc);
    }

    SECTION("platform passes expose selector names and recorded returns") {
        auto pm = make_pm(*env);
        pm->register_pass(std::make_unique<ObjcPass>());
        pm->register_pass(std::make_unique<SyscallInterceptPass>());

        const auto& objc = pm->require("objc").get<ObjcResult>();
        REQUIRE(objc.messages.size() == 1);
        CHECK(objc.messages[0].selector_name == "computeValue:");
        CHECK(objc.messages[0].has_return);
        CHECK(objc.messages[0].return_value == objc_return);

        const auto& calls = pm->require("syscall_intercept")
                                .get<SyscallInterceptResult>().calls;
        REQUIRE(calls.size() == 2);
        CHECK(calls[0].callee_name == "EVP_EncryptInit_ex");
        CHECK(calls[0].has_return);
        CHECK(calls[0].return_value == capi_return);
        CHECK(calls[1].callee_name == "syscall_64");
        CHECK(calls[1].has_return);
        CHECK(calls[1].return_value == svc_return);
        CHECK(calls[1].errno_valid);
        CHECK(calls[1].errno_after == 5);
    }

    SECTION("trace dump emits selector names and real return values") {
        std::ostringstream os;
        DumpOptions options;
        options.format = DumpFormat::Text;
        REQUIRE(dump_trace(*env->reader, options, os).has_value());
        const auto output = os.str();
        CHECK(output.find("selector=computeValue: selector_source=inline selector_resolution=resolved") != std::string::npos);
        CHECK(output.find("CAPICALL name=EVP_EncryptInit_ex api_id=600") != std::string::npos);
        CHECK(output.find("SVC name=write raw_syscall_no=64") != std::string::npos);
        CHECK(output.find("return=unknown (legacy)") == std::string::npos);
        CHECK(output.find("return=unknown\n") != std::string::npos);
        CHECK(output.find("RETVAL source_kind=objc source_id=0") != std::string::npos);
        CHECK(output.find("site=0x") != std::string::npos);
        CHECK(output.find("target=0x0000000000009000 x0=0xA0B0C0D0E0F00123") != std::string::npos);
        CHECK(output.find("RETVAL source_kind=capi source_id=600") != std::string::npos);
        CHECK(output.find("x0=0x1122334455667788") != std::string::npos);
        CHECK(output.find("RETVAL source_kind=svc source_id=64") != std::string::npos);
        CHECK(output.find("target=0x0000000000000000 x0=0xFFFFFFFFFFFFFFFB") != std::string::npos);
        CHECK(output.find("errno_valid=true errno=11->5 raw_error=-5") != std::string::npos);
    }
}

TEST_CASE("dump_trace emits MEMIMG summaries", "[unit][cli][dump][snapshot]") {
    // Arrange
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header_v9();
        tw.write_memimg(0x300001000ULL, {0x10, 0x20, 0x30}, 7);
    }, "dump_v9_memimg");
    REQUIRE(env != nullptr);

    SECTION("text summary") {
        std::ostringstream os;
        DumpOptions options;
        options.format = DumpFormat::Text;

        // Act
        REQUIRE(dump_trace(*env->reader, options, os).has_value());

        // Assert
        CHECK(os.str().find("MEMIMG seq=7 addr=0x0000000300001000 len=3") !=
              std::string::npos);
    }

    SECTION("JSONL summary") {
        std::ostringstream os;
        DumpOptions options;
        options.format = DumpFormat::Jsonl;

        // Act
        REQUIRE(dump_trace(*env->reader, options, os).has_value());

        // Assert
        CHECK(os.str().find("{\"type\":\"memimg\",\"seq\":7,"
                            "\"addr\":\"0x300001000\",\"len\":3}") !=
              std::string::npos);
    }
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
