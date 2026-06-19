/*
 * test_io_trace_reader.cpp — Unit tests for tenet::TraceReader
 *
 * Verifies: header parsing (magic, version, flags, module fields),
 * record iteration (kinds and counts), InstView/CodeView/AnchorView
 * parsing, and record_at random access.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "common/types.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("TraceReader parses header correctly", "[unit][io][trace_reader]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.module_base = 0x100000000ULL;
        tw.module_slide = 0x4000ULL;
        tw.write_header(0x200000);
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "reader_header");

    REQUIRE(env != nullptr);
    const auto& hdr = env->reader->header();

    SECTION("magic and version") {
        REQUIRE(hdr.magic == TRACE_MAGIC);
        REQUIRE(hdr.version == TRACE_VERSION);
    }

    SECTION("architecture and GPR count") {
        REQUIRE(hdr.arch == 1);  // AARCH64
        REQUIRE(hdr.num_gpr == AARCH64_GPR_COUNT);
    }

    SECTION("module addressing") {
        REQUIRE(hdr.module_base == 0x100000000ULL);
        REQUIRE(hdr.module_slide == 0x4000ULL);
        REQUIRE(hdr.trace_start == 0x100004000ULL);
        REQUIRE(hdr.trace_end == 0x100204000ULL);
    }

    SECTION("header flags") {
        REQUIRE(hdr.has_mem());
        REQUIRE(hdr.has_nzcv());
        REQUIRE(hdr.has_code());
        REQUIRE(hdr.reg_diff());
    }

    SECTION("module name") {
        REQUIRE(hdr.module_name == "reader_header");
    }

    SECTION("file size is non-trivial") {
        REQUIRE(env->reader->file_size() > sizeof(qbditrace::qbditrace_file_header_t));
    }
}

TEST_CASE("TraceReader iterates records in order", "[unit][io][trace_reader]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;  // prevent auto-anchor inside emit
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::movz(0, 42), {{0, 42ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1), {{0, 43ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::str_imm(0, 31, 0), {}, {{1, 8, 0x16F000000ULL, 43}});
        tw.emit_anchor(ms);
    }, "reader_iter");

    REQUIRE(env != nullptr);

    int inst_count = 0;
    int anchor_count = 0;
    int code_count = 0;
    // The very first emit() triggers an auto-anchor at inst_count==0 because
    // anchor_interval=256 and 0 % 256 == 0. So we expect: ANCHOR, CODE, INST,
    // CODE, INST, CODE, INST, ANCHOR.

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        switch (rec.kind) {
            case RecordKind::Inst:
                inst_count++;
                break;
            case RecordKind::Anchor:
                anchor_count++;
                break;
            case RecordKind::Code:
                code_count++;
                break;
            default:
                break;
        }
    }

    SECTION("instruction count") {
        REQUIRE(inst_count == 3);
    }

    SECTION("anchor count (auto + explicit)") {
        // 1 auto-anchor at inst 0 + 1 explicit at end = 2
        REQUIRE(anchor_count == 2);
    }

    SECTION("code record count (one per unique PC)") {
        REQUIRE(code_count == 3);
    }
}

TEST_CASE("TraceReader InstView parses reg diffs and mem accesses", "[unit][io][trace_reader]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Instruction with 2 reg diffs and 1 memory write
        tw.emit(ms, 0x1000, enc::str_imm(0, 31, 0),
                {{0, 0xDEADBEEFULL}, {33, tw.rt(0x1004)}},
                {{1, 8, 0x16F000000ULL, 0xDEADBEEFULL}});
        tw.emit_anchor(ms);
    }, "reader_instview");

    REQUIRE(env != nullptr);

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();

        SECTION("PC is correct") {
            REQUIRE(inst.pc == rt_pc(0x1000));
        }

        SECTION("reg diff count and values") {
            REQUIRE(inst.reg_diff_count == 2);

            auto d0 = inst.reg_diff(0);
            REQUIRE(d0.index == 0);
            REQUIRE(d0.value == 0xDEADBEEFULL);

            auto d1 = inst.reg_diff(1);
            REQUIRE(d1.index == 33);  // PC
            REQUIRE(d1.value == rt_pc(0x1004));
        }

        SECTION("memory access count and values") {
            REQUIRE(inst.mem_access_count == 1);

            auto m0 = inst.mem_access(0);
            REQUIRE(m0.type == 1);  // write
            REQUIRE(m0.size == 8);
            REQUIRE(m0.addr == 0x16F000000ULL);
            REQUIRE(m0.value == 0xDEADBEEFULL);
        }
        break;  // only check first INST
    }
}

TEST_CASE("TraceReader CodeView parses opcode bytes", "[unit][io][trace_reader]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        uint32_t opcode = enc::nop();
        tw.emit(ms, 0x1000, opcode, {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "reader_codeview");

    REQUIRE(env != nullptr);

    bool found_code = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Code) continue;

        auto code = rec.as_code();
        REQUIRE(code.pc == rt_pc(0x1000));
        REQUIRE(code.size == 4);

        uint32_t opcode = 0;
        std::memcpy(&opcode, code.bytes, 4);
        REQUIRE(opcode == enc::nop());
        found_code = true;
        break;
    }
    REQUIRE(found_code);
}

TEST_CASE("TraceReader AnchorView provides full GPR snapshot", "[unit][io][trace_reader]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0xAAAABBBBCCCCDDDDULL;
        ms.x(1) = 0x1234567890ABCDEFULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);  // explicit anchor first
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
    }, "reader_anchor");

    REQUIRE(env != nullptr);

    bool found_anchor = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Anchor) continue;

        auto anchor = rec.as_anchor(AARCH64_GPR_COUNT);
        REQUIRE(anchor.num_gpr == AARCH64_GPR_COUNT);

        const uint64_t* gpr = anchor.gpr_values;
        REQUIRE(gpr[0] == 0xAAAABBBBCCCCDDDDULL);
        REQUIRE(gpr[1] == 0x1234567890ABCDEFULL);
        REQUIRE(gpr[IDX_SP] == 0x16F000000ULL);
        found_anchor = true;
        break;
    }
    REQUIRE(found_anchor);
}

TEST_CASE("TraceReader record_at supports random access", "[unit][io][trace_reader]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "reader_rand");

    REQUIRE(env != nullptr);

    // Record at the header offset should be the first record after header
    uint64_t header_size = sizeof(qbditrace::qbditrace_file_header_t);
    auto rec = env->reader->record_at(header_size);

    // The first record after the header could be an anchor (auto) or a code record.
    // With anchor_interval=256, inst_count==0 triggers auto-anchor, so first is ANCHOR.
    // After the anchor: CODE(0x1000), INST, CODE(0x1004), INST, ANCHOR.
    // Just verify we can read *something* at the header offset.
    REQUIRE(rec.kind == RecordKind::Anchor);
}
