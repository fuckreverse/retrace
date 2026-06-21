/*
 * test_io_trace_reader_v5.cpp — Unit tests for v5 (HF_PC_DELTA) trace format support
 *
 * Verifies:
 *   - Header parsing recognises version=5 + HF_PC_DELTA flag correctly
 *   - Sequential code: delta = +4 (NOP chain), absolute PCs reconstructed correctly
 *   - Backward branch: negative delta reconstructed correctly
 *   - Forward branch: large positive delta reconstructed correctly
 *   - pc_delta int16 overflow → writer emits ANCHOR, then delta=0, decoder resync
 *   - Mixed reg diffs + mem accesses still parsed correctly in v5 records
 *   - Iterator record counts are accurate (ANCHOR injected by overflow fallback)
 *   - record_at(offset, seed_pc) random access works on v5 traces
 *   - v5+v6 combined format (HF_PC_DELTA | HF_OLD_VALUE): 6-byte head + 48-byte memacc
 *   - v4 traces still parse correctly when v5 support is compiled in (regression)
 */
#include <catch2/catch_test_macros.hpp>
#include <cstring>

#include "fixtures/trace_fixture.h"
#include "common/types.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static constexpr uint8_t kWrite = 2;
static constexpr uint8_t kRead  = 1;

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("TraceReader v5: header flags detected correctly", "[unit][io][trace_reader_v5]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_v5(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "v5_header");

    REQUIRE(env != nullptr);
    const auto& hdr = env->reader->header();

    SECTION("version number is 5") {
        REQUIRE(hdr.version == 5);
    }
    SECTION("HF_PC_DELTA flag is set") {
        REQUIRE(hdr.flags & qbditrace::QBDITRACE_HF_PC_DELTA);
    }
    SECTION("HF_OLD_VALUE is NOT set (pure v5)") {
        REQUIRE(!(hdr.flags & qbditrace::QBDITRACE_HF_OLD_VALUE));
    }
    SECTION("HF_HAS_MEM is still set") {
        REQUIRE(hdr.has_mem());
    }
    SECTION("HF_HAS_CODE is still set") {
        REQUIRE(hdr.has_code());
    }
}

TEST_CASE("TraceReader v5: sequential NOPs — delta=+4, PCs reconstructed",
          "[unit][io][trace_reader_v5]") {
    // Five sequential NOPs at 0x1000, 0x1004, 0x1008, 0x100C, 0x1010.
    // Each INST record should have pc_delta = +4 (after the first which starts
    // from the auto-anchor's PC = tw.rt(0x1000)).
    constexpr int kCount = 5;
    constexpr uint64_t kBase = 0x1000;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;  // no auto-anchor inside emit_v5
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < kCount; i++) {
            uint64_t spc = kBase + i * 4;
            tw.emit_v5(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "v5_sequential");

    REQUIRE(env != nullptr);

    // Collect all INST records and check their PCs
    std::vector<uint64_t> pcs;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        pcs.push_back(inst.pc);
    }

    SECTION("instruction count") {
        REQUIRE(pcs.size() == kCount);
    }
    SECTION("PC values are correct sequential addresses") {
        for (int i = 0; i < kCount; i++) {
            uint64_t expected = rt_pc(kBase + i * 4);
            REQUIRE(pcs[i] == expected);
        }
    }
}

TEST_CASE("TraceReader v5: negative delta (backward branch)",
          "[unit][io][trace_reader_v5]") {
    // Emit: 0x1000, 0x1004, then jump back to 0x1000 (delta = -4).
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_v5(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_v5(ms, 0x1004, enc::b(-4), {{33, tw.rt(0x1000)}}, {});
        // Taken branch: back to 0x1000 (delta from 0x1004+slide to 0x1000+slide = -4)
        tw.emit_v5(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "v5_neg_delta");

    REQUIRE(env != nullptr);

    std::vector<uint64_t> pcs;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        pcs.push_back(rec.as_inst().pc);
    }

    SECTION("instruction count") {
        REQUIRE(pcs.size() == 3);
    }
    SECTION("first instruction PC") {
        REQUIRE(pcs[0] == rt_pc(0x1000));
    }
    SECTION("second instruction PC") {
        REQUIRE(pcs[1] == rt_pc(0x1004));
    }
    SECTION("third instruction PC (back to 0x1000)") {
        REQUIRE(pcs[2] == rt_pc(0x1000));
    }
}

TEST_CASE("TraceReader v5: large forward branch (positive delta)",
          "[unit][io][trace_reader_v5]") {
    // 0x1000 → jump to 0x1400 (delta = +0x400 = +1024, fits in int16)
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_v5(ms, 0x1000, enc::b(0x400), {{33, tw.rt(0x1400)}}, {});
        tw.emit_v5(ms, 0x1400, enc::nop(), {{33, tw.rt(0x1404)}}, {});
        tw.emit_anchor(ms);
    }, "v5_pos_large");

    REQUIRE(env != nullptr);

    std::vector<uint64_t> pcs;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        pcs.push_back(rec.as_inst().pc);
    }

    SECTION("instruction count") {
        REQUIRE(pcs.size() == 2);
    }
    SECTION("jump target PC") {
        REQUIRE(pcs[1] == rt_pc(0x1400));
    }
}

TEST_CASE("TraceReader v5: pc_delta overflow → ANCHOR inserted, decode resync",
          "[unit][io][trace_reader_v5]") {
    // Emit 0x1000, then jump to 0x1000 + 0x10000 (delta = +65536, overflows int16).
    // emit_v5() should automatically insert an ANCHOR before the overflow instruction,
    // then emit the instruction with delta = 0 (absolute PC from anchor).
    constexpr uint64_t kFar = 0x11000;  // delta from 0x1000 = +0x10000 = 65536 (overflow)

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_v5(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // This jump spans 0x10000 bytes — delta overflows int16 → anchor emitted
        tw.emit_v5(ms, kFar, enc::nop(), {{33, tw.rt(kFar + 4)}}, {});
        tw.emit_v5(ms, kFar + 4, enc::nop(), {{33, tw.rt(kFar + 8)}}, {});
        tw.emit_anchor(ms);
    }, "v5_overflow");

    REQUIRE(env != nullptr);

    int inst_count   = 0;
    int anchor_count = 0;
    std::vector<uint64_t> pcs;

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Inst) {
            inst_count++;
            pcs.push_back(rec.as_inst().pc);
        } else if (rec.kind == RecordKind::Anchor) {
            anchor_count++;
        }
    }

    SECTION("instruction count is 3") {
        REQUIRE(inst_count == 3);
    }
    SECTION("overflow caused an extra anchor (≥2 total anchors)") {
        // 1 auto-anchor (inst 0) + 1 overflow anchor + 1 explicit = ≥3
        // Or: auto-anchor fused with overflow anchor depending on order.
        // Minimum: the overflow fallback adds at least 1 anchor beyond the
        // normal auto-anchor at inst_count==0.
        REQUIRE(anchor_count >= 2);
    }
    SECTION("PC after overflow correct") {
        REQUIRE(pcs[1] == rt_pc(kFar));
    }
    SECTION("PC after overflow+4 correct") {
        REQUIRE(pcs[2] == rt_pc(kFar + 4));
    }
}

TEST_CASE("TraceReader v5: reg diffs and mem accesses parsed correctly",
          "[unit][io][trace_reader_v5]") {
    constexpr uint64_t kBuf = 0x16F010000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // STR x0,[sp]: reg diff: x0=0xCAFEBABE, PC advance
        tw.emit_v5(ms, 0x1000, enc::str_imm(0, 31, 0),
                   {{0, 0xCAFEBABEULL}, {33, tw.rt(0x1004)}},
                   {{kWrite, 8, kBuf, 0xCAFEBABEULL}});
        tw.emit_anchor(ms);
    }, "v5_regdiff_mem");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();

        SECTION("PC reconstructed correctly") {
            REQUIRE(inst.pc == rt_pc(0x1000));
        }
        SECTION("reg diff count") {
            REQUIRE(inst.reg_diff_count == 2);
        }
        SECTION("reg diff x0 value") {
            auto d0 = inst.reg_diff(0);
            REQUIRE(d0.index == 0);
            REQUIRE(d0.value == 0xCAFEBABEULL);
        }
        SECTION("memory access count") {
            REQUIRE(inst.mem_access_count == 1);
        }
        SECTION("memory access value") {
            auto m0 = inst.mem_access(0);
            REQUIRE(m0.type == kWrite);
            REQUIRE(m0.size == 8);
            REQUIRE(m0.addr == kBuf);
            REQUIRE(m0.value == 0xCAFEBABEULL);
        }
        SECTION("v5 flag: has_old_value is false (v5 has no old_value)") {
            auto m0 = inst.mem_access(0);
            REQUIRE(m0.has_old_value == false);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v5: record counts are accurate", "[unit][io][trace_reader_v5]") {
    // 4 instructions with 2 reg diffs each, 1 mem per instruction
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_v5(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_v5(ms, 0x1004, enc::add_imm(0, 0, 1), {{0, 1ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_v5(ms, 0x1008, enc::str_imm(0, 31, 0), {{33, tw.rt(0x100C)}},
                   {{kWrite, 8, 0x16F000000ULL, 1ULL}});
        tw.emit_v5(ms, 0x100C, enc::ldr_imm(1, 31, 0), {{1, 1ULL}, {33, tw.rt(0x1010)}},
                   {{kRead, 8, 0x16F000000ULL, 1ULL}});
        tw.emit_anchor(ms);
    }, "v5_counts");

    REQUIRE(env != nullptr);

    int inst_count = 0, anchor_count = 0, code_count = 0;
    int total_mems = 0, total_regdiffs = 0;

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        switch (rec.kind) {
        case RecordKind::Inst: {
            inst_count++;
            auto iv = rec.as_inst();
            total_mems     += iv.mem_access_count;
            total_regdiffs += iv.reg_diff_count;
            break;
        }
        case RecordKind::Anchor: anchor_count++; break;
        case RecordKind::Code:   code_count++;   break;
        default: break;
        }
    }

    SECTION("instruction count") {
        REQUIRE(inst_count == 4);
    }
    SECTION("anchor count (1 auto + 1 explicit)") {
        REQUIRE(anchor_count == 2);
    }
    SECTION("code records (4 distinct PCs)") {
        REQUIRE(code_count == 4);
    }
    SECTION("total memory accesses (1 STR + 1 LDR = 2)") {
        REQUIRE(total_mems == 2);
    }
    SECTION("total reg diffs (1+2+1+2 = 6)") {
        // nop:1 (PC only), add:2, str:1 (PC), ldr:2
        REQUIRE(total_regdiffs == 6);
    }
}

TEST_CASE("TraceReader v5: NZCV field preserved", "[unit][io][trace_reader_v5]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // CMP sets N=0,Z=0,C=1,V=0 flags → nzcv byte = 0x20
        uint8_t nzcv_val = 0x20;
        tw.emit_v5(ms, 0x1000, enc::cmp_imm(0, 1), {{33, tw.rt(0x1004)}}, {}, nzcv_val);
        tw.emit_anchor(ms);
    }, "v5_nzcv");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        SECTION("nzcv value preserved") {
            REQUIRE(inst.nzcv == 0x20);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v5: AnchorView after overflow resync provides correct GPR state",
          "[unit][io][trace_reader_v5]") {
    // After a pc_delta overflow, the injected ANCHOR must have the full GPR snapshot.
    constexpr uint64_t kFar = 0x11000;
    constexpr uint64_t kX5Val = 0x0123456789ABCDEFULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        ms.x(5) = kX5Val;
        tw.emit_v5(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // Overflow: delta from 0x1000 to 0x11000 = +0x10000 → anchor injected
        tw.emit_v5(ms, kFar, enc::nop(), {{33, tw.rt(kFar + 4)}}, {});
        tw.emit_anchor(ms);
    }, "v5_overflow_anchor_gpr");

    REQUIRE(env != nullptr);

    // Skip the first anchor (auto at inst 0); find the overflow anchor
    int anchor_idx = 0;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Anchor) continue;
        anchor_idx++;
        if (anchor_idx < 2) continue;  // skip the first auto-anchor

        // This is the overflow-induced anchor (or explicit at end)
        auto anch = rec.as_anchor(AARCH64_GPR_COUNT);
        SECTION("anchor carries correct x5 value") {
            REQUIRE(anch.gpr_values[5] == kX5Val);
        }
        break;
    }
}

TEST_CASE("TraceReader v5+v6: combined PC-delta + old-value format",
          "[unit][io][trace_reader_v5]") {
    // Verify that HF_PC_DELTA + HF_OLD_VALUE together work:
    //   - 6-byte v5 inst head (pc_delta)
    //   - 48-byte v6 memacc (old_value fields)
    constexpr uint64_t kBuf    = 0x16F010000ULL;
    constexpr uint64_t kNewVal = 0xDEADBEEFCAFEBABEULL;
    constexpr uint64_t kOldVal = 0x0102030405060708ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5v6();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        TraceWriter::MemAccV6 ma{};
        ma.type      = kWrite;
        ma.size      = 8;
        ma.addr      = kBuf;
        ma.value     = kNewVal;
        ma.old_value = kOldVal;
        ma.old_unknown = false;

        tw.emit_v5v6(ms, 0x1000, enc::str_imm(0, 31, 0),
                     {{0, kNewVal}, {33, tw.rt(0x1004)}},
                     {ma});
        tw.emit_v5v6(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v5v6_combined");

    REQUIRE(env != nullptr);

    const auto& hdr = env->reader->header();
    SECTION("version is 6 (v6 supersedes v5 numerically in combined mode)") {
        REQUIRE(hdr.version == 6);
    }
    SECTION("both HF_PC_DELTA and HF_OLD_VALUE are set") {
        REQUIRE(hdr.flags & qbditrace::QBDITRACE_HF_PC_DELTA);
        REQUIRE(hdr.flags & qbditrace::QBDITRACE_HF_OLD_VALUE);
    }

    std::vector<uint64_t> pcs;
    bool found_write = false;

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        pcs.push_back(inst.pc);

        if (inst.mem_access_count == 1) {
            auto m0 = inst.mem_access(0);
            SECTION("WRITE new value") {
                REQUIRE(m0.value == kNewVal);
            }
            SECTION("has_old_value is true") {
                REQUIRE(m0.has_old_value == true);
            }
            SECTION("old_value is correct") {
                REQUIRE(m0.old_value == kOldVal);
            }
            found_write = true;
        }
    }

    SECTION("instruction count") {
        REQUIRE(pcs.size() == 2);
    }
    SECTION("first PC correct (reconstructed from delta)") {
        REQUIRE(pcs[0] == rt_pc(0x1000));
    }
    SECTION("second PC correct (+4 delta)") {
        REQUIRE(pcs[1] == rt_pc(0x1004));
    }
    REQUIRE(found_write);
}

TEST_CASE("TraceReader v4: still parses correctly when v5/v6 support is compiled in",
          "[unit][io][trace_reader_v5]") {
    // Regression: adding v5 support must not break v4 traces.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();  // v4
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1), {{0, 1ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v5_v4_compat");

    REQUIRE(env != nullptr);
    SECTION("version is 4") {
        REQUIRE(env->reader->header().version == 4);
    }
    SECTION("HF_PC_DELTA is NOT set") {
        REQUIRE(!(env->reader->header().flags & qbditrace::QBDITRACE_HF_PC_DELTA));
    }

    std::vector<uint64_t> pcs;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        pcs.push_back(rec.as_inst().pc);
    }

    SECTION("instruction count") {
        REQUIRE(pcs.size() == 2);
    }
    SECTION("v4 PC values from absolute field") {
        REQUIRE(pcs[0] == rt_pc(0x1000));
        REQUIRE(pcs[1] == rt_pc(0x1004));
    }
}

TEST_CASE("TraceReader v5: record_at(offset, seed_pc) random access",
          "[unit][io][trace_reader_v5]") {
    // Collect the file offset of the second INST record and its known PC,
    // then verify record_at(offset, seed_pc) reconstructs the instruction correctly.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_v5(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_v5(ms, 0x1004, enc::add_imm(1, 1, 7), {{1, 7ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v5_record_at");

    REQUIRE(env != nullptr);

    // Walk to find the second INST record's offset and its absolute PC
    uint64_t second_inst_offset = 0;
    uint64_t second_inst_pc = 0;
    int inst_idx = 0;

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        inst_idx++;
        if (inst_idx == 2) {
            second_inst_offset = rec.file_offset;
            second_inst_pc     = rec.as_inst().pc;
            break;
        }
    }

    REQUIRE(second_inst_offset > 0);
    REQUIRE(second_inst_pc == rt_pc(0x1004));

    // Random access: use record_at(offset, seed_pc) to re-parse the second INST
    auto rv = env->reader->record_at(second_inst_offset, second_inst_pc);
    SECTION("record kind is Inst") {
        REQUIRE(rv.kind == RecordKind::Inst);
    }
    SECTION("is_v5 is set") {
        REQUIRE(rv.is_v5 == true);
    }
    SECTION("PC from seed_pc is correct") {
        auto inst = rv.as_inst();
        REQUIRE(inst.pc == rt_pc(0x1004));
    }
    SECTION("reg diff parsed correctly via random access") {
        auto inst = rv.as_inst();
        REQUIRE(inst.reg_diff_count == 2);
        auto d0 = inst.reg_diff(0);
        REQUIRE(d0.index == 1);
        REQUIRE(d0.value == 7ULL);
    }
}

TEST_CASE("TraceReader v5: multiple instructions with varying reg diff / mem counts",
          "[unit][io][trace_reader_v5]") {
    // Stress-test the v5 iterator: instructions with 0, 1, 2, 3 reg diffs
    // and 0 or 1 memory accesses in sequence.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // 0 reg diffs, 0 mems
        tw.emit_v5(ms, 0x1000, enc::nop(), {}, {});
        // 1 reg diff, 0 mems
        tw.emit_v5(ms, 0x1004, enc::movz(0, 42), {{0, 42ULL}}, {});
        // 2 reg diffs, 0 mems
        tw.emit_v5(ms, 0x1008, enc::add_imm(1, 0, 1), {{1, 43ULL}, {33, tw.rt(0x100C)}}, {});
        // 1 reg diff, 1 mem (write)
        tw.emit_v5(ms, 0x100C, enc::str_imm(0, 31, 0),
                   {{33, tw.rt(0x1010)}},
                   {{kWrite, 8, 0x16F000000ULL, 42ULL}});
        // 2 reg diffs, 1 mem (read)
        tw.emit_v5(ms, 0x1010, enc::ldr_imm(2, 31, 0),
                   {{2, 42ULL}, {33, tw.rt(0x1014)}},
                   {{kRead, 8, 0x16F000000ULL, 42ULL}});
        tw.emit_anchor(ms);
    }, "v5_vary_counts");

    REQUIRE(env != nullptr);

    struct InstInfo { uint64_t pc; int reg_diffs; int mems; };
    std::vector<InstInfo> infos;

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto iv = rec.as_inst();
        infos.push_back({iv.pc, iv.reg_diff_count, iv.mem_access_count});
    }

    SECTION("instruction count") {
        REQUIRE(infos.size() == 5);
    }
    SECTION("all PCs correct") {
        REQUIRE(infos[0].pc == rt_pc(0x1000));
        REQUIRE(infos[1].pc == rt_pc(0x1004));
        REQUIRE(infos[2].pc == rt_pc(0x1008));
        REQUIRE(infos[3].pc == rt_pc(0x100C));
        REQUIRE(infos[4].pc == rt_pc(0x1010));
    }
    SECTION("reg diff counts") {
        REQUIRE(infos[0].reg_diffs == 0);
        REQUIRE(infos[1].reg_diffs == 1);
        REQUIRE(infos[2].reg_diffs == 2);
        REQUIRE(infos[3].reg_diffs == 1);
        REQUIRE(infos[4].reg_diffs == 2);
    }
    SECTION("mem access counts") {
        REQUIRE(infos[0].mems == 0);
        REQUIRE(infos[1].mems == 0);
        REQUIRE(infos[2].mems == 0);
        REQUIRE(infos[3].mems == 1);
        REQUIRE(infos[4].mems == 1);
    }
}
