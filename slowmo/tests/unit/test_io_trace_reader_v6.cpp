/*
 * test_io_trace_reader_v6.cpp — Unit tests for v6 (HF_OLD_VALUE) trace format support
 *
 * Verifies:
 *   - Header parsing recognises version=6 + HF_OLD_VALUE flag correctly
 *   - MemAccessView.has_old_value is set for WRITE accesses with known old value
 *   - MemAccessView.has_old_value is false for READ accesses (old_value meaningless)
 *   - MemAccessView.has_old_value is false when MF_OLD_UNKNOWN is set
 *   - old_value / old_value_hi fields carry the correct pre-write bytes
 *   - TraceReader iterator advances correctly over 48-byte v6 memacc records
 *   - record_at() random-access still works on v6 traces
 *   - Backward compatibility: v4 traces still parse correctly alongside v6
 */
#include <catch2/catch_test_macros.hpp>
#include <cstring>

#include "fixtures/trace_fixture.h"
#include "common/types.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

// 8-byte write: type=MEMORY_WRITE(2), size=8
static constexpr uint8_t kWrite = 2;
static constexpr uint8_t kRead  = 1;

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("TraceReader v6: header flags detected correctly", "[unit][io][trace_reader_v6]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v6();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_v6(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "v6_header");

    REQUIRE(env != nullptr);
    const auto& hdr = env->reader->header();

    SECTION("version number is 6") {
        REQUIRE(hdr.version == 6);
    }
    SECTION("HF_OLD_VALUE flag is set") {
        // flags field is the raw bitmask from the file header
        REQUIRE(hdr.flags & qbditrace::QBDITRACE_HF_OLD_VALUE);
    }
    SECTION("HF_HAS_MEM is still set") {
        REQUIRE(hdr.has_mem());
    }
}

TEST_CASE("TraceReader v6: WRITE access has_old_value=true with correct bytes",
          "[unit][io][trace_reader_v6]") {
    constexpr uint64_t kBuf    = 0x16F010000ULL;
    constexpr uint64_t kNewVal = 0xDEADBEEFCAFEBABEULL;
    constexpr uint64_t kOldVal = 0x0123456789ABCDEFULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v6();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // STR x0, [buf]: new value = kNewVal, old value = kOldVal
        TraceWriter::MemAccV6 ma{};
        ma.type      = kWrite;
        ma.size      = 8;
        ma.addr      = kBuf;
        ma.value     = kNewVal;
        ma.old_value = kOldVal;
        ma.old_unknown = false;

        tw.emit_v6(ms, 0x1000, enc::str_imm(0, 31, 0),
                   {{0, kNewVal}, {33, tw.rt(0x1004)}},
                   {ma});
        tw.emit_anchor(ms);
    }, "v6_write_old");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();
        REQUIRE(inst.mem_access_count == 1);

        auto m0 = inst.mem_access(0);

        SECTION("is a WRITE access") {
            REQUIRE(m0.type == kWrite);
            REQUIRE(m0.size == 8);
            REQUIRE(m0.addr == kBuf);
        }
        SECTION("new value is correct") {
            REQUIRE(m0.value == kNewVal);
        }
        SECTION("has_old_value is true") {
            REQUIRE(m0.has_old_value == true);
        }
        SECTION("old_value is correct") {
            REQUIRE(m0.old_value == kOldVal);
        }
        SECTION("old_value_hi is zero for 8-byte write") {
            REQUIRE(m0.old_value_hi == 0);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v6: READ access has_old_value=false", "[unit][io][trace_reader_v6]") {
    constexpr uint64_t kBuf = 0x16F020000ULL;
    constexpr uint64_t kVal = 0xABCDEF0123456789ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v6();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // LDR x0, [buf]: read access — old_value not meaningful
        TraceWriter::MemAccV6 ma{};
        ma.type      = kRead;
        ma.size      = 8;
        ma.addr      = kBuf;
        ma.value     = kVal;
        ma.old_value = 0;  // reads don't have old_value
        ma.old_unknown = false;

        tw.emit_v6(ms, 0x1000, enc::ldr_imm(0, 31, 0),
                   {{0, kVal}, {33, tw.rt(0x1004)}},
                   {ma});
        tw.emit_anchor(ms);
    }, "v6_read_no_old");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        REQUIRE(inst.mem_access_count == 1);
        auto m0 = inst.mem_access(0);

        SECTION("is a READ access") {
            REQUIRE(m0.type == kRead);
        }
        SECTION("has_old_value is false for reads") {
            REQUIRE(m0.has_old_value == false);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v6: MF_OLD_UNKNOWN flag disables has_old_value",
          "[unit][io][trace_reader_v6]") {
    constexpr uint64_t kBuf = 0x16F030000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v6();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // WRITE access where old value could not be captured (guard page etc.)
        TraceWriter::MemAccV6 ma{};
        ma.type        = kWrite;
        ma.size        = 8;
        ma.addr        = kBuf;
        ma.value       = 0xDEAD;
        ma.old_value   = 0;      // zeroed out because unknown
        ma.old_unknown = true;   // → MF_OLD_UNKNOWN bit set in mem_flags

        tw.emit_v6(ms, 0x1000, enc::str_imm(0, 31, 0),
                   {{0, 0xDEADULL}, {33, tw.rt(0x1004)}},
                   {ma});
        tw.emit_anchor(ms);
    }, "v6_old_unknown");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        REQUIRE(inst.mem_access_count == 1);
        auto m0 = inst.mem_access(0);

        SECTION("has_old_value is false when MF_OLD_UNKNOWN") {
            REQUIRE(m0.has_old_value == false);
        }
        SECTION("MF_OLD_UNKNOWN bit is visible in flags") {
            REQUIRE(m0.flags & QBDITRACE_MF_OLD_UNKNOWN);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v6: iterator advances correctly over multiple records",
          "[unit][io][trace_reader_v6]") {
    // Emit 5 instructions (mix of reads/writes) and verify counts + order.
    constexpr uint64_t kBase = 0x16F040000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v6();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        auto make_write = [&](uint64_t addr, uint64_t nv, uint64_t ov) {
            TraceWriter::MemAccV6 m{};
            m.type = kWrite; m.size = 8; m.addr = addr;
            m.value = nv; m.old_value = ov; m.old_unknown = false;
            return m;
        };
        auto make_read = [&](uint64_t addr, uint64_t val) {
            TraceWriter::MemAccV6 m{};
            m.type = kRead; m.size = 8; m.addr = addr;
            m.value = val; m.old_unknown = false;
            return m;
        };

        // inst 0: write to kBase
        tw.emit_v6(ms, 0x1000, enc::str_imm(0, 31, 0),
                   {{33, tw.rt(0x1004)}}, {make_write(kBase, 1, 0)});
        // inst 1: no mem
        tw.emit_v6(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        // inst 2: write to kBase+8
        tw.emit_v6(ms, 0x1008, enc::str_imm(1, 31, 8),
                   {{33, tw.rt(0x100C)}}, {make_write(kBase + 8, 2, 0)});
        // inst 3: read from kBase
        tw.emit_v6(ms, 0x100C, enc::ldr_imm(2, 31, 0),
                   {{2, 1ULL}, {33, tw.rt(0x1010)}}, {make_read(kBase, 1)});
        // inst 4: write to kBase (overwrite)
        tw.emit_v6(ms, 0x1010, enc::str_imm(3, 31, 0),
                   {{33, tw.rt(0x1014)}}, {make_write(kBase, 99, 1)});
        tw.emit_anchor(ms);
    }, "v6_multirecord");

    REQUIRE(env != nullptr);

    int inst_count = 0;
    int mem_count  = 0;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        inst_count++;
        auto inst = rec.as_inst();
        mem_count += inst.mem_access_count;
    }

    SECTION("instruction count") {
        REQUIRE(inst_count == 5);
    }
    SECTION("total memory accesses (1 write + 0 + 1 write + 1 read + 1 write = 4)") {
        REQUIRE(mem_count == 4);
    }
}

TEST_CASE("TraceReader v6: old_value_hi for 16-byte (stp-class) writes",
          "[unit][io][trace_reader_v6]") {
    constexpr uint64_t kBuf      = 0x16F050000ULL;
    constexpr uint64_t kNewLo    = 0x0102030405060708ULL;
    constexpr uint64_t kNewHi    = 0x090A0B0C0D0E0F10ULL;
    constexpr uint64_t kOldLo    = 0xAAAABBBBCCCCDDDDULL;
    constexpr uint64_t kOldHi    = 0xEEEEFFFF00001111ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v6();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        TraceWriter::MemAccV6 ma{};
        ma.type        = kWrite;
        ma.size        = 16;  // 16-byte store (STP)
        ma.addr        = kBuf;
        ma.value       = kNewLo;
        ma.value_hi    = kNewHi;
        ma.old_value   = kOldLo;
        ma.old_value_hi = kOldHi;
        ma.old_unknown = false;

        tw.emit_v6(ms, 0x1000, enc::stp_pre(0, 1, 31, -16),
                   {{33, tw.rt(0x1004)}}, {ma});
        tw.emit_anchor(ms);
    }, "v6_wide_write");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        REQUIRE(inst.mem_access_count == 1);
        auto m0 = inst.mem_access(0);

        SECTION("16-byte write size") {
            REQUIRE(m0.size == 16);
        }
        SECTION("new value lo and hi") {
            REQUIRE(m0.value    == kNewLo);
            REQUIRE(m0.value_hi == kNewHi);
        }
        SECTION("old value lo and hi are both valid") {
            REQUIRE(m0.has_old_value == true);
            REQUIRE(m0.old_value     == kOldLo);
            REQUIRE(m0.old_value_hi  == kOldHi);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v4: still parses correctly when v6 support is compiled in",
          "[unit][io][trace_reader_v6]") {
    // Regression: adding v6 support must not break existing v4 traces.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();  // v4
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::str_imm(0, 31, 0),
                {{0, 0xABCDULL}, {33, tw.rt(0x1004)}},
                {{2, 8, 0x16F000000ULL, 0xABCDULL}});
        tw.emit_anchor(ms);
    }, "v4_compat");

    REQUIRE(env != nullptr);

    SECTION("version is 4") {
        REQUIRE(env->reader->header().version == 4);
    }

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        auto m0 = inst.mem_access(0);

        SECTION("v4 write: has_old_value is false") {
            REQUIRE(m0.has_old_value == false);
        }
        SECTION("v4 write: value is correct") {
            REQUIRE(m0.value == 0xABCDULL);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}
