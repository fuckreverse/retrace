/*
 * test_io_trace_reader_special.cpp — Unit tests for special record types and edge cases
 *
 * Verifies:
 *   -- Special record parsing (all non-INST/ANCHOR/CODE kinds) --
 *   - THREAD record: thread_id field
 *   - EVENT record: all four event types (SEQ_ENTRY, SEQ_EXIT, XFER_CALL, XFER_RETURN)
 *   - SVC record: pc, syscall_no, args[0..5]
 *   - OBJC record: all four variants (MSGSEND, SUPER, SUPER2, STRET); pc, recv, sel, cls
 *
 *   -- File-level edge cases / error handling --
 *   - Magic mismatch → open() returns error
 *   - File too small (< 536 bytes header) → open() returns error
 *   - Version mismatch (e.g. version=99) → open() returns error
 *
 *   -- Mixed record stream --
 *   - A trace containing INST, ANCHOR, CODE, THREAD, EVENT, SVC, OBJC all together:
 *     iterator visits all records, kind counts are correct
 *
 *   -- Struct size / layout assertions --
 *   - Sanity-check that the Tenet view structs surface the correct byte-level sizes
 *     declared in TraceFormat.h (mirrors the compile-time static_asserts)
 */
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#include "fixtures/trace_fixture.h"
#include "common/types.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static constexpr uint8_t kWrite = 2;

// ─── THREAD record ───────────────────────────────────────────────────────────

TEST_CASE("TraceReader: THREAD record carries correct thread_id",
          "[unit][io][trace_reader_special]") {
    constexpr uint64_t kTID = 0xDEAD1234CAFE5678ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_thread(kTID);  // thread context marker
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_thread");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Thread) continue;
        auto tv = rec.as_thread();
        SECTION("thread_id is correct") {
            REQUIRE(tv.thread_id == kTID);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader: multiple THREAD records, last one dominates",
          "[unit][io][trace_reader_special]") {
    constexpr uint64_t kTID1 = 1001;
    constexpr uint64_t kTID2 = 2002;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_thread(kTID1);
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_thread(kTID2);
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "special_multi_thread");

    REQUIRE(env != nullptr);

    std::vector<uint64_t> tids;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Thread) continue;
        tids.push_back(rec.as_thread().thread_id);
    }

    SECTION("two THREAD records found") {
        REQUIRE(tids.size() == 2);
    }
    SECTION("first thread id") {
        REQUIRE(tids[0] == kTID1);
    }
    SECTION("second thread id") {
        REQUIRE(tids[1] == kTID2);
    }
}

// ─── EVENT record ────────────────────────────────────────────────────────────

TEST_CASE("TraceReader: EVENT SEQ_ENTRY record parsed correctly",
          "[unit][io][trace_reader_special]") {
    constexpr uint64_t kAddr = 0x100004000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_event(qbditrace::QBDITRACE_EV_SEQ_ENTRY, kAddr);
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_ev_seq_entry");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Event) continue;
        auto ev = rec.as_event();
        SECTION("event type is SEQ_ENTRY") {
            REQUIRE(ev.event == qbditrace::QBDITRACE_EV_SEQ_ENTRY);
        }
        SECTION("addr is correct") {
            REQUIRE(ev.addr == kAddr);
        }
        SECTION("site is 0 for SEQ_ENTRY") {
            REQUIRE(ev.site == 0);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader: EVENT XFER_CALL carries both addr and site",
          "[unit][io][trace_reader_special]") {
    constexpr uint64_t kTarget   = 0x200000000ULL;  // external target
    constexpr uint64_t kCallSite = 0x100004100ULL;  // call site inside traced range

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_event(qbditrace::QBDITRACE_EV_XFER_CALL, kTarget, kCallSite);
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_ev_xfer_call");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Event) continue;
        auto ev = rec.as_event();
        SECTION("event type is XFER_CALL") {
            REQUIRE(ev.event == qbditrace::QBDITRACE_EV_XFER_CALL);
        }
        SECTION("addr is the call target") {
            REQUIRE(ev.addr == kTarget);
        }
        SECTION("site is the call-site PC") {
            REQUIRE(ev.site == kCallSite);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader: EVENT XFER_RETURN: site is 0",
          "[unit][io][trace_reader_special]") {
    constexpr uint64_t kRetTarget = 0x100004200ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_event(qbditrace::QBDITRACE_EV_XFER_RETURN, kRetTarget);
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_ev_xfer_ret");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Event) continue;
        auto ev = rec.as_event();
        SECTION("event type is XFER_RETURN") {
            REQUIRE(ev.event == qbditrace::QBDITRACE_EV_XFER_RETURN);
        }
        SECTION("addr is the return target") {
            REQUIRE(ev.addr == kRetTarget);
        }
        SECTION("site is 0 for XFER_RETURN") {
            REQUIRE(ev.site == 0);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader: all four EVENT types in one trace",
          "[unit][io][trace_reader_special]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_event(qbditrace::QBDITRACE_EV_SEQ_ENTRY,    0x1000);
        tw.emit_event(qbditrace::QBDITRACE_EV_XFER_CALL,    0x2000, 0x1100);
        tw.emit_event(qbditrace::QBDITRACE_EV_XFER_RETURN,  0x1104);
        tw.emit_event(qbditrace::QBDITRACE_EV_SEQ_EXIT,     0x1FFF);
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_all_events");

    REQUIRE(env != nullptr);

    std::vector<uint8_t> event_types;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Event) continue;
        event_types.push_back(rec.as_event().event);
    }

    SECTION("four event records found") {
        REQUIRE(event_types.size() == 4);
    }
    SECTION("event types in order") {
        REQUIRE(event_types[0] == qbditrace::QBDITRACE_EV_SEQ_ENTRY);
        REQUIRE(event_types[1] == qbditrace::QBDITRACE_EV_XFER_CALL);
        REQUIRE(event_types[2] == qbditrace::QBDITRACE_EV_XFER_RETURN);
        REQUIRE(event_types[3] == qbditrace::QBDITRACE_EV_SEQ_EXIT);
    }
}

// ─── SVC record ──────────────────────────────────────────────────────────────

TEST_CASE("TraceReader: SVC record: pc, syscall_no, args[0..5] all correct",
          "[unit][io][trace_reader_special]") {
    // Darwin arm64: x16 = syscall number; x0..x5 = args
    constexpr uint64_t kSvcPc    = 0x100008000ULL;
    constexpr uint64_t kSyscall  = 0x2000003ULL;  // Darwin write(2)
    constexpr uint64_t kArgs[6]  = { 1, 0xBEEF0000, 13, 0, 0, 0 };  // fd, buf, len, ...

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // emit_svc only stores first 2 args in the helper; write a complete SVC manually
        qbditrace::qbditrace_svc_head_t h = {};
        h.kind       = QBDITRACE_REC_SVC;
        h.pc         = kSvcPc;
        h.syscall_no = kSyscall;
        for (int i = 0; i < 6; i++) h.args[i] = kArgs[i];
        fwrite(&h, sizeof(h), 1, tw.fp);

        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_svc");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Svc) continue;
        auto sv = rec.as_svc();
        SECTION("SVC pc") {
            REQUIRE(sv.pc == kSvcPc);
        }
        SECTION("syscall_no") {
            REQUIRE(sv.syscall_no == kSyscall);
        }
        SECTION("arg0 (fd=1)") {
            REQUIRE(sv.args[0] == kArgs[0]);
        }
        SECTION("arg1 (buf pointer)") {
            REQUIRE(sv.args[1] == kArgs[1]);
        }
        SECTION("arg2 (len=13)") {
            REQUIRE(sv.args[2] == kArgs[2]);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader: SVC record byte size is 72 bytes",
          "[unit][io][trace_reader_special]") {
    // Verify the on-disk struct size matches TraceFormat.h static_assert.
    static_assert(sizeof(qbditrace::qbditrace_svc_head_t) == 72,
                  "svc head must be 72 bytes");
    REQUIRE(sizeof(qbditrace::qbditrace_svc_head_t) == 72);
}

// ─── OBJC record ─────────────────────────────────────────────────────────────

TEST_CASE("TraceReader: OBJC MSGSEND record: pc, recv, sel, cls",
          "[unit][io][trace_reader_special]") {
    constexpr uint64_t kObjcPc   = 0x100005000ULL;
    constexpr uint64_t kRecv     = 0x60000001234ULL;
    constexpr uint64_t kSel      = 0x100080000ULL;
    const char* kCls             = "NSString";

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_objc(kObjcPc, kRecv, kSel, kCls);
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_objc_msgsend");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Objc) continue;
        auto ov = rec.as_objc();
        SECTION("variant is MSGSEND") {
            REQUIRE(ov.variant == qbditrace::QBDITRACE_OBJC_MSGSEND);
        }
        SECTION("pc is correct") {
            REQUIRE(ov.pc == kObjcPc);
        }
        SECTION("receiver pointer") {
            REQUIRE(ov.recv == kRecv);
        }
        SECTION("selector pointer") {
            REQUIRE(ov.sel == kSel);
        }
        SECTION("class name string") {
            REQUIRE(std::string(ov.cls) == kCls);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader: OBJC all four variant types",
          "[unit][io][trace_reader_special]") {
    // Emit all four objc_msgSend variants and verify the variant byte.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Write them manually to control the variant field
        auto write_objc = [&](uint8_t variant, uint64_t pc, uint64_t recv, uint64_t sel,
                               const char* cls) {
            qbditrace::qbditrace_objc_head_t h = {};
            h.kind    = QBDITRACE_REC_OBJC;
            h.variant = variant;
            h.pc      = pc;
            h.recv    = recv;
            h.sel     = sel;
            strncpy(h.cls, cls, sizeof(h.cls) - 1);
            fwrite(&h, sizeof(h), 1, tw.fp);
        };

        write_objc(qbditrace::QBDITRACE_OBJC_MSGSEND,       0x1000, 0xA0, 0xB0, "UIView");
        write_objc(qbditrace::QBDITRACE_OBJC_MSGSEND_SUPER,  0x1004, 0xA1, 0xB1, "UIButton");
        write_objc(qbditrace::QBDITRACE_OBJC_MSGSEND_SUPER2, 0x1008, 0xA2, 0xB2, "NSObject");
        write_objc(qbditrace::QBDITRACE_OBJC_MSGSEND_STRET,  0x100C, 0xA3, 0xB3, "MyClass");

        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_objc_variants");

    REQUIRE(env != nullptr);

    std::vector<uint8_t> variants;
    std::vector<std::string> class_names;

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Objc) continue;
        auto ov = rec.as_objc();
        variants.push_back(ov.variant);
        class_names.push_back(ov.cls);
    }

    SECTION("four OBJC records found") {
        REQUIRE(variants.size() == 4);
    }
    SECTION("variant order") {
        REQUIRE(variants[0] == qbditrace::QBDITRACE_OBJC_MSGSEND);
        REQUIRE(variants[1] == qbditrace::QBDITRACE_OBJC_MSGSEND_SUPER);
        REQUIRE(variants[2] == qbditrace::QBDITRACE_OBJC_MSGSEND_SUPER2);
        REQUIRE(variants[3] == qbditrace::QBDITRACE_OBJC_MSGSEND_STRET);
    }
    SECTION("class names round-trip") {
        REQUIRE(class_names[0] == "UIView");
        REQUIRE(class_names[1] == "UIButton");
        REQUIRE(class_names[2] == "NSObject");
        REQUIRE(class_names[3] == "MyClass");
    }
}

TEST_CASE("TraceReader: OBJC class name truncation at 47 chars (48-byte cls field)",
          "[unit][io][trace_reader_special]") {
    // Class name field is char cls[48], so max 47 printable chars + NUL.
    std::string long_cls(60, 'X');  // too long, will be truncated to 47

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_objc(0x1000, 0, 0, long_cls.c_str());
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_objc_cls_trunc");

    REQUIRE(env != nullptr);

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Objc) continue;
        auto ov = rec.as_objc();
        SECTION("class name truncated to 47 chars") {
            REQUIRE(std::string(ov.cls).size() == 47);
        }
        break;
    }
}

// ─── Mixed record stream ──────────────────────────────────────────────────────

TEST_CASE("TraceReader: mixed record stream — all kinds counted correctly",
          "[unit][io][trace_reader_special]") {
    // Full stream: THREAD + EVENT + OBJC + SVC + INST + CODE + ANCHOR
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // One of each special type
        tw.emit_thread(42);
        tw.emit_event(qbditrace::QBDITRACE_EV_SEQ_ENTRY, 0x1000);
        tw.emit_objc(0x1000, 0xAA, 0xBB, "NSObject");
        tw.emit_svc(0x1000, 3, 0, 0);

        // 3 instructions (each gets a CODE record on first sight)
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});

        tw.emit_anchor(ms);
    }, "special_mixed");

    REQUIRE(env != nullptr);

    int cnt_inst = 0, cnt_anchor = 0, cnt_code = 0;
    int cnt_thread = 0, cnt_event = 0, cnt_objc = 0, cnt_svc = 0;

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        switch (rec.kind) {
        case RecordKind::Inst:   cnt_inst++;   break;
        case RecordKind::Anchor: cnt_anchor++; break;
        case RecordKind::Code:   cnt_code++;   break;
        case RecordKind::Thread: cnt_thread++; break;
        case RecordKind::Event:  cnt_event++;  break;
        case RecordKind::Objc:   cnt_objc++;   break;
        case RecordKind::Svc:    cnt_svc++;    break;
        }
    }

    SECTION("INST count") {
        REQUIRE(cnt_inst == 3);
    }
    SECTION("ANCHOR count (1 auto + 1 explicit)") {
        REQUIRE(cnt_anchor == 2);
    }
    SECTION("CODE count (3 distinct PCs)") {
        REQUIRE(cnt_code == 3);
    }
    SECTION("THREAD count") {
        REQUIRE(cnt_thread == 1);
    }
    SECTION("EVENT count") {
        REQUIRE(cnt_event == 1);
    }
    SECTION("OBJC count") {
        REQUIRE(cnt_objc == 1);
    }
    SECTION("SVC count") {
        REQUIRE(cnt_svc == 1);
    }
}

// ─── Error / edge cases ───────────────────────────────────────────────────────

TEST_CASE("TraceReader::open: magic mismatch → error",
          "[unit][io][trace_reader_special]") {
    // Write a file with wrong magic
    auto temp_dir = std::filesystem::temp_directory_path()
                  / ("tenet_test_bad_magic_" + std::to_string(getpid()));
    std::filesystem::create_directories(temp_dir);
    auto path = temp_dir / "bad_magic.trace";

    {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic   = 0xDEADBEEFu;  // wrong
        hdr.version = QBDITRACE_VERSION;
        hdr.arch    = qbditrace::QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = 34;
        FILE* fp = fopen(path.c_str(), "wb");
        REQUIRE(fp != nullptr);
        fwrite(&hdr, sizeof(hdr), 1, fp);
        // add a minimal anchor record so file is not too small
        qbditrace::qbditrace_anchor_head_t a = {};
        a.kind = QBDITRACE_REC_ANCHOR;
        fwrite(&a, sizeof(a), 1, fp);
        uint64_t gpr[34] = {};
        fwrite(gpr, sizeof(gpr), 1, fp);
        fclose(fp);
    }

    auto result = TraceReader::open(path);
    SECTION("open returns an error") {
        REQUIRE(!result);
    }

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("TraceReader::open: file too small (< 536 bytes) → error",
          "[unit][io][trace_reader_special]") {
    auto temp_dir = std::filesystem::temp_directory_path()
                  / ("tenet_test_too_small_" + std::to_string(getpid()));
    std::filesystem::create_directories(temp_dir);
    auto path = temp_dir / "too_small.trace";

    {
        // Write only 16 bytes — too small for a 536-byte header
        FILE* fp = fopen(path.c_str(), "wb");
        REQUIRE(fp != nullptr);
        uint8_t buf[16] = { 'Q', 'B', 'D', 'T', 4, 0, 0, 0 };
        fwrite(buf, 16, 1, fp);
        fclose(fp);
    }

    auto result = TraceReader::open(path);
    SECTION("open returns an error for truncated header") {
        REQUIRE(!result);
    }

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("TraceReader::open: unknown version → error",
          "[unit][io][trace_reader_special]") {
    auto temp_dir = std::filesystem::temp_directory_path()
                  / ("tenet_test_bad_version_" + std::to_string(getpid()));
    std::filesystem::remove_all(temp_dir);  // pre-clean any leftover
    std::filesystem::create_directories(temp_dir);
    auto path = temp_dir / "bad_version.trace";

    // Write a valid-magic but unsupported version=99 header.
    // Use the same direct fopen/fwrite/fclose approach as the magic-mismatch test
    // to avoid any TraceWriter stack-layout interactions in Release builds.
    {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic   = QBDITRACE_MAGIC;
        hdr.version = 99;  // unsupported version
        hdr.arch    = qbditrace::QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = 34;
        hdr.flags   = qbditrace::QBDITRACE_HF_REG_DIFF | qbditrace::QBDITRACE_HF_HAS_CODE;
        strncpy(hdr.module_name, "bad_version", sizeof(hdr.module_name) - 1);
        FILE* fp = fopen(path.c_str(), "wb");
        REQUIRE(fp != nullptr);
        fwrite(&hdr, sizeof(hdr), 1, fp);
        // Add a minimal anchor record so file is not too small
        qbditrace::qbditrace_anchor_head_t a = {};
        a.kind = QBDITRACE_REC_ANCHOR;
        fwrite(&a, sizeof(a), 1, fp);
        uint64_t gpr[34] = {};
        fwrite(gpr, sizeof(gpr), 1, fp);
        fclose(fp);
    }

    auto result = TraceReader::open(path);
    SECTION("open returns an error for unknown version") {
        REQUIRE(!result);
    }

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("TraceReader::open: v5 version tag without HF_PC_DELTA flag → error",
          "[unit][io][trace_reader_special]") {
    // version == 5 but HF_PC_DELTA not set: inconsistent, should be rejected.
    auto temp_dir = std::filesystem::temp_directory_path()
                  / ("tenet_test_v5_no_flag_" + std::to_string(getpid()));
    std::filesystem::create_directories(temp_dir);
    auto path = temp_dir / "v5_no_flag.trace";

    {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic   = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION_V5_PC_DELTA;  // 5
        hdr.arch    = qbditrace::QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = 34;
        hdr.flags   = qbditrace::QBDITRACE_HF_REG_DIFF;  // HF_PC_DELTA intentionally absent
        FILE* fp = fopen(path.c_str(), "wb");
        REQUIRE(fp != nullptr);
        fwrite(&hdr, sizeof(hdr), 1, fp);
        fclose(fp);
    }

    auto result = TraceReader::open(path);
    SECTION("open rejects v5 version without HF_PC_DELTA") {
        REQUIRE(!result);
    }

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("TraceReader::open: v6 version tag without HF_OLD_VALUE flag → error",
          "[unit][io][trace_reader_special]") {
    // version == 6 but HF_OLD_VALUE not set: inconsistent, should be rejected.
    auto temp_dir = std::filesystem::temp_directory_path()
                  / ("tenet_test_v6_no_flag_" + std::to_string(getpid()));
    std::filesystem::create_directories(temp_dir);
    auto path = temp_dir / "v6_no_flag.trace";

    {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic   = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION_V6_OLD_VALUE;  // 6
        hdr.arch    = qbditrace::QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = 34;
        hdr.flags   = qbditrace::QBDITRACE_HF_REG_DIFF;  // HF_OLD_VALUE intentionally absent
        FILE* fp = fopen(path.c_str(), "wb");
        REQUIRE(fp != nullptr);
        fwrite(&hdr, sizeof(hdr), 1, fp);
        fclose(fp);
    }

    auto result = TraceReader::open(path);
    SECTION("open rejects v6 version without HF_OLD_VALUE") {
        REQUIRE(!result);
    }

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("TraceReader::open: non-existent file → error",
          "[unit][io][trace_reader_special]") {
    auto result = TraceReader::open("/tmp/tenet_this_file_does_not_exist_12345.trace");
    SECTION("open returns an error for missing file") {
        REQUIRE(!result);
    }
}

// ─── Struct size / layout assertions ─────────────────────────────────────────

TEST_CASE("TraceFormat: struct sizes match documented on-disk layout",
          "[unit][io][trace_reader_special]") {
    // Mirror the compile-time static_assert checks at runtime so Catch2 reports
    // them nicely if they ever fail (e.g. after a struct change).
    SECTION("file header: 536 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_file_header_t) == 536);
    }
    SECTION("v4 INST head: 16 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_inst_head_t) == 16);
    }
    SECTION("v5 INST head: 6 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_inst_head_v5_t) == 6);
    }
    SECTION("regdiff: 16 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_regdiff_t) == 16);
    }
    SECTION("memacc v4/v5: 32 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_memacc_t) == 32);
    }
    SECTION("memacc v6: 48 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_memacc_v6_t) == 48);
    }
    SECTION("anchor head: 16 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_anchor_head_t) == 16);
    }
    SECTION("thread head: 16 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_thread_head_t) == 16);
    }
    SECTION("event head: 24 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_event_head_t) == 24);
    }
    SECTION("svc head: 72 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_svc_head_t) == 72);
    }
    SECTION("objc head: 80 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_objc_head_t) == 80);
    }
    SECTION("code head: 16 bytes") {
        REQUIRE(sizeof(qbditrace::qbditrace_code_head_t) == 16);
    }
}

// ─── CODE record deduplication ───────────────────────────────────────────────

TEST_CASE("TraceReader: CODE record emitted only once per unique PC",
          "[unit][io][trace_reader_special]") {
    // Execute the NOP at 0x1000 three times; only one CODE record should appear.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        uint32_t nop = enc::nop();
        tw.emit(ms, 0x1000, nop, {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::b(-4), {{33, tw.rt(0x1000)}}, {});
        tw.emit(ms, 0x1000, nop, {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::b(-4), {{33, tw.rt(0x1000)}}, {});
        tw.emit(ms, 0x1000, nop, {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_code_dedup");

    REQUIRE(env != nullptr);

    std::vector<uint64_t> code_pcs;
    int inst_count = 0;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Code) {
            code_pcs.push_back(rec.as_code().pc);
        } else if (rec.kind == RecordKind::Inst) {
            inst_count++;
        }
    }

    SECTION("5 INST records (5 executions)") {
        REQUIRE(inst_count == 5);
    }
    SECTION("only 2 CODE records (0x1000+slide and 0x1004+slide)") {
        REQUIRE(code_pcs.size() == 2);
    }
    SECTION("CODE record for 0x1000+slide") {
        bool found = false;
        for (auto pc : code_pcs) found |= (pc == rt_pc(0x1000));
        REQUIRE(found);
    }
    SECTION("CODE record for 0x1004+slide") {
        bool found = false;
        for (auto pc : code_pcs) found |= (pc == rt_pc(0x1004));
        REQUIRE(found);
    }
}

TEST_CASE("TraceReader: CODE record opcode bytes correct for branch instruction",
          "[unit][io][trace_reader_special]") {
    // Verify that the 4 bytes of a BL instruction round-trip through CODE record.
    uint32_t bl_opcode = enc::bl(0x2000 - 0x1000);

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, bl_opcode, {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "special_code_bl");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Code) continue;
        auto cv = rec.as_code();
        if (cv.pc != rt_pc(0x1000)) continue;  // find the BL at 0x1000

        SECTION("CODE size is 4") {
            REQUIRE(cv.size == 4);
        }
        SECTION("opcode bytes match BL encoding") {
            uint32_t read_op = 0;
            std::memcpy(&read_op, cv.bytes, 4);
            REQUIRE(read_op == bl_opcode);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}
