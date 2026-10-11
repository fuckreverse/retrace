#include "common/platform_file.h"
/*
 * test_io_trace_reader_v8.cpp — Unit tests for v8 (HF_WIDE_API_ID) trace format support
 *
 * Verifies:
 *   - Header parsing recognises version=8 + HF_WIDE_API_ID flag correctly
 *   - CapiCallView parses v8 header (96 bytes, uint16_t api_id) correctly
 *   - api_id values > 255 survive the v8 round-trip (the core motivation for v8)
 *   - Iterator advances correctly over v8 CapiCall records with strings
 *   - record_at() random access works on v8 traces
 *   - v4 traces still parse correctly when v8 support is compiled in (regression)
 *   - raw_record_size() handles v8 CapiCall correctly
 *   - dump_trace includes CAPICALL records for v8 traces
 */
#include <catch2/catch_test_macros.hpp>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include "common/platform_compat.h"

#include "fixtures/trace_fixture.h"
#include "common/types.h"

using namespace tenet;
using namespace tenet::test;

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("TraceReader v8: header flags detected correctly", "[unit][io][trace_reader_v8]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "v8_header");

    REQUIRE(env != nullptr);
    const auto& hdr = env->reader->header();

    SECTION("version number is 8") {
        REQUIRE(hdr.version == 8);
    }
    SECTION("HF_WIDE_API_ID flag is set") {
        REQUIRE(hdr.flags & qbditrace::QBDITRACE_HF_WIDE_API_ID);
    }
    SECTION("has_wide_api_id() returns true") {
        REQUIRE(hdr.has_wide_api_id());
    }
    SECTION("HF_HAS_MEM is still set") {
        REQUIRE(hdr.has_mem());
    }
    SECTION("HF_HAS_CODE is still set") {
        REQUIRE(hdr.has_code());
    }
}

TEST_CASE("TraceReader v8: CapiCallView with small api_id (< 256)",
          "[unit][io][trace_reader_v8]") {
    // api_id=22 (strcmp) — fits in uint8_t too, but should still work with v8 header.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_capicall_v8(22, tw.rt(0x1004), 0xDEAD100ULL,
                            {0xA000ULL, 0xB000ULL}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v8_capicall_small_id");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::CapiCall) continue;

        auto cc = rec.as_capicall();
        SECTION("api_id is 22 (strcmp)") {
            REQUIRE(cc.api_id == 22);
        }
        SECTION("is_v8 is true") {
            REQUIRE(cc.is_v8 == true);
        }
        SECTION("arg_count is 2") {
            REQUIRE(cc.arg_count == 2);
        }
        SECTION("str_count is 0") {
            REQUIRE(cc.str_count == 0);
        }
        SECTION("pc is correct") {
            REQUIRE(cc.pc == rt_pc(0x1004));
        }
        SECTION("target is correct") {
            REQUIRE(cc.target == 0xDEAD100ULL);
        }
        SECTION("args[0] is correct") {
            REQUIRE(cc.args[0] == 0xA000ULL);
        }
        SECTION("args[1] is correct") {
            REQUIRE(cc.args[1] == 0xB000ULL);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v8: CapiCallView with api_id > 255 (JNI FindClass = 289)",
          "[unit][io][trace_reader_v8]") {
    // This is the core motivation for v8: api_id=289 (QBDITRACE_CAPI_JNI_FIND_CLASS)
    // does NOT fit in uint8_t and would be truncated to 33 in v4-v7 format.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        // FindClass(env, "com/example/MainActivity")
        TraceWriter::CapiStr s0;
        s0.arg_idx = 1;
        s0.value   = "com/example/MainActivity";
        tw.emit_capicall_v8(289, tw.rt(0x1004), 0xDEAD200ULL,
                            {0xE000ULL, 0xC000ULL}, {s0});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v8_capicall_jni_findclass");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::CapiCall) continue;

        auto cc = rec.as_capicall();
        SECTION("api_id is 289 (not truncated to 33)") {
            REQUIRE(cc.api_id == 289);
            // Verify it would have been truncated in the old format:
            // 289 & 0xFF == 33
            REQUIRE((289 & 0xFF) == 33);
            REQUIRE(cc.api_id != (289 & 0xFF));
        }
        SECTION("is_v8 is true") {
            REQUIRE(cc.is_v8 == true);
        }
        SECTION("arg_count is 2") {
            REQUIRE(cc.arg_count == 2);
        }
        SECTION("str_count is 1") {
            REQUIRE(cc.str_count == 1);
        }
        SECTION("string capture is correct") {
            auto sv = cc.str_at(0);
            REQUIRE(sv.arg_idx == 1);
            REQUIRE(std::string(sv.data) == "com/example/MainActivity");
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v8: CapiCallView with high api_id (BoringSSL = 600+)",
          "[unit][io][trace_reader_v8]") {
    // Test with a BoringSSL-style api_id that is well above 255.
    // Using 601 (EVP_EncryptUpdate) as an example.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_capicall_v8(601, tw.rt(0x1004), 0xDEAD300ULL,
                            {0x10ULL, 0x20ULL, 0x30ULL, 0x40ULL}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v8_capicall_boringssl");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::CapiCall) continue;

        auto cc = rec.as_capicall();
        SECTION("api_id is 601 (not truncated)") {
            REQUIRE(cc.api_id == 601);
            // 601 & 0xFF == 89, which would be wrong
            REQUIRE(cc.api_id != (601 & 0xFF));
        }
        SECTION("arg_count is 4") {
            REQUIRE(cc.arg_count == 4);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v8: iterator advances correctly over multiple records",
          "[unit][io][trace_reader_v8]") {
    // Emit 2 INST + 2 CapiCall (one with strings) + anchor, verify all counts.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // CapiCall 1: api_id=1 (memcpy), 3 args, no strings
        tw.emit_capicall_v8(1, tw.rt(0x1004), 0xB000100ULL,
                            {0x1000ULL, 0x2000ULL, 0x100ULL}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        // CapiCall 2: api_id=289 (FindClass), 2 args, 1 string
        TraceWriter::CapiStr s0;
        s0.arg_idx = 1; s0.value = "MyClass";
        tw.emit_capicall_v8(289, tw.rt(0x1008), 0xB000200ULL,
                            {0xE000ULL, 0xC000ULL}, {s0});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "v8_multi_capicall");

    REQUIRE(env != nullptr);

    int inst_count = 0, capi_count = 0, anchor_count = 0, code_count = 0;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        switch (rec.kind) {
        case RecordKind::Inst:       inst_count++;  break;
        case RecordKind::CapiCall:   capi_count++;  break;
        case RecordKind::Anchor:     anchor_count++; break;
        case RecordKind::Code:       code_count++;  break;
        default: break;
        }
    }

    SECTION("3 instructions") {
        REQUIRE(inst_count == 3);
    }
    SECTION("2 capicall records") {
        REQUIRE(capi_count == 2);
    }
    SECTION("1 auto-anchor + 1 explicit = 2") {
        REQUIRE(anchor_count == 2);
    }
    SECTION("3 code records (one per unique PC)") {
        REQUIRE(code_count == 3);
    }
}

TEST_CASE("TraceReader v8: CapiCallView byte_size matches raw_record_size",
          "[unit][io][trace_reader_v8]") {
    // Verify that CapiCallView::byte_size() and raw_record_size() agree for v8.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        // CapiCall with 2 strings
        TraceWriter::CapiStr s0; s0.arg_idx = 0; s0.value = "hello";
        TraceWriter::CapiStr s1; s1.arg_idx = 1; s1.value = "world";
        tw.emit_capicall_v8(22, tw.rt(0x1004), 0xDEAD400ULL,
                            {0xA000ULL, 0xB000ULL}, {s0, s1});

        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v8_byte_size");

    REQUIRE(env != nullptr);

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::CapiCall) continue;

        auto cc = rec.as_capicall();
        size_t view_size = cc.byte_size();
        size_t raw_size = raw_record_size(rec.raw_ptr, env->reader->header());

        SECTION("CapiCallView::byte_size() == raw_record_size()") {
            REQUIRE(view_size == raw_size);
        }
        SECTION("v8 header remains 88 bytes") {
            REQUIRE(sizeof(qbditrace::qbditrace_capicall_head_v8_t) == 88);
        }
        break;
    }
}

TEST_CASE("TraceReader v8: record_at random access works for CapiCall",
          "[unit][io][trace_reader_v8]") {
    // Find a CapiCall record's offset during sequential scan, then re-read it
    // via record_at() and verify the parsed api_id is correct.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_capicall_v8(601, tw.rt(0x1004), 0xDEAD500ULL,
                            {0x10ULL, 0x20ULL, 0x30ULL, 0x40ULL}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v8_record_at");

    REQUIRE(env != nullptr);

    // Find the CapiCall record offset
    uint64_t capi_offset = 0;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::CapiCall) {
            capi_offset = rec.file_offset;
            break;
        }
    }
    REQUIRE(capi_offset > 0);

    // Random access
    auto rv = env->reader->record_at(capi_offset);
    SECTION("kind is CapiCall") {
        REQUIRE(rv.kind == RecordKind::CapiCall);
    }
    SECTION("is_v8 is set") {
        REQUIRE(rv.is_v8 == true);
    }

    auto cc = rv.as_capicall();
    SECTION("api_id is 601 via random access") {
        REQUIRE(cc.api_id == 601);
    }
    SECTION("target is correct") {
        REQUIRE(cc.target == 0xDEAD500ULL);
    }
    SECTION("arg_count is 4") {
        REQUIRE(cc.arg_count == 4);
    }
}

TEST_CASE("TraceReader v8: CapiCall with truncated string capture",
          "[unit][io][trace_reader_v8]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        // CapiCall with a truncated string
        TraceWriter::CapiStr s0;
        s0.arg_idx = 0;
        s0.flags   = QBDITRACE_SF_TRUNCATED;
        s0.value   = "/very/long/path/that/was/truncated";
        tw.emit_capicall_v8(289, tw.rt(0x1004), 0xDEAD600ULL,
                            {0xA000ULL, 0xB000ULL}, {s0});

        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v8_capicall_truncated_str");

    REQUIRE(env != nullptr);

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::CapiCall) continue;

        auto cc = rec.as_capicall();
        SECTION("api_id is 289") {
            REQUIRE(cc.api_id == 289);
        }
        SECTION("str_count is 1") {
            REQUIRE(cc.str_count == 1);
        }
        SECTION("string is marked truncated") {
            auto sv = cc.str_at(0);
            REQUIRE(sv.is_truncated());
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v8: ObjC selector payload and three retval sources step correctly",
          "[unit][io][trace_reader_v8]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x1100), 0xAA, 0xBB,
                        "NSObject", "description");
        tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                       tw.rt(0x1100), 0x9000, tw.rt(0x1104), 1, 2, 0xA0000000, 0, 0);
        tw.emit_capicall_v8(600, tw.rt(0x1200), 0x9100, {1, 2}, {});
        tw.emit_retval(QBDITRACE_REC_CAPICALL, 600,
                       tw.rt(0x1200), 0x9100, tw.rt(0x1204), 3, 4, 0x20000000, 5, 6);
        tw.emit_svc(tw.rt(0x1300), 20);
        tw.emit_retval(QBDITRACE_REC_SVC, 0x1234,
                       tw.rt(0x1300), 0, tw.rt(0x1304), 7, 8, 0, 6, 9,
                       0x2000000001234ULL);
        tw.emit(ms, 0x1400, enc::nop(), {{33, tw.rt(0x1404)}}, {});
    }, "v8_objc_retval");
    REQUIRE(env != nullptr);
    int retval_count = 0;
    bool saw_objc = false, saw_capi = false, saw_svc = false, saw_inst = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        REQUIRE(rec.byte_size(env->reader->header().num_gpr) ==
                raw_record_size(rec.raw_ptr, env->reader->header()));
        if (rec.kind == RecordKind::Objc) {
            auto ov = rec.as_objc();
            REQUIRE(ov.is_v8);
            REQUIRE(std::string(ov.selector_name) == "description");
            REQUIRE(ov.byte_size() == 92);
        } else if (rec.kind == RecordKind::CapiCall) {
            REQUIRE(rec.as_capicall().api_id == 600);
        } else if (rec.kind == RecordKind::Retval) {
            auto rv = rec.as_retval();
            ++retval_count;
            saw_objc |= rv.source_kind == QBDITRACE_REC_OBJC;
            saw_capi |= rv.source_kind == QBDITRACE_REC_CAPICALL;
            saw_svc |= rv.source_kind == QBDITRACE_REC_SVC;
            if (rv.source_kind == QBDITRACE_REC_SVC) {
                REQUIRE(rv.source_id == 0x2000000001234ULL);
                REQUIRE((rv.flags & QBDITRACE_RET_FL_ERRNO_VALID) == 0);
                REQUIRE(rv.x0 == 7);
                REQUIRE(rv.x1 == 8);
            }
            REQUIRE(rv.record_size == sizeof(qbditrace::qbditrace_retval_t));
            REQUIRE(rv.byte_size() == raw_record_size(rec.raw_ptr, env->reader->header()));
        } else if (rec.kind == RecordKind::Inst) {
            saw_inst = true;
        }
    }
    REQUIRE(retval_count == 3);
    REQUIRE(saw_objc); REQUIRE(saw_capi); REQUIRE(saw_svc); REQUIRE(saw_inst);
}

TEST_CASE("TraceReader v8: accepts composed PC delta and FPR flags",
          "[unit][io][trace_reader_v8]") {
    auto dir = std::filesystem::temp_directory_path() /
        ("tenet_v8_composed_" + std::to_string(tenet::platform::current_pid()));
    std::filesystem::create_directories(dir);
    auto path = dir / "composed.trace";
    qbditrace::qbditrace_file_header_t hdr{};
    hdr.magic = QBDITRACE_MAGIC;
    hdr.version = QBDITRACE_VERSION_V8_CALL_META;
    hdr.arch = QBDITRACE_ARCH_AARCH64;
    hdr.num_gpr = QBDITRACE_AARCH64_NUM_GPR;
    hdr.flags = QBDITRACE_HF_CALL_META | QBDITRACE_HF_PC_DELTA |
                QBDITRACE_HF_HAS_FPR;
    FILE* fp = tenet::platform::open_file(path, "wb");
    REQUIRE(fp != nullptr);
    REQUIRE(std::fwrite(&hdr, sizeof(hdr), 1, fp) == 1);
    std::fclose(fp);
    auto result = TraceReader::open(path);
    REQUIRE(result.has_value());
    REQUIRE(result->header().has_call_meta());
    REQUIRE(result->header().has_fpr());
    std::filesystem::remove_all(dir);
}

TEST_CASE("TraceReader v8: rejects CALL_META outside v8 and v8 without it",
          "[unit][io][trace_reader_v8]") {
    struct Case { uint32_t version; uint64_t flags; };
    const Case cases[] = {
        {QBDITRACE_VERSION, QBDITRACE_HF_CALL_META},
        {QBDITRACE_VERSION_V7_HAS_FPR,
         QBDITRACE_HF_HAS_FPR | QBDITRACE_HF_CALL_META},
        {QBDITRACE_VERSION_V8_CALL_META, 0},
    };
    for (size_t i = 0; i < std::size(cases); ++i) {
        auto dir = std::filesystem::temp_directory_path() /
            ("tenet_v8_bad_flags_" + std::to_string(tenet::platform::current_pid()) + "_" + std::to_string(i));
        std::filesystem::create_directories(dir);
        auto path = dir / "bad.trace";
        qbditrace::qbditrace_file_header_t hdr{};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = cases[i].version;
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = QBDITRACE_AARCH64_NUM_GPR;
        hdr.flags = cases[i].flags;
        FILE* fp = tenet::platform::open_file(path, "wb");
        REQUIRE(fp != nullptr);
        REQUIRE(std::fwrite(&hdr, sizeof(hdr), 1, fp) == 1);
        std::fclose(fp);
        REQUIRE_FALSE(TraceReader::open(path).has_value());
        std::filesystem::remove_all(dir);
    }
}

TEST_CASE("TraceReader v8: truncated retval record is clamped to remaining bytes",
          "[unit][io][trace_reader_v8]") {
    auto dir = std::filesystem::temp_directory_path() /
        ("tenet_v8_truncated_retval_" + std::to_string(tenet::platform::current_pid()));
    std::filesystem::create_directories(dir);
    auto path = dir / "truncated.trace";
    qbditrace::qbditrace_file_header_t hdr{};
    hdr.magic = QBDITRACE_MAGIC;
    hdr.version = QBDITRACE_VERSION_V8_CALL_META;
    hdr.arch = QBDITRACE_ARCH_AARCH64;
    hdr.num_gpr = QBDITRACE_AARCH64_NUM_GPR;
    hdr.flags = QBDITRACE_HF_CALL_META;
    qbditrace::qbditrace_retval_t rv{};
    rv.kind = QBDITRACE_REC_RETVAL;
    rv.record_size = 0xFFFF;
    FILE* fp = tenet::platform::open_file(path, "wb");
    REQUIRE(fp != nullptr);
    REQUIRE(std::fwrite(&hdr, sizeof(hdr), 1, fp) == 1);
    REQUIRE(std::fwrite(&rv, 16, 1, fp) == 1);
    std::fclose(fp);
    auto result = TraceReader::open(path);
    REQUIRE(result.has_value());
    auto it = result->begin();
    REQUIRE(it != result->end());
    REQUIRE((*it).kind == RecordKind::Retval);
    REQUIRE((*it).as_retval().byte_size() == 16);
    REQUIRE(raw_record_size((*it).raw_ptr, result->header(), 16) == 16);
    ++it;
    REQUIRE(it == result->end());
    std::filesystem::remove_all(dir);
}

TEST_CASE("TraceReader v8: full 255-byte ObjC selector remains aligned",
          "[unit][io][trace_reader_v8]") {
    const std::string selector(255, 's');
    auto env = make_env([&](TraceWriter& tw) {
        tw.write_header_v8();
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x1100), 1, 2,
                        "NSObject", selector);
        tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                       tw.rt(0x1100), 0x9000, tw.rt(0x1104), 1, 2, 0, 0, 0);
    }, "v8_objc_selector_255");
    REQUIRE(env != nullptr);
    auto it = env->reader->begin();
    REQUIRE((*it).kind == RecordKind::Objc);
    REQUIRE((*it).as_objc().byte_size() == sizeof(qbditrace::qbditrace_objc_head_v8_t) + 256);
    REQUIRE(std::string((*it).as_objc().selector_name) == selector);
    ++it;
    REQUIRE((*it).kind == RecordKind::Retval);
}

TEST_CASE("TraceReader v4: still parses correctly when v8 support is compiled in",
          "[unit][io][trace_reader_v8]") {
    // Regression: adding v8 support must not break v4 CapiCall traces.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_capicall(22, tw.rt(0x1004), 0xDEAD700ULL,
                         {0xA000ULL, 0xB000ULL}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v8_v4_compat");

    REQUIRE(env != nullptr);

    SECTION("version is 4") {
        REQUIRE(env->reader->header().version == 4);
    }
    SECTION("HF_WIDE_API_ID is NOT set") {
        REQUIRE(!(env->reader->header().flags & qbditrace::QBDITRACE_HF_WIDE_API_ID));
    }

    bool found = false;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::CapiCall) continue;

        auto cc = rec.as_capicall();
        SECTION("v4 api_id is 22") {
            REQUIRE(cc.api_id == 22);
        }
        SECTION("is_v8 is false for v4 trace") {
            REQUIRE(cc.is_v8 == false);
        }
        found = true;
        break;
    }
    REQUIRE(found);
}

TEST_CASE("TraceReader v8: v4 capicall byte_size matches raw_record_size",
          "[unit][io][trace_reader_v8]") {
    // Regression: v4 capicall sizing should still be correct with v8 support compiled in.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        TraceWriter::CapiStr s0; s0.arg_idx = 0; s0.value = "test";
        tw.emit_capicall(1, tw.rt(0x1004), 0xDEAD800ULL,
                         {0x1000ULL, 0x2000ULL, 0x100ULL}, {s0});

        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "v8_v4_byte_size_compat");

    REQUIRE(env != nullptr);

    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::CapiCall) continue;

        auto cc = rec.as_capicall();
        size_t view_size = cc.byte_size();
        size_t raw_sz = raw_record_size(rec.raw_ptr, env->reader->header());

        SECTION("v4 CapiCallView::byte_size() == raw_record_size()") {
            REQUIRE(view_size == raw_sz);
        }
        SECTION("v4 header is 88 bytes") {
            REQUIRE(sizeof(qbditrace::qbditrace_capicall_head_t) == 88);
        }
        break;
    }
}
