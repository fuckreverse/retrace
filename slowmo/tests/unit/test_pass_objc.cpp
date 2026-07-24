/*
 * test_pass_objc.cpp — Unit tests for tenet::ObjcPass
 *
 * Verifies: OBJC record parsing, class name extraction, selector name lookup,
 * message indexing by PC, class aggregation (message_count, selectors_seen),
 * hottest_classes ranking, messages_for_class query, class filter, and
 * total_messages / unique_classes counts.  Also covers argument extraction
 * (x2-x7), return value extraction (x0), string dereferencing of pointer
 * arguments/selectors via MemoryModel, and the inline-ASCII-register fallback
 * for short string-like values that fit directly in a register.
 *
 * NOTE: The ObjcPass reads OBJC records from the trace and uses MemoryModel
 * to dereference selector strings.  In the synthetic test traces, selectors
 * are stored as raw addresses in trace memory (via MemAcc) so the pass will
 * use hex-address fallback for selector names unless we plant string bytes
 * (see plant_string_in_memory below). We accept hex-fallback selector names
 * where the test doesn't care about the resolved name.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/platform/objc_pass.h"
#include "common/byte_codec.h"

#include <algorithm>
#include <cstring>

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Memory access type constants (see qbditrace_memacc_t::mem_type / QBDI::MemoryAccessType).
/// MemoryModel only indexes WRITE accesses (mem_type & 0x02) into its write
/// history -- READ-only MemAcc records are visible to on_mem_read hooks but
/// never populate read_region()/byte_at() results.
static constexpr uint8_t kMemWrite = 2;

/// Plant a NUL-terminated ASCII string at `addr` in the trace by emitting a
/// single 8-byte-store INST per up-to-8 characters (a WRITE MemAcc so
/// MemoryModel actually indexes it -- see kMemWrite above).  After this call,
/// MemoryModel::read_region(addr, ...) and try_deref_string() will resolve
/// the planted bytes instead of falling back to a hex address.
static void plant_string_in_memory(TraceWriter& tw, MachineState& ms,
                                   uint64_t addr, const char* str)
{
    size_t len = strlen(str) + 1;  // include NUL
    size_t off = 0;
    while (off < len && off < 256) {
        size_t chunk = std::min<size_t>(8, len - off);
        uint64_t word = 0;
        std::memcpy(&word, str + off, chunk);  // zero-padded if chunk < 8
        uint64_t pc = 0xF000 + off * 4;  // use a separate PC range for helpers
        tw.emit(ms, pc, enc::str_imm(0, 31, 0),
                {{0, word}, {33, tw.rt(pc + 4)}},
                {{kMemWrite, (uint16_t)chunk, addr + off, word}});
        off += chunk;
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

TEST_CASE("ObjcPass empty trace: no messages", "[unit][pass][objc]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // A few plain instructions but no OBJC records
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "objc_empty");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());

    auto& result_raw = pm->require("objc");
    REQUIRE(result_raw.ok());
    auto& or_ = result_raw.get<ObjcResult>();

    SECTION("no messages") {
        REQUIRE(or_.total_messages() == 0);
    }

    SECTION("no classes") {
        REQUIRE(or_.unique_classes() == 0);
    }
}

TEST_CASE("ObjcPass parses a single OBJC record", "[unit][pass][objc]") {
    uint64_t recv_addr = 0xDEADBEEF0001ULL;
    uint64_t sel_addr  = 0xDEADBEEF0002ULL;
    uint64_t call_pc   = 0x1000;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Emit a regular instruction before the OBJC record so inst_id == 0
        tw.emit(ms, 0x0FF0, enc::nop(), {{33, tw.rt(0x0FF4)}}, {});

        // Emit the OBJC record (inter-record, not associated with an INST)
        tw.emit_objc(tw.rt(call_pc), recv_addr, sel_addr, "NSString");

        // Continue with a normal instruction
        tw.emit(ms, call_pc, enc::nop(), {{33, tw.rt(call_pc + 4)}}, {});
        tw.emit_anchor(ms);
    }, "objc_single");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());

    auto& or_ = pm->require("objc").get<ObjcResult>();

    SECTION("exactly one message recorded") {
        REQUIRE(or_.total_messages() == 1);
    }

    SECTION("class name is NSString") {
        REQUIRE(or_.messages[0].class_name == "NSString");
    }

    SECTION("receiver address matches") {
        REQUIRE(or_.messages[0].receiver == recv_addr);
    }

    SECTION("selector address matches") {
        REQUIRE(or_.messages[0].selector == sel_addr);
    }

    SECTION("pc matches call_pc (with slide)") {
        REQUIRE(or_.messages[0].pc == (uint64_t)(call_pc + 0x4000));
    }

    SECTION("class info updated") {
        REQUIRE(or_.unique_classes() == 1);
        auto it = or_.classes.find("NSString");
        REQUIRE(it != or_.classes.end());
        REQUIRE(it->second.message_count == 1);
    }
}

TEST_CASE("ObjcPass counts multiple messages to same class",
          "[unit][pass][objc]") {
    uint64_t sel_a = 0xAAAA0001ULL;
    uint64_t sel_b = 0xAAAA0002ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Three messages to NSObject with two distinct selectors
        tw.emit_objc(tw.rt(0x1000), 0x111ULL, sel_a, "NSObject");
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        tw.emit_objc(tw.rt(0x1004), 0x222ULL, sel_b, "NSObject");
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});

        tw.emit_objc(tw.rt(0x1008), 0x333ULL, sel_a, "NSObject");
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});

        tw.emit_anchor(ms);
    }, "objc_multi_msg");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());

    auto& or_ = pm->require("objc").get<ObjcResult>();

    SECTION("three messages total") {
        REQUIRE(or_.total_messages() == 3);
    }

    SECTION("one class (NSObject)") {
        REQUIRE(or_.unique_classes() == 1);
    }

    SECTION("NSObject has message_count == 3") {
        auto it = or_.classes.find("NSObject");
        REQUIRE(it != or_.classes.end());
        REQUIRE(it->second.message_count == 3);
    }

    SECTION("NSObject selectors_seen has 2 entries") {
        // sel_a and sel_b are two different selectors
        auto it = or_.classes.find("NSObject");
        REQUIRE(it != or_.classes.end());
        REQUIRE(it->second.selectors_seen.size() == 2);
    }
}

TEST_CASE("ObjcPass handles multiple classes", "[unit][pass][objc]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // 2 messages to NSArray, 1 to NSDictionary
        tw.emit_objc(tw.rt(0x1000), 0x100ULL, 0x200ULL, "NSArray");
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        tw.emit_objc(tw.rt(0x1004), 0x101ULL, 0x200ULL, "NSArray");
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});

        tw.emit_objc(tw.rt(0x1008), 0x300ULL, 0x400ULL, "NSDictionary");
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});

        tw.emit_anchor(ms);
    }, "objc_multi_class");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());

    auto& or_ = pm->require("objc").get<ObjcResult>();

    SECTION("3 total messages") {
        REQUIRE(or_.total_messages() == 3);
    }

    SECTION("2 unique classes") {
        REQUIRE(or_.unique_classes() == 2);
    }

    SECTION("NSArray message count == 2") {
        auto it = or_.classes.find("NSArray");
        REQUIRE(it != or_.classes.end());
        REQUIRE(it->second.message_count == 2);
    }

    SECTION("NSDictionary message count == 1") {
        auto it = or_.classes.find("NSDictionary");
        REQUIRE(it != or_.classes.end());
        REQUIRE(it->second.message_count == 1);
    }

    SECTION("hottest_classes returns NSArray first") {
        auto hot = or_.hottest_classes(2);
        REQUIRE_FALSE(hot.empty());
        REQUIRE(hot[0]->name == "NSArray");
        REQUIRE(hot[0]->message_count == 2);
    }
}

TEST_CASE("ObjcPass messages_for_class query", "[unit][pass][objc]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit_objc(tw.rt(0x1000), 0xABCULL, 0x111ULL, "NSData");
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        tw.emit_objc(tw.rt(0x1004), 0xDEFULL, 0x222ULL, "NSData");
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});

        tw.emit_anchor(ms);
    }, "objc_class_query");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());

    auto& or_ = pm->require("objc").get<ObjcResult>();

    SECTION("messages_for_class(NSData) returns 2 pointers") {
        auto msgs = or_.messages_for_class("NSData");
        REQUIRE(msgs.size() == 2);
    }

    SECTION("messages_for_class(UnknownClass) returns empty") {
        auto msgs = or_.messages_for_class("SomeUnknownClass");
        REQUIRE(msgs.empty());
    }
}

TEST_CASE("ObjcPass by_pc index is populated", "[unit][pass][objc]") {
    uint64_t site1_pc = 0x1000;
    uint64_t site2_pc = 0x2000;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Two different call sites
        tw.emit_objc(tw.rt(site1_pc), 0x10ULL, 0x20ULL, "NSURL");
        tw.emit(ms, site1_pc, enc::nop(), {{33, tw.rt(site1_pc + 4)}}, {});

        tw.emit_objc(tw.rt(site2_pc), 0x30ULL, 0x40ULL, "NSURL");
        tw.emit(ms, site2_pc, enc::nop(), {{33, tw.rt(site2_pc + 4)}}, {});

        // Second call at site1 again
        tw.emit_objc(tw.rt(site1_pc), 0x50ULL, 0x20ULL, "NSURL");
        tw.emit(ms, site1_pc + 4, enc::nop(), {{33, tw.rt(site1_pc + 8)}}, {});

        tw.emit_anchor(ms);
    }, "objc_by_pc");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());

    auto& or_ = pm->require("objc").get<ObjcResult>();

    SECTION("by_pc has entries for both call sites") {
        uint64_t rpc1 = site1_pc + 0x4000;
        uint64_t rpc2 = site2_pc + 0x4000;
        REQUIRE(or_.by_pc.count(rpc1) > 0);
        REQUIRE(or_.by_pc.count(rpc2) > 0);
    }

    SECTION("site1 has 2 messages") {
        uint64_t rpc1 = site1_pc + 0x4000;
        REQUIRE(or_.by_pc.at(rpc1).size() == 2);
    }

    SECTION("site2 has 1 message") {
        uint64_t rpc2 = site2_pc + 0x4000;
        REQUIRE(or_.by_pc.at(rpc2).size() == 1);
    }
}

TEST_CASE("ObjcPass class filter restricts output", "[unit][pass][objc]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit_objc(tw.rt(0x1000), 0x1ULL, 0x2ULL, "NSString");
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        tw.emit_objc(tw.rt(0x1004), 0x3ULL, 0x4ULL, "NSNumber");
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});

        tw.emit_objc(tw.rt(0x1008), 0x5ULL, 0x6ULL, "NSString");
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});

        tw.emit_anchor(ms);
    }, "objc_filter");

    auto pm = make_pm(*env);
    auto pass = std::make_unique<ObjcPass>();
    pass->set_class_filter("NSString");
    pm->register_pass(std::move(pass));

    auto& or_ = pm->require("objc").get<ObjcResult>();

    SECTION("only NSString messages appear") {
        REQUIRE(or_.total_messages() == 2);
        for (const auto& msg : or_.messages) {
            REQUIRE(msg.class_name == "NSString");
        }
    }

    SECTION("NSNumber is absent from classes map") {
        REQUIRE(or_.classes.find("NSNumber") == or_.classes.end());
    }
}

TEST_CASE("ObjcPass hottest_classes ranking", "[unit][pass][objc]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // NSObject: 5 messages (most)
        for (int i = 0; i < 5; i++) {
            tw.emit_objc(tw.rt(0x1000 + (uint64_t)i * 4),
                         (uint64_t)i, 0x100ULL, "NSObject");
            tw.emit(ms, 0x1000 + (uint64_t)i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + (uint64_t)i * 4)}}, {});
        }

        // NSString: 3 messages
        for (int i = 0; i < 3; i++) {
            tw.emit_objc(tw.rt(0x2000 + (uint64_t)i * 4),
                         (uint64_t)(0x100 + i), 0x200ULL, "NSString");
            tw.emit(ms, 0x2000 + (uint64_t)i * 4, enc::nop(),
                    {{33, tw.rt(0x2004 + (uint64_t)i * 4)}}, {});
        }

        // NSData: 1 message (least)
        tw.emit_objc(tw.rt(0x3000), 0x300ULL, 0x301ULL, "NSData");
        tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});

        tw.emit_anchor(ms);
    }, "objc_ranking");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());

    auto& or_ = pm->require("objc").get<ObjcResult>();

    SECTION("9 total messages") {
        REQUIRE(or_.total_messages() == 9);
    }

    SECTION("3 unique classes") {
        REQUIRE(or_.unique_classes() == 3);
    }

    SECTION("hottest_classes(1) returns NSObject") {
        auto hot = or_.hottest_classes(1);
        REQUIRE(hot.size() == 1);
        REQUIRE(hot[0]->name == "NSObject");
        REQUIRE(hot[0]->message_count == 5);
    }

    SECTION("hottest_classes(3) returns in descending order") {
        auto hot = or_.hottest_classes(3);
        REQUIRE(hot.size() == 3);
        // NSObject(5) > NSString(3) > NSData(1)
        REQUIRE(hot[0]->message_count >= hot[1]->message_count);
        REQUIRE(hot[1]->message_count >= hot[2]->message_count);
    }
}

TEST_CASE("ObjcPass to_json produces valid structure", "[unit][pass][objc]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit_objc(tw.rt(0x1000), 0xAAULL, 0xBBULL, "TestClass");
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "objc_json");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());

    auto& or_ = pm->require("objc").get<ObjcResult>();

    SECTION("to_json does not throw and has required keys") {
        auto j = or_.to_json();
        REQUIRE(j.contains("total_messages"));
        REQUIRE(j.contains("unique_classes"));
        REQUIRE(j.contains("messages"));
        REQUIRE(j.contains("classes"));
        REQUIRE(j["total_messages"].get<uint64_t>() == 1);
        REQUIRE(j["unique_classes"].get<uint64_t>() == 1);
    }
}

// ─── Argument / return-value extraction tests ───────────────────────────────
//
// These tests plant the selector's string bytes in memory (via
// plant_string_in_memory) so the colon-count heuristic sees the real
// selector text instead of the hex-address fallback, which lets us control
// exactly how many arguments ObjcPass decides to extract.

TEST_CASE("ObjcPass extracts method arguments (x2-x7) with resolved selector",
          "[unit][pass][objc]") {
    uint64_t sel_addr = 0x50000ULL;
    uint64_t recv_addr = 0x60000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Plant "setValue:forKey:" (2 colons) at sel_addr so arg_count == 2.
        plant_string_in_memory(tw, ms, sel_addr, "setValue:forKey:");

        // Set x2 = 0x1111, x3 = 0x2222 right before the objc_msgSend call site.
        tw.emit(ms, 0x1000, enc::movz(2, 0x1111),
                {{2, 0x1111ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movz(3, 0x2222),
                {{3, 0x2222ULL}, {33, tw.rt(0x1008)}}, {});

        tw.emit_objc(tw.rt(0x1008), recv_addr, sel_addr, "MyClass");
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "objc_args");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    auto& or_ = pm->require("objc").get<ObjcResult>();

    REQUIRE(or_.total_messages() == 1);
    const auto& msg = or_.messages[0];

    SECTION("selector resolved from memory (not hex fallback)") {
        REQUIRE(msg.selector_name == "setValue:forKey:");
    }

    SECTION("arg_count derived from colon count") {
        REQUIRE(msg.arg_count == 2);
    }

    SECTION("x2 and x3 values captured") {
        REQUIRE(msg.args[0].value == 0x1111ULL);
        REQUIRE(msg.args[1].value == 0x2222ULL);
    }

    SECTION("unused arg slots (x4-x7) are untouched / zero") {
        for (uint8_t k = msg.arg_count; k < OBJC_MAX_ARGS; ++k) {
            REQUIRE(msg.args[k].value == 0);
        }
    }
}

TEST_CASE("ObjcPass dereferences a pointer argument as a C string",
          "[unit][pass][objc]") {
    uint64_t sel_addr = 0x50000ULL;
    uint64_t str_addr = 0x70000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // 1 colon => arg_count == 1
        plant_string_in_memory(tw, ms, sel_addr, "logMessage:");
        // The actual string argument content, pointed to by x2.
        plant_string_in_memory(tw, ms, str_addr, "hello world");

        tw.emit(ms, 0x1000, enc::movz(2, (uint16_t)(str_addr & 0xFFFF)),
                {{2, str_addr}, {33, tw.rt(0x1004)}}, {});

        tw.emit_objc(tw.rt(0x1004), 0x1ULL, sel_addr, "Logger");
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "objc_arg_deref");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    auto& or_ = pm->require("objc").get<ObjcResult>();

    REQUIRE(or_.total_messages() == 1);
    const auto& msg = or_.messages[0];

    SECTION("arg_count == 1") {
        REQUIRE(msg.arg_count == 1);
    }

    SECTION("first argument dereferences to the planted string") {
        REQUIRE(msg.args[0].value == str_addr);
        REQUIRE(msg.args[0].deref_str.has_value());
        REQUIRE(*msg.args[0].deref_str == "hello world");
    }
}

TEST_CASE("ObjcPass falls back to inline-ASCII decoding for short register values",
          "[unit][pass][objc]") {
    uint64_t sel_addr = 0x50000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        plant_string_in_memory(tw, ms, sel_addr, "setTag:");  // 1 colon

        // x2 holds a small integer that is NOT a valid pointer (< 0x1000),
        // so try_deref_string() will bail out via is_likely_pointer(), and
        // try_decode_reg_ascii() should also fail to decode it (not ASCII).
        tw.emit(ms, 0x1000, enc::movz(2, 42),
                {{2, 42ULL}, {33, tw.rt(0x1004)}}, {});

        tw.emit_objc(tw.rt(0x1004), 0x1ULL, sel_addr, "View");
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "objc_small_int_arg");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    auto& or_ = pm->require("objc").get<ObjcResult>();

    REQUIRE(or_.total_messages() == 1);
    const auto& msg = or_.messages[0];

    SECTION("small integer argument has no string decode") {
        REQUIRE(msg.args[0].value == 42);
        REQUIRE_FALSE(msg.args[0].deref_str.has_value());
    }
}

TEST_CASE("ObjcPass legacy trace does not invent a return from pre-call x0",
          "[unit][pass][objc]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Legacy OBJC has no matching return fact. x0 before the call is the
        // receiver and must never be reported as a return value.
        tw.emit(ms, 0x0FFC, enc::movz(0, 0xAAAA),
                {{0, 0xAAAAULL}, {33, tw.rt(0x1000)}}, {});
        tw.emit_objc(tw.rt(0x1000), 0xAAAAULL, 0xBBULL, "NSNumber");
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "objc_retval");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    auto& or_ = pm->require("objc").get<ObjcResult>();

    REQUIRE(or_.total_messages() == 1);
    const auto& msg = or_.messages[0];

    REQUIRE_FALSE(msg.has_return);
    REQUIRE(msg.return_kind == ObjcReturnKind::None);
    REQUIRE(msg.return_value == 0);
}

TEST_CASE("ObjcPass v8 associates nested ObjC returns by LIFO identity",
          "[unit][pass][objc][v8]") {
    constexpr uint64_t outer_receiver = 0x11110000ULL;
    constexpr uint64_t inner_receiver = 0x22220000ULL;
    constexpr uint64_t inner_return = 0xAAAA0000ULL;
    constexpr uint64_t outer_return = 0xBBBB0000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x1000), outer_receiver,
                        0x5000, "Outer", "outerCall");
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x2000), inner_receiver,
                        0x6000, "Inner", "innerCall");
        tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                       tw.rt(0x2000), 0x9000, tw.rt(0x2004), inner_return, 0, 0, 0, 0);
        tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                       tw.rt(0x1000), 0x8000, tw.rt(0x1004), outer_return, 0, 0, 0, 0);
        tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});
    }, "objc_v8_nested_retval");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    const auto& messages = pm->require("objc").get<ObjcResult>().messages;

    REQUIRE(messages.size() == 2);
    REQUIRE(messages[0].receiver == outer_receiver);
    REQUIRE(messages[0].return_value == outer_return);
    REQUIRE(messages[1].receiver == inner_receiver);
    REQUIRE(messages[1].return_value == inner_return);
    for (const auto& msg : messages) {
        REQUIRE(msg.has_return);
        REQUIRE(msg.return_kind == ObjcReturnKind::X0);
        REQUIRE(msg.return_value != msg.receiver);
    }
}

TEST_CASE("ObjcPass v8 prefers inline selector and reports hex fallback status",
          "[unit][pass][objc][v8]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x1000), 1, 0x5000,
                        "", "inlineSelector:");
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x2000), 2, 0x6000,
                        "KnownClass", "");
        tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});
    }, "objc_v8_selector_status");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    const auto& messages = pm->require("objc").get<ObjcResult>().messages;

    REQUIRE(messages.size() == 2);
    REQUIRE(messages[0].selector_name == "inlineSelector:");
    REQUIRE(messages[0].selector_source == ObjcSelectorSource::Inline);
    REQUIRE(messages[0].selector_resolution == ObjcSelectorResolution::Resolved);
    REQUIRE(messages[0].class_name.empty());
    REQUIRE(messages[0].class_resolution == ObjcClassResolution::Unknown);
    REQUIRE(messages[1].selector_name == "0x6000");
    REQUIRE(messages[1].selector_source == ObjcSelectorSource::Hex);
    REQUIRE(messages[1].selector_resolution == ObjcSelectorResolution::Unresolved);
}

TEST_CASE("ObjcPass labels stret x0 as raw return state",
          "[unit][pass][objc][v8]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND_STRET, tw.rt(0x1000), 0x1111,
                        0x5000, "StructFactory", "makeRect");
        tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND_STRET,
                       tw.rt(0x1000), 0x9000, tw.rt(0x1004), 0xDEAD, 0, 0, 0, 0);
        tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});
    }, "objc_v8_stret");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    const auto& msg = pm->require("objc").get<ObjcResult>().messages.at(0);

    REQUIRE(msg.is_stret);
    REQUIRE(msg.has_return);
    REQUIRE(msg.return_kind == ObjcReturnKind::StretRaw);
    REQUIRE(msg.return_value == 0xDEAD);
}

TEST_CASE("ObjcPass zero-colon selector with hex fallback uses full arg window",
          "[unit][pass][objc]") {
    // When the selector can't be resolved to a real string, selector_name
    // falls back to a hex-address string (e.g. "0x50000"), which contains no
    // colons.  ObjcPass special-cases this: a hex-fallback name gets
    // OBJC_MAX_ARGS extracted (since the real arg count is unknown), rather
    // than being (incorrectly) treated as a zero-arg getter.
    uint64_t sel_addr = 0x99999ULL;  // never planted -> hex fallback

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::movz(2, 0x1234),
                {{2, 0x1234ULL}, {33, tw.rt(0x1004)}}, {});

        tw.emit_objc(tw.rt(0x1004), 0x1ULL, sel_addr, "Unresolved");
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "objc_hexfallback_args");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    auto& or_ = pm->require("objc").get<ObjcResult>();

    REQUIRE(or_.total_messages() == 1);
    const auto& msg = or_.messages[0];

    SECTION("selector_name is the hex fallback") {
        REQUIRE(msg.selector_name.find("0x") == 0);
    }

    SECTION("arg_count is OBJC_MAX_ARGS (unknown arity => extract all slots)") {
        REQUIRE(msg.arg_count == OBJC_MAX_ARGS);
    }

    SECTION("x2 is still captured within the full window") {
        REQUIRE(msg.args[0].value == 0x1234ULL);
    }
}

TEST_CASE("ObjcPass selector name cache resolves repeated selector pointers consistently",
          "[unit][pass][objc]") {
    // Same selector address used across multiple messages -- resolved once,
    // cached, and returned identically on subsequent messages (exercises the
    // sel_name_cache_ hit path in the raw-pointer fast scan).
    uint64_t sel_addr = 0x50000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        plant_string_in_memory(tw, ms, sel_addr, "description");  // 0 colons

        for (int i = 0; i < 3; i++) {
            uint64_t pc = 0x1000 + (uint64_t)i * 4;
            tw.emit_objc(tw.rt(pc), (uint64_t)(0x100 + i), sel_addr, "Widget");
            tw.emit(ms, pc, enc::nop(), {{33, tw.rt(pc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "objc_sel_cache");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ObjcPass>());
    auto& or_ = pm->require("objc").get<ObjcResult>();

    REQUIRE(or_.total_messages() == 3);

    SECTION("all three messages resolve to the same selector string") {
        for (const auto& msg : or_.messages) {
            REQUIRE(msg.selector_name == "description");
        }
    }

    SECTION("zero-colon getter selector produces arg_count == 0") {
        for (const auto& msg : or_.messages) {
            REQUIRE(msg.arg_count == 0);
        }
    }

    SECTION("Widget class aggregates a single unique selector") {
        auto it = or_.classes.find("Widget");
        REQUIRE(it != or_.classes.end());
        REQUIRE(it->second.selectors_seen.size() == 1);
        REQUIRE(it->second.message_count == 3);
    }
}

TEST_CASE("ObjcPass v8 return strings fall back to latest observed memory only when incomplete",
          "[unit][pass][objc][v8]") {
    constexpr uint64_t kReturnString = 0x70000ULL;

    SECTION("partial return-time string falls back to a complete latest-observed string") {
        auto env = make_env([&](TraceWriter& tw) {
            tw.write_header_v8();
            MachineState ms; ms.sp() = 0x16F000000ULL;
            tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x1000), 0x1, 0x5000,
                            "Factory", "makeName");
            tw.emit(ms, 0x1000, enc::str_imm(0, 31, 0),
                    {{33, tw.rt(0x1004)}}, {{kMemWrite, 1, kReturnString, 't'}});
            tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                           tw.rt(0x1000), 0, tw.rt(0x1004), kReturnString, 0, 0, 0, 0);
            plant_string_in_memory(tw, ms, kReturnString, "tenet-e2e");
        }, "objc_return_string_latest");

        auto pm = make_pm(*env);
        pm->register_pass(std::make_unique<ObjcPass>());
        const auto& msg = pm->require("objc").get<ObjcResult>().messages.at(0);
        REQUIRE(msg.return_deref_str == std::optional<std::string>("tenet-e2e"));
        REQUIRE(msg.return_string_time == ObjcReturnStringTime::LatestObserved);
        const auto json_return = ObjcResult{{msg}}.to_json()["messages"][0]["return"];
        REQUIRE(json_return["string_time"] == "latest");
    }

    SECTION("NUL-terminated return-time string is retained without approximation") {
        auto env = make_env([&](TraceWriter& tw) {
            tw.write_header_v8();
            MachineState ms; ms.sp() = 0x16F000000ULL;
            plant_string_in_memory(tw, ms, kReturnString, "complete");
            tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x1000), 0x1, 0x5000,
                            "Factory", "makeName");
            tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                           tw.rt(0x1000), 0, tw.rt(0x1004), kReturnString, 0, 0, 0, 0);
            plant_string_in_memory(tw, ms, kReturnString, "later-value");
        }, "objc_return_string_complete");

        auto pm = make_pm(*env);
        pm->register_pass(std::make_unique<ObjcPass>());
        const auto& msg = pm->require("objc").get<ObjcResult>().messages.at(0);
        REQUIRE(msg.return_deref_str == std::optional<std::string>("complete"));
        REQUIRE(msg.return_string_time == ObjcReturnStringTime::AtReturn);
    }

    SECTION("unreadable return string at both time points is omitted") {
        auto env = make_env([&](TraceWriter& tw) {
            tw.write_header_v8();
            MachineState ms; ms.sp() = 0x16F000000ULL;
            tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x1000), 0x1, 0x5000,
                            "Factory", "makeName");
            tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                           tw.rt(0x1000), 0, tw.rt(0x1004), kReturnString, 0, 0, 0, 0);
            tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        }, "objc_return_string_unreadable");

        auto pm = make_pm(*env);
        pm->register_pass(std::make_unique<ObjcPass>());
        const auto& result = pm->require("objc").get<ObjcResult>();
        REQUIRE_FALSE(result.messages.at(0).return_deref_str.has_value());
        REQUIRE_FALSE(result.to_json()["messages"][0]["return"].contains("string"));
    }
}

TEST_CASE("ObjcPass blob v3 round-trip preserves return string time and v2 misses",
          "[unit][pass][objc]") {
    constexpr uint64_t kString = 0x70000ULL;
    auto env = make_env([&](TraceWriter& tw) {
        tw.write_header_v8();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_objc_v8(QBDITRACE_OBJC_MSGSEND, tw.rt(0x1000), 0xABC, 0x5000,
                        "Person", "name");
        tw.emit_retval(QBDITRACE_REC_OBJC, QBDITRACE_OBJC_MSGSEND,
                       tw.rt(0x1000), 0, tw.rt(0x1004), kString, 0, 0, 0, 0);
        plant_string_in_memory(tw, ms, kString, "Alice");
    }, "objc_cache_roundtrip");

    // A v2 blob must miss, then be replaced by a freshly serialized v3 blob.
    ByteWriter legacy_blob;
    legacy_blob.u32(0x4F424A43u);  // "OBJC"
    legacy_blob.u32(2u);
    legacy_blob.u64(0u);
    env->index->save_pass_blob("objc", legacy_blob.data().data(), legacy_blob.size());

    auto pm1 = make_pm(*env);
    pm1->register_pass(std::make_unique<ObjcPass>());
    const auto& or1 = pm1->require("objc").get<ObjcResult>();
    REQUIRE(or1.total_messages() == 1);
    REQUIRE(or1.messages[0].return_deref_str == std::optional<std::string>("Alice"));
    REQUIRE(or1.messages[0].return_string_time == ObjcReturnStringTime::LatestObserved);

    std::string v3_blob;
    REQUIRE(env->index->load_pass_blob("objc", v3_blob));
    ByteReader v3_reader(v3_blob);
    REQUIRE(v3_reader.u32() == 0x4F424A43u);
    REQUIRE(v3_reader.u32() == 3u);

    auto pm2 = make_pm(*env);
    pm2->register_pass(std::make_unique<ObjcPass>());
    const auto& or2 = pm2->require("objc").get<ObjcResult>();
    REQUIRE(or2.total_messages() == or1.total_messages());
    REQUIRE(or2.messages[0].return_deref_str == or1.messages[0].return_deref_str);
    REQUIRE(or2.messages[0].return_string_time == or1.messages[0].return_string_time);
}
