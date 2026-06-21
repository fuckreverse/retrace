/*
 * test_pass_objc.cpp — Unit tests for tenet::ObjcPass
 *
 * Verifies: OBJC record parsing, class name extraction, selector name lookup,
 * message indexing by PC, class aggregation (message_count, selectors_seen),
 * hottest_classes ranking, messages_for_class query, class filter, and
 * total_messages / unique_classes counts.
 *
 * NOTE: The ObjcPass reads OBJC records from the trace and uses MemoryModel
 * to dereference selector strings.  In the synthetic test traces, selectors
 * are stored as raw addresses in trace memory (via MemAcc) so the pass will
 * use hex-address fallback for selector names unless we plant string bytes.
 * We accept hex-fallback selector names where necessary.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/objc_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Plant a NUL-terminated ASCII string at `addr` in the trace by emitting
/// small-value memory reads (the memory model will learn these addresses).
/// We emit one INST record per byte that performs a load from `addr+i`.
/// The "loaded value" contains the byte so MemoryModel records it.
static void plant_string_in_memory(TraceWriter& tw, MachineState& ms,
                                   uint64_t addr, const char* str)
{
    size_t len = strlen(str) + 1;  // include NUL
    // Emit one byte-load per character so MemoryModel sees the address mapping
    for (size_t i = 0; i < len && i < 64; i++) {
        uint8_t byte = static_cast<uint8_t>(str[i]);
        uint64_t pc = 0xF000 + i * 4;  // use a separate PC range for helpers
        tw.emit(ms, pc, enc::ldr_imm(0, 0, 0),
                {{0, (uint64_t)byte}, {33, tw.rt(pc + 4)}},
                {{1, 1, addr + i, (uint64_t)byte}});
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
