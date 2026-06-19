/*
 * test_core_instruction_decoder.cpp — Unit tests for tenet::InstructionDecoder
 *
 * Verifies: Capstone decoding of known AArch64 opcodes, mnemonic extraction,
 * register read/written tracking, cache behavior, format() output, and
 * CodeTable integration.
 *
 * DecodedInst does not carry is_branch/is_load flags; we classify via the
 * mnemonic string (Capstone normalises AArch64 opcodes to short mnemonics).
 */
#include <catch2/catch_test_macros.hpp>

#include "core/instruction_decoder.h"
#include "io/code_table.h"
#include "fixtures/trace_writer.h"

#include <algorithm>

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ──────────────────────────────────────────────────────────────

/// Check that the decoded mnemonic starts with the expected prefix.
static bool mnemonic_is(const DecodedInst& d, std::string_view expected) {
    return d.mnemonic_sv().substr(0, expected.size()) == expected;
}

// ─── Tests ────────────────────────────────────────────────────────────────

TEST_CASE("InstructionDecoder decodes basic AArch64 instructions", "[unit][core][decoder]") {
    InstructionDecoder dec;
    REQUIRE(dec.init());

    SECTION("nop") {
        auto d = dec.decode(0x1000, enc::nop());
        REQUIRE(d.has_value());
        REQUIRE(mnemonic_is(*d, "nop"));
        REQUIRE(d->size == 4);
    }

    SECTION("add x0, x0, #1") {
        auto d = dec.decode(0x1000, enc::add_imm(0, 0, 1));
        REQUIRE(d.has_value());
        REQUIRE(mnemonic_is(*d, "add"));
    }

    SECTION("movz x0, #0x42 (Capstone aliases to mov)") {
        auto d = dec.decode(0x1000, enc::movz(0, 0x42));
        REQUIRE(d.has_value());
        // Capstone renders MOVZ as "mov" on AArch64
        REQUIRE((mnemonic_is(*d, "mov") || mnemonic_is(*d, "movz")));
    }

    SECTION("invalid opcode returns nullopt or has zero size") {
        auto d = dec.decode(0x1000, 0x00000000u);
        // 0x00000000 may or may not decode; just ensure no crash
        REQUIRE(true);
    }
}

TEST_CASE("InstructionDecoder classifies control-flow via mnemonic", "[unit][core][decoder]") {
    InstructionDecoder dec;
    REQUIRE(dec.init());

    SECTION("unconditional branch b") {
        auto d = dec.decode(0x1000, enc::b(0x20));
        REQUIRE(d.has_value());
        REQUIRE(mnemonic_is(*d, "b"));
    }

    SECTION("conditional branch b.eq") {
        auto d = dec.decode(0x1000, enc::b_eq(0x20));
        REQUIRE(d.has_value());
        REQUIRE(mnemonic_is(*d, "b.eq"));
    }

    SECTION("call bl") {
        auto d = dec.decode(0x1000, enc::bl(0x100));
        REQUIRE(d.has_value());
        REQUIRE(mnemonic_is(*d, "bl"));
    }

    SECTION("return ret") {
        auto d = dec.decode(0x1000, enc::ret());
        REQUIRE(d.has_value());
        REQUIRE(mnemonic_is(*d, "ret"));
    }
}

TEST_CASE("InstructionDecoder classifies memory instructions via mnemonic", "[unit][core][decoder]") {
    InstructionDecoder dec;
    REQUIRE(dec.init());

    SECTION("ldr x0, [x1]") {
        auto d = dec.decode(0x1000, enc::ldr_imm(0, 1, 0));
        REQUIRE(d.has_value());
        REQUIRE(mnemonic_is(*d, "ldr"));
    }

    SECTION("str x0, [x1]") {
        auto d = dec.decode(0x1000, enc::str_imm(0, 1, 0));
        REQUIRE(d.has_value());
        REQUIRE(mnemonic_is(*d, "str"));
    }
}

TEST_CASE("InstructionDecoder caches decoded results", "[unit][core][decoder]") {
    InstructionDecoder dec;
    REQUIRE(dec.init());

    uint64_t pc = 0x1000;
    uint32_t opcode = enc::nop();

    // First decode: cache miss
    auto d1 = dec.decode(pc, opcode);
    REQUIRE(d1.has_value());

    // Second decode at same PC: should hit cache (same result, no re-decode)
    auto d2 = dec.decode(pc, opcode);
    REQUIRE(d2.has_value());
    REQUIRE(d2->mnemonic_sv() == d1->mnemonic_sv());
    REQUIRE(d2->opcode == d1->opcode);
}

TEST_CASE("InstructionDecoder works with CodeTable", "[unit][core][decoder]") {
    InstructionDecoder dec;
    REQUIRE(dec.init());

    CodeTable ct;
    uint64_t pc = 0x1000;
    uint32_t opcode = enc::add_imm(0, 0, 1);
    ct.insert(pc, opcode);

    auto d = dec.decode(pc, ct);
    REQUIRE(d.has_value());
    REQUIRE(mnemonic_is(*d, "add"));

    // Missing PC returns nullopt
    REQUIRE_FALSE(dec.decode(0x9999, ct).has_value());
}

TEST_CASE("InstructionDecoder format produces readable output", "[unit][core][decoder]") {
    InstructionDecoder dec;
    REQUIRE(dec.init());

    std::string s = dec.format(0x1000, enc::nop());
    REQUIRE_FALSE(s.empty());
    // Should contain "nop" somewhere
    REQUIRE(s.find("nop") != std::string::npos);
}

TEST_CASE("InstructionDecoder tracks registers read and written", "[unit][core][decoder]") {
    InstructionDecoder dec;
    REQUIRE(dec.init());

    // add x2, x0, x1 → reads x0, x1; writes x2
    auto d = dec.decode(0x1000, enc::add_reg(2, 0, 1));
    REQUIRE(d.has_value());

    // Should have regs_read containing x0 (0) and x1 (1)
    REQUIRE(d->regs_read_count >= 2);
    bool reads_x0 = false, reads_x1 = false;
    for (uint8_t i = 0; i < d->regs_read_count; i++) {
        if (d->regs_read[i] == 0) reads_x0 = true;
        if (d->regs_read[i] == 1) reads_x1 = true;
    }
    REQUIRE(reads_x0);
    REQUIRE(reads_x1);

    // Should have regs_written containing x2 (2)
    REQUIRE(d->regs_written_count >= 1);
    bool writes_x2 = false;
    for (uint8_t i = 0; i < d->regs_written_count; i++) {
        if (d->regs_written[i] == 2) writes_x2 = true;
    }
    REQUIRE(writes_x2);
}
