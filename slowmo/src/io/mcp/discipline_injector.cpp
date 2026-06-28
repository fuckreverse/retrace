#include "discipline_injector.h"

using json = nlohmann::json;

namespace tenet {

// ═══════════════════════════════════════════════════════════════════════════
// DisciplineInjector implementation
// ═══════════════════════════════════════════════════════════════════════════

DisciplineInjector::DisciplineInjector(int short_interval, int full_interval)
    : short_interval_(short_interval), full_interval_(full_interval) {}

const char* DisciplineInjector::full_rules() {
    return
        "═══ TENET ANALYSIS DISCIPLINE (Auto-injected) ═══\n"
        "\n"
        "R1: NEVER claim a register/memory value without checking via regstate/memread.\n"
        "R2: NEVER conclude an algorithm identification without at least 2 independent evidence sources.\n"
        "R3: ALWAYS use hypothesis_add BEFORE claiming something is true.\n"
        "R4: ALWAYS verify evidence via verify_evidence BEFORE marking it as verified.\n"
        "R5: When taint shows propagation, CONFIRM the actual values at source and sink.\n"
        "R6: Do NOT assume function names or purposes — verify via disasm + call_context.\n"
        "R7: If loop_semantics reports \"Feistel\" or \"SPN\", cross-check with constants_scan.\n"
        "R8: Memory addresses are RUNTIME addresses (contain ASLR slide). Always note the slide.\n"
        "R9: If you find yourself making claims without tool calls, STOP and use tools to verify.\n"
        "\n"
        "═══ END DISCIPLINE BLOCK ═══";
}

const char* DisciplineInjector::short_reminder(int index) {
    static const char* reminders[] = {
        "\xe2\x9a\xa1 Reminder: Verify claims with tools. Don't assume \xe2\x80\x94 check regstate/memread.",
        "\xe2\x9a\xa1 Reminder: Use hypothesis_add before drawing conclusions.",
        "\xe2\x9a\xa1 Reminder: Evidence must be verified (verify_evidence) before concluding.",
        "\xe2\x9a\xa1 Reminder: Cross-check algorithm IDs with at least 2 sources (constants + patterns + loops).",
        "\xe2\x9a\xa1 Reminder: All addresses include ASLR slide. Static addr = runtime - slide."
    };
    return reminders[index % kNumReminders];
}

std::string DisciplineInjector::on_tool_call(const std::string& tool_name) {
    std::lock_guard<std::mutex> lk(mutex_);
    call_count_++;

    // Hypothesis tools are already disciplined — don't nag
    if (tool_name.rfind("hypothesis_", 0) == 0 || tool_name == "verify_evidence")
        return {};

    // Full reinjection every full_interval calls
    if (call_count_ % full_interval_ == 0)
        return full_rules();

    // Short reminder every short_interval calls
    if (call_count_ % short_interval_ == 0) {
        auto r = short_reminder(reminder_index_);
        reminder_index_++;
        return r;
    }

    return {};
}

void DisciplineInjector::reset() {
    std::lock_guard<std::mutex> lk(mutex_);
    call_count_ = 0;
    reminder_index_ = 0;
}

json DisciplineInjector::stats() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return {
        {"total_tool_calls", call_count_},
        {"short_reminders_sent", call_count_ / short_interval_},
        {"full_injections_sent", call_count_ / full_interval_},
        {"next_short_in", short_interval_ - (call_count_ % short_interval_)},
        {"next_full_in", full_interval_ - (call_count_ % full_interval_)}
    };
}

}  // namespace tenet
