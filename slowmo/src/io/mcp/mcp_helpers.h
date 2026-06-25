#pragma once

// Shared helper functions and constants for MCP tool implementations.
// This is an internal header — only included by mcp_tools_*.cpp files.

#include "analysis/pass_manager.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/pattern_pass.h"

#include <fmt/core.h>

#include <string>
#include <string_view>
#include <cstdint>
#include <stdexcept>

namespace tenet {

// ─── Helper: require a pass and return its typed result ───────────────────
// Throws std::runtime_error if PassManager is null or the pass fails.

template<typename ResultT>
inline const ResultT& require_pass(PassManager* pm, std::string_view pass_name,
                                    std::string_view error_prefix) {
    if (!pm) throw std::runtime_error("PassManager not available");
    const auto& raw = pm->require(pass_name);
    if (!raw.ok())
        throw std::runtime_error(std::string(error_prefix) + ": " + raw.error_message);
    return raw.get<ResultT>();
}

// ─── AArch64 register names ──────────────────────────────────────────────

inline const char* kRegNames[] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","fp","lr","sp","nzcv","pc"
};

inline int reg_name_to_idx(const std::string& name) {
    for (int i = 0; i < 34; i++) {
        if (name == kRegNames[i]) return i;
    }
    if (name == "x29") return 29;
    if (name == "x30") return 30;
    return -1;
}

inline const char* propagation_type_str(PropagationType t) {
    switch (t) {
        case PropagationType::RegToReg:  return "RegToReg";
        case PropagationType::RegToMem:  return "RegToMem";
        case PropagationType::MemToReg:  return "MemToReg";
        case PropagationType::MemToMem:  return "MemToMem";
        case PropagationType::Immediate: return "Immediate";
        case PropagationType::Call:      return "Call";
        case PropagationType::Return:    return "Return";
        case PropagationType::Kill:      return "Kill";
    }
    return "Unknown";
}

inline const char* pattern_category_str(PatternCategory cat) {
    switch (cat) {
        case PatternCategory::Crypto:      return "Crypto";
        case PatternCategory::AntiDebug:   return "AntiDebug";
        case PatternCategory::AntiTamper:  return "AntiTamper";
        case PatternCategory::Obfuscation: return "Obfuscation";
        case PatternCategory::Networking:  return "Networking";
        case PatternCategory::KeySchedule: return "KeySchedule";
    }
    return "Unknown";
}

inline const char* pattern_confidence_str(PatternConfidence conf) {
    switch (conf) {
        case PatternConfidence::Low:    return "Low";
        case PatternConfidence::Medium: return "Medium";
        case PatternConfidence::High:   return "High";
    }
    return "Unknown";
}

// ─── Helper: parse hex address from string ────────────────────────────────

inline uint64_t parse_hex(const std::string& s) {
    std::string clean = s;
    if (clean.size() > 2 && (clean.substr(0,2) == "0x" || clean.substr(0,2) == "0X")) {
        clean = clean.substr(2);
    }
    return std::stoull(clean, nullptr, 16);
}

}  // namespace tenet
