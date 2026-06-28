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

// ─── Non-blocking pass execution ─────────────────────────────────────────
//
// When an MCP tool needs a pass that hasn't completed yet, we don't want to
// block the HTTP request for potentially tens of seconds.  Instead:
//
//   1. If the pass is already Completed → return the result immediately.
//   2. If the pass is Running or NotRun → kick it off in the background
//      (if not already running), then throw PassNotReady so the MCP layer
//      can return a friendly "retry later" response with progress info.
//   3. If the pass Failed → throw std::runtime_error as before.

/// Thrown when a pass is not yet ready (NotRun or Running).
/// Caught by process_message() to return a non-error "retry later" response.
struct PassNotReady : std::exception {
    std::string pass_name;
    float       progress;    // [0,1], 0 for not-yet-started
    std::string progress_msg;

    PassNotReady(std::string name, float pct, std::string msg)
        : pass_name(std::move(name)), progress(pct), progress_msg(std::move(msg)) {}

    const char* what() const noexcept override { return "pass not ready"; }
};

// ─── Helper: require a pass and return its typed result ───────────────────
// Non-blocking: throws PassNotReady if the pass hasn't completed yet,
// after ensuring it is scheduled for background execution.
// Throws std::runtime_error if PassManager is null or the pass failed.

template<typename ResultT>
inline const ResultT& require_pass(PassManager* pm, std::string_view pass_name,
                                    std::string_view error_prefix) {
    if (!pm) throw std::runtime_error("PassManager not available");

    auto st = pm->state(pass_name);

    if (st == PassManager::PassState::Completed) {
        // Fast path: already done, return cached result.
        const auto& raw = pm->require(pass_name);
        if (!raw.ok())
            throw std::runtime_error(std::string(error_prefix) + ": " + raw.error_message);
        return raw.get<ResultT>();
    }

    if (st == PassManager::PassState::Failed) {
        // Pass already ran and failed — return the error.
        const auto& raw = pm->require(pass_name);
        throw std::runtime_error(std::string(error_prefix) + ": " + raw.error_message);
    }

    // Pass is NotRun or Running.
    // If NotRun, kick off background execution.
    if (st == PassManager::PassState::NotRun) {
        std::thread([pm, name = std::string(pass_name)]() {
            pm->require(name);
        }).detach();
    }

    // Return progress info for the response.
    float pct = pm->progress_of(pass_name);
    std::string msg = pm->progress_msg_of(pass_name);
    throw PassNotReady(std::string(pass_name), pct, std::move(msg));
}

/// Non-blocking require that returns the raw PassResult.
/// Same semantics as require_pass but without typing.  Throws PassNotReady
/// if the pass is NotRun or Running; kicks off background execution if NotRun.
inline const PassResult& require_pass_nb(PassManager* pm, std::string_view pass_name) {
    if (!pm) throw std::runtime_error("PassManager not available");

    auto st = pm->state(pass_name);
    if (st == PassManager::PassState::Completed || st == PassManager::PassState::Failed) {
        return pm->require(pass_name);
    }
    if (st == PassManager::PassState::NotRun) {
        std::thread([pm, name = std::string(pass_name)]() {
            pm->require(name);
        }).detach();
    }
    float pct = pm->progress_of(pass_name);
    std::string msg = pm->progress_msg_of(pass_name);
    throw PassNotReady(std::string(pass_name), pct, std::move(msg));
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
