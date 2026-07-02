/*
 * QBDITraceInternal.h — Internal types and pure-logic helpers for qbditrace.
 *
 * This header is intentionally kept free of any QBDI dependency so that:
 *   1. QBDITrace.cpp includes it and gets the full implementation.
 *   2. Host-side unit tests can include it without a QBDI install, enabling
 *      in-process testing of the pure classification / lookup logic.
 *
 * DO NOT include this from public API users — use QBDITrace.h instead.
 *
 * Exported for testing:
 *   struct Config              — tracer runtime configuration
 *   classifyObjcTarget()      — ObjC dispatcher matching
 *   lookupCApiFunc()          — sorted C API address lookup
 *   classifySyscall()         — Darwin/Linux syscall flag classification
 */
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

/* Forward-declare only the constants needed from QBDITrace.h and TraceFormat.h.
 * We do NOT include those headers directly here to avoid disturbing the
 * system-header include order in QBDITrace.cpp (which uses _XOPEN_SOURCE and
 * platform-specific guards before including <dlfcn.h>).  When this header is
 * included from the unit test suite, the test file provides its own includes
 * of QBDITrace.h and TraceFormat.h before including this header. */
#ifndef QBDITRACE_MAX_EXCLUDE_RANGES
#  include "QBDITrace.h"
#endif
#ifndef QBDITRACE_SVC_FL_MACH_TRAP
#  include "TraceFormat.h"
#endif

namespace qbditrace_internal {

using namespace qbditrace;

/* ---------------------------------------------------------------------------
 * Config — tracer runtime configuration.
 *
 * All fields default to zero/false so that zero-initializing the struct is
 * always safe.  Fields are populated by qbditrace_configure() from the public
 * C ABI struct.
 * --------------------------------------------------------------------------- */
struct Config {
  uint64_t trace_start = 0;
  uint64_t trace_end   = 0;
  uint64_t module_base  = 0;
  uint64_t module_slide = 0;
  std::string module_name;
  std::string output_path;
  uint32_t record         = QBDITRACE_REC_DEFAULT;
  uint32_t anchor_interval = 0;
  size_t   ring_bytes     = 64u * 1024u * 1024u;

  /* ObjC dispatcher addresses */
  uint64_t objc_msgSend        = 0;
  uint64_t objc_msgSendSuper   = 0;
  uint64_t objc_msgSendSuper2  = 0;
  uint64_t objc_msgSend_stret  = 0;

  /* Extra range */
  uint64_t extra_range_start = 0;
  uint64_t extra_range_end   = 0;

  /* Exclude ranges */
  uint32_t n_exclude_ranges = 0;
  struct ExcludeRange { uint64_t start; uint64_t end; };
  ExcludeRange exclude_ranges[QBDITRACE_MAX_EXCLUDE_RANGES] = {};

  /* ── C API interception ──────────────────────────────────────────────────
   * When capi_intercept is true, EXEC_TRANSFER_CALL targets are matched against
   * a sorted address lookup table and a REC_CAPICALL record is emitted on hit. */
  bool capi_intercept = false;

  struct CApiFunc {
    uint64_t  addr;     /* runtime address (0 = unused) */
    uint16_t  api_id;   /* qbditrace_capi_id_t (uint16 to hold ids > 255) */
    uint8_t   n_args;   /* meaningful arg count (0..8) */
    uint8_t   str_args; /* bitmask: bit i => args[i] is a string/buffer pointer */
  };
  static constexpr uint32_t kMaxCapiFuncs = QBDITRACE_MAX_CAPI_FUNCS;
  CApiFunc capi_funcs[kMaxCapiFuncs] = {};
  uint32_t n_capi_funcs = 0;

  /* Sorted lookup table built once at configure() time from capi_funcs[]. */
  struct CApiLookup { uint64_t addr; uint32_t idx; };
  std::vector<CApiLookup> capi_lookup;

  /* Format options */
  bool embed_code       = true;
  bool pc_delta_mode    = false;
  bool fpr_mode         = false;
  bool compress         = true;
  bool branch_hint_mode = true;

  /* Build the sorted capi_lookup table from capi_funcs[0..n_capi_funcs).
   * Entries with addr == 0 are skipped.  Call this after populating capi_funcs. */
  void buildCapiLookup() {
    capi_lookup.clear();
    for (uint32_t i = 0; i < n_capi_funcs; ++i) {
      if (capi_funcs[i].addr != 0) {
        capi_lookup.push_back({capi_funcs[i].addr, i});
      }
    }
    std::sort(capi_lookup.begin(), capi_lookup.end(),
              [](const CApiLookup &a, const CApiLookup &b) {
                return a.addr < b.addr;
              });
  }
};

/* ---------------------------------------------------------------------------
 * classifyObjcTarget
 *
 * Matches a EXEC_TRANSFER_CALL target against the four ObjC dispatcher
 * addresses in cfg.  Returns a qbditrace_objc_variant_t value on match,
 * or -1 if the target is not a recognised dispatcher.
 * --------------------------------------------------------------------------- */
inline int classifyObjcTarget(const Config &c, uint64_t target) {
  if (target == 0) return -1;
  if (c.objc_msgSend       && target == c.objc_msgSend)        return QBDITRACE_OBJC_MSGSEND;
  if (c.objc_msgSendSuper  && target == c.objc_msgSendSuper)   return QBDITRACE_OBJC_MSGSEND_SUPER;
  if (c.objc_msgSendSuper2 && target == c.objc_msgSendSuper2)  return QBDITRACE_OBJC_MSGSEND_SUPER2;
  if (c.objc_msgSend_stret && target == c.objc_msgSend_stret)  return QBDITRACE_OBJC_MSGSEND_STRET;
  return -1;
}

/* ---------------------------------------------------------------------------
 * lookupCApiFunc
 *
 * Binary-search the sorted capi_lookup table for `target`.
 * Returns a pointer into capi_funcs[] on hit, nullptr on miss.
 * --------------------------------------------------------------------------- */
inline const Config::CApiFunc *lookupCApiFunc(const Config &c, uint64_t target) {
  if (target == 0 || c.capi_lookup.empty()) return nullptr;
  auto it = std::lower_bound(
      c.capi_lookup.begin(), c.capi_lookup.end(), target,
      [](const Config::CApiLookup &e, uint64_t v) { return e.addr < v; });
  if (it != c.capi_lookup.end() && it->addr == target) {
    return &c.capi_funcs[it->idx];
  }
  return nullptr;
}

/* ---------------------------------------------------------------------------
 * classifySyscall
 *
 * Pure function: maps a Darwin / Linux arm64 syscall selector to a bitmask
 * of QBDITRACE_SVC_FL_* flags.  No side-effects, no memory access.
 *
 * Darwin (iOS/macOS arm64):
 *   x16 encodes both BSD and Mach trap classes.
 *   Bit 31 set in x16 → Mach trap.
 *   BSD number = x16 & 0x00FFFFFF (strips the 0x02000000 class prefix).
 *
 * Linux / Android arm64:
 *   x8 = plain syscall number (no class prefix).
 * --------------------------------------------------------------------------- */
inline uint8_t classifySyscall(uint64_t syscall_no) {
  uint8_t flags = 0;
#if defined(__APPLE__)
  /* Mach trap: bit 31 set (negative int32 in x16). */
  if (syscall_no >> 31) {
    flags |= QBDITRACE_SVC_FL_MACH_TRAP;
  }
  /* Canonical BSD number (strip class prefix 0x02000000). */
  uint64_t bsd_no = syscall_no & 0x00FFFFFFull;
  switch (bsd_no) {
    /* ── I/O (memory r/w via fd) ── */
    case 3:  case 4:   case 153: case 154: case 396: case 397: case 245:
      flags |= QBDITRACE_SVC_FL_MEM_OP; break;
    /* ── Virtual memory ── */
    case 197: case 73: case 74: case 75: case 286:
      flags |= QBDITRACE_SVC_FL_MEM_OP; break;
    /* ── File system ── */
    case 5:  case 6:  case 7:  case 339: case 188: case 189: case 190:
    case 338: case 295: case 33: case 136: case 137: case 128: case 10:
    case 15: case 16: case 120: case 121: case 252:
      flags |= QBDITRACE_SVC_FL_FILE_OP; break;
    /* ── Network ── */
    case 97:  case 98:  case 99:  case 100: case 101: case 102: case 103:
    case 104: case 26:  case 27:  case 28:  case 133: case 198: case 417:
    case 418: case 419: case 420: case 424: case 425:
      flags |= QBDITRACE_SVC_FL_NET_OP; break;
    /* ── Crypto / entropy ── */
    case 430:
      flags |= QBDITRACE_SVC_FL_CRYPTO_OP; break;
    default:
      /* Mach trap memory-management ops. */
      if (flags & QBDITRACE_SVC_FL_MACH_TRAP) {
        uint64_t mt_no = (~syscall_no + 1) & 0xFFFFull; /* |negative| */
        switch (mt_no) {
          case 10: case 12: case 14: case 32: case 33:
            flags |= QBDITRACE_SVC_FL_MEM_OP; break;
          default: break;
        }
      }
      break;
  }
#elif defined(__linux__) || defined(__ANDROID__)
  switch (syscall_no) {
    /* ── Memory r/w via fd ── */
    case 0:  case 63: case 64: case 67: case 68: case 65: case 66:
    case 69: case 70: case 71: case 72: case 187:
      flags |= QBDITRACE_SVC_FL_MEM_OP; break;
    /* ── Virtual memory ── */
    case 9:  case 11: case 10: case 28: case 226: case 222: case 216: case 25:
      flags |= QBDITRACE_SVC_FL_MEM_OP; break;
    /* ── File system ── */
    case 2:  case 3:  case 56:  case 257: case 4:  case 5:  case 6:
    case 262: case 439: case 21: case 269: case 78: case 79: case 34:
    case 258: case 35: case 263: case 82: case 264: case 316: case 14:
    case 84:  case 1:  case 8:  case 17: case 18: case 43: case 217:
      flags |= QBDITRACE_SVC_FL_FILE_OP; break;
    /* ── Network ── */
    case 198: case 203: case 204: case 205: case 206: case 207: case 208:
    case 209: case 210: case 211: case 212: case 213: case 200: case 201:
    case 202: case 242: case 243: case 244: case 320: case 299:
      flags |= QBDITRACE_SVC_FL_NET_OP; break;
    /* ── Crypto / entropy ── */
    case 278:
      flags |= QBDITRACE_SVC_FL_CRYPTO_OP; break;
    /* ── Android Binder via ioctl ── */
    case 29:
      flags |= QBDITRACE_SVC_FL_BINDER_IOC | QBDITRACE_SVC_FL_MEM_OP; break;
    default: break;
  }
#endif
  return flags;
}

} // namespace qbditrace_internal
