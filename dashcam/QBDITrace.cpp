/*
 * qbditrace - high performance instruction tracer built on QBDI
 *
 * QBDITrace.cpp
 *
 * Core tracer. One QBDI::VM is created per traced thread (QBDI VMs are not
 * thread-safe and must not be shared). Each thread also owns a ThreadBuffer for
 * lock-free record emission. A single shared BackgroundWriter drains all
 * threads' chunks to one trace file.
 *
 * Hot-path design (the per-instruction callback) does the minimum possible:
 *   - read NZCV (single GPR slot)
 *   - for each register this instruction writes (precomputed at instrument time
 *     and cached by PC), read its new value from the GPRState
 *   - optionally pull memory accesses recorded by QBDI for this instruction
 *   - append one packed variable-length record to the thread-local buffer
 * No disassembly, no symbolization, no allocation, no I/O on the hot path.
 *
 * PC handling: the executed instruction's address is captured cheaply in the
 * PREINST callback (QBDI_GPR_GET PC slot still points at the current
 * instruction there) and reused in POSTINST, avoiding any analysis lookup on
 * the hot path.
 */

/* _DARWIN_C_SOURCE exposes non-POSIX Darwin extensions (RTLD_DEFAULT, MAP_ANON,
 * etc.) that are hidden when _XOPEN_SOURCE / _POSIX_C_SOURCE are set strictly.
 * Must be defined before any system header. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif

/* Required so <ucontext.h> exposes the (otherwise deprecated) ucontext_t /
 * mcontext routines used by the diagnostic fault handler to read the faulting
 * PC. Must be defined before any system header is included. */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "QBDITrace.h"
#include "RingBuffer.h"
#include "TraceFormat.h"
#include "FlatContainers.h"

#include "QBDI.h"

/* QBDI provides QBDI_GPR_GET for GPRState (rword[] reinterpret), but has no
 * equivalent for FPRState.  FPRState contains 32 × __uint128_t (v0-v31) laid
 * out contiguously, so reinterpreting it as a uint64_t array gives:
 *   slot 2*i   → v[i] low  64 bits
 *   slot 2*i+1 → v[i] high 64 bits
 * This matches the trace format's per-half storage convention. */
#define QBDI_FPR_GET(state, i) \
  (reinterpret_cast<const uint64_t *>(state)[i])

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <shared_mutex>
#include <pthread.h>
#include <string>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#elif defined(__linux__)
#include <sys/uio.h>       /* process_vm_readv (Linux 3.2+ / Android API 23+) */
#include <sys/syscall.h>   /* __NR_gettid */
#include <dlfcn.h>
#endif

/* Weak reference to the Objective-C runtime so the tracer can resolve a
 * message-send receiver's class name live, without hard-linking libobjc (the
 * symbol resolves to non-null on any iOS/macOS process that loads the ObjC
 * runtime, and stays null otherwise). Declared minimally to avoid pulling in
 * <objc/runtime.h>. */
extern "C" {
typedef struct objc_object *id;
const char *object_getClassName(id obj) __attribute__((weak_import));
}

/* Internal types (Config, classifySyscall, classifyObjcTarget, lookupCApiFunc)
 * shared with the unit test suite.  Must be included before the anonymous
 * namespace so the definitions are visible at file scope. */
#include "QBDITraceInternal.h"

/* ----------------------------------------------------------------------------
 * Live statistics page
 *
 * A process-global, cache-line-aligned struct whose fields are updated by
 * relaxed atomics on the hot path. The Frida JS agent obtains the address
 * once via qbditrace_stats_page(), then polls individual fields with
 * Memory.readU64() on a setInterval timer — zero function-call overhead
 * per poll.
 *
 * We use a plain C struct (matching QBDITrace.h) for the exported page, but
 * internally write through a parallel array of std::atomic<uint64_t> that
 * shares the same storage via reinterpret_cast. This is safe because:
 *   - uint64_t and std::atomic<uint64_t> have identical size/alignment on all
 *     targets we care about (aarch64, x86_64) with the standard library impls
 *     (libc++, libstdc++).
 *   - We only ever access the storage through the atomic accessors (relaxed),
 *     never via the C struct directly, so there is no data race.
 * ------------------------------------------------------------------------- */
static_assert(sizeof(std::atomic<uint64_t>) == sizeof(uint64_t),
              "atomic<uint64_t> must be lock-free and same size as uint64_t");

alignas(64) static qbditrace_stats_t g_stats_page;

/* Convenience accessors into g_stats_page fields as relaxed atomics. */
static inline std::atomic<uint64_t> &statsField(size_t byte_offset) {
  return *reinterpret_cast<std::atomic<uint64_t> *>(
      reinterpret_cast<uint8_t *>(&g_stats_page) + byte_offset);
}
/* Named accessors for each counter (offsets match qbditrace_stats_t layout). */
static inline void statsIncInstructions() {
  statsField(offsetof(qbditrace_stats_t, total_instructions))
      .fetch_add(1, std::memory_order_relaxed);
}
static inline void statsIncAnchors() {
  statsField(offsetof(qbditrace_stats_t, total_anchors))
      .fetch_add(1, std::memory_order_relaxed);
}
static inline void statsAddMemAccesses(uint64_t n) {
  statsField(offsetof(qbditrace_stats_t, total_mem_accesses))
      .fetch_add(n, std::memory_order_relaxed);
}
static inline void statsIncEvents() {
  statsField(offsetof(qbditrace_stats_t, total_events))
      .fetch_add(1, std::memory_order_relaxed);
}
static inline void statsIncSvc() {
  statsField(offsetof(qbditrace_stats_t, total_svc))
      .fetch_add(1, std::memory_order_relaxed);
}
static inline void statsIncObjc() {
  statsField(offsetof(qbditrace_stats_t, total_objc))
      .fetch_add(1, std::memory_order_relaxed);
}
static inline void statsIncCodeEntries() {
  statsField(offsetof(qbditrace_stats_t, total_code_entries))
      .fetch_add(1, std::memory_order_relaxed);
}
static inline void statsIncCapi() {
  statsField(offsetof(qbditrace_stats_t, total_capi))
      .fetch_add(1, std::memory_order_relaxed);
}
static inline void statsAddBytesWritten(uint64_t n) {
  statsField(offsetof(qbditrace_stats_t, bytes_written))
      .fetch_add(n, std::memory_order_relaxed);
}

/* Platform-portable nanosecond wall clock. */
static inline uint64_t nowNs() {
#if defined(__APPLE__)
  /* mach_absolute_time is ~20 ns on Apple Silicon; numer/denom == 1/1 on
   * all Apple Silicon Macs and iPhones, so the value IS nanoseconds. */
  return mach_absolute_time();
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static void statsReset() {
  std::memset(&g_stats_page, 0, sizeof(g_stats_page));
  g_stats_page.start_time_ns = nowNs();
}

/* Update the elapsed_ns field from the stored start time. Called lazily by the
 * reader (qbditrace_stats_page returns the struct; the JS side reads
 * elapsed_ns, which the dylib keeps up-to-date on every instruction — but
 * that would be too expensive). Instead we update it in the background writer
 * after each chunk flush, which gives ~100ms granularity. */
static inline void statsUpdateElapsed() {
  uint64_t start = statsField(offsetof(qbditrace_stats_t, start_time_ns))
      .load(std::memory_order_relaxed);
  if (start != 0) {
    statsField(offsetof(qbditrace_stats_t, elapsed_ns))
        .store(nowNs() - start, std::memory_order_relaxed);
  }
}

namespace {

using namespace qbditrace;
using namespace qbditrace_internal;

/* ----------------------------------------------------------------------------
 * Fault-tolerant memory probe.
 *
 * The tracer runs inside a heavily protected target (ByteGuard/VMP). Reading
 * arbitrary addresses captured from register values (store destinations, objc
 * receivers) with a plain memcpy can fault on guard pages, freed/unmapped
 * regions, MMIO, or partially-mapped spans straddling a page boundary. Such a
 * fault crashes the whole process and aborts the trace.
 *
 * safeRead() copies up to `len` bytes from `addr` into `out` using mach's
 * mach_vm_read_overwrite, which returns an error (instead of trapping) when the
 * source is not fully readable. Returns true only when the full span was
 * copied. On platforms without mach we fall back to a conservative no-op (the
 * value is simply left unknown rather than risking a crash). */
inline bool safeRead(uint64_t addr, void *out, size_t len) {
  if (addr == 0 || len == 0) {
    return false;
  }
#if defined(__APPLE__)
  /* vm_read_overwrite (mach/vm_map.h) is the iOS-supported form; mach_vm.h is
   * unavailable on the device SDK. outsize is vm_size_t (pointer width). */
  vm_size_t got = 0;
  kern_return_t kr = vm_read_overwrite(
      mach_task_self(), (vm_address_t)addr, (vm_size_t)len,
      (vm_address_t)out, &got);
  return kr == KERN_SUCCESS && got == (vm_size_t)len;
#elif defined(__linux__)
  /* process_vm_readv (Linux 3.2+, Android API 23+) reads from our own address
   * space and returns an error instead of trapping when the source page is not
   * readable (guard page, unmapped, MMIO, etc.). */
  struct iovec local  = { out, len };
  struct iovec remote = { reinterpret_cast<void *>(addr), len };
  ssize_t nr = ::process_vm_readv(::getpid(), &local, 1, &remote, 1, 0);
  return nr == static_cast<ssize_t>(len);
#else
  (void)addr;
  (void)out;
  (void)len;
  return false;
#endif
}

/* Heuristically validate that `recv` looks like a live Objective-C object
 * before handing it to object_getClassName (which dereferences the isa). This
 * avoids crashing on nil, freed objects, or non-object pointers that merely
 * happened to sit in the receiver register. Tagged pointers (top or bottom bit
 * set per ABI) are always safe for object_getClassName, so we accept them
 * without a memory probe. For ordinary pointers we require the isa slot to be
 * readable. */
inline bool looksLikeObjcObject(uint64_t recv) {
  if (recv == 0) {
    return false;
  }
#if defined(__arm64__) || defined(__aarch64__)
  /* arm64 tagged-pointer: MSB set => objc tagged pointer; handled safely. */
  if (recv & (1ull << 63)) {
    return true;
  }
#endif
  /* Reject obviously misaligned pointers (real objects are at least 8-aligned)
   * and probe the isa word for readability. */
  if (recv & 0x7ull) {
    return false;
  }
  uint64_t isa = 0;
  return safeRead(recv, &isa, sizeof(isa)) && isa != 0;
}

/* Default spacing (in instructions) between full-register ANCHOR checkpoints
 * when the caller does not specify anchor_interval. Diffs carry absolute values
 * so anchors are only resync points for partial/seek reads; a coarse interval
 * keeps the file small while still bounding reconstruction cost. */
static constexpr uint32_t kDefaultAnchorInterval = 1024;

/* ----------------------------------------------------------------------------
 * Global tracer state (configuration + shared writer + per-PC write-reg cache)
 *
 * Config, classifyObjcTarget, lookupCApiFunc, and classifySyscall are defined
 * in QBDITraceInternal.h (included above the anonymous namespace) and brought
 * into scope via `using namespace qbditrace_internal`.
 * --------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * Native C API address auto-resolution.
 *
 * When the caller (JS Frida agent) does NOT provide capi_funcs[] entries
 * (n_capi_funcs == 0), the tracer resolves the well-known function addresses
 * itself at configure() time using dlsym(RTLD_DEFAULT, name).  This makes the
 * tracer self-contained: even a minimal JS loader that only sets the trace
 * range and output path gets full C API interception automatically.
 *
 * The function fills as many slots in cfg.capi_funcs[] as fit up to
 * Config::kMaxCapiFuncs, updating cfg.n_capi_funcs accordingly.
 *
 * Thread safety: called only from configure(), which holds setup_mtx_.
 * dlsym(RTLD_DEFAULT) is async-signal-unsafe but safe from a mutex-protected
 * setup path.  The results are cached in cfg_ for the tracer's lifetime.
 * --------------------------------------------------------------------------- */

struct NativeCApiEntry {
  const char  *name;
  uint16_t     api_id;   /* qbditrace_capi_id_t (uint16 to hold ids > 255) */
  uint8_t      n_args;
  uint8_t      str_args; /* bitmask */
};

/* Resolve and append one entry to cfg.capi_funcs[].
 * Returns true if added, false if table is full or symbol not found. */
static bool appendCApiEntry(Config &cfg, const char *name,
                             uint16_t api_id, uint8_t n_args, uint8_t str_args) {
if (cfg.n_capi_funcs >= Config::kMaxCapiFuncs) return false;
void *p = ::dlsym(RTLD_DEFAULT, name);
if (!p) return false;
  uint32_t idx = cfg.n_capi_funcs++;
  cfg.capi_funcs[idx].addr     = reinterpret_cast<uint64_t>(p);
  cfg.capi_funcs[idx].api_id   = api_id;
  cfg.capi_funcs[idx].n_args   = n_args;
  cfg.capi_funcs[idx].str_args = str_args;
  return true;
}

/* Try to resolve via an explicit handle (for Android linker namespace).
 * handle == RTLD_DEFAULT is legal: dlsym(RTLD_DEFAULT, name) searches all
 * already-loaded libraries (same as appendCApiEntry).  We must NOT reject it
 * with !handle because RTLD_DEFAULT is defined as (void*)0 on Linux/Android. */
static bool appendCApiEntryFromHandle(Config &cfg, void *handle,
                                      const char *name,
                                      uint16_t api_id, uint8_t n_args,
                                      uint8_t str_args) {
  /* Note: handle may be RTLD_DEFAULT (== (void*)0 on Linux/Android), which is
   * a valid pseudo-handle for dlsym.  Do NOT check !handle here. */
  if (cfg.n_capi_funcs >= Config::kMaxCapiFuncs) return false;
  void *p = ::dlsym(handle, name);
  if (!p) return false;
  uint32_t idx = cfg.n_capi_funcs++;
  cfg.capi_funcs[idx].addr     = reinterpret_cast<uint64_t>(p);
  cfg.capi_funcs[idx].api_id   = api_id;
  cfg.capi_funcs[idx].n_args   = n_args;
  cfg.capi_funcs[idx].str_args = str_args;
  return true;
}

/* Macro helpers: capi ID constants from TraceFormat.h */
#define CAPI_(name, id, na, sa) appendCApiEntry(cfg, name, id, na, sa)
#define CAPI_H(handle, name, id, na, sa) appendCApiEntryFromHandle(cfg, handle, name, id, na, sa)

static void resolveCApiAddrsIntoConfig(Config &cfg) {
  using namespace qbditrace;

  /* ── Common: memory ─────────────────────────────────────────────── */
  CAPI_("memcpy",        QBDITRACE_CAPI_MEMCPY,         3, 0x06);
  CAPI_("memmove",       QBDITRACE_CAPI_MEMMOVE,        3, 0x06);
  CAPI_("memset",        QBDITRACE_CAPI_MEMSET,         3, 0x00);
  CAPI_("memcmp",        QBDITRACE_CAPI_MEMCMP,         3, 0x03);
  CAPI_("memchr",        QBDITRACE_CAPI_MEMCHR,         3, 0x01);
  CAPI_("bcopy",         QBDITRACE_CAPI_BCOPY,          3, 0x02);
  CAPI_("bzero",         QBDITRACE_CAPI_BZERO,          2, 0x00);

  /* ── Common: string ─────────────────────────────────────────────── */
  CAPI_("strlen",        QBDITRACE_CAPI_STRLEN,         1, 0x01);
  CAPI_("strnlen",       QBDITRACE_CAPI_STRNLEN,        2, 0x01);
  CAPI_("strcmp",        QBDITRACE_CAPI_STRCMP,         2, 0x03);
  CAPI_("strncmp",       QBDITRACE_CAPI_STRNCMP,        3, 0x03);
  CAPI_("strcasecmp",    QBDITRACE_CAPI_STRCASECMP,     2, 0x03);
  CAPI_("strncasecmp",   QBDITRACE_CAPI_STRNCASECMP,    3, 0x03);
  CAPI_("strcpy",        QBDITRACE_CAPI_STRCPY,         2, 0x02);
  CAPI_("strncpy",       QBDITRACE_CAPI_STRNCPY,        3, 0x02);
  CAPI_("strlcpy",       QBDITRACE_CAPI_STRLCPY,        3, 0x02);
  CAPI_("strcat",        QBDITRACE_CAPI_STRCAT,         2, 0x02);
  CAPI_("strncat",       QBDITRACE_CAPI_STRNCAT,        3, 0x02);
  CAPI_("strlcat",       QBDITRACE_CAPI_STRLCAT,        3, 0x02);
  CAPI_("strdup",        QBDITRACE_CAPI_STRDUP,         1, 0x01);
  CAPI_("strndup",       QBDITRACE_CAPI_STRNDUP,        2, 0x01);
  CAPI_("strchr",        QBDITRACE_CAPI_STRCHR,         2, 0x01);
  CAPI_("strrchr",       QBDITRACE_CAPI_STRRCHR,        2, 0x01);
  CAPI_("strstr",        QBDITRACE_CAPI_STRSTR,         2, 0x03);
  CAPI_("sprintf",       QBDITRACE_CAPI_SPRINTF,        2, 0x02);
  CAPI_("snprintf",      QBDITRACE_CAPI_SNPRINTF,       3, 0x04);
  CAPI_("atoi",          QBDITRACE_CAPI_ATOI,           1, 0x01);
  CAPI_("strtol",        QBDITRACE_CAPI_STRTOL,         3, 0x01);
  CAPI_("strtoul",       QBDITRACE_CAPI_STRTOUL,        3, 0x01);
  CAPI_("strtoll",       QBDITRACE_CAPI_STRTOLL,        3, 0x01);
  CAPI_("strtoull",      QBDITRACE_CAPI_STRTOULL,       3, 0x01);

  /* ── Common: heap ───────────────────────────────────────────────── */
  CAPI_("malloc",        QBDITRACE_CAPI_MALLOC,         1, 0x00);
  CAPI_("calloc",        QBDITRACE_CAPI_CALLOC,         2, 0x00);
  CAPI_("realloc",       QBDITRACE_CAPI_REALLOC,        2, 0x00);
  CAPI_("free",          QBDITRACE_CAPI_FREE,           1, 0x00);

  /* ── Common: I/O ────────────────────────────────────────────────── */
  CAPI_("fopen",         QBDITRACE_CAPI_FOPEN,          2, 0x01);
  CAPI_("fclose",        QBDITRACE_CAPI_FCLOSE,         1, 0x00);
  CAPI_("fread",         QBDITRACE_CAPI_FREAD,          4, 0x00);
  CAPI_("fwrite",        QBDITRACE_CAPI_FWRITE,         4, 0x00);
  CAPI_("open",          QBDITRACE_CAPI_OPEN,           2, 0x01);
  CAPI_("close",         QBDITRACE_CAPI_CLOSE,          1, 0x00);
  CAPI_("read",          QBDITRACE_CAPI_READ,           3, 0x00);
  CAPI_("write",         QBDITRACE_CAPI_WRITE,          3, 0x00);

  /* ── Common: anti-debug ─────────────────────────────────────────── */
  CAPI_("ptrace",        QBDITRACE_CAPI_PTRACE,         4, 0x00);
  CAPI_("getenv",        QBDITRACE_CAPI_GETENV,         1, 0x01);
  CAPI_("access",        QBDITRACE_CAPI_ACCESS,         2, 0x01);
  CAPI_("kill",          QBDITRACE_CAPI_KILL,           2, 0x00);
  CAPI_("getpid",        QBDITRACE_CAPI_GETPID,         0, 0x00);
  CAPI_("stat",          QBDITRACE_CAPI_STAT,           2, 0x01);
  CAPI_("lstat",         QBDITRACE_CAPI_STAT,           2, 0x01);

  /* ── Common: network ────────────────────────────────────────────── */
  CAPI_("socket",        QBDITRACE_CAPI_SOCKET,         3, 0x00);
  CAPI_("connect",       QBDITRACE_CAPI_CONNECT,        3, 0x00);
  CAPI_("send",          QBDITRACE_CAPI_SEND,           4, 0x00);
  CAPI_("recv",          QBDITRACE_CAPI_RECV,           4, 0x00);
  CAPI_("sendto",        QBDITRACE_CAPI_SENDTO,         6, 0x00);
  CAPI_("recvfrom",      QBDITRACE_CAPI_RECVFROM,       6, 0x00);

  /* ── Common: dl* / pthread ──────────────────────────────────────── */
  CAPI_("dlopen",        QBDITRACE_CAPI_DLOPEN,         2, 0x01);
  CAPI_("dlsym",         QBDITRACE_CAPI_DLSYM,          2, 0x02);
  CAPI_("pthread_create",         QBDITRACE_CAPI_PTHREAD_CREATE,       4, 0x00);
  CAPI_("pthread_mutex_lock",     QBDITRACE_CAPI_PTHREAD_MUTEX_LOCK,   1, 0x00);
  CAPI_("pthread_mutex_unlock",   QBDITRACE_CAPI_PTHREAD_MUTEX_UNLOCK, 1, 0x00);

  /* ── Common: more file ops ──────────────────────────────────────── */
  CAPI_("rename",        QBDITRACE_CAPI_RENAME,         2, 0x03);
  CAPI_("unlink",        QBDITRACE_CAPI_UNLINK,         1, 0x01);
  CAPI_("mkdir",         QBDITRACE_CAPI_MKDIR,          2, 0x01);
  CAPI_("rmdir",         QBDITRACE_CAPI_RMDIR,          1, 0x01);
  CAPI_("mmap",          QBDITRACE_CAPI_MMAP,           6, 0x00);
  CAPI_("mprotect",      QBDITRACE_CAPI_MPROTECT,       3, 0x00);
  CAPI_("munmap",        QBDITRACE_CAPI_MUNMAP,         2, 0x00);

#if defined(__APPLE__)
  /* ── iOS/macOS: sysctl / entropy ───────────────────────────────── */
  CAPI_("sysctlbyname",  QBDITRACE_CAPI_SYSCTLBYNAME,   6, 0x01);
  CAPI_("sysctl",        QBDITRACE_CAPI_SYSCTL,         6, 0x00);
  CAPI_("isatty",        QBDITRACE_CAPI_ISATTY,         1, 0x00);

  /* ── iOS/macOS: CommonCrypto (handle = self-dlopen RTLD_DEFAULT works since
   * libcommonCrypto is re-exported by libSystem on iOS; RTLD_DEFAULT searches
   * all loaded dylibs) ────────────────────────────────────────────── */
  CAPI_("CCCrypt",                QBDITRACE_CAPI_CC_CRYPT,            7, 0x00);
  CAPI_("CCHmac",                 QBDITRACE_CAPI_CC_HMAC,             6, 0x00);
  CAPI_("CCHmacInit",             QBDITRACE_CAPI_CC_HMAC_INIT,        4, 0x00);
  CAPI_("CCHmacUpdate",           QBDITRACE_CAPI_CC_HMAC_UPDATE,      3, 0x00);
  CAPI_("CCHmacFinal",            QBDITRACE_CAPI_CC_HMAC_FINAL,       2, 0x00);
  CAPI_("CCCryptorCreate",        QBDITRACE_CAPI_CC_CRYPTOR_CREATE,   7, 0x00);
  CAPI_("CCCryptorUpdate",        QBDITRACE_CAPI_CC_CRYPTOR_UPDATE,   6, 0x00);
  CAPI_("CCCryptorFinal",         QBDITRACE_CAPI_CC_CRYPTOR_FINAL,    3, 0x00);
  CAPI_("CCCryptorRelease",       QBDITRACE_CAPI_CC_CRYPTOR_RELEASE,  1, 0x00);
  CAPI_("CCRandomGenerateBytes",  QBDITRACE_CAPI_CC_RANDOM_GENERATE,  2, 0x00);
  CAPI_("CCKeyDerivationPBKDF",   QBDITRACE_CAPI_CC_KEY_DERIVE_PBKDF, 8, 0x02);
  CAPI_("CC_SHA1",                QBDITRACE_CAPI_CC_DIGEST,           3, 0x00);
  CAPI_("CC_SHA224",              QBDITRACE_CAPI_CC_SHA224,           3, 0x00);
  CAPI_("CC_SHA256",              QBDITRACE_CAPI_CC_DIGEST,           3, 0x00);
  CAPI_("CC_SHA384",              QBDITRACE_CAPI_CC_SHA384,           3, 0x00);
  CAPI_("CC_SHA512",              QBDITRACE_CAPI_CC_SHA512,           3, 0x00);
  CAPI_("CC_MD5",                 QBDITRACE_CAPI_CC_DIGEST,           3, 0x00);
  CAPI_("CC_SHA256_Init",         QBDITRACE_CAPI_CC_SHA256_INIT,      1, 0x00);
  CAPI_("CC_SHA256_Update",       QBDITRACE_CAPI_CC_SHA256_UPDATE,    3, 0x00);
  CAPI_("CC_SHA256_Final",        QBDITRACE_CAPI_CC_SHA256_FINAL,     2, 0x00);

  /* ── iOS/macOS: CoreFoundation ──────────────────────────────────── */
  CAPI_("CFStringCreateWithCString",  QBDITRACE_CAPI_CF_STR_CREATE_UTF8,  3, 0x02);
  CAPI_("CFStringCreateWithBytes",    QBDITRACE_CAPI_CF_STR_CREATE_BYTES, 5, 0x00);
  CAPI_("CFStringGetCString",         QBDITRACE_CAPI_CF_STR_GET_CSTR,     4, 0x00);
  CAPI_("CFStringGetCStringPtr",      QBDITRACE_CAPI_CF_STR_GET_PTR,      2, 0x00);
  CAPI_("CFStringCompare",            QBDITRACE_CAPI_CF_STR_COMPARE,      3, 0x00);
  CAPI_("CFStringHasPrefix",          QBDITRACE_CAPI_CF_STR_HASPREFIX,    2, 0x00);
  CAPI_("CFStringHasSuffix",          QBDITRACE_CAPI_CF_STR_HASSUFFIX,    2, 0x00);
  CAPI_("CFDataCreate",               QBDITRACE_CAPI_CF_DATA_CREATE,      3, 0x00);
  CAPI_("CFDataGetBytePtr",           QBDITRACE_CAPI_CF_DATA_GET_PTR,     1, 0x00);
  CAPI_("CFDataGetLength",            QBDITRACE_CAPI_CF_DATA_GET_LEN,     1, 0x00);
  CAPI_("CFDictionaryGetValue",       QBDITRACE_CAPI_CF_DICT_GET_VAL,     2, 0x00);
  CAPI_("CFArrayGetValueAtIndex",     QBDITRACE_CAPI_CF_ARRAY_GET_VAL,    2, 0x00);
  CAPI_("CFRelease",                  QBDITRACE_CAPI_CF_RELEASE,          1, 0x00);
  CAPI_("CFRetain",                   QBDITRACE_CAPI_CF_RETAIN,           1, 0x00);
  CAPI_("CFURLGetString",             QBDITRACE_CAPI_CF_URL_GET_STR,      1, 0x00);

  /* ── iOS/macOS: Security framework ─────────────────────────────── */
  CAPI_("SecItemCopyMatching",             QBDITRACE_CAPI_SEC_ITEM_COPY_MATCH, 2, 0x00);
  CAPI_("SecItemAdd",                      QBDITRACE_CAPI_SEC_ITEM_ADD,        2, 0x00);
  CAPI_("SecItemUpdate",                   QBDITRACE_CAPI_SEC_ITEM_UPDATE,     2, 0x00);
  CAPI_("SecItemDelete",                   QBDITRACE_CAPI_SEC_ITEM_DELETE,     1, 0x00);
  CAPI_("SecRandomCopyBytes",              QBDITRACE_CAPI_SEC_RAND_COPY_BYTES, 3, 0x00);
  CAPI_("SecKeyCopyExternalRepresentation",QBDITRACE_CAPI_SEC_KEY_COPY_EXT,   2, 0x00);
  CAPI_("SecKeyEncrypt",                   QBDITRACE_CAPI_SEC_KEY_ENCRYPT,     6, 0x00);
  CAPI_("SecKeyDecrypt",                   QBDITRACE_CAPI_SEC_KEY_DECRYPT,     6, 0x00);
  CAPI_("SecTrustEvaluate",                QBDITRACE_CAPI_SEC_TRUST_EVAL,      2, 0x00);

  /* ── iOS/macOS: GCD / libdispatch ──────────────────────────────── */
  CAPI_("dispatch_async",   QBDITRACE_CAPI_DISPATCH_ASYNC, 2, 0x00);
  CAPI_("dispatch_sync",    QBDITRACE_CAPI_DISPATCH_SYNC,  2, 0x00);
  CAPI_("dispatch_after",   QBDITRACE_CAPI_DISPATCH_AFTER, 3, 0x00);
  CAPI_("dispatch_once",    QBDITRACE_CAPI_DISPATCH_ONCE,  2, 0x00);

#elif defined(__ANDROID__) || defined(__linux__)
  /* ── Android: system calls extras ─────────────────────────────── */
  CAPI_("prctl",         QBDITRACE_CAPI_PRCTL,           5, 0x00);
  CAPI_("getaddrinfo",   QBDITRACE_CAPI_GETADDRINFO,     4, 0x01);
  CAPI_("inet_ntop",     QBDITRACE_CAPI_INET_NTOP,       4, 0x00);
  CAPI_("getrandom",     QBDITRACE_CAPI_GETRANDOM,       3, 0x00);

  /* ── Android: logging (liblog.so) ──────────────────────────────── */
  {
    /* Try to open liblog.so explicitly to reach namespace-private symbol. */
    void *hlog = ::dlopen("liblog.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!hlog) hlog = ::dlopen("liblog.so", RTLD_LAZY | RTLD_GLOBAL);
    if (hlog) {
      CAPI_H(hlog, "__android_log_print",     QBDITRACE_CAPI_ALOG_PRINT,  3, 0x06);
      CAPI_H(hlog, "__android_log_write",     QBDITRACE_CAPI_ALOG_WRITE,  3, 0x06);
      CAPI_H(hlog, "__android_log_buf_write", QBDITRACE_CAPI_ALOG_WRITE,  4, 0x0c);
      /* Don't dlclose — we want the lib to stay loaded. */
    } else {
      /* Fallback: RTLD_DEFAULT may find it if already loaded. */
      CAPI_("__android_log_print",  QBDITRACE_CAPI_ALOG_PRINT,  3, 0x06);
      CAPI_("__android_log_write",  QBDITRACE_CAPI_ALOG_WRITE,  3, 0x06);
    }
  }

  /* ── Android: OpenSSL / BoringSSL (libcrypto.so / libssl.so) ────── */
  {
    /* BoringSSL on Android is namespaced; try NOLOAD first then fallback. */
    static const char *kCryptoLibs[] = {
      "libcrypto.so", "libssl.so", "libcrypto.so.3",
      "libcrypto_static.so", nullptr
    };
    void *hcrypto = nullptr;
    for (int i = 0; kCryptoLibs[i] && !hcrypto; ++i) {
      hcrypto = ::dlopen(kCryptoLibs[i], RTLD_NOLOAD | RTLD_LAZY);
    }
    if (!hcrypto) hcrypto = RTLD_DEFAULT;

    CAPI_H(hcrypto, "EVP_EncryptInit_ex",  QBDITRACE_CAPI_EVP_ENCRYPT_INIT,   5, 0x00);
    CAPI_H(hcrypto, "EVP_EncryptUpdate",   QBDITRACE_CAPI_EVP_ENCRYPT_UPDATE,  5, 0x00);
    CAPI_H(hcrypto, "EVP_EncryptFinal_ex", QBDITRACE_CAPI_EVP_ENCRYPT_FINAL,   3, 0x00);
    CAPI_H(hcrypto, "EVP_DecryptInit_ex",  QBDITRACE_CAPI_EVP_DECRYPT_INIT,    5, 0x00);
    CAPI_H(hcrypto, "EVP_DecryptUpdate",   QBDITRACE_CAPI_EVP_DECRYPT_UPDATE,  5, 0x00);
    CAPI_H(hcrypto, "EVP_DecryptFinal_ex", QBDITRACE_CAPI_EVP_DECRYPT_FINAL,   3, 0x00);
    CAPI_H(hcrypto, "EVP_DigestInit_ex",   QBDITRACE_CAPI_EVP_DIGESTINIT,      3, 0x00);
    CAPI_H(hcrypto, "EVP_DigestUpdate",    QBDITRACE_CAPI_EVP_DIGESTUPDATE,    3, 0x00);
    CAPI_H(hcrypto, "EVP_DigestFinal_ex",  QBDITRACE_CAPI_EVP_DIGESTFINAL,     3, 0x00);
    CAPI_H(hcrypto, "HMAC_Init_ex",        QBDITRACE_CAPI_HMAC_INIT_EX,        5, 0x00);
    CAPI_H(hcrypto, "HMAC_Update",         QBDITRACE_CAPI_HMAC_UPDATE,         3, 0x00);
    CAPI_H(hcrypto, "HMAC_Final",          QBDITRACE_CAPI_HMAC_FINAL,          3, 0x00);
    CAPI_H(hcrypto, "SHA256_Init",         QBDITRACE_CAPI_SHA256_INIT,         1, 0x00);
    CAPI_H(hcrypto, "SHA256_Update",       QBDITRACE_CAPI_SHA256_UPDATE,       3, 0x00);
    CAPI_H(hcrypto, "SHA256_Final",        QBDITRACE_CAPI_SHA256_FINAL,        2, 0x00);
    CAPI_H(hcrypto, "AES_set_encrypt_key", QBDITRACE_CAPI_AES_SET_ENC_KEY,    3, 0x01);
    CAPI_H(hcrypto, "AES_set_decrypt_key", QBDITRACE_CAPI_AES_SET_DEC_KEY,    3, 0x01);
    CAPI_H(hcrypto, "AES_cbc_encrypt",     QBDITRACE_CAPI_AES_CBC_ENCRYPT,    6, 0x00);
    CAPI_H(hcrypto, "RSA_sign",            QBDITRACE_CAPI_RSA_SIGN,            6, 0x00);
    CAPI_H(hcrypto, "RSA_verify",          QBDITRACE_CAPI_RSA_VERIFY,          6, 0x00);
    CAPI_H(hcrypto, "RAND_bytes",          QBDITRACE_CAPI_RAND_BYTES,          2, 0x00);
    CAPI_H(hcrypto, "BIO_new_mem_buf",     QBDITRACE_CAPI_BIO_NEW_MEM_BUF,     2, 0x00);
  }

  /* ── Android: SQLite (libsqlite3.so or embedded) ─────────────────── */
  {
    static const char *kSqliteLibs[] = {
      "libsqlite3.so", "libsqlite.so", nullptr
    };
    void *hsql = nullptr;
    for (int i = 0; kSqliteLibs[i] && !hsql; ++i) {
      hsql = ::dlopen(kSqliteLibs[i], RTLD_NOLOAD | RTLD_LAZY);
    }
    if (hsql) {
      CAPI_H(hsql, "sqlite3_open",        QBDITRACE_CAPI_SQLITE3_OPEN,        2, 0x01);
      CAPI_H(hsql, "sqlite3_open_v2",     QBDITRACE_CAPI_SQLITE3_OPEN,        4, 0x01);
      CAPI_H(hsql, "sqlite3_prepare_v2",  QBDITRACE_CAPI_SQLITE3_PREPARE,     5, 0x02);
      CAPI_H(hsql, "sqlite3_exec",        QBDITRACE_CAPI_SQLITE3_EXEC,        5, 0x02);
      CAPI_H(hsql, "sqlite3_step",        QBDITRACE_CAPI_SQLITE3_STEP,        1, 0x00);
      CAPI_H(hsql, "sqlite3_column_text", QBDITRACE_CAPI_SQLITE3_COLUMN_TEXT, 2, 0x00);
      CAPI_H(hsql, "sqlite3_close",       QBDITRACE_CAPI_SQLITE3_CLOSE,       1, 0x00);
    }
  }
#endif
}

#undef CAPI_
#undef CAPI_H

/* WriteRegList, FlatPcSet, FlatWriteRegCache are defined in FlatContainers.h
 * (extracted for independent unit testing). */
using qbditrace::WriteRegList;
using qbditrace::FlatPcSet;
using qbditrace::FlatWriteRegCache;

class Tracer {
public:
  static Tracer &get() {
    static Tracer instance;
    return instance;
  }

  bool configure(const Config &cfg) {
    std::lock_guard<std::mutex> lk(setup_mtx_);
    statsReset();
    cfg_ = cfg;

    if (cfg_.output_path.empty()) {
      cfg_.output_path = defaultOutputPath();
    }
    if (cfg_.ring_bytes < (1u << 16)) {
      cfg_.ring_bytes = 64u * 1024u * 1024u;
    }
    if (cfg_.anchor_interval == 0) {
      cfg_.anchor_interval = kDefaultAnchorInterval;
    }

    /* Native auto-resolution: if the caller enabled C API interception but
     * did not supply any capi_funcs[] entries (e.g. a minimal JS loader),
     * fill the table ourselves using dlsym at configure time.  This makes
     * the tracer fully self-contained — the JS agent only needs to set the
     * trace range and output path; all common platform functions are
     * intercepted automatically without requiring the JS side to enumerate
     * and pass 100+ addresses. */
    if (cfg_.capi_intercept && cfg_.n_capi_funcs == 0) {
      resolveCApiAddrsIntoConfig(cfg_);
    }

    /* Build sorted C API lookup table from capi_funcs[].  Entries with
     * addr == 0 are skipped.  The table is sorted by address so that
     * lookupCApiFunc() can use binary search instead of linear scan. */
    cfg_.capi_lookup.clear();
    if (cfg_.capi_intercept && cfg_.n_capi_funcs > 0) {
      cfg_.capi_lookup.reserve(cfg_.n_capi_funcs);
      for (uint32_t i = 0; i < cfg_.n_capi_funcs; ++i) {
        if (cfg_.capi_funcs[i].addr != 0) {
          cfg_.capi_lookup.push_back({cfg_.capi_funcs[i].addr, i});
        }
      }
      std::sort(cfg_.capi_lookup.begin(), cfg_.capi_lookup.end(),
                [](const Config::CApiLookup &a, const Config::CApiLookup &b) {
                  return a.addr < b.addr;
                });
    }

    if (!writer_started_) {
      if (!writer_.start(cfg_.output_path.c_str(), cfg_.ring_bytes,
                         cfg_.compress)) {
        return false;
      }
      /* Hook up the live stats page so the background writer updates
       * bytes_written and elapsed_ns after each chunk flush. */
      writer_.setStatsCounter(
          reinterpret_cast<std::atomic<uint64_t> *>(
              reinterpret_cast<uint8_t *>(&g_stats_page) +
              offsetof(qbditrace_stats_t, bytes_written)),
          statsUpdateElapsed);
      writeFileHeader();
      writer_started_ = true;
    }
    configured_ = true;
    return true;
  }

  bool configured() const { return configured_; }
  const Config &cfg() const { return cfg_; }
  BackgroundWriter &writer() { return writer_; }

  /* Look up (or compute and cache) the GPRs written by the instruction at `pc`.
   * Computed once per PC via QBDI's operand analysis; later executions are a
   * pure hash lookup. Safe to call from the callback (VM running). */
  const WriteRegList *writeRegsFor(QBDI::VMInstanceRef vm, QBDI::rword pc) {
    {
      /* Hot path: most instructions hit the cache. shared_lock allows concurrent
       * readers without contention — eliminates ~20-40 ns mutex overhead/insn. */
      std::shared_lock<std::shared_mutex> lk(cache_mtx_);
      auto it = write_reg_cache_.find(pc);
      if (it != write_reg_cache_.end()) {
        return &it->second;
      }
    }
    /* Cold path: first time seeing this PC, compute and insert. */
    WriteRegList wl = computeWriteRegs(vm, pc);
    std::unique_lock<std::shared_mutex> lk(cache_mtx_);
    auto res = write_reg_cache_.emplace(pc, wl);
    return &res.first->second;
  }

  void stop() {
    std::lock_guard<std::mutex> lk(setup_mtx_);
    if (writer_started_) {
      flushAllThreads();
      writer_.stop();
      writer_started_ = false;
    }
    configured_ = false;
    /* Clear the write-reg cache so a re-configure with a different range does
     * not serve stale analysis results. */
    {
      std::unique_lock<std::shared_mutex> lk2(cache_mtx_);
      write_reg_cache_.clear();
    }
    /* Clear thread_buffers_ registry; thread-local pointers are cleaned up
     * separately by the caller (qbditrace_stop) after this returns. */
    {
      std::lock_guard<std::mutex> lk3(tb_mtx_);
      thread_buffers_.clear();
    }
  }

  void registerThreadBuffer(ThreadBuffer *tb) {
    std::lock_guard<std::mutex> lk(tb_mtx_);
    thread_buffers_.push_back(tb);
  }
  void unregisterThreadBuffer(ThreadBuffer *tb) {
    std::lock_guard<std::mutex> lk(tb_mtx_);
    for (auto &p : thread_buffers_) {
      if (p == tb) {
        p = thread_buffers_.back();
        thread_buffers_.pop_back();
        break;
      }
    }
  }

  std::string outputPath() {
    std::lock_guard<std::mutex> lk(setup_mtx_);
    if (cfg_.output_path.empty()) {
      cfg_.output_path = defaultOutputPath();
    }
    return cfg_.output_path;
  }

private:
  Tracer() = default;

  void flushAllThreads() {
    std::lock_guard<std::mutex> lk(tb_mtx_);
    for (ThreadBuffer *tb : thread_buffers_) {
      tb->flush();
    }
  }

  static std::string defaultOutputPath() {
    const char *env = getenv("QBDITRACE_OUT");
    if (env && *env) {
      return std::string(env);
    }
    const char *home = getenv("HOME");
    if (home && *home) {
      return std::string(home) + "/Documents/qbditrace.bin";
    }
#if defined(__ANDROID__)
    /* Android: HOME is often unset; /data/local/tmp is always writable for
     * shell/root and is the conventional staging directory for Frida payloads. */
    return "/data/local/tmp/qbditrace.bin";
#else
    return "/tmp/qbditrace.bin";
#endif
  }

  void writeFileHeader() {
    qbditrace_file_header_t h;
    std::memset(&h, 0, sizeof(h));
    h.magic = QBDITRACE_MAGIC;
    // Version selection: v7 > v6 > v5 > v4. Each bumps a version number so
    // older readers can gracefully reject traces they cannot parse correctly.
    if (cfg_.fpr_mode)
      h.version = QBDITRACE_VERSION_V7_HAS_FPR;
    else if (cfg_.pc_delta_mode)
      h.version = QBDITRACE_VERSION_V5_PC_DELTA;
    else
      h.version = QBDITRACE_VERSION;
#if defined(__x86_64__)
    h.arch = QBDITRACE_ARCH_X86_64;
    h.num_gpr = 18; /* x86_64 path is secondary; decoder reads num_gpr. */
#else
    h.arch = QBDITRACE_ARCH_AARCH64;
    h.num_gpr = QBDITRACE_AARCH64_NUM_GPR;
#endif
    h.module_base = cfg_.module_base;
    h.module_slide = cfg_.module_slide;
    h.trace_start = cfg_.trace_start;
    h.trace_end = cfg_.trace_end;
    h.flags = 0;
    if (cfg_.record & QBDITRACE_REC_MEM)
      h.flags |= QBDITRACE_HF_HAS_MEM;
    if (cfg_.record & QBDITRACE_REC_NZCV)
      h.flags |= QBDITRACE_HF_HAS_NZCV;
    if (cfg_.record & QBDITRACE_REC_REGDIFF)
      h.flags |= QBDITRACE_HF_REG_DIFF;
    if (cfg_.embed_code)
      h.flags |= QBDITRACE_HF_HAS_CODE;
    if (cfg_.pc_delta_mode)
      h.flags |= QBDITRACE_HF_PC_DELTA;
    if (cfg_.fpr_mode)
      h.flags |= QBDITRACE_HF_HAS_FPR;
    if (cfg_.compress && writer_.compressed())
      h.flags |= QBDITRACE_HF_BLOCK_COMPRESSED;
    if (cfg_.branch_hint_mode)
      h.flags |= QBDITRACE_HF_BRANCH_HINT;
    std::strncpy(h.module_name, cfg_.module_name.c_str(),
                 sizeof(h.module_name) - 1);
#if defined(__APPLE__)
    h.target_os = QBDITRACE_OS_IOS;
#elif defined(__ANDROID__)
    h.target_os = QBDITRACE_OS_ANDROID;
#elif defined(__linux__)
    h.target_os = QBDITRACE_OS_LINUX;
#else
    h.target_os = QBDITRACE_OS_UNKNOWN;
#endif
    writer_.writeHeaderRaw(&h, sizeof(h));
  }

  WriteRegList computeWriteRegs(QBDI::VMInstanceRef vm, QBDI::rword pc) {
    WriteRegList wl;
    const QBDI::InstAnalysis *a =
        reinterpret_cast<QBDI::VM *>(vm)->getCachedInstAnalysis(
            pc, QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_OPERANDS);
    if (a == nullptr) {
      return wl;
    }
    for (uint8_t i = 0; i < a->numOperands; ++i) {
      const QBDI::OperandAnalysis &op = a->operands[i];
      if ((op.regAccess & QBDI::REGISTER_WRITE) == 0) {
        continue;
      }
      if (op.type == QBDI::OPERAND_GPR) {
        if (op.regCtxIdx < 0 || op.regCtxIdx > 30) {
          continue; /* sp/nzcv/pc captured via anchors, not the diff list */
        }
        if (wl.count < 8) {
          bool dup = false;
          for (uint8_t k = 0; k < wl.count; ++k) {
            if (wl.idx[k] == static_cast<uint8_t>(op.regCtxIdx)) {
              dup = true;
              break;
            }
          }
          if (!dup) {
            wl.idx[wl.count++] = static_cast<uint8_t>(op.regCtxIdx);
          }
        }
      } else if (op.type == QBDI::OPERAND_FPR) {
        /* FPR: regCtxIdx encodes the QBDI FPR slot.  For AArch64 NEON, the
         * 128-bit lane index is regCtxIdx >> 1 (QBDI uses one slot per 64-bit
         * half).  We record the lane index (0..31 = v0..v31) by dividing by 2
         * and capping at 31. */
        if (op.regCtxIdx < 0) {
          continue;
        }
        uint8_t lane = static_cast<uint8_t>(op.regCtxIdx >> 1);
        if (lane > 31) {
          continue;
        }
        if (wl.fpr_count < 8) {
          bool dup = false;
          for (uint8_t k = 0; k < wl.fpr_count; ++k) {
            if (wl.fpr_idx[k] == lane) {
              dup = true;
              break;
            }
          }
          if (!dup) {
            wl.fpr_idx[wl.fpr_count++] = lane;
          }
        }
      }
    }
    return wl;
  }

  Config cfg_;
  std::mutex setup_mtx_;
  std::shared_mutex cache_mtx_;
  std::mutex tb_mtx_;
  BackgroundWriter writer_;
  bool writer_started_ = false;
  bool configured_ = false;
  std::unordered_map<uint64_t, WriteRegList> write_reg_cache_;
  std::vector<ThreadBuffer *> thread_buffers_;
};

/* ----------------------------------------------------------------------------
 * Per-thread tracing context (buffer + diff baseline + executed PC carry)
 * ------------------------------------------------------------------------- */

struct ThreadCtx {
  ThreadBuffer *buf = nullptr;
  const Config *cached_cfg = nullptr; /* cached pointer to Tracer::get().cfg();
                                       * avoids Meyers-singleton atomic guard
                                       * check on every instruction. Set once in
                                       * ensureThreadCtx and never changes (the
                                       * Config object lives inside Tracer which
                                       * is a process-lifetime singleton). */
  uint64_t inst_count = 0;
  uint64_t cur_pc = 0;       /* executed PC carried PREINST -> POSTINST */
  QBDI::FPRState *cur_fpr = nullptr; /* FPR pointer carried PREINST -> POSTINST */
  uint64_t prev_reg[31] = {0}; /* x0..lr snapshot for diffing */
  bool prev_valid = false;

  /* Stack-depth sentinel for run_call / run_at termination.
   *
   * Set to the SP value just before vm.run() begins.  When preInstCB detects
   * that the current SP has risen back to or above this value, the traced
   * function's stack frame has been fully unwound — i.e. the call has returned
   * (or escaped via tail-call / longjmp).  Returning VMAction::STOP at that
   * point cleanly terminates the VM, even if the normal stop-address mechanism
   * (PC == safeRet) failed to trigger (e.g. because of a tail-call chain that
   * never executes `ret` to the sentinel address).
   *
   * A value of 0 disables the check (e.g. if ensureThreadCtx created the
   * context but no run entry point has set the sentinel yet). */
  uint64_t initial_sp = 0;
  /* Instructions executed since the last full-register ANCHOR was written. Used
   * to emit periodic resync checkpoints instead of one anchor per sequence. */
  uint64_t since_anchor = 0;
  bool need_anchor = true; /* force an anchor before the first record */
  /* v5 PC-delta mode: the PC of the last INST record emitted by this thread.
   * Used to compute pc_delta = exec_pc - last_emitted_pc.
   * Reset to 0 after emitting an ANCHOR (which re-anchors the running PC). */
  uint64_t last_emitted_pc = 0;

  /* LDXR/STXR exclusive monitor protection.
   *
   * AArch64 LDXR (Load-Exclusive) / STXR (Store-Exclusive) pairs form the
   * hardware LL/SC mechanism underpinning all spinlocks, atomics, and OS
   * primitives. The ARM architecture guarantees that the exclusive reservation
   * is cleared by ANY memory access or exception between LDXR and STXR, which
   * causes STXR to fail (returns 1 in Ws) and forces a retry loop.
   *
   * QBDI's per-instruction callbacks ARE such interrupts: the POSTINST callback
   * runs as a function call between every executed instruction. For a
   * LDXR → <other insns> → STXR sequence, the callbacks in between break the
   * exclusive reservation, causing the STXR to always return 1 → infinite loop.
   *
   * Mitigation: we detect LDXR in preInstCB and set `ldxr_pending = true`.
   * In postInstCB, while ldxr_pending is set, we skip the anchor checkpoint
   * (the only operation that touches memory other than the ring buffer) and
   * emit a *minimal* record (header only, no full GPR snapshot). The ring
   * buffer write itself uses a lock-free append (no OS calls, no memory
   * barriers beyond what the buffer already provides) so it is safe.
   *
   * When STXR is detected (postInstCB sees the exclusive-store opcode),
   * ldxr_pending is cleared regardless of whether STXR succeeded or failed.
   * If STXR failed, the CPU will retry; if it succeeded, we resume normal
   * recording from the next instruction.
   *
   * Opcode detection is purely based on the raw 4 bytes at cur_pc (already
   * available in preInstCB). We only skip anchors, NOT the INST record itself —
   * the INST record's ring-buffer write is a simple mmap store and does not
   * disturb the exclusive monitor on ARM (no ldrex/strex instructions). */
  bool ldxr_pending = false;   // true between LDXR and its paired STXR
  uint64_t ldxr_pc = 0;        // PC of the pending LDXR (for diagnostics)

  /* Deferred CODE emission for instructions executed inside an LL/SC critical
   * section (between LDXR and STXR). While ldxr_pending is true we cannot call
   * emitCodeOnce (its safeRead/prepareRecord may take a syscall/mutex that
   * tears the ARM exclusive reservation), so the CODE records for those PCs
   * would be lost forever — the decoder then shows "<no code>" for the whole
   * LL/SC body. To fix this, preInstCB pushes (pc, opcode) pairs here (the
   * opcode was already read by pcRingPush, so no extra syscall), and when the
   * STXR closes the window we flush the queue with emitCodeWithBytes (safe:
   * the reservation is no longer live). Capped to bound memory on pathological
   * spinlocks; the cap is large enough for any real CAS loop. */
  struct PendingCode { uint64_t pc; uint32_t opcode; };
  std::vector<PendingCode> pending_code;
  static constexpr size_t kPendingCodeCap = 4096;

  /* Per-thread flat cache for WriteRegList (definition in FlatContainers.h). */
  FlatWriteRegCache wreg_cache;

  /* Pointer to the WriteRegList looked up in preInstCB and reused by postInstCB
   * for the same instruction.  Avoids a second cache lookup per instruction. */
  const WriteRegList *cur_wl = nullptr;

  /* Per-thread PC dedup set for CODE records (definition in FlatContainers.h). */
  FlatPcSet seen_code;

  ~ThreadCtx(); /* defined after flushPendingCode (uses it for LL/SC cleanup) */
};

thread_local ThreadCtx *g_tctx = nullptr;

uint64_t currentThreadId() {
#if defined(__APPLE__)
  uint64_t tid = 0;
  pthread_threadid_np(nullptr, &tid);
  return tid;
#elif defined(__linux__)
  return static_cast<uint64_t>(::syscall(__NR_gettid));
#else
  return 0;
#endif
}

ThreadCtx *ensureThreadCtx() {
  if (g_tctx) {
    return g_tctx;
  }
  Tracer &T = Tracer::get();
  ThreadCtx *c = new ThreadCtx();
  c->buf = new ThreadBuffer(&T.writer(), currentThreadId());
  c->cached_cfg = &T.cfg();
  T.registerThreadBuffer(c->buf);
  g_tctx = c;
  return c;
}

inline void emitThreadMarker(ThreadBuffer *buf) {
  uint8_t *p = buf->reserve(sizeof(qbditrace_thread_head_t));
  qbditrace_thread_head_t th;
  th.kind = QBDITRACE_REC_THREAD;
  th.reserved[0] = th.reserved[1] = th.reserved[2] = 0;
  th.thread_id = buf->threadId();
  std::memcpy(p, &th, sizeof(th));
  buf->markerEmitted();
}

/*
 * Ensure the upcoming record of `payload` bytes lands in the SAME chunk as its
 * THREAD marker (if one is needed). We pre-reserve room for marker+payload so a
 * chunk rotation cannot sneak in between the two writes and orphan the record
 * from its marker. After this call, a reserve(payload) is guaranteed not to
 * rotate. Returns after emitting the marker if it was needed.
 *
 * Steady-state fast path: needThreadMarker() is false except right after a
 * chunk rotation (roughly once per 64 MB of records), so we mark the marker
 * branch as [[unlikely]] and keep the common path to a single room check.
 */
inline void prepareRecord(ThreadBuffer *buf, size_t payload) {
  if (__builtin_expect(!buf->needThreadMarker(), 1)) {
    buf->ensureRoom(payload);
    return;
  }
  /* Slow path: marker needed — account for its size, ensure room for both,
   * then emit the marker before the caller writes its record. */
  buf->ensureRoom(payload + sizeof(qbditrace_thread_head_t));
  emitThreadMarker(buf);
}

inline void emitAnchor(ThreadBuffer *buf, QBDI::GPRState *gpr,
                       QBDI::FPRState *fpr, uint64_t pc,
                       bool fpr_mode) {
  statsIncAnchors();
  const uint32_t n = QBDITRACE_AARCH64_NUM_GPR;
  const size_t fpr_bytes = fpr_mode ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
  const size_t payload =
      sizeof(qbditrace_anchor_head_t) + (size_t)n * sizeof(uint64_t) + fpr_bytes;
  prepareRecord(buf, payload);
  uint8_t *p = buf->reserve(payload);
  qbditrace_anchor_head_t ah;
  ah.kind = QBDITRACE_REC_ANCHOR;
  ah.reserved[0] = ah.reserved[1] = ah.reserved[2] = 0;
  ah.pc = pc;
  std::memcpy(p, &ah, sizeof(ah));
  p += sizeof(ah);
  for (uint32_t i = 0; i < n; ++i) {
    uint64_t v = QBDI_GPR_GET(gpr, i);
    std::memcpy(p, &v, sizeof(v));
    p += sizeof(v);
  }
  if (fpr_mode && fpr != nullptr) {
    /* Append 32 × 128-bit FPR values: lo (bits 63:0) then hi (bits 127:64)
     * for v0..v31, stored as pairs of uint64_t. QBDI stores each 64-bit
     * half in a separate FPR slot: slot 2*i = v[i] lo, slot 2*i+1 = v[i] hi. */
    for (uint32_t i = 0; i < QBDITRACE_AARCH64_NUM_FPR; ++i) {
      uint64_t lo = QBDI_FPR_GET(fpr, 2 * i);
      uint64_t hi = QBDI_FPR_GET(fpr, 2 * i + 1);
      std::memcpy(p, &lo, sizeof(lo)); p += sizeof(lo);
      std::memcpy(p, &hi, sizeof(hi)); p += sizeof(hi);
    }
  }
}

/* Emit a REC_CODE carrying the raw bytes of the instruction at `pc`, the first
 * time this thread sees that PC. AArch64 instructions are a fixed 4 bytes; the
 * bytes are read straight from the (already de-trampolined) target memory with
 * the fault-tolerant safeRead so a guard page never crashes the tracer. */
inline void emitCodeOnce(ThreadCtx *c, uint64_t pc) {
if (pc == 0 || !c->seen_code.insert(pc)) {
return; /* already emitted (or invalid pc) */
}
uint8_t bytes[4];
if (!safeRead(pc, bytes, sizeof(bytes))) {
/* Could not read the instruction bytes (unmapped/guarded); leave it to the
* decoder's --image fallback. Keep it in seen_code so we don't retry. */
return;
}
const size_t payload = sizeof(qbditrace_code_head_t) + sizeof(bytes);
prepareRecord(c->buf, payload);
uint8_t *p = c->buf->reserve(payload);
qbditrace_code_head_t ch;
ch.kind = QBDITRACE_REC_CODE;
ch.size = (uint8_t)sizeof(bytes);
ch.reserved[0] = ch.reserved[1] = 0;
ch.pc = pc;
std::memcpy(p, &ch, sizeof(ch));
std::memcpy(p + sizeof(ch), bytes, sizeof(bytes));
statsIncCodeEntries();
}

/* Emit a REC_CODE using opcode bytes the caller already obtained (e.g. from
* pcRingPush's direct deref). Unlike emitCodeOnce this does NOT call safeRead,
* so it is safe to invoke right after an LL/SC window closes — we reuse the
* bytes captured earlier instead of issuing a vm_read_overwrite.
* Dedups via seen_code exactly like emitCodeOnce. */
inline void emitCodeWithBytes(ThreadCtx *c, uint64_t pc, uint32_t opcode) {
if (pc == 0 || opcode == 0 || !c->seen_code.insert(pc)) {
return; /* already emitted, or no usable bytes */
}
uint8_t bytes[4];
std::memcpy(bytes, &opcode, sizeof(bytes));
const size_t payload = sizeof(qbditrace_code_head_t) + sizeof(bytes);
prepareRecord(c->buf, payload);
uint8_t *p = c->buf->reserve(payload);
qbditrace_code_head_t ch;
ch.kind = QBDITRACE_REC_CODE;
ch.size = (uint8_t)sizeof(bytes);
ch.reserved[0] = ch.reserved[1] = 0;
ch.pc = pc;
std::memcpy(p, &ch, sizeof(ch));
std::memcpy(p + sizeof(ch), bytes, sizeof(bytes));
statsIncCodeEntries();
}

/* Flush deferred CODE records that were queued while inside an LL/SC critical
 * section. Called from preInstCB once the STXR closes the window (ldxr_pending
 * just cleared), so syscalls/mutexes are safe again. */
inline void flushPendingCode(ThreadCtx *c) {
if (c->pending_code.empty()) return;
for (const auto &e : c->pending_code) {
emitCodeWithBytes(c, e.pc, e.opcode);
}
c->pending_code.clear();
}

/* ThreadCtx destructor — defined here (after flushPendingCode) because it calls
 * flushPendingCode to drain any CODE records still deferred when the thread
 * exits mid-LL/SC. The buffer is still alive, so the flushed records land in
 * the final chunk that `delete buf` writes to disk. */
ThreadCtx::~ThreadCtx() {
if (!pending_code.empty()) {
flushPendingCode(this);
}
if (buf) {
Tracer::get().unregisterThreadBuffer(buf);
delete buf; /* destructor flushes the last chunk */
buf = nullptr;
}
}

/* ----------------------------------------------------------------------------
 * Crash-locating PC ring window (diagnostic)
 *
 * Background: with whole-module instrumentation the tracer runs far into the
 * target (Douyin L1 VMP interpreter + every main-binary sub-call). A fault
 * ("access violation accessing 0x2a") happens deep inside qbdt.runCall with no
 * QBDI ERROR in the log. To pinpoint *which* instruction faults without the IO
 * cost of full DEBUG tracing (~29M lines), we keep the last N executed PCs in a
 * fixed in-memory ring (written cheaply in PREINST, zero IO on the hot path),
 * and install a SIGSEGV/SIGBUS handler that, on a fault, dumps the window plus
 * the faulting PC/address to QBDI_LOG_FILE, then re-raises with the default
 * disposition so the process still crashes naturally (we never swallow it).
 *
 * Everything here is opt-in via QBDI_LOG_FILE being set; with no log file the
 * ring is still maintained (a few stores per insn) but never dumped.
 * ------------------------------------------------------------------------- */

constexpr size_t kPcRingSize = 2048; /* power of two; last 2048 executed PCs */
struct PcRingEntry {
  uint64_t pc;       /* address of the instruction about to execute */
  uint32_t opcode;   /* raw 4-byte AArch64 instruction word (0 if unreadable) */
};
PcRingEntry g_pc_ring[kPcRingSize];
std::atomic<uint64_t> g_pc_ring_pos{0}; /* monotonically increasing write index;
                                          * relaxed ordering suffices: only the
                                          * owning thread writes, readers (fault
                                          * handler / dump) tolerate stale values. */

inline void pcRingPush(uint64_t pc) {
  uint64_t pos = g_pc_ring_pos.load(std::memory_order_relaxed);
  uint64_t i = pos & (kPcRingSize - 1);
  g_pc_ring[i].pc = pc;
  /* Direct dereference: QBDI guarantees instrumented PCs are readable code
   * pages — no need for vm_read_overwrite syscall on the hot path. The old
   * safeRead() call here was the single largest per-instruction bottleneck
   * (~800-2000 ns Mach trap on every instruction for a diagnostic-only ring).
   * If the PC were somehow unreadable, QBDI itself would have already faulted
   * during disassembly/JIT, so this deref is safe for all instrumented code. */
  g_pc_ring[i].opcode = *reinterpret_cast<const uint32_t *>(pc);
  g_pc_ring_pos.store(pos + 1, std::memory_order_relaxed);
}

/* async-signal-safe-ish writer: only uses write(2) and integer formatting. */
void asWriteHex(int fd, uint64_t v) {
  char b[19];
  b[0] = '0';
  b[1] = 'x';
  for (int i = 0; i < 16; ++i) {
    unsigned nib = (unsigned)((v >> ((15 - i) * 4)) & 0xF);
    b[2 + i] = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
  }
  (void)::write(fd, b, sizeof(b));
}

struct sigaction g_old_segv;
struct sigaction g_old_bus;
volatile sig_atomic_t g_in_fault_handler = 0;

/* Write the PC ring window (oldest first) to fd. Async-signal-safe (write(2)
 * + integer formatting only). Shared by the SIGSEGV/SIGBUS handler and the
 * qbditrace_dump_pcring() export (called from the Frida side after Frida's own
 * exceptor intercepts the fault inside the NativeFunction trampoline, where our
 * signal handler never runs). */
void writePcRing(int fd) {
  static const char win[] = "\n--- last executed PCs (oldest first) ---\n";
  (void)::write(fd, win, sizeof(win) - 1);

  uint64_t total = g_pc_ring_pos.load(std::memory_order_relaxed);
  uint64_t count = total < kPcRingSize ? total : kPcRingSize;
  uint64_t start = total - count;
  for (uint64_t k = 0; k < count; ++k) {
    uint64_t idx = (start + k) & (kPcRingSize - 1);
    asWriteHex(fd, g_pc_ring[idx].pc);
    (void)::write(fd, "  ", 2);
    asWriteHex(fd, g_pc_ring[idx].opcode);
    (void)::write(fd, "\n", 1);
  }
}

void faultHandler(int sig, siginfo_t *info, void *ucv) {
  /* Guard against re-entrancy (a fault while dumping). */
  if (g_in_fault_handler) {
    _exit(139);
  }
  g_in_fault_handler = 1;

  const char *path = ::getenv("QBDI_LOG_FILE");
  int fd = -1;
  if (path && *path) {
    fd = ::open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  }
  if (fd < 0) {
    fd = 2; /* stderr fallback */
  }

  static const char hdr[] = "\n=== QBDITRACE FAULT ===\nsignal=";
  (void)::write(fd, hdr, sizeof(hdr) - 1);
  asWriteHex(fd, (uint64_t)sig);

  static const char fa[] = " fault_addr=";
  (void)::write(fd, fa, sizeof(fa) - 1);
  asWriteHex(fd, info ? (uint64_t)info->si_addr : 0);

  /* Faulting PC from the trampoline/JITed context if available. */
  uint64_t fault_pc = 0;
  if (ucv) {
    ucontext_t *uc = reinterpret_cast<ucontext_t *>(ucv);
#if defined(__APPLE__) && defined(__aarch64__)
    if (uc->uc_mcontext) {
      fault_pc = (uint64_t)uc->uc_mcontext->__ss.__pc;
    }
#elif defined(__linux__) && defined(__aarch64__)
    fault_pc = (uint64_t)uc->uc_mcontext.pc;
#endif
  }
  static const char pcl[] = " ctx_pc=";
  (void)::write(fd, pcl, sizeof(pcl) - 1);
  asWriteHex(fd, fault_pc);

  writePcRing(fd);

  static const char end[] = "=== END FAULT ===\n";
  (void)::write(fd, end, sizeof(end) - 1);
  if (fd != 2) {
    ::close(fd);
  }

  /* Restore default disposition and re-raise so the process crashes naturally
   * (do NOT swallow the fault). */
  struct sigaction *old = (sig == SIGBUS) ? &g_old_bus : &g_old_segv;
  ::sigaction(sig, old, nullptr);
  ::raise(sig);
  _exit(139);
}

bool g_fault_handler_installed = false;
void installFaultHandler() {
  if (g_fault_handler_installed) {
    return;
  }
  g_fault_handler_installed = true;
  struct sigaction sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = faultHandler;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  ::sigaction(SIGSEGV, &sa, &g_old_segv);
  ::sigaction(SIGBUS, &sa, &g_old_bus);
}

/* ----------------------------------------------------------------------------
 * AArch64 LDXR / STXR exclusive-monitor opcode classification
 *
 * ARM Architecture Reference Manual defines the Load-Exclusive and
 * Store-Exclusive instruction encodings in the A64 "LDXR / STLXR / LDXP /
 * STXP / ..." group. All share a common bit-field layout:
 *
 *   [31:30] size     (00=byte, 01=half, 10=word, 11=dword)
 *   [29:24] 001000   — fixed for the Load/Store-Exclusive class
 *   [23]    ordered  (1 = acquire/release variant)
 *   [22]    L        (1 = Load, 0 = Store)
 *   [21]    o0       (0 = single, 1 = pair)
 *   [20:16] Rs / o1
 *   [15]    o0
 *   [14:10] Rt2 / 0
 *   [9:5]   Rn
 *   [4:0]   Rt
 *
 * The bit pattern for the whole Load-Exclusive class (LDXR, LDAXR, LDXRB,
 * LDXRH, LDXP, LDAXP, …) is: bits[29:24] == 001000 AND L==1 (bit 22).
 * The Store-Exclusive class has the same [29:24]==001000 AND L==0 (bit 22).
 *
 * We use a simple bitmask check that covers the entire class (including
 * LDAXR / STLXR acquire-release variants) while avoiding false positives on
 * unrelated instructions.
 * ------------------------------------------------------------------------- */

/// Returns true for any Load-Exclusive instruction (LDXR, LDAXR, LDXRB,
/// LDXRH, LDXP, LDAXP, …). These set the hardware exclusive reservation.
///
/// IMPORTANT: bit[23] distinguishes the *exclusive* class (bit[23]=0) from the
/// *acquire/release* class (bit[23]=1, i.e. LDAR/STLR). LDAR/STLR do NOT touch
/// the exclusive reservation, so they must NOT be treated as LDXR/STXR.
/// A previous version used mask 0x3F400000 (bits[29:24]+bit[22]) which matched
/// LDAR as LDXR — the resulting ldxr_pending guard then suppressed CODE
/// emission for LDAR and every instruction until the next STXR-class opcode,
/// producing widespread "<no code>" gaps in the trace.
inline bool isLdxr(uint32_t opcode) {
/* bits[29:23] == 0010000 and bit[22] (L) == 1 */
return (opcode & 0x3FC00000u) == 0x08400000u;
}

/// Returns true for any Store-Exclusive instruction (STXR, STLXR, STXRB,
/// STXRH, STXP, STLXP, …). These consume the exclusive reservation.
inline bool isStxr(uint32_t opcode) {
/* bits[29:23] == 0010000 and bit[22] (L) == 0 */
return (opcode & 0x3FC00000u) == 0x08000000u;
}

/* ----------------------------------------------------------------------------
 * AArch64 branch-hint classification (for HF_BRANCH_HINT nzcv encoding)
 *
 * Returns the QBDITRACE_BRANCH_HINT_* value (0, 1, 2, or 4) for the given
 * AArch64 instruction opcode.  The result is placed in bits[7:4] of the
 * nzcv byte in every REC_INST record when HF_BRANCH_HINT is set.
 *
 * Encodings (AArch64 ARM DDI 0487):
 *   BL   imm26    — bits[31:26] == 100101 → 0x94000000 mask 0xFC000000
 *   BLR  Xn       — bits[31:10] == 1101011000111111000000 → 0xD63F0000 / 0xFFFFFC1F mask
 *   BLRAAZ/etc.   — pointer-auth variants share the same top bits
 *   RET  Xn       — bits[31:10] == 1101011001011111000000 → 0xD65F0000 / 0xFFFFFC1F
 *   RETAA/RETAB   — bits[31:0]  == 0xD65F0BFF / 0xD65F0FFF
 *   B    imm26    — bits[31:26] == 000101 → 0x14000000 mask 0xFC000000
 *   BR   Xn       — bits[31:10] == 1101011000011111000000 → 0xD61F0000 / 0xFFFFFC1F
 *
 * This function is called once per executed instruction inside postInstCB.
 * All checks are simple bitmask operations (one & + one ==) — sub-nanosecond.
 * -------------------------------------------------------------------------- */
inline uint8_t branchHintBits(uint32_t opcode) {
  /* BL imm26: bits[31:26] == 100101 */
  if ((opcode & 0xFC000000u) == 0x94000000u)
    return QBDITRACE_BRANCH_HINT_CALL;

  /* BLR Xn (and pointer-auth variants BLRAAZ, BLRAA, BLRABZ, BLRAB):
   * bits[31:10] == 1101011000111111000000
   * Covers opcode range 0xD63F0000 .. 0xD63F03FF */
  if ((opcode & 0xFFFFFC00u) == 0xD63F0000u)
    return QBDITRACE_BRANCH_HINT_CALL;

  /* BLRAAZ / BLRABZ (no-register pointer-auth BLR variants):
   * Opcode 0xD63F081F / 0xD63F0C1F — already covered by the mask above
   * (bits[31:10] check passes). No extra case needed. */

  /* RET Xn (default Xn=X30): bits[31:10] == 1101011001011111000000
   * Covers 0xD65F0000 .. 0xD65F03FF */
  if ((opcode & 0xFFFFFC00u) == 0xD65F0000u)
    return QBDITRACE_BRANCH_HINT_RET;

  /* B imm26: bits[31:26] == 000101 */
  if ((opcode & 0xFC000000u) == 0x14000000u)
    return QBDITRACE_BRANCH_HINT_BRANCH;

  /* BR Xn: bits[31:10] == 1101011000011111000000
   * Covers 0xD61F0000 .. 0xD61F03FF */
  if ((opcode & 0xFFFFFC00u) == 0xD61F0000u)
    return QBDITRACE_BRANCH_HINT_BRANCH;

  return QBDITRACE_BRANCH_HINT_NONE;
}

/* ----------------------------------------------------------------------------
 * Hot-path callbacks
 * ------------------------------------------------------------------------- */

QBDI::VMAction preInstCB(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr,
                         QBDI::FPRState *fpr, void * /*data*/) {
  (void)vm;
  ThreadCtx *c = ensureThreadCtx();
  const Config &cfg = *c->cached_cfg;

  /* ── Stack-depth sentinel ─────────────────────────────────────────────────
   * When initial_sp is armed, check whether the current SP has risen
   * **strictly above** the entry-frame value.  This means the traced
   * function's stack frame (and the simulateCallA shim frame beneath it)
   * has been fully unwound — the call is semantically finished.
   *
   * Why strictly-greater-than (>) instead of >=?
   *   At function entry the first instruction sees cur_sp == initial_sp
   *   (the prologue hasn't pushed anything yet).  Using >= would
   *   immediately STOP before a single instruction executes.  The normal
   *   return path (epilogue restores SP then executes `ret`) is already
   *   handled by QBDI's stop-address mechanism (PC == safeRet).  The
   *   sentinel only needs to catch abnormal exits:
   *
   *   • tail-call chains that jump to un-instrumented code without
   *     returning to the safeRet sentinel
   *   • longjmp / exception unwind past the traced frame
   *
   * In those cases SP rises *above* initial_sp (the shim frame is
   * popped), so `>` is the correct predicate.
   *
   * The check is essentially free: one register read + one comparison. */
  if (c->initial_sp != 0) {
    uint64_t cur_sp = QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_SP);
    if (cur_sp > c->initial_sp) {
      return QBDI::STOP;
    }
  }

  /* Store fpr pointer so postInstCB can use it without re-fetching. QBDI
   * guarantees the same FPRState pointer is valid through the POSTINST
   * callback for the same instruction. */
  c->cur_fpr = fpr;

  /* Diagnostic: record this PC + opcode in the crash-locating ring.
   * Now truly cheap: one direct 4-byte deref + two stores, no syscall. */
  pcRingPush(QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_PC));

  /* PC slot still points at the current (about to execute) instruction. */
  c->cur_pc = QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_PC);

  /* ── LDXR/STXR exclusive-monitor protection ──────────────────────────────
   * We need to classify the current instruction to manage the ldxr_pending
   * flag. Certain operations (mutex, syscall) will clear the ARM exclusive
   * reservation if called while it is live (after LDXR has executed).
   *
   * Strategy: both branches now use the opcode from the pc_ring entry written
   * by pcRingPush at the top of this callback (a plain memory dereference,
   * no syscall). This eliminates the previous safeRead (vm_read_overwrite)
   * that was the second-largest per-instruction bottleneck.
   *
   *   • When ldxr_pending is FALSE: read opcode from pc_ring, check for LDXR.
   *   • When ldxr_pending is TRUE: read opcode from pc_ring, watch for STXR.
   *
   * The dangerous calls that tear the exclusive reservation are:
   *   - emitAnchor  → prepareRecord → may trigger chunk write (mutex)
   *   - emitCodeWithBytes → calls prepareRecord (may trigger chunk write)
   * Both are still guarded by !c->ldxr_pending checks further below.
   *
   * For opcode-based STXR detection while pending, we use the opcode word
   * stored in the pc_ring by pcRingPush (which ran at the top of this
   * callback, before the reservation was live for THIS instruction).         */
  uint32_t cur_opcode = 0;
#if !defined(__x86_64__)
  if (!c->ldxr_pending) {
    /* Reuse the opcode already read by pcRingPush (direct deref, no syscall).
     * Previously this was a second safeRead(vm_read_overwrite) on the same PC,
     * wasting another ~800-2000 ns Mach trap per instruction.  The pcRing entry
     * for THIS instruction is at (g_pc_ring_pos - 1) since pcRingPush already
     * incremented the position counter above. */
    uint64_t ring_idx = (g_pc_ring_pos.load(std::memory_order_relaxed) - 1u) & (kPcRingSize - 1u);
    cur_opcode = g_pc_ring[ring_idx].opcode;
    if (isLdxr(cur_opcode)) {
      /* The LDXR is about to execute — emit its CODE record NOW, while the
       * reservation is still NOT live (so prepareRecord's potential mutex is
       * harmless). postInstCB would skip it because we set ldxr_pending next,
       * which previously left the entire LL/SC body without CODE records. */
      if (cfg.embed_code) {
        emitCodeWithBytes(c, c->cur_pc, cur_opcode);
      }
      /* Arm the guard for subsequent insns. */
      c->ldxr_pending = true;
      c->ldxr_pc = c->cur_pc;
    }
  } else {
    /* Inside exclusive window: read opcode from the pc_ring entry that
     * pcRingPush already wrote (g_pc_ring is a plain in-memory array, no
     * syscall). The ring index for THIS instruction is (g_pc_ring_pos - 1)
     * because pcRingPush incremented g_pc_ring_pos before we reach here. */
    uint64_t ring_idx = (g_pc_ring_pos.load(std::memory_order_relaxed) - 1u) & (kPcRingSize - 1u);
    cur_opcode = (uint32_t)g_pc_ring[ring_idx].opcode;
    if (isStxr(cur_opcode)) {
      /* STXR is about to execute — the critical section ends with this insn.
       * Clear the flag now so postInstCB and the NEXT preInstCB are free to
       * call safeRead / emit anchors again.                                  */
      c->ldxr_pending = false;
      /* Now that the reservation is no longer live, flush the CODE records
       * deferred for the LL/SC body (LDXR's own CODE was already emitted in
       * the !ldxr_pending branch above; this covers the middle instructions).
       * The STXR's own CODE is handled by postInstCB's emitCodeWithBytes
       * (which runs because ldxr_pending is now false).                     */
      if (cfg.embed_code) {
        flushPendingCode(c);
      }
    } else {
      /* Middle instruction inside the LL/SC body: we cannot emit its CODE
       * now (safeRead/prepareRecord would tear the reservation). Defer it —
       * pcRingPush already captured the opcode, so this is a plain memory
       * push with no syscall. Flushed when the STXR closes the window.     */
      if (cfg.embed_code &&
          c->pending_code.size() < ThreadCtx::kPendingCodeCap) {
        c->pending_code.push_back({c->cur_pc, cur_opcode});
      }
    }
  }
#endif

  /* Precision prev_reg snapshot: look up the WriteRegList for this PC and
   * only capture the 1-2 registers the instruction actually writes.  This
   * replaces the previous brute-force loop over all 31 GPRs.
   *
   * The lookup goes through FlatWriteRegCache (per-thread, lock-free); on a
   * miss it falls through to Tracer::writeRegsFor (global shared_mutex) and
   * then populates the per-thread cache.  After steady-state warm-up (a few
   * hundred distinct PCs), virtually every access is a single hash probe.
   *
   * cur_wl is stashed so postInstCB can reuse the same WriteRegList without a
   * second lookup.
   *
   * EXCEPTION: inside an LL/SC critical section (ldxr_pending), we must NOT
   * call Tracer::writeRegsFor (which takes a shared_mutex, a potential syscall
   * that clears the ARM exclusive reservation).  The per-thread cache lookup
   * is always safe (pure memory reads), but a cache miss while ldxr_pending
   * would need to call through to the global cache.  In that case we fall back
   * to a full 31-register snapshot so that no register change is ever lost. */
  if (cfg.record & QBDITRACE_REC_REGDIFF) {
    const WriteRegList *wl = c->wreg_cache.find(c->cur_pc);
    if (!wl) {
      if (!c->ldxr_pending) {
        /* Cache miss, safe to call global (outside LL/SC). */
        const WriteRegList *global_wl = Tracer::get().writeRegsFor(vm, c->cur_pc);
        if (global_wl) {
          c->wreg_cache.insert(c->cur_pc, *global_wl);
          wl = c->wreg_cache.find(c->cur_pc);
        }
      }
    }
    c->cur_wl = wl;
    if (wl && c->prev_valid) {
      /* Precise snapshot: only the GPRs that this instruction will write. */
      for (uint8_t k = 0; k < wl->count; ++k) {
        c->prev_reg[wl->idx[k]] = QBDI_GPR_GET(gpr, wl->idx[k]);
      }
    } else {
      /* First instruction or cache miss inside LL/SC: full snapshot. */
      for (int i = 0; i <= 30; ++i) {
        c->prev_reg[i] = QBDI_GPR_GET(gpr, i);
      }
    }
    c->prev_valid = true;
  }

  /* Periodic full-register ANCHOR (resync checkpoint). Diffs are absolute, so
   * anchors are NOT required at sequence boundaries for correctness; pacing
   * them by instruction count keeps the trace small. need_anchor forces one
   * before the very first record of the thread.
   *
   * EXCEPTION: while an exclusive reservation is live (ldxr_pending), skip the
   * anchor to avoid calling into the OS (mach_task_self / vm_read_overwrite /
   * mutex) inside the LL/SC critical section, which would break the hardware
   * reservation and cause the STXR to always fail (infinite retry loop). */
  if (!c->ldxr_pending &&
      (c->need_anchor || c->since_anchor >= cfg.anchor_interval)) {
    emitAnchor(c->buf, gpr, fpr, c->cur_pc, cfg.fpr_mode); /* handles marker/chunk atomicity */
    c->since_anchor = 0;
    c->need_anchor = false;
  }

  return QBDI::CONTINUE;
}

/* Serialize the regdiff + [fprdiff] + memacc payload that is common to both
 * v4 and v5 instruction records.  Returns the pointer past the last byte
 * written.  This avoids duplicating the loop + safeRead logic in two code
 * paths.
 *
 * v7 mode (fpr_mode): after the GPR diff section, emit n_fprdiff *
 * qbditrace_fprdiff_t records (24 bytes each).  fprbuf and fprbuf_n describe
 * which FPR indices changed; their 128-bit values are read from `fpr_state`.
 * `fpr_state`, `fprbuf`, and `fprbuf_n` may be null/0 in v4/v5/v6 mode. */
static inline uint8_t *serializeInstPayload(
    uint8_t *p,
    const qbditrace_regdiff_t *regbuf, uint8_t regbuf_n,
    const QBDI::MemoryAccess *macc, uint8_t n_mem,
    const QBDI::FPRState *fpr_state = nullptr,
    const uint8_t *fprbuf = nullptr, uint8_t fprbuf_n = 0) {
  for (uint8_t k = 0; k < regbuf_n; ++k) {
    std::memcpy(p, &regbuf[k], sizeof(qbditrace_regdiff_t));
    p += sizeof(qbditrace_regdiff_t);
  }

  /* FPR diffs (v7 only): emit 128-bit values for each written vector register. */
  if (fpr_state != nullptr && fprbuf != nullptr) {
    for (uint8_t k = 0; k < fprbuf_n; ++k) {
      qbditrace_fprdiff_t fd;
      fd.fpr_index = fprbuf[k];
      std::memset(fd.reserved, 0, sizeof(fd.reserved));
      /* QBDI stores each 64-bit half in a separate FPR slot:
       * slot 2*i = v[i] low 64 bits, slot 2*i+1 = v[i] high 64 bits. */
      fd.lo = QBDI_FPR_GET(fpr_state, 2 * fprbuf[k]);
      fd.hi = QBDI_FPR_GET(fpr_state, 2 * fprbuf[k] + 1);
      std::memcpy(p, &fd, sizeof(fd));
      p += sizeof(fd);
    }
  }

  for (uint8_t k = 0; k < n_mem; ++k) {
    const QBDI::MemoryAccess &m = macc[k];
    qbditrace_memacc_t mr;
    mr.mem_type  = (uint8_t)m.type;
    mr.mem_flags = (uint8_t)m.flags;
    mr.size      = m.size;
    mr.addr      = m.accessAddress;
    mr.value     = m.value;
    mr.value_hi  = 0;
    /* Recover value for both READ and WRITE when QBDI reports unknown. */
    if ((m.flags & QBDI::MEMORY_UNKNOWN_VALUE) &&
        m.size > 0 && m.size <= 16) {
      uint8_t bytes[16] = {0};
      if (safeRead(m.accessAddress, bytes, m.size)) {
        std::memcpy(&mr.value, bytes, 8);
        std::memcpy(&mr.value_hi, bytes + 8, 8);
        mr.mem_flags &= (uint8_t)(~(unsigned)QBDI::MEMORY_UNKNOWN_VALUE);
      }
    }
    std::memcpy(p, &mr, sizeof(mr));
    p += sizeof(mr);
  }
  return p;
}

QBDI::VMAction postInstCB(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr,
                          QBDI::FPRState *fpr, void * /*data*/) {
  ThreadCtx *c = g_tctx ? g_tctx : ensureThreadCtx();
  ThreadBuffer *buf = c->buf;
  const Config &cfg = *c->cached_cfg;
  const uint64_t exec_pc = c->cur_pc;
  /* Use the FPR pointer stashed in preInstCB (same instruction, same pointer). */
  if (fpr == nullptr) fpr = c->cur_fpr;

  /* Embed the raw instruction bytes once per distinct PC so the decoder can
   * disassemble without --image. Deduplicated, so this is free in loops. The
   * CODE record is independent of the INST record that follows (the decoder
   * keys it by PC), so ordering/chunk boundaries between them do not matter.
   *
   * We use emitCodeWithBytes with the opcode already captured by pcRingPush
   * (a direct 4-byte deref, no syscall).  The previous emitCodeOnce called
   * safeRead (mach_vm_read_overwrite), adding ~800-2000 ns per *first-time*
   * PC.  Since pcRingPush runs on every instruction anyway, reusing its
   * opcode is free.  The pc_ring entry for this instruction is at
   * (g_pc_ring_pos - 1) because pcRingPush already incremented the counter.
   *
   * Skip inside an LL/SC critical section: prepareRecord may take a mutex/
   * syscall that clears the ARM exclusive reservation.  The CODE record
   * for those PCs is deferred via pending_code and flushed when STXR closes
   * the window. */
  if (cfg.embed_code && !c->ldxr_pending) {
    uint64_t ring_idx = (g_pc_ring_pos.load(std::memory_order_relaxed) - 1u) & (kPcRingSize - 1u);
    emitCodeWithBytes(c, exec_pc, g_pc_ring[ring_idx].opcode);
  }

  /* --- register diff (absolute values; decoder rebuilds prev from anchors) --- */
  uint8_t regbuf_n = 0;
  qbditrace_regdiff_t regbuf[8];
  /* --- FPR diff (v7 only) --- */
  uint8_t fprbuf_n = 0;
  uint8_t fprbuf[8]; /* indices of FPRs that changed */
  if (cfg.record & QBDITRACE_REC_REGDIFF) {
    /* Reuse the WriteRegList looked up in preInstCB (stashed in cur_wl).
     * If preInstCB had a cache miss inside LL/SC (cur_wl is null), fall back
     * to the global lookup — we are now in postInstCB where ldxr_pending may
     * already be cleared (STXR just executed), so the mutex is safe. */
    const WriteRegList *wl = c->cur_wl;
    if (!wl) {
      wl = Tracer::get().writeRegsFor(vm, exec_pc);
      /* Populate the per-thread cache for future iterations. */
      if (wl) {
        c->wreg_cache.insert(exec_pc, *wl);
      }
    }
    if (wl && c->prev_valid) {
      for (uint8_t k = 0; k < wl->count; ++k) {
        uint8_t idx = wl->idx[k];
        uint64_t now = QBDI_GPR_GET(gpr, idx);
        if (now != c->prev_reg[idx]) {
          regbuf[regbuf_n].reg_index = idx;
          regbuf[regbuf_n].value = now;
          ++regbuf_n;
        }
      }
      /* FPR diffs: collect written vector registers when fpr_mode is on. */
      if (cfg.fpr_mode && fpr != nullptr) {
        for (uint8_t k = 0; k < wl->fpr_count && fprbuf_n < 8; ++k) {
          fprbuf[fprbuf_n++] = wl->fpr_idx[k];
        }
      }
    }
  }

  /* --- nzcv (bits 31..28 of the NZCV slot) --- */
  uint8_t nzcv = 0;
  if (cfg.record & QBDITRACE_REC_NZCV) {
    uint64_t flags = QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_NZCV);
    nzcv = (uint8_t)((flags >> 28) & 0xF);
  }

  /* --- branch-hint encoding (HF_BRANCH_HINT) ---
   * Encode the instruction's branch class in bits[7:4] of nzcv.
   * The opcode was already read by pcRingPush in preInstCB — reuse it here
   * (a plain array dereference, no syscall, zero hot-path overhead).
   * branchHintBits() consists solely of bitmask comparisons (sub-nanosecond).
   * We always compute the hint regardless of cfg.branch_hint_mode because the
   * opcode is already in cache from the CODE record path above. */
  if (cfg.branch_hint_mode) {
#if !defined(__x86_64__)
    uint64_t ring_idx = (g_pc_ring_pos.load(std::memory_order_relaxed) - 1u) & (kPcRingSize - 1u);
    uint32_t inst_opcode = g_pc_ring[ring_idx].opcode;
    nzcv |= (uint8_t)(branchHintBits(inst_opcode) << 4);
#endif
  }

  /* --- memory accesses ---
   * Reuse a thread-local vector so our side never reallocates: move-assigning
   * the result swaps buffers and keeps capacity across instructions. (QBDI
   * still builds one vector internally; eliminating that would require patching
   * QBDI core, which is out of scope here.) */
  static thread_local std::vector<QBDI::MemoryAccess> macc;
  macc.clear();
  if (cfg.record & QBDITRACE_REC_MEM) {
    macc = reinterpret_cast<QBDI::VM *>(vm)->getInstMemoryAccess();
  }
  /* One instruction never produces anywhere near 255 accesses (a load/store
   * pair is at most 2); the clamp is purely defensive against a corrupt count. */
  uint8_t n_mem = macc.size() > 255 ? 255 : (uint8_t)macc.size();

  /* --- assemble + emit one packed record ---
   * v4: qbditrace_inst_head_t (16 bytes) with absolute pc
   * v5: qbditrace_inst_head_v5_t (6 bytes) with int16 pc_delta
   *     If delta overflows int16, emit an ANCHOR first then use delta=0.
   */
  const size_t fpr_diff_bytes = (size_t)fprbuf_n * sizeof(qbditrace_fprdiff_t);
  const size_t payload_tail = (size_t)regbuf_n * sizeof(qbditrace_regdiff_t) +
                              fpr_diff_bytes +
                              (size_t)n_mem * sizeof(qbditrace_memacc_t);

  /* FPR state pointer for v7 serialization */
  const QBDI::FPRState *fpr_for_serial = (cfg.fpr_mode && fprbuf_n > 0) ? fpr : nullptr;

  if (cfg.pc_delta_mode) {
    // Compute delta from last emitted INST PC
    int64_t raw_delta = static_cast<int64_t>(exec_pc) -
                        static_cast<int64_t>(c->last_emitted_pc);
    // If this is the first record or delta overflows int16, force an ANCHOR.
    // The ANCHOR re-anchors the decoder's running PC, then delta=0.
    if (c->last_emitted_pc == 0 ||
        raw_delta < -32768 || raw_delta > 32767) {
      emitAnchor(c->buf, gpr, fpr, exec_pc, cfg.fpr_mode);
      c->since_anchor = 0;
      c->need_anchor = false;
      raw_delta = 0;
    }
    int16_t pc_delta = static_cast<int16_t>(raw_delta);

    if (cfg.fpr_mode) {
      /* v7 + v5: use qbditrace_inst_head_v7_v5_t (8 bytes) */
      size_t need = sizeof(qbditrace_inst_head_v7_v5_t) + payload_tail;
      prepareRecord(buf, need);
      uint8_t *p = buf->reserve(need);
      qbditrace_inst_head_v7_v5_t ih;
      ih.kind = QBDITRACE_REC_INST;
      ih.nzcv = nzcv;
      ih.n_regdiff = regbuf_n;
      ih.n_mem = n_mem;
      std::memcpy(&ih.pc_delta, &pc_delta, sizeof(pc_delta));
      ih.n_fprdiff = fprbuf_n;
      ih.reserved_v7 = 0;
      std::memcpy(p, &ih, sizeof(ih));
      p += sizeof(ih);
      serializeInstPayload(p, regbuf, regbuf_n, macc.data(), n_mem,
                           fpr_for_serial, fprbuf, fprbuf_n);
    } else {
      size_t need = sizeof(qbditrace_inst_head_v5_t) + payload_tail;
      prepareRecord(buf, need);
      uint8_t *p = buf->reserve(need);
      qbditrace_inst_head_v5_t ih5;
      ih5.kind = QBDITRACE_REC_INST;
      ih5.nzcv = nzcv;
      ih5.n_regdiff = regbuf_n;
      ih5.n_mem = n_mem;
      std::memcpy(&ih5.pc_delta, &pc_delta, sizeof(pc_delta));
      std::memcpy(p, &ih5, sizeof(ih5));
      p += sizeof(ih5);
      serializeInstPayload(p, regbuf, regbuf_n, macc.data(), n_mem);
    }

    c->last_emitted_pc = exec_pc;
    statsIncInstructions();
    if (n_mem) statsAddMemAccesses(n_mem);
    ++c->inst_count;
    ++c->since_anchor;
    return QBDI::CONTINUE;
  }

  if (cfg.fpr_mode) {
    /* v7 path: use qbditrace_inst_head_v7_t (24 bytes) */
    size_t need = sizeof(qbditrace_inst_head_v7_t) + payload_tail;
    prepareRecord(buf, need);
    uint8_t *p = buf->reserve(need);
    qbditrace_inst_head_v7_t ih7;
    ih7.kind = QBDITRACE_REC_INST;
    ih7.nzcv = nzcv;
    ih7.n_regdiff = regbuf_n;
    ih7.n_mem = n_mem;
    ih7.pc = exec_pc;
    ih7.n_fprdiff = fprbuf_n;
    std::memset(ih7.reserved_v7, 0, sizeof(ih7.reserved_v7));
    std::memcpy(p, &ih7, sizeof(ih7));
    p += sizeof(ih7);
    serializeInstPayload(p, regbuf, regbuf_n, macc.data(), n_mem,
                         fpr_for_serial, fprbuf, fprbuf_n);
    statsIncInstructions();
    if (n_mem) statsAddMemAccesses(n_mem);
    ++c->inst_count;
    ++c->since_anchor;
    return QBDI::CONTINUE;
  }

  // v4 path: absolute PC
  size_t need = sizeof(qbditrace_inst_head_t) + payload_tail;
  /* Keep this record and its THREAD marker (if any) in the same chunk. */
  prepareRecord(buf, need);
  uint8_t *p = buf->reserve(need);

  qbditrace_inst_head_t ih;
  ih.kind = QBDITRACE_REC_INST;
  ih.nzcv = nzcv;
  ih.n_regdiff = regbuf_n;
  ih.n_mem = n_mem;
  ih.pc = exec_pc;
  std::memcpy(p, &ih, sizeof(ih));
  p += sizeof(ih);

  serializeInstPayload(p, regbuf, regbuf_n, macc.data(), n_mem);

  statsIncInstructions();
  if (n_mem) statsAddMemAccesses(n_mem);
  ++c->inst_count;
  ++c->since_anchor;
  return QBDI::CONTINUE;
}

/* PREINST callback bound to the SVC mnemonic. On Darwin arm64 the syscall
 * selector is in x16; on Linux/Android arm64 the syscall number is in x8.
 * Arguments are x0..x5 on both platforms. We snapshot them before the trap
 * executes so the decoder can name the syscall and show its arguments. */
QBDI::VMAction svcCB(QBDI::VMInstanceRef /*vm*/, QBDI::GPRState *gpr,
                     QBDI::FPRState * /*fpr*/, void * /*data*/) {
  ThreadCtx *c = ensureThreadCtx();
  ThreadBuffer *buf = c->buf;

  qbditrace_svc_head_t sh;
  sh.kind = QBDITRACE_REC_SVC;
  sh.reserved[0] = sh.reserved[1] = sh.reserved[2] = 0;
  sh.pc = QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_PC);
#if defined(__APPLE__)
  sh.syscall_no = QBDI_GPR_GET(gpr, 16); /* x16 = Darwin syscall selector */
#elif defined(__linux__)
  sh.syscall_no = QBDI_GPR_GET(gpr, 8);  /* x8 = Linux syscall number */
#else
  sh.syscall_no = QBDI_GPR_GET(gpr, 16);
#endif
  /* Classify the syscall for fast routing in the decoder (e.g. detect
   * Mach traps, binder ioctls, memory/file/network categories). */
  sh.reserved[0] = classifySyscall(sh.syscall_no);
  for (int i = 0; i < 6; ++i) {
    sh.args[i] = QBDI_GPR_GET(gpr, i); /* x0..x5 */
  }
  prepareRecord(buf, sizeof(sh));
  uint8_t *p = buf->reserve(sizeof(sh));
  std::memcpy(p, &sh, sizeof(sh));
  statsIncSvc();
  return QBDI::CONTINUE;
}

QBDI::VMAction vmEventCB(QBDI::VMInstanceRef vm, const QBDI::VMState *st,
                         QBDI::GPRState *gpr, QBDI::FPRState * /*fpr*/,
                         void * /*data*/) {
  (void)vm;
  ThreadCtx *c = ensureThreadCtx();
  ThreadBuffer *buf = c->buf;
  const Config &cfg = *c->cached_cfg;

  auto emitEvent = [&](uint8_t ev, uint64_t addr, uint64_t site) {
    prepareRecord(buf, sizeof(qbditrace_event_head_t));
    uint8_t *p = buf->reserve(sizeof(qbditrace_event_head_t));
    qbditrace_event_head_t eh;
    eh.kind = QBDITRACE_REC_EVENT;
    eh.event = ev;
    eh.reserved[0] = eh.reserved[1] = 0;
    eh.addr = addr;
    eh.site = site;
    std::memcpy(p, &eh, sizeof(eh));
    statsIncEvents();
  };

  /* Emit an OBJC dispatch record (receiver + selector) captured at the call
   * site, before the dispatcher runs. */
  auto emitObjc = [&](int variant, uint64_t site) {
    qbditrace_objc_head_t oh;
    std::memset(&oh, 0, sizeof(oh));
    oh.kind = QBDITRACE_REC_OBJC;
    oh.variant = (uint8_t)variant;
    oh.pc = site;
    /* For the *_stret variant x0 is the hidden struct-return pointer, so the
     * receiver is in x1 and the selector in x2; otherwise x0/x1. */
    if (variant == QBDITRACE_OBJC_MSGSEND_STRET) {
      oh.recv = QBDI_GPR_GET(gpr, 1);
      oh.sel = QBDI_GPR_GET(gpr, 2);
    } else {
      oh.recv = QBDI_GPR_GET(gpr, 0);
      oh.sel = QBDI_GPR_GET(gpr, 1);
    }
    /* Resolve the receiver's class name *live* (it cannot be recovered from the
     * static image). object_getClassName handles tagged pointers and the arm64e
     * isa packing safely. For the *Super variants the "receiver" is an
     * objc_super struct pointer, not an object, so we skip class resolution. */
    if (object_getClassName != nullptr && oh.recv != 0 &&
        variant != QBDITRACE_OBJC_MSGSEND_SUPER &&
        variant != QBDITRACE_OBJC_MSGSEND_SUPER2 &&
        looksLikeObjcObject(oh.recv)) {
      const char *cn = object_getClassName(reinterpret_cast<id>(oh.recv));
      if (cn != nullptr) {
        std::strncpy(oh.cls, cn, sizeof(oh.cls) - 1);
      }
    }
    prepareRecord(buf, sizeof(oh));
    uint8_t *p = buf->reserve(sizeof(oh));
    std::memcpy(p, &oh, sizeof(oh));
    statsIncObjc();
  };

  /* NOTE: register diffs store ABSOLUTE post-values, so the diff chain does not
   * break across sequence/transfer boundaries and these events no longer need
   * to emit a full anchor. Anchors are paced purely by instruction count (see
   * preInstCB). We request a fresh anchor after a control-flow transfer so a
   * reader that seeks into the trace has a nearby checkpoint, but we do not
   * force one on ordinary sequence entries (those are extremely frequent). */
  /* SEQ_ENTRY/SEQ_EXIT fire roughly once per taken branch (twice per loop
   * iteration for a tight back-edge), making them the highest-volume event
   * type in hot-loop-heavy traces. No analysis pass depends on their
   * semantic content (basic blocks/loops are reconstructed from the plain
   * REC_INST PC stream instead — see tenet's cfg_pass), and they do not
   * drive ANCHOR placement (that's XFER_CALL/RETURN + anchor_interval only,
   * unconditionally below). Gate them behind QBDITRACE_REC_SEQEVENTS so
   * sampling-mode traces (record = QBDITRACE_REC_SAMPLING) can skip this
   * bulk of bookkeeping entirely. */
  if (cfg.record & QBDITRACE_REC_SEQEVENTS) {
    if (st->event & QBDI::SEQUENCE_ENTRY) {
      emitEvent(QBDITRACE_EV_SEQ_ENTRY, st->sequenceStart, 0);
    }
    if (st->event & QBDI::SEQUENCE_EXIT) {
      emitEvent(QBDITRACE_EV_SEQ_EXIT, st->sequenceEnd, 0);
    }
  }
  if (st->event & QBDI::EXEC_TRANSFER_CALL) {
    /* basicBlockStart is the transfer destination (the call target);
     * c->cur_pc is the PC of the instruction that performed the transfer
     * (the call site inside the traced range). */
    const uint64_t target = st->basicBlockStart;
    const uint64_t site = c->cur_pc;
    if (cfg.record & QBDITRACE_REC_MSGSEND) {
      int variant = classifyObjcTarget(cfg, target);
      if (variant >= 0) {
        emitObjc(variant, site);
      }
    }
    /* C API interception: if enabled and the target matches a known library
     * function, emit a REC_CAPICALL record with the function identity,
     * argument registers, and optional string/buffer captures from pointer
     * arguments. */
    if (cfg.capi_intercept && (cfg.record & QBDITRACE_REC_CAPI)) {
      const Config::CApiFunc *cf = lookupCApiFunc(cfg, target);
      if (cf != nullptr) {
        /* --- Emit fixed header --- */
        qbditrace_capicall_head_t ch;
        std::memset(&ch, 0, sizeof(ch));
        ch.kind      = QBDITRACE_REC_CAPICALL;
        /* FIXME(api_id-width): cf->api_id is uint16_t (holds ids up to ~726,
         * see QBDITrace.h), but qbditrace_capicall_head_t::api_id on disk is
         * uint8_t (TraceFormat.h) — this narrows and silently truncates any
         * id >= 256 (all Android/BoringSSL + most JNI-extended ids). Needs a
         * trace format bump to fix properly (tracer + trace_decode + tenet
         * must agree); not fixed yet, tracked via the FIXME in
         * TraceFormat.h next to qbditrace_capicall_head_t. */
        ch.api_id    = static_cast<uint8_t>(cf->api_id);
        ch.arg_count = cf->n_args;
        ch.pc        = site;
        ch.target    = target;
        /* Capture argument registers x0..x7. */
        for (uint8_t i = 0; i < cf->n_args && i < 8; ++i) {
          ch.args[i] = QBDI_GPR_GET(gpr, i);
        }

        /* --- Build variable-length string captures --- */
        /* We collect up to QBDITRACE_CAPICALL_MAX_STR_CAPS string captures
         * from pointer arguments indicated by the str_args bitmask.
         * Each capture consists of a qbditrace_capicall_str_t header +
         * NUL-terminated content padded to 4-byte alignment. */
        uint8_t str_count = 0;
        /* Stack-allocated scratch for one string capture at a time (max 256B
         * payload + 1 NUL + 3 pad = 260). */
        char str_buf[QBDITRACE_CAPICALL_MAX_STR_BYTES + 4];
        /* We need to compute the total variable-length size for prepareRecord,
         * so we do a two-pass approach: first pass computes sizes, second pass
         * writes. To avoid two safeRead calls per string, we cache the results
         * of the first pass into small on-stack descriptors. */
        struct StrDesc {
          uint8_t arg_idx;  /* which arg this string came from */
          uint8_t str_len;  /* byte length of content (no NUL) */
          uint8_t str_flags;
          uint8_t _pad;
          uint16_t total_bytes; /* total bytes for this capture (header + data + pad) */
        } descs[QBDITRACE_CAPICALL_MAX_STR_CAPS];
        uint16_t var_total = 0; /* total variable-length bytes */

        for (uint8_t i = 0; i < 8 && str_count < QBDITRACE_CAPICALL_MAX_STR_CAPS; ++i) {
          if (!(cf->str_args & (1u << i))) continue;
          uint64_t ptr_val = ch.args[i];
          if (ptr_val == 0) continue;

          StrDesc &d = descs[str_count];
          d.arg_idx  = i;
          d.str_len  = 0;
          d.str_flags = 0;
          d._pad     = 0;

          /* safeRead up to MAX_STR_BYTES + 1 (so we can detect truncation). */
          bool ok = safeRead(ptr_val, str_buf, QBDITRACE_CAPICALL_MAX_STR_BYTES + 1);
          if (!ok) {
            /* If we can't read even one byte, try a smaller probe. */
            ok = safeRead(ptr_val, str_buf, 1);
            if (!ok) {
              d.str_flags = QBDITRACE_SF_SAFE_READ_FAIL;
              d.str_len   = 0;
            }
          }
          if (ok) {
            /* Find the string length by scanning for NUL up to MAX_STR_BYTES.
             * If no NUL within MAX_STR_BYTES, mark as truncated. For binary
             * buffers (mem*), the caller can set str_args on the size arg too,
             * but we capture at most MAX_STR_BYTES of the pointed-to data. */
            uint16_t slen = 0;
            bool found_nul = false;
            for (; slen < QBDITRACE_CAPICALL_MAX_STR_BYTES; ++slen) {
              if (str_buf[slen] == '\0') { found_nul = true; break; }
            }
            if (!found_nul) {
              /* No NUL terminator within MAX_STR_BYTES — truncate. */
              d.str_flags |= QBDITRACE_SF_TRUNCATED;
              d.str_len = QBDITRACE_CAPICALL_MAX_STR_BYTES;
              /* Check if the content looks like binary data. */
              bool has_binary = false;
              for (uint16_t j = 0; j < d.str_len; ++j) {
                unsigned char c = static_cast<unsigned char>(str_buf[j]);
                if (c < 0x09 || (c > 0x0d && c < 0x20)) { has_binary = true; break; }
              }
              if (has_binary) d.str_flags |= QBDITRACE_SF_BINARY;
            } else {
              d.str_len = slen;
              /* Check for binary content in the valid portion. */
              bool has_binary = false;
              for (uint16_t j = 0; j < d.str_len; ++j) {
                unsigned char c = static_cast<unsigned char>(str_buf[j]);
                if (c < 0x09 || (c > 0x0d && c < 0x20)) { has_binary = true; break; }
              }
              if (has_binary) d.str_flags |= QBDITRACE_SF_BINARY;
            }
          }
          /* Compute total bytes for this capture:
           *   qbditrace_capicall_str_t (4B) + str_len + 1(NUL) + pad to 4B */
          uint16_t data_bytes = d.str_len + 1; /* content + NUL */
          uint16_t padded = (data_bytes + 3u) & ~3u; /* 4-byte aligned */
          d.total_bytes = sizeof(qbditrace_capicall_str_t) + padded;
          var_total += d.total_bytes;
          str_count++;
        }

        ch.str_count = str_count;
        const uint16_t rec_total = sizeof(ch) + var_total;
        prepareRecord(buf, rec_total);
        uint8_t *p = buf->reserve(rec_total);
        /* Write fixed header. */
        std::memcpy(p, &ch, sizeof(ch));
        p += sizeof(ch);
        /* Write string captures. */
        for (uint8_t si = 0; si < str_count; ++si) {
          const StrDesc &d = descs[si];
          /* Re-read the string data for this arg. We could cache the data from
           * the first pass, but that would require 4 × 256B of stack. Instead,
           * for low str_count (typically 1-2) the overhead of a second safeRead
           * is negligible compared to the cost of the transfer itself. */
          qbditrace_capicall_str_t sh;
          sh.str_arg_idx = d.arg_idx;
          sh.str_len     = d.str_len;
          sh.str_flags   = d.str_flags;
          sh._reserved   = 0;
          std::memcpy(p, &sh, sizeof(sh));
          p += sizeof(sh);

          if (d.str_len > 0 && !(d.str_flags & QBDITRACE_SF_SAFE_READ_FAIL)) {
            char tmp[QBDITRACE_CAPICALL_MAX_STR_BYTES + 1];
            bool rd = safeRead(ch.args[d.arg_idx], tmp, d.str_len);
            if (rd) {
              std::memcpy(p, tmp, d.str_len);
              p += d.str_len;
            }
            /* NUL terminator. */
            *p++ = '\0';
            /* Padding to 4-byte alignment. */
            uint16_t data_bytes = d.str_len + 1;
            uint16_t padded = (data_bytes + 3u) & ~3u;
            uint16_t pad_bytes = padded - data_bytes;
            for (uint16_t j = 0; j < pad_bytes; ++j) {
              *p++ = '\0';
            }
          } else {
            /* Empty capture: just NUL + 3 bytes padding (4 total). */
            *p++ = '\0';
            *p++ = '\0'; *p++ = '\0'; *p++ = '\0';
          }
        }
        statsIncCapi();
      }
    }
    emitEvent(QBDITRACE_EV_XFER_CALL, target, site);
    c->need_anchor = true; /* checkpoint after returning into the range */
  }
  if (st->event & QBDI::EXEC_TRANSFER_RETURN) {
    emitEvent(QBDITRACE_EV_XFER_RETURN, st->basicBlockStart, 0);
    c->need_anchor = true;
  }

  /* BASIC_BLOCK_NEW fires the very first time QBDI instruments a basic block.
   * At this precise moment the code pages are guaranteed readable (QBDI just
   * read them for JIT patching), so we batch-emit CODE records for every
   * instruction in the BB. This solves the execute-only page problem: by the
   * time postInstCB's emitCodeOnce runs, the page permissions may have been
   * restored to --x, making safeRead (vm_read_overwrite) fail.
   *
   * We iterate [basicBlockStart, basicBlockEnd) in 4-byte steps (AArch64 fixed
   * width) and use a direct pointer dereference — not safeRead — because we
   * know the page is currently mapped RX (QBDI holds it that way during
   * instrumentation). The seen_code dedup inside emitCodeWithBytes ensures no
   * duplicates if emitCodeOnce also succeeds later. */
  if (st->event & QBDI::BASIC_BLOCK_NEW) {
    const uint64_t bbStart = st->basicBlockStart;
    const uint64_t bbEnd = st->basicBlockEnd;
    if (bbStart != 0 && bbEnd > bbStart) {
      if (cfg.embed_code) {
        for (uint64_t pc = bbStart; pc < bbEnd; pc += 4) {
          uint32_t opcode = *reinterpret_cast<const uint32_t *>(pc);
          emitCodeWithBytes(c, pc, opcode);
        }
      }
    }
  }

  return QBDI::CONTINUE;
}

/* ----------------------------------------------------------------------------
 * Per-thread VM setup + run
 * ------------------------------------------------------------------------- */

/* Configure a fresh VM with the instrumented ranges, recorders and callbacks
 * shared by every run entry point. Returns false if the tracer is not yet
 * configured. */
static bool setupVM(QBDI::VM &vm) {
  Tracer &T = Tracer::get();
  if (!T.configured()) {
    return false;
  }
  const Config &cfg = T.cfg();

  /* Diagnostic: install a SIGSEGV/SIGBUS handler that dumps the PC ring window
   * (last executed instructions) to QBDI_LOG_FILE on a fault, then re-raises so
   * the process still crashes naturally. Lets us pinpoint the faulting PC for
   * the "access violation accessing 0x2a" without full DEBUG-log IO cost. */
  installFaultHandler();

  /* Trace semantics: start at the entry function and follow its full
   * execution — including every sub-call that lands *inside the main binary* —
   * until it returns, while letting all system-library code run natively
   * (ExecBroker transfers, untraced).
   *
   * Previously we instrumented only a fixed [trace_start, trace_start+0x400)
   * window. That window is too small: real entry functions (e.g. the Douyin
   * signing block invoke) are larger than 0x400 and tail-call sibling helpers
   * a few bytes past the right (open) edge of the window. Once PC leaves the
   * window, isInstrumented() returns false; if ExecBroker also can't find a
   * valid return point (helper hasn't spilled LR to the stack yet), QBDI falls
   * back to *instrumenting* that out-of-range code — and snowballs straight
   * into libsystem's LSE atomic locks, deadlocking the process.
   *
   * Fix: instrument the *entire executable segment of the module that owns the
   * entry address*. This covers the whole entry function and any in-module
   * sub-call, so PC never leaves the instrumented set while still inside the
   * main binary; calls into system libraries naturally fall outside the
   * module's ranges and are transferred natively as intended.
   *
   * If for any reason the module can't be resolved (no maps / unnamed region),
   * fall back to the original fixed window so behaviour degrades gracefully. */
  if (!vm.addInstrumentedModuleFromAddr(cfg.trace_start)) {
    vm.addInstrumentedRange(cfg.trace_start, cfg.trace_end);
  }
  if (cfg.extra_range_end > cfg.extra_range_start) {
    vm.addInstrumentedRange(cfg.extra_range_start, cfg.extra_range_end);
  }

  /* Remove excluded ranges from the instrumented set. Code in these regions
   * will execute natively at full speed without producing trace records.
   * The QBDI VM automatically writes an ANCHOR when execution re-enters the
   * instrumented range, so the decoder can reconstruct register state. */
  for (uint32_t i = 0; i < cfg.n_exclude_ranges; ++i) {
    if (cfg.exclude_ranges[i].end > cfg.exclude_ranges[i].start) {
      vm.removeInstrumentedRange(cfg.exclude_ranges[i].start,
                                 cfg.exclude_ranges[i].end);
    }
  }

  /* Register the memory-access recorder before callbacks that read it. */
  if (cfg.record & QBDITRACE_REC_MEM) {
    vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
  }

  /* Hot-path callbacks. Priority kept at/below PRIORITY_MEMACCESS_LIMIT so
   * getInstMemoryAccess() is valid inside the POSTINST callback. */
  vm.addCodeCB(QBDI::PREINST, preInstCB, nullptr, QBDI::PRIORITY_DEFAULT);
  vm.addCodeCB(QBDI::POSTINST, postInstCB, nullptr, QBDI::PRIORITY_DEFAULT);
  vm.addVMEventCB(QBDI::SEQUENCE_ENTRY | QBDI::SEQUENCE_EXIT |
                      QBDI::EXEC_TRANSFER_CALL | QBDI::EXEC_TRANSFER_RETURN |
                      QBDI::BASIC_BLOCK_NEW,
                  vmEventCB, nullptr);

  /* Trap supervisor calls (syscalls). The mnemonic callback fires only on `svc`
   * so it adds no cost to ordinary instructions. */
#if !defined(__x86_64__)
  if (cfg.record & QBDITRACE_REC_SYSCALL) {
    vm.addMnemonicCB("SVC", QBDI::PREINST, svcCB, nullptr, QBDI::PRIORITY_DEFAULT);
  }
#endif
  return true;
}

/* Provide a *real, readable* fake return address for the top-level QBDI call.
 *
 * Why this exists: QBDI::VM::callA() hard-codes its fake return address to
 * FAKE_RET_ADDR == 42 (0x2a). It pushes 42 as LR/x30 and runs the target with
 * 42 as the VM-exit sentinel. That is fine for plain functions, but breaks any
 * function whose ARC return path tail-calls objc_autoreleaseReturnValue (the
 * RVO / "return-value optimization" runtime helper). That helper *dereferences
 * its caller's return address* (LR) to look for the `mov x29, x29` ARC elision
 * marker that decides the fast vs. slow autorelease path. With LR == 42 the
 * helper reads address 0x2a and the process faults with
 * "access violation accessing 0x2a" — which is exactly the crash we hit at the
 * very end of the Douyin sign block invoke (sub_8DBA0E0 ends with
 * `B objc_autoreleaseReturnValue`), *after* the signature has already been
 * computed.
 *
 * Fix: instead of vm.callA() we drive the call ourselves with a return address
 * that points at a page we own. The page is mapped readable+executable and its
 * first word holds a single AArch64 `ret` instruction. Effects:
 *   - It is readable, so objc_autoreleaseReturnValue's marker probe does not
 *     fault; it reads the `ret` encoding (not a `mov x29,x29` marker) and takes
 *     the normal slow path.
 *   - It is a valid VM-exit sentinel for vm.run(function, retAddr): when the
 *     traced code returns to it, QBDI stops the VM. The `ret` is never actually
 *     executed, but having a legal RX page makes the address robust even if the
 *     helper inspects a few instructions around it.
 * Allocated once per process and cached. */
QBDI::rword getSafeReturnAddress() {
  static QBDI::rword cached = 0;
  static std::once_flag once;
  std::call_once(once, [] {
    long pgsz = ::sysconf(_SC_PAGESIZE);
    size_t sz = (pgsz > 0) ? (size_t)pgsz : 0x4000;
    /* MAP_ANON/MAP_ANONYMOUS may be hidden by the strict _XOPEN_SOURCE mode set
     * at the top of this file; fall back to the Darwin value (0x1000). */
#ifndef MAP_ANON
#define MAP_ANON 0x1000
#endif
    void *p = ::mmap(nullptr, sz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) {
      cached = 0;
      return;
    }
    /* AArch64 `ret` (returns to x30): encoding 0xD65F03C0. */
    *reinterpret_cast<uint32_t *>(p) = 0xD65F03C0u;
    /* Make it executable so the address is a fully legal code pointer. If
     * mprotect fails we still keep it readable, which is enough to avoid the
     * ARC marker-probe fault. */
    ::mprotect(p, sz, PROT_READ | PROT_EXEC);
    cached = reinterpret_cast<QBDI::rword>(p);
  });
  return cached;
}

bool runWithVM(uint64_t *ret_out, uint64_t function, uint32_t argc,
               const uint64_t *argv) {
  /* On arm64e (A12+ real devices) the kernel/userland uses pointer
   * authentication: indirect branches/calls are emitted as braa/brab/blraa/
   * blrab and returns as retaa/retab. QBDI must strip/bypass the PAC before it
   * re-derives the target, otherwise the very first authenticated indirect
   * branch (e.g. an objc_msgSend tail `braa x17` or a PAC'd `br x16`) faults.
   * OPT_BYPASS_PAUTH makes QBDI ignore the authentication so the trace can
   * follow the real control flow. Harmless on non-PAC arm64. */
#if !defined(__x86_64__)
  QBDI::Options opts = QBDI::OPT_BYPASS_PAUTH;
  QBDI::VM vm("", {}, opts);
#else
  QBDI::VM vm;
#endif

  if (!setupVM(vm)) {
    return false;
  }

  /* Build a virtual stack for the QBDI run and seed the GPRState with the
   * forwarded arguments. */
  QBDI::GPRState *state = vm.getGPRState();
  uint8_t *fakestack = nullptr;
  QBDI::allocateVirtualStack(state, 0x800000, &fakestack);

  std::vector<QBDI::rword> args;
  args.reserve(argc);
  for (uint32_t i = 0; i < argc; ++i) {
    args.push_back((QBDI::rword)argv[i]);
  }

  /* Drive the top-level call manually instead of vm.callA().
   *
   * vm.callA() would push FAKE_RET_ADDR == 42 (0x2a) as LR and run with 42 as
   * the VM-exit sentinel. The Douyin sign block invoke (sub_8DBA0E0) ends with
   * an ARC tail-call `B objc_autoreleaseReturnValue`, and that helper
   * dereferences the caller's return address (LR) to probe for the ARC elision
   * marker — dereferencing 0x2a faults ("access violation accessing 0x2a")
   * right after the signature is already computed. We replace 42 with a real,
   * readable RX page (a single `ret`) so the probe reads valid memory and takes
   * the normal slow path. The sequence below mirrors VM::callA() exactly except
   * for the return address. */
  QBDI::rword safeRet = getSafeReturnAddress();
  if (safeRet == 0) {
    /* Mapping failed; fall back to the original behaviour rather than aborting
     * the whole trace. */
    QBDI::rword ret = 0;
    bool okFb = vm.callA(&ret, (QBDI::rword)function, argc,
                         reinterpret_cast<const QBDI::rword *>(args.data()));
    if (ret_out) {
      *ret_out = (uint64_t)ret;
    }
    if (g_tctx && g_tctx->buf) {
      g_tctx->buf->flush();
    }
    if (fakestack) {
      QBDI::alignedFree(fakestack);
    }
    return okFb;
  }

  /* Push arguments + safeRet (as LR) into the current GPRState, then run the
   * target until control returns to safeRet (the VM-exit sentinel). */
  QBDI::simulateCallA(state, safeRet, argc,
                      reinterpret_cast<const QBDI::rword *>(args.data()));

  /* Arm the stack-depth sentinel so preInstCB can detect when the traced call
   * has returned (SP restored to or above entry-frame value).  The SP after
   * simulateCallA is the callee's entry SP — the function's prologue will push
   * SP lower, and its epilogue will restore it.  When SP >= this value again
   * the call is semantically over. */
  ThreadCtx *tc = ensureThreadCtx();
  tc->initial_sp = QBDI_GPR_GET(state, QBDITRACE_AARCH64_IDX_SP);

  bool ok = vm.run((QBDI::rword)function, safeRet);

  /* Disarm the sentinel so it does not interfere with a subsequent run. */
  tc->initial_sp = 0;

  QBDI::rword ret = QBDI_GPR_GET(vm.getGPRState(), QBDI::REG_RETURN);
  if (ret_out) {
    *ret_out = (uint64_t)ret;
  }

  /* Flush this thread's buffer so the trace is complete even if the thread
   * keeps running afterwards. */
  if (g_tctx && g_tctx->buf) {
    g_tctx->buf->flush();
  }

  if (fakestack) {
    QBDI::alignedFree(fakestack);
  }
  return ok;
}

/* In-place trace: replay a real call using the *captured* register state.
 *
 * Unlike runWithVM (which calls a function in isolation with synthetic
 * arguments on a fresh fake stack), this seeds the VM's GPRState from the live
 * registers captured at the hook entry — including the real SP and all of
 * x0..x28/fp — and runs from `start_pc` until control returns to the captured
 * link register. This is required for non-reentrant thin wrappers (e.g. the
 * Douyin L1-VM sign dispatcher sub_8DB023C) whose behaviour depends on the
 * caller's stack frame and globals already prepared at the real call site.
 *
 * We do NOT allocate a fake stack: the captured SP already points at a valid,
 * live stack with the caller's frame. The stop PC is the real return address
 * (LR) — when the traced code executes its final `ret`, QBDI stops there. */
#if !defined(__x86_64__)
bool runWithVMState(uint64_t *ret_out, uint64_t start_pc,
                    const uint64_t gpr[31], uint64_t sp, uint64_t lr) {
  /* Same options as runWithVM: bypass PAC. See runWithVM. */
  QBDI::Options opts = QBDI::OPT_BYPASS_PAUTH;
  QBDI::VM vm("", {}, opts);

  if (!setupVM(vm)) {
    return false;
  }

  QBDI::GPRState *state = vm.getGPRState();
  /* gpr[0..28] -> x0..x28 (contiguous in GPRState), then fp/lr/sp set
   * explicitly. The captured register array is x0..x28 (29 entries) plus the
   * frame pointer x29 at index 29 and lr at 30. */
  QBDI::rword *dst = reinterpret_cast<QBDI::rword *>(state); // x0 is first field
  for (int i = 0; i < 29; ++i) {
    dst[i] = (QBDI::rword)gpr[i];
  }
  state->x29 = (QBDI::rword)gpr[29]; // frame pointer
  state->lr = (QBDI::rword)lr;       // captured return address (stop target)
  state->sp = (QBDI::rword)sp;       // live caller stack
  state->pc = (QBDI::rword)start_pc;

  /* Arm the stack-depth sentinel: the captured SP is the callee's entry SP.
   * Same logic as runWithVM — see the comment there. */
  ThreadCtx *tc = ensureThreadCtx();
  tc->initial_sp = sp;

  /* Run from the function entry until it returns to the real caller (lr). */
  bool ok = vm.run((QBDI::rword)start_pc, (QBDI::rword)lr);

  /* Disarm the sentinel. */
  tc->initial_sp = 0;

  if (ret_out) {
    QBDI::GPRState *after = vm.getGPRState();
    *ret_out = (uint64_t)after->x0;
  }

  if (g_tctx && g_tctx->buf) {
    g_tctx->buf->flush();
  }
  return ok;
}
#endif

} // namespace

/* ----------------------------------------------------------------------------
 * Public C ABI
 * ------------------------------------------------------------------------- */

extern "C" int qbditrace_configure(const qbditrace_config_t *in) {
  if (!in || in->trace_end <= in->trace_start) {
    return -1;
  }
  /* ABI forward-compatibility: if struct_size is 0 (legacy caller that doesn't
   * know about the field) we accept the whole struct as-is. If struct_size is
   * set but smaller than the current sizeof, fields beyond that offset are
   * treated as zero (the caller zero-initialized everything). If struct_size is
   * larger than ours (future caller, library is older), we only read what we
   * understand. Either way, all new fields are appended at the end and default
   * to 0, so this is safe. */
  (void)in->struct_size; /* acknowledged; no action needed for current fields */
  Config cfg;
  cfg.trace_start = in->trace_start;
  cfg.trace_end = in->trace_end;
  cfg.module_base = in->module_base;
  cfg.module_slide = in->module_slide;
  cfg.module_name = in->module_name ? in->module_name : "";
  cfg.output_path = in->output_path ? in->output_path : "";
  cfg.record = in->record ? in->record : QBDITRACE_REC_DEFAULT;
  cfg.anchor_interval = in->anchor_interval;
  cfg.ring_bytes = in->ring_bytes ? (size_t)in->ring_bytes
                                  : (size_t)(64u * 1024u * 1024u);
  cfg.objc_msgSend = in->objc_msgSend;
  cfg.objc_msgSendSuper = in->objc_msgSendSuper;
  cfg.objc_msgSendSuper2 = in->objc_msgSendSuper2;
  cfg.objc_msgSend_stret = in->objc_msgSend_stret;
  cfg.extra_range_start = in->extra_range_start;
  cfg.extra_range_end = in->extra_range_end;
  cfg.n_exclude_ranges = in->n_exclude_ranges;
  if (cfg.n_exclude_ranges > QBDITRACE_MAX_EXCLUDE_RANGES)
    cfg.n_exclude_ranges = QBDITRACE_MAX_EXCLUDE_RANGES;
  for (uint32_t i = 0; i < cfg.n_exclude_ranges; ++i) {
    cfg.exclude_ranges[i].start = in->exclude_ranges[i].start;
    cfg.exclude_ranges[i].end = in->exclude_ranges[i].end;
  }
  /* Inverted ABI sense: 0 (the zero-initialized default) keeps embedding on. */
  cfg.embed_code = (in->disable_embed_code == 0);
  /* v5 PC-delta mode: non-zero enables it (normal positive sense). */
  cfg.pc_delta_mode = (in->enable_pc_delta != 0);
  /* [REMOVED] old_value_mode no longer exists; _reserved_old_value is ignored. */
  /* v7 FPR mode: non-zero enables NEON/vector register diff recording. */
  cfg.fpr_mode = (in->enable_fpr != 0);
  /* Compression: inverted ABI sense (0 = compressed, the default). */
  cfg.compress = (in->disable_compress == 0);
  /* Branch-hint: inverted ABI sense (0 = enabled, the default). */
  cfg.branch_hint_mode = (in->disable_branch_hint == 0);
  /* C API interception. */
  cfg.capi_intercept = (in->enable_capi_intercept != 0);
  cfg.n_capi_funcs = in->n_capi_funcs;
  if (cfg.n_capi_funcs > Config::kMaxCapiFuncs) {
    cfg.n_capi_funcs = Config::kMaxCapiFuncs;
  }
  for (uint32_t i = 0; i < cfg.n_capi_funcs; ++i) {
    cfg.capi_funcs[i].addr     = in->capi_funcs[i].addr;
    cfg.capi_funcs[i].api_id   = in->capi_funcs[i].api_id;
    cfg.capi_funcs[i].n_args   = in->capi_funcs[i].n_args;
    cfg.capi_funcs[i].str_args = in->capi_funcs[i].str_args;
  }
  return Tracer::get().configure(cfg) ? 0 : -2;
}

extern "C" int qbditrace_run_call(uint64_t *ret_out, uint64_t function,
                                  uint32_t argc, const uint64_t *argv) {
  if (argc > 8) {
    return -1;
  }
  return runWithVM(ret_out, function, argc, argv) ? 0 : -3;
}

extern "C" int qbditrace_run_at(uint64_t *ret_out, uint64_t start_pc,
                                const uint64_t *gpr, uint64_t sp, uint64_t lr) {
#if !defined(__x86_64__)
  if (!gpr || !start_pc || !lr) {
    return -1;
  }
  return runWithVMState(ret_out, start_pc, gpr, sp, lr) ? 0 : -3;
#else
  (void)ret_out; (void)start_pc; (void)gpr; (void)sp; (void)lr;
  return -1;
#endif
}

extern "C" void qbditrace_stop(void) {
  Tracer::get().stop();
  /* Clean up thread-local state so a subsequent configure+run cycle starts
   * fresh with a new ThreadBuffer pointing at the new writer. Tracer::stop()
   * already called flushAllThreads() which submitted all pending data. We
   * null out buf to prevent ~ThreadCtx from calling flush/submit on the
   * stopped writer, then delete the ThreadCtx. ThreadBuffer itself is
   * intentionally leaked (trivial amount; its destructor would try to submit
   * to a closed writer). */
  if (g_tctx) {
    g_tctx->buf = nullptr; /* prevent ~ThreadCtx from flushing */
    delete g_tctx;
    g_tctx = nullptr;
  }
}

extern "C" const char *qbditrace_output_path(void) {
  static std::string cached;
  cached = Tracer::get().outputPath();
  return cached.c_str();
}

/* qbditrace_force_anchor: insert a full-register ANCHOR at the current
 * execution point. Useful from Frida scripts to checkpoint exact state before
 * a critical function call or after an interesting event.
 *
 * Implementation: we cannot directly call emitAnchor from outside QBDI's
 * callback (we don't hold a GPRState pointer), so we set the need_anchor flag
 * on the calling thread's ThreadCtx. The *next* preInstCB will pick this up
 * and emit the full ANCHOR before the next instruction record.
 *
 * This is sufficient for the "checkpoint before I call X" pattern: the Frida
 * hook calls qbditrace_force_anchor() before the traced execution continues,
 * and the anchor lands as the very first record of the next instruction. */
extern "C" int qbditrace_force_anchor(void) {
  if (!Tracer::get().configured()) {
    return -1;
  }
  ThreadCtx *c = g_tctx; /* may be null if not yet traced on this thread */
  if (c) {
    c->need_anchor = true;
  }
  /* Even if c is null (no thread ctx yet), the flag will be set when the
   * thread context is created in the next ensureThreadCtx() call, because
   * ThreadCtx initializes need_anchor = true by default. Return 0 regardless. */
  return 0;
}

/* Diagnostic: dump the crash-locating PC ring window to `path` (appended), or
 * to stderr when path is null/empty. Intended to be called from the Frida side
 * inside the driveActiveOnce() catch block: Frida's own exceptor intercepts the
 * fault inside the qbditrace_run_call NativeFunction trampoline before our
 * SIGSEGV handler can run, so we read the still-intact in-memory ring afterward
 * to recover the last executed PCs leading up to the "0x2a" access violation.
 * Returns the number of PC entries written. */
extern "C" int qbditrace_dump_pcring(const char *path) {
  int fd = -1;
  if (path && *path) {
    fd = ::open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  }
  if (fd < 0) {
    fd = 2;
  }
  static const char hdr[] = "\n=== QBDITRACE PCRING (post-fault) ===\n";
  (void)::write(fd, hdr, sizeof(hdr) - 1);
  writePcRing(fd);
  static const char end[] = "=== END PCRING ===\n";
  (void)::write(fd, end, sizeof(end) - 1);
  if (fd != 2) {
    ::close(fd);
  }
  uint64_t total = g_pc_ring_pos.load(std::memory_order_relaxed);
  return (int)(total < kPcRingSize ? total : kPcRingSize);
}

extern "C" const qbditrace_stats_t *qbditrace_stats_page(void) {
  statsUpdateElapsed();
  return &g_stats_page;
}
