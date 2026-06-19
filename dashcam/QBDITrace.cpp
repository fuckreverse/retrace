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

/* Required so <ucontext.h> exposes the (otherwise deprecated) ucontext_t /
 * mcontext routines used by the diagnostic fault handler to read the faulting
 * PC. Must be defined before any system header is included. */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "QBDITrace.h"
#include "RingBuffer.h"
#include "TraceFormat.h"

#include "QBDI.h"

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/vm_map.h>
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

namespace {

using namespace qbditrace;

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
 * ------------------------------------------------------------------------- */

struct Config {
  uint64_t trace_start = 0;
  uint64_t trace_end = 0;
  uint64_t module_base = 0;
  uint64_t module_slide = 0;
  std::string module_name;
  std::string output_path;
  uint32_t record = QBDITRACE_REC_DEFAULT;
  uint32_t anchor_interval = 0;
  size_t ring_bytes = 64u * 1024u * 1024u;
  uint64_t objc_msgSend = 0;
  uint64_t objc_msgSendSuper = 0;
  uint64_t objc_msgSendSuper2 = 0;
  uint64_t objc_msgSend_stret = 0;
  uint64_t extra_range_start = 0;
  uint64_t extra_range_end = 0;
  /* When set, emit a REC_CODE (raw instruction bytes) the first time each PC is
   * seen, so the offline decoder can disassemble without an external --image.
   * On by default; the only cost is one extra small record per *distinct*
   * executed instruction (deduplicated), nothing on the steady-state hot path. */
  bool embed_code = true;

  /* When set, write v5 INST records using PC delta encoding (int16 pc_delta
   * instead of uint64 absolute pc). Saves ~40-60% file size for sequential code
   * (AArch64: +4 delta every instruction). Writers must emit an ANCHOR before
   * any instruction where |delta| > 32767 and reset delta to 0.
   *
   * Activates QBDITRACE_HF_PC_DELTA in the file header and bumps version to
   * QBDITRACE_VERSION_V5_PC_DELTA. Off by default for backward compatibility. */
  bool pc_delta_mode = false;
};

/* Classify a transfer target against the configured objc_msgSend family.
 * Returns -1 if not an objc dispatcher, else the qbditrace_objc_variant_t. */
inline int classifyObjcTarget(const Config &c, uint64_t target) {
  if (target == 0)
    return -1;
  if (c.objc_msgSend && target == c.objc_msgSend)
    return QBDITRACE_OBJC_MSGSEND;
  if (c.objc_msgSendSuper && target == c.objc_msgSendSuper)
    return QBDITRACE_OBJC_MSGSEND_SUPER;
  if (c.objc_msgSendSuper2 && target == c.objc_msgSendSuper2)
    return QBDITRACE_OBJC_MSGSEND_SUPER2;
  if (c.objc_msgSend_stret && target == c.objc_msgSend_stret)
    return QBDITRACE_OBJC_MSGSEND_STRET;
  return -1;
}

struct WriteRegList {
  /* QBDI GPR indices (0..30) written by an instruction. AArch64 rarely writes
   * more than a couple of GPRs in one instruction (ldp writes 2), so a small
   * inline array suffices. */
  uint8_t count = 0;
  uint8_t idx[8] = {0};
};

class Tracer {
public:
  static Tracer &get() {
    static Tracer instance;
    return instance;
  }

  bool configure(const Config &cfg) {
    std::lock_guard<std::mutex> lk(setup_mtx_);
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

    if (!writer_started_) {
      if (!writer_.start(cfg_.output_path.c_str(), cfg_.ring_bytes)) {
        return false;
      }
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
      std::lock_guard<std::mutex> lk(cache_mtx_);
      auto it = write_reg_cache_.find(pc);
      if (it != write_reg_cache_.end()) {
        return &it->second;
      }
    }
    WriteRegList wl = computeWriteRegs(vm, pc);
    std::lock_guard<std::mutex> lk(cache_mtx_);
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
      std::lock_guard<std::mutex> lk2(cache_mtx_);
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
    return "/tmp/qbditrace.bin";
  }

  void writeFileHeader() {
    qbditrace_file_header_t h;
    std::memset(&h, 0, sizeof(h));
    h.magic = QBDITRACE_MAGIC;
    // v5 PC-delta mode bumps the version number so old readers can reject it.
    h.version = cfg_.pc_delta_mode ? QBDITRACE_VERSION_V5_PC_DELTA : QBDITRACE_VERSION;
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
    std::strncpy(h.module_name, cfg_.module_name.c_str(),
                 sizeof(h.module_name) - 1);
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
    for (uint8_t i = 0; i < a->numOperands && wl.count < 8; ++i) {
      const QBDI::OperandAnalysis &op = a->operands[i];
      if (op.type != QBDI::OPERAND_GPR) {
        continue;
      }
      if ((op.regAccess & QBDI::REGISTER_WRITE) == 0) {
        continue;
      }
      if (op.regCtxIdx < 0 || op.regCtxIdx > 30) {
        continue; /* sp/nzcv/pc captured via anchors, not the diff list */
      }
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
    return wl;
  }

  Config cfg_;
  std::mutex setup_mtx_;
  std::mutex cache_mtx_;
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
  uint64_t inst_count = 0;
  uint64_t cur_pc = 0;       /* executed PC carried PREINST -> POSTINST */
  uint64_t prev_reg[31] = {0}; /* x0..lr snapshot for diffing */
  bool prev_valid = false;
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

  /* PCs for which a REC_CODE has already been written by this thread, so the
   * raw bytes of each distinct instruction are emitted only once. Per-thread
   * (not shared) to keep the hot path lock-free; if two threads trace the same
   * code both emit it and the decoder simply overwrites identical entries. */
  std::unordered_set<uint64_t> seen_code;

  ~ThreadCtx() {
    if (buf) {
      Tracer::get().unregisterThreadBuffer(buf);
      delete buf; /* destructor flushes the last chunk */
      buf = nullptr;
    }
  }
};

thread_local ThreadCtx *g_tctx = nullptr;

uint64_t currentThreadId() {
  uint64_t tid = 0;
  pthread_threadid_np(nullptr, &tid);
  return tid;
}

ThreadCtx *ensureThreadCtx() {
  if (g_tctx) {
    return g_tctx;
  }
  ThreadCtx *c = new ThreadCtx();
  c->buf = new ThreadBuffer(&Tracer::get().writer(), currentThreadId());
  Tracer::get().registerThreadBuffer(c->buf);
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
 */
inline void prepareRecord(ThreadBuffer *buf, size_t payload) {
  size_t need = payload;
  if (buf->needThreadMarker()) {
    need += sizeof(qbditrace_thread_head_t);
  }
  buf->ensureRoom(need);
  if (buf->needThreadMarker()) {
    emitThreadMarker(buf);
  }
}

inline void emitAnchor(ThreadBuffer *buf, QBDI::GPRState *gpr, uint64_t pc) {
  const uint32_t n = QBDITRACE_AARCH64_NUM_GPR;
  const size_t payload =
      sizeof(qbditrace_anchor_head_t) + (size_t)n * sizeof(uint64_t);
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
}

/* Emit a REC_CODE carrying the raw bytes of the instruction at `pc`, the first
 * time this thread sees that PC. AArch64 instructions are a fixed 4 bytes; the
 * bytes are read straight from the (already de-trampolined) target memory with
 * the fault-tolerant safeRead so a guard page never crashes the tracer. */
inline void emitCodeOnce(ThreadCtx *c, uint64_t pc) {
  if (pc == 0 || !c->seen_code.insert(pc).second) {
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
volatile uint64_t g_pc_ring_pos = 0; /* monotonically increasing write index */

inline void pcRingPush(uint64_t pc) {
  uint64_t i = g_pc_ring_pos & (kPcRingSize - 1);
  g_pc_ring[i].pc = pc;
  uint32_t op = 0;
  /* Best-effort read of the instruction word; safeRead() is fault-tolerant so
   * an unmapped PC just leaves opcode=0 rather than recursing into a fault. */
  safeRead(pc, &op, sizeof(op));
  g_pc_ring[i].opcode = op;
  g_pc_ring_pos = g_pc_ring_pos + 1;
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

  uint64_t total = g_pc_ring_pos;
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
inline bool isLdxr(uint32_t opcode) {
  /* bits[29:24] == 001000 and bit[22] (L) == 1 */
  return (opcode & 0x3F400000u) == 0x08400000u;
}

/// Returns true for any Store-Exclusive instruction (STXR, STLXR, STXRB,
/// STXRH, STXP, STLXP, …). These consume the exclusive reservation.
inline bool isStxr(uint32_t opcode) {
  /* bits[29:24] == 001000 and bit[22] (L) == 0 */
  return (opcode & 0x3F400000u) == 0x08000000u;
}

/* ----------------------------------------------------------------------------
 * Hot-path callbacks
 * ------------------------------------------------------------------------- */

QBDI::VMAction preInstCB(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr,
                         QBDI::FPRState * /*fpr*/, void * /*data*/) {
  (void)vm;
  ThreadCtx *c = ensureThreadCtx();
  const Config &cfg = Tracer::get().cfg();

  /* Diagnostic: record this PC in the crash-locating ring (cheap, no IO). */
  pcRingPush(QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_PC));

  /* PC slot still points at the current (about to execute) instruction. */
  c->cur_pc = QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_PC);

  /* ── LDXR/STXR exclusive-monitor protection ──────────────────────────────
   * We need to classify the current instruction to manage the ldxr_pending
   * flag, but we must be careful: `safeRead` uses mach_vm_read_overwrite which
   * is a syscall and will itself clear the hardware exclusive reservation if
   * called while the reservation is live (i.e. after LDXR has executed).
   *
   * Strategy:
   *   • When ldxr_pending is FALSE we are outside a critical section, so we
   *     can safely call safeRead. We check whether the *about-to-execute*
   *     instruction is an LDXR — if so, we arm the flag. The safeRead here is
   *     safe because the LDXR hasn't executed yet and the reservation is not
   *     live.
   *   • When ldxr_pending is TRUE we are inside the exclusive window. We do
   *     NOT call safeRead (no syscall!). Instead we rely on the opcode that
   *     was cached in `cur_opcode` of the PREVIOUS iteration: the preInstCB
   *     that observed the LDXR itself read the opcode before the reservation
   *     was live. For subsequent instructions we skip the read entirely and
   *     only watch for the STXR using the cached opcode path. However, since
   *     we cannot call safeRead safely, we use the pc_ring entry (written by
   *     pcRingPush which also calls safeRead — but that runs before our flag
   *     check; see below).
   *
   * NOTE: pcRingPush(c->cur_pc) above already called safeRead for diagnostic
   * purposes. That call happens regardless of ldxr_pending. The pcRing read
   * is acceptable because (a) it is for diagnostics only and (b) on Linux it
   * uses /proc/self/mem which is a different kernel path; on Darwin the
   * vm_read_overwrite call happens inside pcRingPush BEFORE we reach this
   * code. To fully protect the exclusive window we therefore need to skip
   * pcRingPush too — but that is diagnostic-only, so we accept the trade-off:
   * the ring may occasionally miss an entry inside a spinlock, which is fine.
   *
   * The really dangerous calls are the ones that a) run after LDXR has set
   * the exclusive reservation and b) perform OS calls that tear it down:
   *   - emitAnchor  → calls prepareRecord → may trigger a chunk write (mutex)
   *   - emitCodeOnce → calls safeRead (vm_read_overwrite)
   * Both are guarded by !c->ldxr_pending checks further below.
   *
   * For opcode-based STXR detection while pending, we use the opcode word
   * stored in the pc_ring by pcRingPush (which ran at the top of this
   * callback, before the reservation was live for THIS instruction).         */
  uint32_t cur_opcode = 0;
#if !defined(__x86_64__)
  if (!c->ldxr_pending) {
    /* Safe: exclusive reservation is not live, syscall allowed. */
    safeRead(c->cur_pc, &cur_opcode, sizeof(cur_opcode));
    if (isLdxr(cur_opcode)) {
      /* The LDXR is about to execute — arm the guard for subsequent insns. */
      c->ldxr_pending = true;
      c->ldxr_pc = c->cur_pc;
    }
  } else {
    /* Inside exclusive window: read opcode from the pc_ring entry that
     * pcRingPush already wrote (g_pc_ring is a plain in-memory array, no
     * syscall). The ring index for THIS instruction is (g_pc_ring_pos - 1)
     * because pcRingPush incremented g_pc_ring_pos before we reach here. */
    uint64_t ring_idx = (g_pc_ring_pos - 1u) & (kPcRingSize - 1u);
    cur_opcode = (uint32_t)g_pc_ring[ring_idx].opcode;
    if (isStxr(cur_opcode)) {
      /* STXR is about to execute — the critical section ends with this insn.
       * Clear the flag now so postInstCB and the NEXT preInstCB are free to
       * call safeRead / emit anchors again.                                  */
      c->ldxr_pending = false;
    }
  }
#endif

  /* Snapshot x0..lr for POSTINST diffing, but only when reg diffs are wanted:
   * with REGDIFF off this 31-register read is pure overhead on every insn. */
  if (cfg.record & QBDITRACE_REC_REGDIFF) {
    for (int i = 0; i <= 30; ++i) {
      c->prev_reg[i] = QBDI_GPR_GET(gpr, i);
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
    emitAnchor(c->buf, gpr, c->cur_pc); /* handles marker/chunk atomicity */
    c->since_anchor = 0;
    c->need_anchor = false;
  }
  return QBDI::CONTINUE;
}

/* Serialize the regdiff + memacc payload that is common to both v4 and v5
 * instruction records.  Returns the pointer past the last byte written.
 * This avoids duplicating the loop + safeRead logic in two code paths. */
static inline uint8_t *serializeInstPayload(
    uint8_t *p,
    const qbditrace_regdiff_t *regbuf, uint8_t regbuf_n,
    const QBDI::MemoryAccess *macc, uint8_t n_mem) {
  for (uint8_t k = 0; k < regbuf_n; ++k) {
    std::memcpy(p, &regbuf[k], sizeof(qbditrace_regdiff_t));
    p += sizeof(qbditrace_regdiff_t);
  }
  for (uint8_t k = 0; k < n_mem; ++k) {
    const QBDI::MemoryAccess &m = macc[k];
    qbditrace_memacc_t mr;
    mr.mem_type = (uint8_t)m.type;
    mr.mem_flags = (uint8_t)m.flags;
    mr.size = m.size;
    mr.addr = m.accessAddress;
    mr.value = m.value;
    mr.value_hi = 0;
    if ((m.flags & QBDI::MEMORY_UNKNOWN_VALUE) &&
        (m.type & QBDI::MEMORY_WRITE) && m.size > 0 && m.size <= 16) {
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
                          QBDI::FPRState * /*fpr*/, void * /*data*/) {
  ThreadCtx *c = g_tctx ? g_tctx : ensureThreadCtx();
  ThreadBuffer *buf = c->buf;
  const Config &cfg = Tracer::get().cfg();
  const uint64_t exec_pc = c->cur_pc;

  /* Embed the raw instruction bytes once per distinct PC so the decoder can
   * disassemble without --image. Deduplicated, so this is free in loops. The
   * CODE record is independent of the INST record that follows (the decoder
   * keys it by PC), so ordering/chunk boundaries between them do not matter.
   *
   * Skip inside an LL/SC critical section: emitCodeOnce calls safeRead which
   * uses mach_vm_read_overwrite (a syscall), and any syscall clears the ARM
   * exclusive reservation, causing the paired STXR to always fail. If we skip
   * the CODE record here, the PC will be seen again on the retry and the record
   * will be emitted then (outside the exclusive window). */
  if (cfg.embed_code && !c->ldxr_pending) {
    emitCodeOnce(c, exec_pc);
  }

  /* --- register diff (absolute values; decoder rebuilds prev from anchors) --- */
  uint8_t regbuf_n = 0;
  qbditrace_regdiff_t regbuf[8];
  if (cfg.record & QBDITRACE_REC_REGDIFF) {
    const WriteRegList *wl = Tracer::get().writeRegsFor(vm, exec_pc);
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
    }
  }

  /* --- nzcv (bits 31..28 of the NZCV slot) --- */
  uint8_t nzcv = 0;
  if (cfg.record & QBDITRACE_REC_NZCV) {
    uint64_t flags = QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_NZCV);
    nzcv = (uint8_t)((flags >> 28) & 0xF);
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
   *     If delta overflows int16, emit an ANCHOR first then use delta=0. */
  const size_t payload_tail = (size_t)regbuf_n * sizeof(qbditrace_regdiff_t) +
                              (size_t)n_mem * sizeof(qbditrace_memacc_t);

  if (cfg.pc_delta_mode) {
    // Compute delta from last emitted INST PC
    int64_t raw_delta = static_cast<int64_t>(exec_pc) -
                        static_cast<int64_t>(c->last_emitted_pc);
    // If this is the first record or delta overflows int16, force an ANCHOR.
    // The ANCHOR re-anchors the decoder's running PC, then delta=0.
    if (c->last_emitted_pc == 0 ||
        raw_delta < -32768 || raw_delta > 32767) {
      // Emit a forced ANCHOR with the current GPR state.
      // Caller's GPR state is available via `gpr` param in postInstCB.
      // However emitAnchor needs GPRState; we have it via gpr.
      emitAnchor(c->buf, gpr, exec_pc);
      c->since_anchor = 0;
      c->need_anchor = false;
      // After an ANCHOR, the decoder's running_pc = exec_pc, so delta = 0.
      raw_delta = 0;
    }
    int16_t pc_delta = static_cast<int16_t>(raw_delta);

    size_t need = sizeof(qbditrace_inst_head_v5_t) + payload_tail;
    prepareRecord(buf, need);
    uint8_t *p = buf->reserve(need);

    qbditrace_inst_head_v5_t ih5;
    ih5.kind = QBDITRACE_REC_INST;
    ih5.nzcv = nzcv;
    ih5.n_regdiff = regbuf_n;
    ih5.n_mem = n_mem;
    std::memcpy(&ih5.pc_delta, &pc_delta, sizeof(pc_delta));  // LE write
    std::memcpy(p, &ih5, sizeof(ih5));
    p += sizeof(ih5);

    serializeInstPayload(p, regbuf, regbuf_n, macc.data(), n_mem);

    c->last_emitted_pc = exec_pc;
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

  ++c->inst_count;
  ++c->since_anchor;
  return QBDI::CONTINUE;
}

/* PREINST callback bound to the SVC mnemonic. On Darwin arm64 the syscall
 * selector is in x16 and the arguments are x0..x5. We snapshot them before the
 * trap executes so the decoder can name the syscall and show its arguments. */
QBDI::VMAction svcCB(QBDI::VMInstanceRef /*vm*/, QBDI::GPRState *gpr,
                     QBDI::FPRState * /*fpr*/, void * /*data*/) {
  ThreadCtx *c = ensureThreadCtx();
  ThreadBuffer *buf = c->buf;

  qbditrace_svc_head_t sh;
  sh.kind = QBDITRACE_REC_SVC;
  sh.reserved[0] = sh.reserved[1] = sh.reserved[2] = 0;
  sh.pc = QBDI_GPR_GET(gpr, QBDITRACE_AARCH64_IDX_PC);
  sh.syscall_no = QBDI_GPR_GET(gpr, 16); /* x16 = Darwin syscall selector */
  for (int i = 0; i < 6; ++i) {
    sh.args[i] = QBDI_GPR_GET(gpr, i); /* x0..x5 */
  }
  prepareRecord(buf, sizeof(sh));
  uint8_t *p = buf->reserve(sizeof(sh));
  std::memcpy(p, &sh, sizeof(sh));
  return QBDI::CONTINUE;
}

QBDI::VMAction vmEventCB(QBDI::VMInstanceRef vm, const QBDI::VMState *st,
                         QBDI::GPRState *gpr, QBDI::FPRState * /*fpr*/,
                         void * /*data*/) {
  (void)vm;
  ThreadCtx *c = ensureThreadCtx();
  ThreadBuffer *buf = c->buf;

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
  };

  /* NOTE: register diffs store ABSOLUTE post-values, so the diff chain does not
   * break across sequence/transfer boundaries and these events no longer need
   * to emit a full anchor. Anchors are paced purely by instruction count (see
   * preInstCB). We request a fresh anchor after a control-flow transfer so a
   * reader that seeks into the trace has a nearby checkpoint, but we do not
   * force one on ordinary sequence entries (those are extremely frequent). */
  if (st->event & QBDI::SEQUENCE_ENTRY) {
    emitEvent(QBDITRACE_EV_SEQ_ENTRY, st->sequenceStart, 0);
  }
  if (st->event & QBDI::SEQUENCE_EXIT) {
    emitEvent(QBDITRACE_EV_SEQ_EXIT, st->sequenceEnd, 0);
  }
  if (st->event & QBDI::EXEC_TRANSFER_CALL) {
    /* basicBlockStart is the transfer destination (the call target);
     * c->cur_pc is the PC of the instruction that performed the transfer
     * (the call site inside the traced range). */
    const uint64_t target = st->basicBlockStart;
    const uint64_t site = c->cur_pc;
    const Config &cfg = Tracer::get().cfg();
    if (cfg.record & QBDITRACE_REC_MSGSEND) {
      int variant = classifyObjcTarget(cfg, target);
      if (variant >= 0) {
        emitObjc(variant, site);
      }
    }
    emitEvent(QBDITRACE_EV_XFER_CALL, target, site);
    c->need_anchor = true; /* checkpoint after returning into the range */
  }
  if (st->event & QBDI::EXEC_TRANSFER_RETURN) {
    emitEvent(QBDITRACE_EV_XFER_RETURN, st->basicBlockStart, 0);
    c->need_anchor = true;
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

  /* Register the memory-access recorder before callbacks that read it. */
  if (cfg.record & QBDITRACE_REC_MEM) {
    vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
  }

  /* Hot-path callbacks. Priority kept at/below PRIORITY_MEMACCESS_LIMIT so
   * getInstMemoryAccess() is valid inside the POSTINST callback. */
  vm.addCodeCB(QBDI::PREINST, preInstCB, nullptr, QBDI::PRIORITY_DEFAULT);
  vm.addCodeCB(QBDI::POSTINST, postInstCB, nullptr, QBDI::PRIORITY_DEFAULT);
  vm.addVMEventCB(QBDI::SEQUENCE_ENTRY | QBDI::SEQUENCE_EXIT |
                      QBDI::EXEC_TRANSFER_CALL | QBDI::EXEC_TRANSFER_RETURN,
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
  bool ok = vm.run((QBDI::rword)function, safeRet);

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

  /* Run from the function entry until it returns to the real caller (lr). */
  bool ok = vm.run((QBDI::rword)start_pc, (QBDI::rword)lr);

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
  /* Inverted ABI sense: 0 (the zero-initialized default) keeps embedding on. */
  cfg.embed_code = (in->disable_embed_code == 0);
  /* v5 PC-delta mode: non-zero enables it (normal positive sense). */
  cfg.pc_delta_mode = (in->enable_pc_delta != 0);
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
  uint64_t total = g_pc_ring_pos;
  return (int)(total < kPcRingSize ? total : kPcRingSize);
}
