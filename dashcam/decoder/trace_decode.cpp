/*
 * qbditrace - offline trace decoder
 *
 * trace_decode.cpp
 *
 * Reads a binary trace produced by libqbditrace and renders it either as a
 * human-readable listing (default) or as machine-readable JSON Lines
 * (--format jsonl) for downstream analysis (jq / pandas / IDA scripting).
 *
 * Disassembly is performed offline with Capstone, exactly once per unique PC
 * (cached). Register state is rebuilt per thread from anchor snapshots plus the
 * per-instruction diffs. Since v3 the diffs store only the *new* value, so the
 * decoder derives the "before" value from the running register file it rebuilds
 * (anchors are the resync checkpoints).
 *
 * Address normalization: every emitted address is shown both as the runtime
 * address and as a "static" address (runtime - module_slide) so it lines up
 * with what you see in IDA/Ghidra.
 *
 * Disassembly input: by default the trace embeds a deduplicated code table
 * (REC_CODE: the raw bytes of every distinct executed instruction), so the
 * decoder disassembles without any external input -- it is self-contained.
 * The embedded table is keyed by static PC (runtime - module_slide).
 *
 * The external --image <file> --image-base <static_addr> option is DEPRECATED
 * (kept only as a fallback for older traces and may be removed): <file> is a raw
 * dump of the module's code whose first byte corresponds to static address
 * <image-base>, and the decoder fetches bytes at (static_pc - image_base) for
 * any PC missing from the embedded table. With neither a code table nor an
 * image (e.g. an old trace decoded bare), only addresses + register/memory
 * changes are printed.
 *
 * Build: see CMakeLists.txt (links Capstone). Standalone host tool.
 */

#include "../TraceFormat.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(QBDITRACE_HAVE_CAPSTONE)
#include <capstone/capstone.h>
#endif

using namespace qbditrace;

namespace {

enum class Format { Text, Jsonl };

struct Options {
  std::string trace_path;
  std::string image_path;
  uint64_t image_base = 0;
  bool have_image_base = false;
  bool show_regs = true;
  bool show_mem = true;
  bool symbolize = true;   /* e2: annotate adrp/adr targets + static strings */
  bool call_summary = true; /* e1: aggregate args/retval around xfer_call */
  bool show_depth = true;  /* e3: tag each instruction with call depth */
  uint64_t limit = 0; /* 0 = no limit */
  Format format = Format::Text;
  std::string diff_path; /* e4: second trace to diff against (jsonl-based) */
};

const char *gprName(uint8_t idx) {
  static const char *names[] = {
      "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",   "x7",  "x8",
      "x9",  "x10", "x11", "x12", "x13", "x14", "x15",  "x16", "x17",
      "x18", "x19", "x20", "x21", "x22", "x23", "x24",  "x25", "x26",
      "x27", "x28", "fp",  "lr",  "sp",  "nzcv", "pc"};
  if (idx < sizeof(names) / sizeof(names[0])) {
    return names[idx];
  }
  return "?";
}

/* Best-effort name for a Darwin/XNU arm64 BSD syscall number (selector in x16).
 * Covers the syscalls most commonly seen while tracing app code; unknown
 * numbers fall back to the raw value. Mach traps (negative selectors) are not
 * named here. */
const char *darwinSyscallName(uint64_t no) {
  switch (no) {
  case 1: return "exit";
  case 2: return "fork";
  case 3: return "read";
  case 4: return "write";
  case 5: return "open";
  case 6: return "close";
  case 20: return "getpid";
  case 24: return "getuid";
  case 33: return "access";
  case 73: return "munmap";
  case 74: return "mprotect";
  case 75: return "madvise";
  case 92: return "fcntl";
  case 97: return "socket";
  case 116: return "gettimeofday";
  case 153: return "pread";
  case 154: return "pwrite";
  case 169: return "csops";
  case 197: return "mmap";
  case 199: return "lseek";
  case 202: return "sysctl";
  case 286: return "pthread_getugid_np";
  case 327: return "issetugid";
  case 336: return "proc_info";
  case 338: return "stat64";
  case 339: return "fstat64";
  case 340: return "lstat64";
  case 344: return "getdirentries64";
  case 357: return "getaudit_addr";
  case 372: return "thread_selfid";
  case 396: return "read_nocancel";
  case 397: return "write_nocancel";
  case 398: return "open_nocancel";
  case 399: return "close_nocancel";
  case 416: return "stat64_extended";
  case 443: return "guarded_open_np";
  default: return nullptr;
  }
}

/* Read a NUL-terminated C string out of the loaded image at a given static
 * address. Used to resolve objc selector strings (which live in __objc_methname
 * inside the image). Returns empty if the address is outside the image or no
 * terminator is found within a sane bound. */
std::string readImageCString(const std::vector<uint8_t> &image,
                             uint64_t image_base, bool have_image,
                             uint64_t static_addr) {
  if (!have_image || static_addr < image_base) {
    return std::string();
  }
  uint64_t off = static_addr - image_base;
  if (off >= image.size()) {
    return std::string();
  }
  const char *base = reinterpret_cast<const char *>(image.data());
  size_t max = image.size();
  std::string out;
  for (uint64_t i = off; i < max && (i - off) < 256; ++i) {
    char ch = base[i];
    if (ch == '\0') {
      return out;
    }
    if (ch < 0x20 || ch > 0x7e) {
      return std::string(); /* not a printable selector */
    }
    out.push_back(ch);
  }
  return std::string();
}

/* Try to read a printable, NUL-terminated C string at the *pointer value*
 * loaded by an adrp(+add/ldr) pair, when that pointer lands inside the image.
 * Returns empty otherwise. Mirrors readImageCString but is named for the e2
 * call site to make intent clear. */
std::string readStaticString(const std::vector<uint8_t> &image,
                             uint64_t image_base, bool have_image,
                             uint64_t static_addr) {
  return readImageCString(image, image_base, have_image, static_addr);
}

const char *objcVariantName(uint8_t v) {
  switch (v) {
  case QBDITRACE_OBJC_MSGSEND: return "objc_msgSend";
  case QBDITRACE_OBJC_MSGSEND_SUPER: return "objc_msgSendSuper";
  case QBDITRACE_OBJC_MSGSEND_SUPER2: return "objc_msgSendSuper2";
  case QBDITRACE_OBJC_MSGSEND_STRET: return "objc_msgSend_stret";
  default: return "objc_msgSend?";
  }
}

/* Escape a string for embedding in a JSON string literal. */
std::string jsonEscape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    case '\t': out += "\\t"; break;
    default:
      if ((unsigned char)c < 0x20) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
        out += buf;
      } else {
        out.push_back(c);
      }
    }
  }
  return out;
}

/* Whole-file loader. */
bool loadFile(const std::string &path, std::vector<uint8_t> &out) {
  FILE *f = std::fopen(path.c_str(), "rb");
  if (!f) {
    return false;
  }
  std::fseek(f, 0, SEEK_END);
  long sz = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  if (sz <= 0) {
    std::fclose(f);
    return false;
  }
  out.resize((size_t)sz);
  size_t rd = std::fread(out.data(), 1, (size_t)sz, f);
  std::fclose(f);
  return rd == (size_t)sz;
}

/* Structured info about one decoded instruction, derived once from Capstone's
 * detail mode and cached. Used for symbolization (e2) and call-depth tracking
 * (e3). */
struct InsnInfo {
  std::string text;        /* "mnemonic op_str" */
  bool valid = false;      /* decode succeeded */
  bool is_call = false;    /* bl / blr (group CS_GRP_CALL) */
  bool is_ret = false;     /* ret (group CS_GRP_RET) */
  bool is_branch = false;  /* any jump/branch (group CS_GRP_JUMP) */
  /* PC-relative address computed by adr/adrp/b/bl with an immediate operand.
   * has_target == false when the target is register-indirect (blr/br/ret). */
  bool has_target = false;
  uint64_t target = 0;
  /* For adrp: the destination GPR index (QBDI ordering, 0..30) so an
   * immediately-following add/ldr can be paired to recover a full pointer.
   * adrp_reg < 0 means "this instruction is not an adrp". */
  int adrp_reg = -1;
};

/* Disassembler wrapper. Caches structured info per static address. */
class Disassembler {
public:
  Disassembler(const std::vector<uint8_t> &image, uint64_t image_base,
               bool have_image)
      : image_(image), image_base_(image_base), have_image_(have_image) {
#if defined(QBDITRACE_HAVE_CAPSTONE)
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle_) == CS_ERR_OK) {
      cs_ok_ = true;
      /* Detail mode gives us groups + operands needed for e2/e3. */
      cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    }
#endif
  }

  ~Disassembler() {
#if defined(QBDITRACE_HAVE_CAPSTONE)
    if (cs_ok_) {
      cs_close(&handle_);
    }
#endif
  }

  /* Returns disassembly text for the instruction at static address. Empty if
   * unavailable. Cached. */
  const std::string &textFor(uint64_t static_addr) {
    return infoFor(static_addr).text;
  }

  /* Returns full structured info for the instruction at static address.
   * Cached. */
  const InsnInfo &infoFor(uint64_t static_addr) {
    auto it = cache_.find(static_addr);
    if (it != cache_.end()) {
      return it->second;
    }
    InsnInfo info = disasm(static_addr);
    auto res = cache_.emplace(static_addr, std::move(info));
    return res.first->second;
  }

  /* Feed the embedded code table (REC_CODE). `static_addr` is the normalized
   * static PC; `bytes`/`n` are the raw instruction bytes captured at runtime.
   * Multiple traces may report the same PC; we keep the first non-empty entry
   * (they must agree, being the same code). Cheap: AArch64 => n == 4. */
  void addCode(uint64_t static_addr, const uint8_t *bytes, size_t n) {
    if (n == 0 || n > sizeof(CodeEntry::bytes)) {
      return;
    }
    auto &e = code_[static_addr];
    if (e.len != 0) {
      return; /* already have it */
    }
    std::memcpy(e.bytes, bytes, n);
    e.len = (uint8_t)n;
  }

  bool haveEmbeddedCode() const { return !code_.empty(); }

private:
  struct CodeEntry {
    uint8_t bytes[8] = {0};
    uint8_t len = 0;
  };

  /* Resolve the instruction bytes for a static PC, preferring the embedded
   * code table, then falling back to the external --image. Returns the byte
   * pointer and length, or {nullptr,0} when unavailable. */
  const uint8_t *bytesFor(uint64_t static_addr, size_t &n_out) {
    auto it = code_.find(static_addr);
    if (it != code_.end() && it->second.len != 0) {
      n_out = it->second.len;
      return it->second.bytes;
    }
    if (have_image_ && static_addr >= image_base_) {
      uint64_t off = static_addr - image_base_;
      if (off + 4 <= image_.size()) {
        n_out = 4;
        return image_.data() + off;
      }
    }
    n_out = 0;
    return nullptr;
  }

  InsnInfo disasm(uint64_t static_addr) {
    InsnInfo info;
    size_t n = 0;
    const uint8_t *code = bytesFor(static_addr, n);
    if (!code || n == 0) {
      return info;
    }
#if defined(QBDITRACE_HAVE_CAPSTONE)
    if (!cs_ok_) {
      return info;
    }
    cs_insn *insn = nullptr;
    size_t count = cs_disasm(handle_, code, n, static_addr, 1, &insn);
    if (count > 0) {
      info.text = std::string(insn[0].mnemonic) + " " + insn[0].op_str;
      info.valid = true;
      classify(insn[0], info);
      cs_free(insn, count);
    }
    return info;
#else
    /* No Capstone: show raw opcode word. */
    uint32_t word = 0;
    std::memcpy(&word, code, n >= 4 ? 4 : n);
    char buf[32];
    std::snprintf(buf, sizeof(buf), ".word 0x%08x", word);
    info.text = std::string(buf);
    info.valid = true;
    return info;
#endif
  }

#if defined(QBDITRACE_HAVE_CAPSTONE)
  /* Map a Capstone arm64 register id to a QBDI GPR index (x0..x30), or -1. */
  static int csRegToGpr(unsigned reg) {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
      return (int)(reg - ARM64_REG_X0); /* x0..x28 -> 0..28 */
    }
    if (reg == ARM64_REG_X29) return 29; /* fp */
    if (reg == ARM64_REG_X30) return 30; /* lr */
    /* w-regs alias the same GPR. */
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28) {
      return (int)(reg - ARM64_REG_W0);
    }
    if (reg == ARM64_REG_W29) return 29;
    if (reg == ARM64_REG_W30) return 30;
    return -1;
  }

  void classify(const cs_insn &insn, InsnInfo &info) {
    const cs_detail *d = insn.detail;
    if (!d) {
      return;
    }
    for (uint8_t i = 0; i < d->groups_count; ++i) {
      switch (d->groups[i]) {
      case CS_GRP_CALL: info.is_call = true; break;
      case CS_GRP_RET: info.is_ret = true; break;
      case CS_GRP_JUMP: info.is_branch = true; break;
      default: break;
      }
    }
    const cs_arm64 &a = d->arm64;
    unsigned id = insn.id;
    /* PC-relative immediate target for adr/adrp and direct b/bl. */
    if (id == ARM64_INS_ADR || id == ARM64_INS_ADRP) {
      /* operands: [0]=dest reg, [1]=imm (absolute page/byte address). */
      if (a.op_count >= 2 && a.operands[1].type == ARM64_OP_IMM) {
        info.has_target = true;
        info.target = (uint64_t)a.operands[1].imm;
      }
      if (a.op_count >= 1 && a.operands[0].type == ARM64_OP_REG) {
        info.adrp_reg = csRegToGpr(a.operands[0].reg);
      }
    } else if (info.is_branch || info.is_call) {
      /* Direct branch: last operand is the absolute target imm. */
      for (uint8_t i = 0; i < a.op_count; ++i) {
        if (a.operands[i].type == ARM64_OP_IMM) {
          info.has_target = true;
          info.target = (uint64_t)a.operands[i].imm;
        }
      }
    }
  }
#endif

  const std::vector<uint8_t> &image_;
  uint64_t image_base_;
  bool have_image_;
  std::unordered_map<uint64_t, InsnInfo> cache_;
  /* Embedded code table: static_pc -> raw instruction bytes (REC_CODE). */
  std::unordered_map<uint64_t, CodeEntry> code_;
#if defined(QBDITRACE_HAVE_CAPSTONE)
  csh handle_ = 0;
  bool cs_ok_ = false;
#endif
};

/* Per-thread reconstructed register file (QBDI ordering, 34 slots). */
struct RegFile {
  uint64_t regs[QBDITRACE_AARCH64_NUM_GPR] = {0};
  bool valid = false;
};

/* Running statistics for the trailing summary. */
struct Stats {
  uint64_t inst = 0;
  uint64_t anchors = 0;
  uint64_t seq_entry = 0, seq_exit = 0;
  uint64_t xfer_call = 0, xfer_return = 0;
  uint64_t svc = 0, objc = 0;
  uint64_t mem_reads = 0, mem_writes = 0;
  std::unordered_map<uint64_t, uint64_t> pc_hits; /* static_pc -> count */
};

void usage(const char *argv0) {
  std::fprintf(stderr,
               "usage: %s <trace.bin> [--image <file> --image-base <hex>]\n"
               "           [--format text|jsonl] [--no-regs] [--no-mem]\n"
               "           [--no-symbols] [--no-call-summary] [--no-depth]\n"
               "           [--limit N] [--diff <trace2.bin>]\n"
               "\n"
               "  --image <file>     [DEPRECATED] external raw code image for "
               "disassembly. Traces\n"
               "                     now embed a self-contained code table (see "
               "the code= flag),\n"
               "                     so this is rarely needed and may be "
               "removed in a future\n"
               "                     version; kept only as a fallback for "
               "older traces.\n"
               "  --no-symbols       disable adrp/adr target + static string "
               "annotation (e2)\n"
               "  --no-call-summary  disable arg/retval aggregation around "
               "calls (e1)\n"
               "  --no-depth         disable call-depth indentation (e3)\n"
               "  --diff <trace2>    compare two traces instruction-by-"
               "instruction (e4);\n"
               "                     stack/heap addresses are normalized so only "
               "real value\n"
               "                     divergences are shown\n",
               argv0);
}

bool parseArgs(int argc, char **argv, Options &o) {
  if (argc < 2) {
    return false;
  }
  o.trace_path = argv[1];
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--image" && i + 1 < argc) {
      o.image_path = argv[++i];
    } else if (a == "--image-base" && i + 1 < argc) {
      o.image_base = strtoull(argv[++i], nullptr, 0);
      o.have_image_base = true;
    } else if (a == "--format" && i + 1 < argc) {
      std::string f = argv[++i];
      if (f == "text") {
        o.format = Format::Text;
      } else if (f == "jsonl" || f == "json") {
        o.format = Format::Jsonl;
      } else {
        std::fprintf(stderr, "unknown format: %s\n", f.c_str());
        return false;
      }
    } else if (a == "--no-regs") {
      o.show_regs = false;
    } else if (a == "--no-mem") {
      o.show_mem = false;
    } else if (a == "--no-symbols") {
      o.symbolize = false;
    } else if (a == "--no-call-summary") {
      o.call_summary = false;
    } else if (a == "--no-depth") {
      o.show_depth = false;
    } else if (a == "--diff" && i + 1 < argc) {
      o.diff_path = argv[++i];
    } else if (a == "--limit" && i + 1 < argc) {
      o.limit = strtoull(argv[++i], nullptr, 0);
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
      return false;
    }
  }
  return true;
}

/* Mask a value to its access width for display. */
uint64_t maskToWidth(uint64_t v, uint16_t size) {
  if (size > 0 && size < 8) {
    return v & ((1ull << (size * 8)) - 1);
  }
  return v;
}

/* ------------------------------------------------------------------ e4 ----
 * Diff support. We capture, per executed instruction, a normalized fingerprint
 * (static PC + the *values* it produced into registers/memory) with stack/heap
 * addresses canonicalized so two runs of the same code don't appear different
 * merely because the stack lives at a different address.
 */
struct DiffRec {
  uint64_t seq = 0;
  uint64_t static_pc = 0;
  /* PC relative to the trace's own first instruction. Two runs of the same
   * code line up on rel_pc even when the recorded module slide differs (e.g.
   * the traced code lives in a different image than the one whose slide the
   * header captured), so the diff compares rel_pc rather than static_pc. */
  uint64_t rel_pc = 0;
  std::string text;                 /* disassembly */
  std::vector<std::pair<uint8_t, uint64_t>> regs; /* (idx, value) */
  /* normalized (addr_class, value) pairs for memory effects */
  std::vector<std::pair<std::string, uint64_t>> mems;
};

/* Classify an address as stack / image / heap-or-other relative to the trace's
 * known ranges, returning a stable label that does not embed the absolute
 * address (so ASLR / stack relocation does not create false diffs). */
std::string classifyAddr(uint64_t addr, uint64_t stack_hint,
                         uint64_t img_lo, uint64_t img_hi) {
  if (img_lo && addr >= img_lo && addr < img_hi) {
    char b[32];
    std::snprintf(b, sizeof(b), "img+0x%" PRIx64, addr - img_lo);
    return std::string(b);
  }
  /* Heuristic: addresses within 1 MiB below the highest seen SP are "stack". */
  if (stack_hint && addr <= stack_hint && (stack_hint - addr) < (1u << 20)) {
    char b[32];
    std::snprintf(b, sizeof(b), "stack-0x%" PRIx64, stack_hint - addr);
    return std::string(b);
  }
  return std::string("heap/abs");
}

/* Decode a single trace. When `quiet` is true nothing is printed (used to
 * silently collect DiffRecs for --diff). When `collect` is non-null the
 * per-instruction normalized fingerprints are appended to it. */
int decodeTrace(const Options &opt, const std::string &trace_path, bool quiet,
                std::vector<DiffRec> *collect);

/* e4: run the two-trace diff. Declared here, defined after decodeTrace. */
int runDiff(const Options &opt);

int decodeTrace(const Options &opt, const std::string &trace_path, bool quiet,
                std::vector<DiffRec> *collect) {
  const bool json = (opt.format == Format::Jsonl);

  std::vector<uint8_t> trace;
  if (!loadFile(trace_path, trace)) {
    std::fprintf(stderr, "cannot read trace: %s\n", trace_path.c_str());
    return 1;
  }
  if (trace.size() < sizeof(qbditrace_file_header_t)) {
    std::fprintf(stderr, "trace too small / truncated header\n");
    return 1;
  }

  qbditrace_file_header_t hdr;
  std::memcpy(&hdr, trace.data(), sizeof(hdr));
  if (hdr.magic != QBDITRACE_MAGIC) {
    std::fprintf(stderr, "bad magic 0x%08x (not a qbditrace file)\n", hdr.magic);
    return 1;
  }
  if (hdr.version != QBDITRACE_VERSION) {
    std::fprintf(stderr, "unsupported version %u (decoder supports %u)\n",
                 hdr.version, QBDITRACE_VERSION);
    return 1;
  }

  const uint64_t slide = hdr.module_slide;
  auto toStatic = [&](uint64_t rt) -> uint64_t { return rt - slide; };

  std::vector<uint8_t> image;
  bool have_image = false;
  uint64_t image_base = 0;
  if (!opt.image_path.empty()) {
    if (!loadFile(opt.image_path, image)) {
      std::fprintf(stderr, "warning: cannot read image %s; disassembly off\n",
                   opt.image_path.c_str());
    } else {
      have_image = true;
      image_base =
          opt.have_image_base ? opt.image_base : toStatic(hdr.trace_start);
    }
  }

  const bool emit = !quiet;

  /* Image static address range (for diff address classification). */
  const uint64_t img_lo = have_image ? image_base : 0;
  const uint64_t img_hi = have_image ? image_base + image.size() : 0;

  if (emit && !json) {
    std::printf("; qbditrace decode\n");
    std::printf("; module        : %s\n", hdr.module_name);
    std::printf("; arch          : %s\n",
                hdr.arch == QBDITRACE_ARCH_AARCH64 ? "aarch64" : "x86_64");
    std::printf("; module_base   : 0x%016" PRIx64 "\n", hdr.module_base);
    std::printf("; module_slide  : 0x%016" PRIx64 "\n", hdr.module_slide);
    std::printf("; trace range   : 0x%016" PRIx64 " - 0x%016" PRIx64
                " (runtime)\n",
                hdr.trace_start, hdr.trace_end);
    std::printf("; static range  : 0x%016" PRIx64 " - 0x%016" PRIx64 "\n",
                toStatic(hdr.trace_start), toStatic(hdr.trace_end));
    std::printf("; flags         : mem=%d nzcv=%d regdiff=%d code=%d\n",
                (hdr.flags & QBDITRACE_HF_HAS_MEM) ? 1 : 0,
                (hdr.flags & QBDITRACE_HF_HAS_NZCV) ? 1 : 0,
                (hdr.flags & QBDITRACE_HF_REG_DIFF) ? 1 : 0,
                (hdr.flags & QBDITRACE_HF_HAS_CODE) ? 1 : 0);
    if (hdr.flags & QBDITRACE_HF_HAS_CODE) {
      std::printf("; code          : embedded (disassembly self-contained; "
                  "--image not needed)\n");
    }
    if (have_image) {
      std::printf("; image         : %s (base 0x%016" PRIx64 ")\n",
                  opt.image_path.c_str(), image_base);
    }
    std::printf(
        "; ----------------------------------------------------------\n");
  } else if (emit && json) {
    /* First JSONL line: a "header" object describing the trace. */
    std::printf("{\"type\":\"header\",\"module\":\"%s\",\"arch\":\"%s\","
                "\"module_base\":%" PRIu64 ",\"module_slide\":%" PRIu64 ","
                "\"trace_start\":%" PRIu64 ",\"trace_end\":%" PRIu64
                ",\"version\":%u}\n",
                jsonEscape(hdr.module_name).c_str(),
                hdr.arch == QBDITRACE_ARCH_AARCH64 ? "aarch64" : "x86_64",
                hdr.module_base, hdr.module_slide, hdr.trace_start,
                hdr.trace_end, hdr.version);
  }

  Disassembler dis(image, image_base, have_image);

  /* Walk the record stream. */
  const uint8_t *p = trace.data() + sizeof(hdr);
  const uint8_t *end = trace.data() + trace.size();

  std::map<uint64_t, RegFile> reg_by_thread;  /* thread_id -> reg file */
  std::map<uint64_t, uint64_t> seq_by_thread; /* thread_id -> instr seq no */
  uint64_t cur_thread = 0;
  uint64_t emitted = 0;
  bool limited = false;
  Stats st;

  /* e1: when a call is taken we snapshot the argument regs (x0..x7) from the
   * running register file, and remember the call so we can pair the return
   * value (x0) when the matching xfer_return arrives. Keyed per thread. */
  struct PendingCall {
    uint64_t target_static = 0;
    uint64_t args[8] = {0};
    int depth = 0;
  };
  std::map<uint64_t, std::vector<PendingCall>> call_stack; /* tid -> stack */

  /* e3: current call depth per thread (driven by xfer_call/xfer_return). */
  std::map<uint64_t, int> depth_by_thread;

  /* Highest stack pointer (x31/sp index 31) seen per thread, used by the diff
   * collector to canonicalize stack addresses. */
  std::map<uint64_t, uint64_t> stack_hint;

  /* Static PC of the very first instruction in this trace. Used by the diff
   * collector to express each PC as an offset from the entry, so two runs of
   * the same code align regardless of the recorded module slide. */
  uint64_t first_static_pc = 0;
  bool have_first_pc = false;

  auto remain = [&](size_t need) -> bool {
    return (size_t)(end - p) >= need;
  };

  while (p < end) {
    uint8_t kind = *p;

    if (kind == QBDITRACE_REC_THREAD) {
      if (!remain(sizeof(qbditrace_thread_head_t)))
        break;
      qbditrace_thread_head_t th;
      std::memcpy(&th, p, sizeof(th));
      p += sizeof(th);
      cur_thread = th.thread_id;
      reg_by_thread.emplace(cur_thread, RegFile());
      seq_by_thread.emplace(cur_thread, 0);
      if (emit && json) {
        std::printf("{\"type\":\"thread\",\"tid\":%" PRIu64 "}\n", cur_thread);
      } else if (emit) {
        std::printf("; --- thread 0x%" PRIx64 " ---\n", cur_thread);
      }
      continue;
    }

    if (kind == QBDITRACE_REC_CODE) {
      if (!remain(sizeof(qbditrace_code_head_t)))
        break;
      qbditrace_code_head_t ch;
      std::memcpy(&ch, p, sizeof(ch));
      const uint8_t *q = p + sizeof(ch);
      if ((size_t)(end - q) < ch.size)
        break;
      /* Record the raw bytes under the normalized static PC; the writer emits
       * this the first time it sees a PC, before that PC's INST record. */
      dis.addCode(toStatic(ch.pc), q, ch.size);
      p = q + ch.size;
      continue;
    }

    if (kind == QBDITRACE_REC_ANCHOR) {
      if (!remain(sizeof(qbditrace_anchor_head_t)))
        break;
      qbditrace_anchor_head_t ah;
      std::memcpy(&ah, p, sizeof(ah));
      const uint8_t *q = p + sizeof(ah);
      size_t regs_bytes = (size_t)hdr.num_gpr * sizeof(uint64_t);
      if ((size_t)(end - q) < regs_bytes)
        break;
      RegFile &rf = reg_by_thread[cur_thread];
      for (uint32_t i = 0; i < hdr.num_gpr && i < QBDITRACE_AARCH64_NUM_GPR;
           ++i) {
        std::memcpy(&rf.regs[i], q + (size_t)i * sizeof(uint64_t),
                    sizeof(uint64_t));
      }
      rf.valid = true;
      p = q + regs_bytes;
      ++st.anchors;
      continue;
    }

    if (kind == QBDITRACE_REC_EVENT) {
      if (!remain(sizeof(qbditrace_event_head_t)))
        break;
      qbditrace_event_head_t eh;
      std::memcpy(&eh, p, sizeof(eh));
      p += sizeof(eh);
      const char *name = "event";
      switch (eh.event) {
      case QBDITRACE_EV_SEQ_ENTRY: name = "seq_entry"; ++st.seq_entry; break;
      case QBDITRACE_EV_SEQ_EXIT: name = "seq_exit"; ++st.seq_exit; break;
      case QBDITRACE_EV_XFER_CALL: name = "xfer_call"; ++st.xfer_call; break;
      case QBDITRACE_EV_XFER_RETURN:
        name = "xfer_return";
        ++st.xfer_return;
        break;
      default: break;
      }

      /* e1/e3: maintain the per-thread call stack and depth. */
      const RegFile &rfev = reg_by_thread[cur_thread];
      bool have_args = false;
      PendingCall pc_args; /* args captured for an outgoing call */
      bool have_ret = false;
      PendingCall ret_call; /* the matching call we are returning from */
      uint64_t ret_value = 0;

      if (eh.event == QBDITRACE_EV_XFER_CALL) {
        PendingCall c;
        c.target_static = toStatic(eh.addr);
        for (int r = 0; r < 8; ++r) {
          c.args[r] = rfev.regs[r];
        }
        /* Report the current instruction-driven depth (set in INST handler). */
        c.depth = depth_by_thread[cur_thread];
        if (opt.call_summary) {
          call_stack[cur_thread].push_back(c);
          have_args = true;
          pc_args = c;
        }
      } else if (eh.event == QBDITRACE_EV_XFER_RETURN) {
        if (opt.call_summary && !call_stack[cur_thread].empty()) {
          ret_call = call_stack[cur_thread].back();
          call_stack[cur_thread].pop_back();
          ret_value = rfev.regs[0]; /* x0 holds the return value */
          have_ret = true;
          /* Inter-module calls run code we don't trace (no visible ret), so the
           * instruction-driven depth can drift upward across a library call.
           * Snap it back to the depth captured at the matching call site. */
          depth_by_thread[cur_thread] = ret_call.depth;
        }
      }

      if (emit && json) {
        if (eh.event == QBDITRACE_EV_XFER_CALL && eh.site != 0) {
          std::printf("{\"type\":\"event\",\"event\":\"%s\",\"tid\":%" PRIu64
                      ",\"site\":%" PRIu64 ",\"site_static\":%" PRIu64
                      ",\"target\":%" PRIu64 ",\"target_static\":%" PRIu64
                      ",\"depth\":%d",
                      name, cur_thread, eh.site, toStatic(eh.site), eh.addr,
                      toStatic(eh.addr), pc_args.depth);
          if (have_args) {
            std::printf(",\"args\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
                        ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]",
                        pc_args.args[0], pc_args.args[1], pc_args.args[2],
                        pc_args.args[3], pc_args.args[4], pc_args.args[5],
                        pc_args.args[6], pc_args.args[7]);
          }
          std::printf("}\n");
        } else {
          std::printf("{\"type\":\"event\",\"event\":\"%s\",\"tid\":%" PRIu64
                      ",\"addr\":%" PRIu64 ",\"addr_static\":%" PRIu64,
                      name, cur_thread, eh.addr, toStatic(eh.addr));
          if (have_ret) {
            std::printf(",\"ret\":%" PRIu64 ",\"ret_target_static\":%" PRIu64,
                        ret_value, ret_call.target_static);
          }
          std::printf("}\n");
        }
      } else if (emit) {
        if (eh.event == QBDITRACE_EV_XFER_CALL && eh.site != 0) {
          std::printf("; [%s] 0x%" PRIx64 " (static 0x%" PRIx64
                      ") -> target 0x%" PRIx64 " (static 0x%" PRIx64
                      ")  depth=%d\n",
                      name, eh.site, toStatic(eh.site), eh.addr,
                      toStatic(eh.addr), pc_args.depth);
          if (have_args) {
            std::printf(";        args: x0=0x%" PRIx64 " x1=0x%" PRIx64
                        " x2=0x%" PRIx64 " x3=0x%" PRIx64 "\n"
                        ";              x4=0x%" PRIx64 " x5=0x%" PRIx64
                        " x6=0x%" PRIx64 " x7=0x%" PRIx64 "\n",
                        pc_args.args[0], pc_args.args[1], pc_args.args[2],
                        pc_args.args[3], pc_args.args[4], pc_args.args[5],
                        pc_args.args[6], pc_args.args[7]);
            /* If an arg points into the image, try to surface the string. */
            std::string s0 = readStaticString(image, image_base, have_image,
                                              toStatic(pc_args.args[0]));
            if (!s0.empty()) {
              std::printf(";              x0 -> \"%s\"\n", s0.c_str());
            }
          }
        } else {
          std::printf("; [%s] @ 0x%" PRIx64 " (static 0x%" PRIx64 ")", name,
                      eh.addr, toStatic(eh.addr));
          if (have_ret) {
            std::printf("  ret(x0)=0x%" PRIx64 "  (from target static 0x%"
                        PRIx64 ")",
                        ret_value, ret_call.target_static);
          }
          std::printf("\n");
        }
      }
      continue;
    }

    if (kind == QBDITRACE_REC_SVC) {
      if (!remain(sizeof(qbditrace_svc_head_t)))
        break;
      qbditrace_svc_head_t sh;
      std::memcpy(&sh, p, sizeof(sh));
      p += sizeof(sh);
      ++st.svc;
      const char *sname = darwinSyscallName(sh.syscall_no);
      if (emit && json) {
        std::printf("{\"type\":\"svc\",\"tid\":%" PRIu64 ",\"pc\":%" PRIu64
                    ",\"pc_static\":%" PRIu64 ",\"syscall_no\":%" PRIu64
                    ",\"syscall\":\"%s\",\"args\":[%" PRIu64 ",%" PRIu64
                    ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]}\n",
                    cur_thread, sh.pc, toStatic(sh.pc), sh.syscall_no,
                    sname ? sname : "?", sh.args[0], sh.args[1], sh.args[2],
                    sh.args[3], sh.args[4], sh.args[5]);
      } else if (emit) {
        std::printf("; [svc] @ 0x%" PRIx64 " (static 0x%" PRIx64
                    ") %s (#%" PRIu64 ") args=(0x%" PRIx64 ", 0x%" PRIx64
                    ", 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64
                    ")\n",
                    sh.pc, toStatic(sh.pc), sname ? sname : "syscall",
                    sh.syscall_no, sh.args[0], sh.args[1], sh.args[2],
                    sh.args[3], sh.args[4], sh.args[5]);
      }
      continue;
    }

    if (kind == QBDITRACE_REC_OBJC) {
      if (!remain(sizeof(qbditrace_objc_head_t)))
        break;
      qbditrace_objc_head_t oh;
      std::memcpy(&oh, p, sizeof(oh));
      p += sizeof(oh);
      ++st.objc;
      const char *variant = objcVariantName(oh.variant);
      /* The selector pointer lives in the image (__objc_methname); try to
       * resolve it for nicer output. The receiver class name was captured live
       * by the tracer and stored in oh.cls. */
      std::string sel =
          readImageCString(image, image_base, have_image, toStatic(oh.sel));
      /* Ensure cls is NUL-terminated before use. */
      char clsbuf[sizeof(oh.cls) + 1];
      std::memcpy(clsbuf, oh.cls, sizeof(oh.cls));
      clsbuf[sizeof(oh.cls)] = '\0';
      const bool have_cls = clsbuf[0] != '\0';
      if (emit && json) {
        std::printf("{\"type\":\"objc\",\"tid\":%" PRIu64 ",\"pc\":%" PRIu64
                    ",\"pc_static\":%" PRIu64 ",\"variant\":\"%s\",\"recv\":%"
                    PRIu64 ",\"sel_ptr\":%" PRIu64 ",\"sel\":\"%s\",\"class\":"
                    "\"%s\"}\n",
                    cur_thread, oh.pc, toStatic(oh.pc), variant, oh.recv,
                    oh.sel, jsonEscape(sel).c_str(),
                    have_cls ? jsonEscape(clsbuf).c_str() : "");
      } else if (emit) {
        if (have_cls && !sel.empty()) {
          std::printf("; [objc] @ 0x%" PRIx64 " (static 0x%" PRIx64
                      ") %s -[%s %s] (recv=0x%" PRIx64 ")\n",
                      oh.pc, toStatic(oh.pc), variant, clsbuf, sel.c_str(),
                      oh.recv);
        } else if (!sel.empty()) {
          std::printf("; [objc] @ 0x%" PRIx64 " (static 0x%" PRIx64
                      ") %s sel=\"%s\" recv=0x%" PRIx64 "\n",
                      oh.pc, toStatic(oh.pc), variant, sel.c_str(), oh.recv);
        } else if (have_cls) {
          std::printf("; [objc] @ 0x%" PRIx64 " (static 0x%" PRIx64
                      ") %s class=%s recv=0x%" PRIx64 " sel_ptr=0x%" PRIx64 "\n",
                      oh.pc, toStatic(oh.pc), variant, clsbuf, oh.recv, oh.sel);
        } else {
          std::printf("; [objc] @ 0x%" PRIx64 " (static 0x%" PRIx64
                      ") %s recv=0x%" PRIx64 " sel_ptr=0x%" PRIx64 "\n",
                      oh.pc, toStatic(oh.pc), variant, oh.recv, oh.sel);
        }
      }
      continue;
    }

    if (kind == QBDITRACE_REC_INST) {
      if (!remain(sizeof(qbditrace_inst_head_t)))
        break;
      qbditrace_inst_head_t ih;
      std::memcpy(&ih, p, sizeof(ih));
      const uint8_t *q = p + sizeof(ih);

      /* Parse register diffs (v3: reg_index + value, no prev_value). */
      struct Diff {
        uint8_t idx;
        uint64_t prev;
        uint64_t value;
      };
      std::vector<Diff> diffs;
      diffs.reserve(ih.n_regdiff);
      RegFile &rf = reg_by_thread[cur_thread];
      bool overrun = false;
      for (uint8_t i = 0; i < ih.n_regdiff; ++i) {
        if ((size_t)(end - q) < sizeof(qbditrace_regdiff_t)) {
          overrun = true;
          break;
        }
        qbditrace_regdiff_t rd;
        std::memcpy(&rd, q, sizeof(rd));
        q += sizeof(rd);
        uint64_t prev = (rd.reg_index < QBDITRACE_AARCH64_NUM_GPR)
                            ? rf.regs[rd.reg_index]
                            : 0;
        diffs.push_back({rd.reg_index, prev, rd.value});
        /* Apply to the running register file so the next instruction's "before"
         * is correct. */
        if (rd.reg_index < QBDITRACE_AARCH64_NUM_GPR) {
          rf.regs[rd.reg_index] = rd.value;
        }
      }
      if (overrun)
        break;

      /* Parse memory accesses (v3: value + value_hi). */
      struct Mem {
        uint8_t type;
        uint8_t flags;
        uint16_t size;
        uint64_t addr;
        uint64_t value;
        uint64_t value_hi;
      };
      std::vector<Mem> mems;
      mems.reserve(ih.n_mem);
      for (uint8_t i = 0; i < ih.n_mem; ++i) {
        if ((size_t)(end - q) < sizeof(qbditrace_memacc_t)) {
          overrun = true;
          break;
        }
        qbditrace_memacc_t ma;
        std::memcpy(&ma, q, sizeof(ma));
        q += sizeof(ma);
        mems.push_back(
            {ma.mem_type, ma.mem_flags, ma.size, ma.addr, ma.value, ma.value_hi});
        if (ma.mem_type & 1u)
          ++st.mem_reads;
        if (ma.mem_type & 2u)
          ++st.mem_writes;
      }
      if (overrun)
        break;

      p = q;
      ++st.inst;
      uint64_t seq = seq_by_thread[cur_thread]++;
      uint64_t static_pc = toStatic(ih.pc);
      st.pc_hits[static_pc]++;
      if (!have_first_pc) {
        first_static_pc = static_pc;
        have_first_pc = true;
      }

      /* Track the running stack pointer (index 31) for diff normalization. */
      {
        uint64_t sp = rf.regs[31];
        uint64_t &hint = stack_hint[cur_thread];
        if (sp > hint) {
          hint = sp;
        }
      }

      /* e4: collect a normalized fingerprint for this instruction. */
      if (collect) {
        DiffRec rec;
        rec.seq = seq;
        rec.static_pc = static_pc;
        rec.rel_pc = static_pc - first_static_pc;
        rec.text = dis.textFor(static_pc);
        if (opt.show_regs) {
          for (const Diff &d : diffs) {
            /* Skip pc/sp themselves: they are inherently run-dependent. */
            if (d.idx == 31 || d.idx == 33) {
              continue;
            }
            rec.regs.emplace_back(d.idx, d.value);
          }
        }
        if (opt.show_mem) {
          uint64_t sh = stack_hint[cur_thread];
          for (const Mem &m : mems) {
            bool unknown_val = (m.flags & (1u << 2)) != 0;
            uint64_t v = unknown_val ? 0 : maskToWidth(m.value, m.size);
            rec.mems.emplace_back(classifyAddr(m.addr, sh, img_lo, img_hi), v);
          }
        }
        collect->push_back(std::move(rec));
      }

      /* e3: depth prefix (indentation reflecting the call stack). Depth is
       * driven by the instructions themselves (bl/blr -> deeper, ret ->
       * shallower) so that *intra-module* calls and recursion are captured,
       * which the xfer_call/return events (inter-module only) cannot see. The
       * current instruction is shown at the depth it executes *at*; a call
       * deepens the following instructions, a ret shallows them. */
      const InsnInfo &dinfo = dis.infoFor(static_pc);
      int &depth_ref = depth_by_thread[cur_thread];
      if (dinfo.is_ret && depth_ref > 0) {
        --depth_ref; /* ret executes in the callee, but show it dedented */
      }
      const int cur_depth = depth_ref;
      if (dinfo.is_call) {
        ++depth_ref; /* the callee's instructions are one level deeper */
      }
      char depth_prefix[64];
      depth_prefix[0] = '\0';
      if (opt.show_depth && cur_depth > 0) {
        int n = cur_depth < 30 ? cur_depth : 30;
        for (int k = 0; k < n; ++k) {
          depth_prefix[k] = ' ';
        }
        depth_prefix[n] = '\0';
      }

      if (opt.limit != 0 && emitted >= opt.limit) {
        limited = true;
        /* keep walking to accumulate stats but stop printing instructions */
      } else if (emit) {
        ++emitted;
        const InsnInfo &info = dis.infoFor(static_pc);
        const std::string &text = info.text;

        /* e2: build a symbolic annotation for PC-relative targets / strings. */
        std::string sym;
        if (opt.symbolize && info.has_target) {
          char b[96];
          std::snprintf(b, sizeof(b), "  ; -> 0x%" PRIx64, info.target);
          sym = b;
          std::string s = readStaticString(image, image_base, have_image,
                                           info.target);
          if (!s.empty()) {
            sym += " \"" + s + "\"";
          }
        }

        if (json) {
          std::printf("{\"type\":\"inst\",\"tid\":%" PRIu64 ",\"seq\":%" PRIu64
                      ",\"pc\":%" PRIu64 ",\"pc_static\":%" PRIu64 ",\"asm\":"
                      "\"%s\",\"depth\":%d,\"nzcv\":%u",
                      cur_thread, seq, ih.pc, static_pc,
                      jsonEscape(text).c_str(), cur_depth,
                      (unsigned)(ih.nzcv & 0xf));
          if (info.has_target) {
            std::printf(",\"target\":%" PRIu64, info.target);
            std::string s = readStaticString(image, image_base, have_image,
                                             info.target);
            if (!s.empty()) {
              std::printf(",\"target_str\":\"%s\"", jsonEscape(s).c_str());
            }
          }
          if (opt.show_regs && !diffs.empty()) {
            std::printf(",\"regs\":[");
            for (size_t i = 0; i < diffs.size(); ++i) {
              std::printf("%s{\"reg\":\"%s\",\"prev\":%" PRIu64 ",\"value\":%"
                          PRIu64 "}",
                          i ? "," : "", gprName(diffs[i].idx), diffs[i].prev,
                          diffs[i].value);
            }
            std::printf("]");
          }
          if (opt.show_mem && !mems.empty()) {
            std::printf(",\"mem\":[");
            for (size_t i = 0; i < mems.size(); ++i) {
              const Mem &m = mems[i];
              const char *acc = (m.type & 2u) ? ((m.type & 1u) ? "rw" : "w")
                                              : "r";
              std::printf("%s{\"acc\":\"%s\",\"size\":%u,\"addr\":%" PRIu64
                          ",\"value\":%" PRIu64 ",\"value_hi\":%" PRIu64 "}",
                          i ? "," : "", acc, (unsigned)m.size, m.addr,
                          maskToWidth(m.value, m.size), m.value_hi);
            }
            std::printf("]");
          }
          std::printf("}\n");
        } else {
          std::printf("[%6" PRIu64 "] 0x%012" PRIx64 "  %s%-32s",
                      seq, static_pc, depth_prefix,
                      text.empty() ? "<no image>" : text.c_str());
          if (hdr.flags & QBDITRACE_HF_HAS_NZCV) {
            std::printf("  {N=%d Z=%d C=%d V=%d}",
                        (ih.nzcv >> 3) & 1, (ih.nzcv >> 2) & 1,
                        (ih.nzcv >> 1) & 1, ih.nzcv & 1);
          }
          if (!sym.empty()) {
            std::printf("%s", sym.c_str());
          }
          std::printf("\n");
          if (opt.show_regs) {
            for (const Diff &d : diffs) {
              std::printf("            %-4s 0x%016" PRIx64 " -> 0x%016" PRIx64
                          "\n",
                          gprName(d.idx), d.prev, d.value);
            }
          }
          if (opt.show_mem) {
            for (const Mem &m : mems) {
              const char *acc = (m.type & 2u) ? ((m.type & 1u) ? "rw" : "w")
                                              : "r";
              bool unknown_val = (m.flags & (1u << 2)) != 0;
              if (m.size > 8) {
                std::printf("            mem[%s] 0x%016" PRIx64
                            " (%uB) = 0x%016" PRIx64 "%016" PRIx64 "\n",
                            acc, m.addr, (unsigned)m.size, m.value_hi, m.value);
              } else if (unknown_val) {
                std::printf("            mem[%s] 0x%016" PRIx64
                            " (%uB) = <unknown>\n",
                            acc, m.addr, (unsigned)m.size);
              } else {
                std::printf("            mem[%s] 0x%016" PRIx64
                            " (%uB) = 0x%016" PRIx64 "\n",
                            acc, m.addr, (unsigned)m.size,
                            maskToWidth(m.value, m.size));
              }
            }
          }
        }
      }
      continue;
    }

    /* Unknown record kind: cannot safely resynchronize, stop. */
    if (emit && !json) {
      std::fprintf(stderr,
                   "; warning: unknown record kind %u at offset %ld; stopping\n",
                   kind, (long)(p - trace.data()));
    }
    break;
  }

  /* ---- Trailing summary ---- */
  /* Find the hottest PCs for the summary. */
  uint64_t unique_pcs = st.pc_hits.size();
  uint64_t hot_pc = 0, hot_count = 0;
  for (const auto &kv : st.pc_hits) {
    if (kv.second > hot_count) {
      hot_count = kv.second;
      hot_pc = kv.first;
    }
  }

  if (emit && json) {
    std::printf("{\"type\":\"summary\",\"instructions\":%" PRIu64
                ",\"anchors\":%" PRIu64 ",\"seq_entry\":%" PRIu64
                ",\"seq_exit\":%" PRIu64 ",\"xfer_call\":%" PRIu64
                ",\"xfer_return\":%" PRIu64 ",\"svc\":%" PRIu64 ",\"objc\":%"
                PRIu64 ",\"mem_reads\":%" PRIu64 ",\"mem_writes\":%" PRIu64
                ",\"unique_pcs\":%" PRIu64 ",\"hottest_pc_static\":%" PRIu64
                ",\"hottest_pc_count\":%" PRIu64 ",\"truncated\":%s}\n",
                st.inst, st.anchors, st.seq_entry, st.seq_exit, st.xfer_call,
                st.xfer_return, st.svc, st.objc, st.mem_reads, st.mem_writes,
                unique_pcs, hot_pc, hot_count, limited ? "true" : "false");
  } else if (emit) {
    std::printf(
        "; ----------------------------------------------------------\n");
    std::printf("; summary\n");
    std::printf(";   instructions : %" PRIu64 "  (unique PCs: %" PRIu64 ")\n",
                st.inst, unique_pcs);
    std::printf(";   anchors      : %" PRIu64 "\n", st.anchors);
    std::printf(";   seq entry/ex : %" PRIu64 " / %" PRIu64 "\n", st.seq_entry,
                st.seq_exit);
    std::printf(";   xfer call/ret: %" PRIu64 " / %" PRIu64 "\n", st.xfer_call,
                st.xfer_return);
    std::printf(";   svc / objc   : %" PRIu64 " / %" PRIu64 "\n", st.svc,
                st.objc);
    std::printf(";   mem rd / wr  : %" PRIu64 " / %" PRIu64 "\n", st.mem_reads,
                st.mem_writes);
    if (hot_count > 0) {
      std::printf(";   hottest PC   : static 0x%" PRIx64 " (%" PRIu64
                  " hits)\n",
                  hot_pc, hot_count);
    }
    if (limited) {
      std::printf(";   note         : instruction printing capped at --limit %"
                  PRIu64 " (stats cover full trace)\n",
                  opt.limit);
    }
  }

  return 0;
}

/* ------------------------------------------------------------------ e4 ----
 * Two-trace diff. We decode both traces quietly into DiffRec streams (with
 * stack/heap addresses normalized) and walk them in lockstep, reporting only
 * instructions whose produced values differ. Sequence numbers are used to align
 * the streams; if they desynchronize (different number of instructions) we
 * report that and stop at the first length divergence.
 */
static std::string regsToStr(const std::vector<std::pair<uint8_t, uint64_t>> &r) {
  std::string s;
  char b[64];
  for (const auto &kv : r) {
    std::snprintf(b, sizeof(b), "%s%s=0x%" PRIx64, s.empty() ? "" : " ",
                  gprName(kv.first), kv.second);
    s += b;
  }
  return s;
}

static std::string memsToStr(
    const std::vector<std::pair<std::string, uint64_t>> &m) {
  std::string s;
  char b[64];
  for (const auto &kv : m) {
    std::snprintf(b, sizeof(b), "%s[%s]=0x%" PRIx64, s.empty() ? "" : " ",
                  kv.first.c_str(), kv.second);
    s += b;
  }
  return s;
}

int runDiff(const Options &opt) {
  Options o = opt;
  o.diff_path.clear();        /* avoid recursion */
  o.limit = 0;                /* never cap when collecting */
  o.format = Format::Jsonl;   /* irrelevant in quiet mode */

  std::vector<DiffRec> a, b;
  int ra = decodeTrace(o, opt.trace_path, /*quiet=*/true, &a);
  if (ra != 0) {
    return ra;
  }
  int rb = decodeTrace(o, opt.diff_path, /*quiet=*/true, &b);
  if (rb != 0) {
    return rb;
  }

  std::printf("; qbditrace diff\n");
  std::printf(";   A = %s  (%zu instructions)\n", opt.trace_path.c_str(),
              a.size());
  std::printf(";   B = %s  (%zu instructions)\n", opt.diff_path.c_str(),
              b.size());
  std::printf(";   note: register/memory *values* compared; pc/sp and stack/"
              "heap addresses are normalized so only real divergences show.\n");
  std::printf(
      "; ----------------------------------------------------------\n");

  size_t n = a.size() < b.size() ? a.size() : b.size();
  uint64_t diffs = 0;
  size_t i = 0;
  for (; i < n; ++i) {
    const DiffRec &x = a[i];
    const DiffRec &y = b[i];
    /* If the control flow itself diverged (different code offsets at the same
     * step), report it prominently and stop -- everything after is unaligned.
     * Compare rel_pc (offset from each trace's entry) so a differing module
     * slide between the two runs does not look like a divergence. */
    if (x.rel_pc != y.rel_pc) {
      std::printf("[%6zu] CONTROL FLOW DIVERGES\n", i);
      std::printf("        A: +0x%-8" PRIx64 " (0x%012" PRIx64 ")  %s\n",
                  x.rel_pc, x.static_pc, x.text.c_str());
      std::printf("        B: +0x%-8" PRIx64 " (0x%012" PRIx64 ")  %s\n",
                  y.rel_pc, y.static_pc, y.text.c_str());
      ++diffs;
      break;
    }
    std::string ar = regsToStr(x.regs), br = regsToStr(y.regs);
    std::string am = memsToStr(x.mems), bm = memsToStr(y.mems);
    if (ar != br || am != bm) {
      ++diffs;
      std::printf("[%6zu] +0x%-8" PRIx64 "  %s\n", i, x.rel_pc,
                  x.text.c_str());
      if (ar != br) {
        std::printf("        A.regs: %s\n", ar.empty() ? "-" : ar.c_str());
        std::printf("        B.regs: %s\n", br.empty() ? "-" : br.c_str());
      }
      if (am != bm) {
        std::printf("        A.mem : %s\n", am.empty() ? "-" : am.c_str());
        std::printf("        B.mem : %s\n", bm.empty() ? "-" : bm.c_str());
      }
    }
  }

  std::printf(
      "; ----------------------------------------------------------\n");
  if (a.size() != b.size() && i == n) {
    std::printf("; length differs: A has %zu, B has %zu instructions "
                "(compared first %zu)\n",
                a.size(), b.size(), n);
  }
  std::printf("; diverging instructions: %" PRIu64 " / %zu compared\n", diffs,
              n);
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  Options opt;
  if (!parseArgs(argc, argv, opt)) {
    usage(argv[0]);
    return 1;
  }

  /* e4: two-trace diff mode. */
  if (!opt.diff_path.empty()) {
    return runDiff(opt);
  }

  return decodeTrace(opt, opt.trace_path, /*quiet=*/false, /*collect=*/nullptr);
}
