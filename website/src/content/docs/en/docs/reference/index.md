---
title: Trace format specification
sidebar:
  order: 1
---

The binary trace format is the contract between any capture engine and Tenet. As long as a tool emits a compliant `.bin` file, Tenet can analyze it—QBDITrace is the official implementation, not the only option.

The authoritative C definition is `dashcam/TraceFormat.h`. This document restates the format for implementors of custom collectors.

## File header

536 bytes, written once at the start of the file. All multi-byte integers are little-endian (native AArch64).

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x000 | 4 | `magic` | `0x51424454` ("QBDT") |
| 0x004 | 4 | `version` | 4 (baseline), 5 (PC-delta), 6 (old-value), 7 (FPR), 8 (call metadata) |
| 0x008 | 4 | `arch` | Architecture tag: 1 = AArch64, 2 = x86_64 |
| 0x00C | 4 | `num_gpr` | GPR count in anchor snapshots (AArch64: 34) |
| 0x010 | 8 | `module_base` | Runtime base address of the traced module |
| 0x018 | 8 | `module_slide` | ASLR slide (runtime − preferred static base) |
| 0x020 | 8 | `trace_start` | Runtime start of traced range (inclusive) |
| 0x028 | 8 | `trace_end` | Runtime end of traced range (exclusive) |
| 0x030 | 8 | `flags` | Header flags (see below) |
| 0x038 | 256 | `module_name` | NUL-terminated module path |
| 0x138 | 4 | `target_os` | 0 = Unknown, 1 = iOS, 2 = Android, 3 = Linux |
| 0x13C | 220 | `reserved` | Padding to 536 bytes |

### Address normalization

```
static_address = runtime_address − module_slide
```

Tenet normalizes all runtime PCs back to the static image so they match IDA/Ghidra.

## Header flags

The `flags` field at offset 0x030 controls record layout and compression. Flags are orthogonal to the version tag: the version is set by the *highest* flag that changes the on-disk layout.

| Bit | Name | Effect |
|-----|------|--------|
| 0 | `HF_HAS_MEM` | Records may carry memory accesses |
| 1 | `HF_HAS_NZCV` | INST records carry NZCV flags |
| 2 | `HF_REG_DIFF` | INST records store register diffs (not full snapshots) |
| 3 | `HF_HAS_CODE` | Stream contains `REC_CODE` records |
| 4 | `HF_PC_DELTA` | **v5**: INST header uses 2-byte signed PC delta instead of 8-byte absolute PC |
| 5 | `HF_OLD_VALUE` | **v6**: Memory access records carry pre-write values (48 B each) |
| 6 | `HF_HAS_FPR` | **v7**: ANCHOR carries 512 B FPR snapshot; INST carries FPR diffs |
| 7 | `HF_COMPRESSED` | Legacy: entire record stream is one zstd frame (historical) |
| 8 | `HF_BLOCK_COMPRESSED` | 1 MiB zstd blocks with tail index for random access (default) |
| 9 | `HF_BRANCH_HINT` | nzcv high nibble encodes CALL/RET/BRANCH class |
| 10 | `HF_CALL_META` | **v8**: enables v8 OBJC/CAPICALL layouts and `REC_RETVAL`; may combine with `HF_PC_DELTA` / `HF_HAS_FPR` |

## Version evolution

| Version | Gate flag | Key change |
|---------|-----------|------------|
| v4 | baseline | INST head 16 B, ANCHOR 288 B, REC_CODE introduced |
| v5 | `HF_PC_DELTA` | INST head shrinks to 6 B (int16 PC delta); decoder maintains running PC |
| v6 | `HF_OLD_VALUE` | Memory access records grow to 48 B (pre-write old_value fields); **writer removed** |
| v7 | `HF_HAS_FPR` | ANCHOR gains 512 B FPR block (total 800 B); INST gains FPR diff section |
| v8 | `HF_CALL_META` | Adds true return facts in `REC_RETVAL`, inline OBJC selectors, and a `uint16_t` CAPICALL `api_id`; may combine with `HF_PC_DELTA` / `HF_HAS_FPR` |

Readers that do not recognise a flag **must** reject the file.

## Record types

Every record begins with a single-byte `kind` tag:

| Kind | Value | Description |
|------|-------|-------------|
| `REC_INST` | 0 | Per-instruction register/memory diff |
| `REC_ANCHOR` | 1 | Full register snapshot (rebuild checkpoint) |
| `REC_THREAD` | 2 | Thread context marker |
| `REC_EVENT` | 3 | VM event (sequence entry/exit, cross-boundary transfer) |
| `REC_SVC` | 4 | Supervisor call / syscall site |
| `REC_OBJC` | 5 | ObjC msgSend-family dispatch |
| `REC_CODE` | 6 | Raw instruction bytes (emitted once per distinct PC) |
| `REC_CAPICALL` | 7 | C/platform API call with semantic argument captures |
| `REC_RETVAL` | 8 | True return fact for an OBJC/CAPI/SVC call in v8 |

### REC_INST (kind = 0)

The most frequent record. Stores only the *changes* an instruction produced.

**v4 layout** (`HF_PC_DELTA` not set):

```
qbditrace_inst_head_t    16 bytes
  kind        u8
  nzcv        u8    (low 4 bits = N/Z/C/V; high 4 bits = branch hint when HF_BRANCH_HINT)
  n_regdiff   u8
  n_mem       u8
  pc          u64   (runtime absolute PC)
n_regdiff × regdiff_t    16 bytes each
  reg_index   u8    (QBDI GPR ordering: 0=x0 … 30=lr, 31=sp, 32=nzcv, 33=pc)
  [padding]   7 B
  value       u64   (value after the instruction executed)
n_mem × memacc_t         32 bytes each
  mem_type    u8    (bit0 = read, bit1 = write)
  mem_flags   u8    (bit0 = unknown_size, bit1 = minimum_size, bit2 = unknown_value)
  size        u16
  addr        u64
  value       u64   (low 8 bytes)
  value_hi    u64   (high 8 bytes for 9–16 byte stores; 0 otherwise)
```

**v5 layout** (`HF_PC_DELTA` set): identical except `pc` is replaced by `pc_delta` (int16 LE). The decoder maintains `running_pc += pc_delta`. If `|delta| > 32767`, emit an ANCHOR first (which resets running_pc with its absolute pc), then use delta = 0. Header size: 6 bytes.

**v7 layout** (`HF_HAS_FPR` set): after the GPR diffs, an FPR diff section is interleaved before memory accesses:

```
inst_head (v7 or v7+v5 variant)
n_regdiff × regdiff_t
n_fprdiff × fprdiff_t     24 bytes each
  fpr_index   u8    (0..31 = v0..v31)
  [padding]   7 B
  lo          u64   (bits 63:0)
  hi          u64   (bits 127:64)
n_mem × memacc_t
```

### REC_ANCHOR (kind = 1)

Periodic full-register checkpoint. The decoder uses the most recent anchor to reconstruct state at any instruction.

**v4/v5/v6 layout:**

```
anchor_head_t             16 bytes
  kind        u8
  [reserved]  3 B
  pc          u64   (absolute runtime PC)
num_gpr × u64             272 bytes (34 × 8 B for AArch64)
```

Total: 288 bytes.

**v7 layout** (`HF_HAS_FPR` set): after the GPR block, a 512-byte FPR snapshot is appended:

```
anchor_head_t + GPR block    288 bytes
fpr_lo[32]                   256 bytes  (bits 63:0 of v0..v31)
fpr_hi[32]                   256 bytes  (bits 127:64 of v0..v31)
```

Total: 800 bytes.

### REC_THREAD (kind = 2)

```
thread_head_t   16 bytes
  kind       u8
  [reserved] 3 B
  thread_id  u64
```

Emitted at the start of each per-thread stream. Currently Tenet assumes single-thread traces.

### REC_EVENT (kind = 3)

```
event_head_t    24 bytes
  kind       u8
  event      u8    (1=SEQ_ENTRY, 2=SEQ_EXIT, 3=XFER_CALL, 4=XFER_RETURN)
  [reserved] 2 B
  addr       u64   (for XFER_CALL: target address; for XFER_RETURN: return target)
  site       u64   (for XFER_CALL: call-site PC; 0 otherwise)
```

### REC_SVC (kind = 4)

```
svc_head_t      72 bytes
  kind        u8
  [reserved]  3 B
  pc          u64   (address of the svc instruction)
  syscall_no  u64   (x16 on Darwin, x8 on Linux/Android)
  args[6]     6×u64 (x0..x5)
```

### REC_OBJC (kind = 5)

**Legacy v4-v7 layout:**

```
objc_head_t     80 bytes
  kind       u8
  variant    u8    (0=msgSend, 1=msgSendSuper, 2=msgSendSuper2, 3=msgSend_stret)
  [reserved] 2 B
  pc         u64   (call-site PC)
  recv       u64   (x0: receiver or super struct pointer)
  sel        u64   (x1: selector; x2 for *Super variants)
  cls[48]          (NUL-terminated runtime class name; "" if unavailable)
```

**v8 layout** (`HF_CALL_META` set): the fixed header remains 80 bytes but adds `sel_len` and `flags`; an inline selector follows as `sel_len` content bytes plus a NUL, padded to 4-byte alignment. The flags report selector truncation or read failure. `HF_CALL_META` is a file-wide layout contract, so legacy and v8 OBJC layouts are never mixed in one file.

### REC_CODE (kind = 6)

Raw instruction bytes for one distinct PC. Emitted once on first execution, deduplicated by PC. Enables offline disassembly without an external image.

```
code_head_t     16 bytes
  kind       u8
  size       u8    (instruction length; 4 on AArch64)
  [reserved] 2 B
  pc         u64   (runtime address)
  bytes[size]      (raw little-endian encoding)
```

### REC_CAPICALL (kind = 7)

Captures a call to a well-known C/platform API function. Contains a fixed 88-byte header plus 0–4 variable-length inline string captures.

**Legacy v4-v7 layout:**

```
capicall_head_t     88 bytes
  kind        u8
  api_id      u8    (numeric ID from the capi_id enum)
  arg_count   u8    (valid entries in args[], 0..8)
  str_count   u8    (inline string captures that follow, 0..4)
  pc          u64   (call-site PC)
  target      u64   (runtime address of the called function)
  args[8]     8×u64 (x0..x7 at call time)
```

**v8 layout** (`HF_CALL_META` set): the fixed header remains 88 bytes, with reordered fields and a `uint16_t api_id` that preserves IDs above 255. The file-wide flag requires every CAPICALL in the file to use the v8 layout.

Followed by `str_count` variable-length captures (identical for both layouts):

```
capicall_str_t      4 bytes
  str_arg_idx  u8   (which arg this string came from, 0..7)
  str_len      u8   (content byte length, not counting NUL; max 255)
  str_flags    u8   (bit0=truncated, bit1=binary, bit2=safe-read-failed)
  [_reserved]  u8
str_data[str_len + 1]    (NUL-terminated; padded to 4-byte alignment)
```

### REC_RETVAL (kind = 8)

Present only in v8 files with `HF_CALL_META`. This 64-byte self-describing record associates true architectural return state with an OBJC, CAPICALL, or SVC call. It carries source kind/ID, call site, target, resume address, and raw `x0`, `x1`, and `nzcv`; `record_size` lets future readers safely skip extensions.

## Compression

### Block compression (`HF_BLOCK_COMPRESSED`)

Default for all new traces. The data after the 536-byte header is divided into independent 1 MiB zstd frames. A tail index at the end of the file enables O(1) random access.

**File layout:**

```
[file header: 536 B, uncompressed]
[block 0: zstd frame]
[block 1: zstd frame]
...
[block N: zstd frame]
[block index table: N × 24 B entries]
[block footer: 16 B]
```

**Block index entry** (24 bytes each):

| Field | Size | Description |
|-------|------|-------------|
| `original_offset` | u64 | Logical (decompressed) byte offset from record start |
| `compressed_offset` | u64 | Physical file offset of the compressed block |
| `original_size` | u32 | Decompressed byte count |
| `compressed_size` | u32 | Compressed byte count on disk |

**Block footer** (last 16 bytes of file):

| Field | Size | Description |
|-------|------|-------------|
| `index_offset` | u64 | File offset of the first index entry |
| `block_count` | u32 | Number of compressed blocks |
| `magic` | u32 | `0x51424249` ("QBBI") |

### Legacy stream compression (`HF_COMPRESSED`)

Historical format: the entire record stream after the header is a single zstd frame. No random access. `HF_COMPRESSED` and `HF_BLOCK_COMPRESSED` are mutually exclusive.

## Branch hints

When `HF_BRANCH_HINT` is set, the high nibble of the `nzcv` byte in `REC_INST` encodes the instruction's branch class:

| High nibble | Value | Meaning |
|-------------|-------|---------|
| `0b0000` | 0 | Ordinary instruction (not a branch) |
| `0b0001` | 1 | CALL (BL / BLR) |
| `0b0010` | 2 | RET (RET / RETAA / RETAB) |
| `0b0100` | 4 | BRANCH (B / BR — unconditional non-call jump) |

This encoding costs zero additional bytes and lets the decoder skip the pc_kind table for ~95–98% of instructions. Backward-compatible: old traces never set the high nibble, so old readers see no change.

## AArch64 register indices

GPR indices (used in `regdiff_t.reg_index` and anchor snapshots):

| Index | Register |
|-------|----------|
| 0–28 | x0–x28 |
| 29 | fp (x29) |
| 30 | lr (x30) |
| 31 | sp |
| 32 | nzcv |
| 33 | pc |

FPR indices (used in `fprdiff_t.fpr_index`):

| Index | Register |
|-------|----------|
| 0–31 | v0–v31 (128-bit NEON) |

## Compatibility tiers

Tenet opens any trace with `QBDT` magic and version ≥ 4. Missing records degrade gracefully—only the passes whose inputs are present will run.

### Minimum viable trace

Required: valid `QBDT` magic, version ≥ 4, `REC_INST` records with PC, and at least one `REC_ANCHOR`.

Result: basic instruction listing and address normalization.

### Recommended trace

Add: `HF_REG_DIFF`, `HF_HAS_NZCV`, `HF_HAS_MEM`, `HF_HAS_CODE`, `HF_BRANCH_HINT`, `REC_EVENT`.

Result: full CFG recovery, function boundary detection, call graphs, loop analysis, register reconstruction, memory model, taint analysis.

### Platform-enhanced trace

Add: `REC_SVC`, `REC_OBJC`, `REC_CAPICALL`; v8 traces may also add `HF_CALL_META` and `REC_RETVAL`.

Result: syscall naming, ObjC message resolution, C API argument capture and string inspection; v8 adds inline selectors and true return facts.

### Vector-enhanced trace

Add: `HF_HAS_FPR` (v7).

Result: NEON/vector register reconstruction, crypto algorithm identification.

## Implementing a custom collector

Common alternatives to QBDITrace include **Frida Stalker** (emit `REC_INST` + `REC_ANCHOR` + `REC_CODE` from `Stalker.follow`), DynamoRIO, Pin, or custom emulators such as Unicorn—all that matters is conformance to the binary format described above.

1. Write the 536-byte file header with `magic = 0x51424454`, `version = 4`, and the appropriate `flags`.
2. Emit `REC_ANCHOR` records periodically (every 1024 instructions is a good default). Each anchor must contain the full GPR snapshot.
3. For each executed instruction, emit a `REC_INST` record with the PC (absolute or delta), NZCV, register diffs, and memory accesses.
4. Optionally emit `REC_CODE` records for each distinct PC on first execution.
5. Use block compression for efficient random access: compress in 1 MiB chunks and append the index table and footer.
6. Set `module_base` and `module_slide` correctly so Tenet can normalize runtime addresses back to the static image.

### Minimal example (pseudo-code)

```c
// Write header
qbditrace_file_header_t hdr = {0};
hdr.magic        = 0x51424454;
hdr.version      = 4;
hdr.arch         = 1; // AArch64
hdr.num_gpr      = 34;
hdr.module_base  = runtime_base;
hdr.module_slide = slide;
hdr.trace_start  = range_start;
hdr.trace_end    = range_end;
hdr.flags        = QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_NZCV
                  | QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_CODE
                  | QBDITRACE_HF_BLOCK_COMPRESSED | QBDITRACE_HF_BRANCH_HINT;
strncpy(hdr.module_name, path, 255);
write(fd, &hdr, 536);

// Per instruction:
qbditrace_inst_head_t inst = {0};
inst.kind      = 0;
inst.nzcv      = current_nzcv;
inst.n_regdiff = count_written_regs;
inst.n_mem     = count_mem_accesses;
inst.pc        = runtime_pc;
write(fd, &inst, 16);
write(fd, reg_diffs, inst.n_regdiff * 16);
write(fd, mem_accesses, inst.n_mem * 32);

// Periodically:
qbditrace_anchor_head_t anchor = {0};
anchor.kind = 1;
anchor.pc   = runtime_pc;
write(fd, &anchor, 16);
write(fd, gpr_snapshot, num_gpr * 8);
```

## C API reference

The QBDITrace dylib exposes a stable C ABI for programmatic capture:

```c
int  qbditrace_configure(const qbditrace_config_t *cfg);
int  qbditrace_run_call(uint64_t *ret_out, uint64_t fn,
                        uint32_t argc, const uint64_t *argv);
int  qbditrace_run_at(uint64_t *ret_out, uint64_t start_pc,
                      const uint64_t *gpr31, uint64_t sp, uint64_t lr);
void qbditrace_stop(void);

int         qbditrace_force_anchor(void);
const char *qbditrace_output_path(void);
int         qbditrace_dump_pcring(const char *path);
const qbditrace_stats_t *qbditrace_stats_page(void);
```

See [Capture > Configuration](/en/docs/capture/configuration/) for the Python loader that wraps these calls.
