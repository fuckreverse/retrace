---
title: Memory, strings and value search
sidebar:
  order: 4
---

Tenet reconstructs memory at a chosen moment, discovers strings, captures snapshots, searches for patterns and values, measures entropy and runs YARA rules. Every result is tied to an instruction ID.

## MemoryModel time semantics

`MemoryModel` persists every memory write into RocksDB with keys encoding `[page_addr | page_offset | inst_id]`. Queries answer "what did memory look like at time T" by scanning back to the most recent write at each byte. Each byte carries an independent `known` flag — unwritten bytes surface as `??`.

The time model uses an exclusive `at_inst_id`: queries find writes with `inst_id < at_inst_id` (state *before* instruction N executes). A critical asymmetry handles reads vs. writes:

- **Write @ inst N**: stored as `inst_id = N`, visible when `at_inst_id >= N+1` (new value exists *after* the write).
- **Read @ inst N**: derived record stored as `inst_id = N-1`, visible when `at_inst_id >= N`. A read does not alter memory, so the observed value must be readable at the natural query point (the read instruction itself); otherwise `memread` at that instruction would contradict the raw record seen in `disasm`.

This semantics is guarded by `compute_trace_fingerprint()` schema version (currently 2), which invalidates stale persisted indexes to force rebuild.

Recorded reads can recover data prepared by uninstrumented code (shared cache, system libraries). Data never observed at all remains irretrievable — unless it was captured in a configure-time snapshot (below).

### Configure-time snapshot base layer (v9)

When the trace was recorded with `qbditrace --snapshot-range` (v9 `REC_MEMIMG` records), `MemoryModel` lazily loads those chunks as a **base layer beneath the access logs**. Byte resolution order is: write log → read log → snapshot. The snapshot fills only bytes no traced instruction ever touched — typically globals set up by uninstrumented code before tracing started (decrypted strings or keys in `.data`/`.bss`, runtime-filled tables).

Snapshot bytes carry the sentinel `writer_inst_id` `kSnapshotWriterId` (`UINT64_MAX`, check with `is_snapshot_writer()`): the value is the memory content at trace start (`inst_id 0`), so using it at a later instant is an *explicitly marked approximation*, never a silent one. At `at_inst_id == 0` the snapshot answers directly. Snapshot regions do not count as accesses — they never appear in `active_pages()` or `was_accessed()`.

## Time-aware memory read

`memread` reads a region at a given instant; unknown bytes appear as `??`; each reported byte carries `writer_inst_id`. `--mem-history` lists every recorded write overlapping an address range (up to 500 entries by default). Neither is a Pass — both are direct queries against `MemoryModel`.

```bash
./tenet [options] trace.bin --memread 0x16fdff200 32 50000
./tenet [options] trace.bin --mem-history 0x16fdff200 32
```

:::note[MCP naming]
The CLI uses `--mem-history`, while the MCP tool is named `mem_write_history`. Both query `MemoryModel::write_history()`, but their output shapes differ: CLI prints write details including PC, while MCP returns paginated writer instruction IDs.
:::

## Strings

| Pass | Method | Best for |
|---|---|---|
| `strings` | Time-consistent snapshot per memory write | Stable strings, ObjC selectors, symbol names, constant data |
| `memory_strings` | Live pointer reconstruction at call sites | Transient decrypted/decoded strings |

### How `strings` actually works

`strings` is **not** a "final snapshot" pass. It iterates every memory *write* in the trace (reads are skipped — a read cannot introduce new byte content), reconstructs a small window around the write address **immediately after that instruction executes** (query time `inst_id + 1`), and scans the reconstructed window for ASCII / UTF-16LE runs. All bytes considered together for one string are therefore guaranteed mutually consistent in time — the pass cannot stitch together bytes from different moments into a bogus string.

Because the scan runs at *every* write event, not just the final one, `strings` captures intermediate buffer contents that are later overwritten; the "snapshot per write" framing is more accurate than "final snapshot".

Dedup: consecutive identical writes to the same address (spinlocks, refcounts, hot counters) reuse the previous scan result to avoid repeated RocksDB probes.

```bash
./tenet [options] trace.bin --strings
```

### `memory_strings`

`MemoryStringPass` collects "call site" instructions (BL / BLR / SVC and REC ObjC message sends) by scanning the trace once, then for each call site:

1. Snapshots register state via `RegisterFile::state_before(site.inst_id)`.
2. Reads **x0–x7** and **SP-relative stack** as pointers (`>= min_pointer_value`, default `0x100000000`).
3. For each unique pointer, calls `read_region(ptr, scan_size, call_site_inst_id)` and scans for printable runs.
4. **Deep probe**: a hit truncated by the window edge (not by NUL or non-printable byte) triggers `deep_probe_string()` to walk real write history and recover the full content.

Result sources are labeled as `RegPointer` (with `source_reg` 0–7), `StackLocal` (`source_reg` = 31), or `DeepProbe`.

```bash
./tenet [options] trace.bin --memory-strings
./tenet [options] trace.bin --memory-strings --memory-strings-scan-size 512
./tenet [options] trace.bin --memory-strings --memory-strings-max-sites 2000
```

MCP: `memory_strings` tool.

## Memory snapshots

`memory_snapshot` captures memory regions at explicit `inst_id`s and/or every function-call site. With explicit IDs it snapshots **SP** plus **any of x0–x7** that looks like a pointer; with `snapshot_at_function_calls = true` (the default) it collects pointers at every call event discovered by the (optional) `function` pass. Captured regions are returned in insertion order; the `by_inst_id` index maps each `inst_id` to its snapshots.

Region size is controlled by `--memory-snapshot-size` (default 64). The CLI exposes explicit IDs and size; `snapshot_at_function_calls` is an internal/default configuration rather than a separate CLI flag.

```bash
./tenet [options] trace.bin --memory-snapshot 5000 --memory-snapshot-size 128
./tenet [options] trace.bin --memory-snapshot 5000 --memory-snapshot 6000 --memory-snapshot 7200
```

Two-phase snapshot collection: Phase A collects `(addr, inst_id)` tuples using only `RegisterFile::state_before` (~170 µs/call); Phase B sorts by page number so consecutive reads hit the thread-local page cache, transforming N random RocksDB seeks into a page-sorted sequential access pattern. Memory scaling is bounded by `config_.max_snapshots`.

MCP: `memory_snapshot` tool accepts explicit `inst_ids`; Tauri frontend: **Tools → Memory Snapshot…**

## Value and pattern search

`mem_search` offers two complementary modes within one pass:

| Mode | Input source | Backend |
|---|---|---|
| Byte patterns | `--mem-search "DE AD ?? BE EF"` | YARA Aho-Corasick if available and no wildcards; otherwise mask-based linear scan |
| Exact values | `--mem-search-value 0x9E3779B97F4A7C15` (repeatable) | O(1) hash-map lookup against register diffs, memory-write values, and (with `--mem-search-immediates`) MOVZ/MOVK fields |

`--literal-search` is a deprecated alias for `--mem-search-value`.

`--mem-search-range <start> <end>` limits both modes to an inst_id window. `--run-pass mem_search` is a legacy shorthand and does not configure patterns / values — provide them through the CLI flags above or through Tauri frontend / MCP.

```bash
./tenet [options] trace.bin --mem-search "48 8B ?? ?? 48 89"
./tenet [options] trace.bin --mem-search-value 0x67452301 --mem-search-value 0xEFCDAB89
./tenet [options] trace.bin --mem-search-value 0x9E3779B97F4A7C15 --mem-search-immediates
./tenet [options] trace.bin --mem-search "FF 25" --mem-search-range 10000 50000
```

MCP: `mem_search` tool accepts `patterns` (with `??` wildcards), `exact_values`, `range`, `search_reg_values`, and `search_immediates`.

Tauri frontend: **Tools → Memory / Value Search…**

## Entropy

`entropy` measures Shannon entropy of a memory region at a chosen `inst_id`. Per-block values feed a heuristic classifier:

| Classification | Condition |
|---|---|
| Unknown | known bytes < 8 |
| Plaintext | entropy < 4.0 |
| Compressed | entropy 6.0–7.5 |
| Encrypted | entropy > 7.5 |
| KeyMaterial | entropy 4.0–6.0 and region ≤ 64 bytes |

:::caution[Heuristic only]
These categories are statistical signals, not proof. Compressed data may score below 7.5; small key schedules may score above 4.0. Always corroborate with `pattern` / `taint` / `loop_semantics` evidence before drawing conclusions.
:::

The actual CLI signature is `--entropy <addr_hex> <size>`: the first argument is a hexadecimal memory address and the second is a decimal byte count. Use `--entropy-at <inst_id>` to choose the sampling instant, and `--entropy-timeline` to resample the region at its write-history points.

The Tauri frontend's Entropy panel likewise exposes address, size, sampling instant, and timeline controls. MCP `entropy_analysis` paginates the backend `entropy` pass results.

```bash
./tenet [options] trace.bin --entropy 0x16fdff200 4096
./tenet [options] trace.bin --entropy 0x16fdff200 4096 --entropy-at 5000
./tenet [options] trace.bin --entropy 0x16fdff200 4096 --entropy-timeline
```

MCP: `entropy_analysis` tool.

## YARA memory scan

`yara_mem_scan` runs YARA rules against reconstructed heap / stack memory pages plus optional explicit inst_id scan and an optional code-bytes buffer. Available only when built with `TENET_ENABLE_YARA=ON` (requires `libyara`). The pass is still *registered* in YARA-disabled builds so `tools/list` stays stable, but invoking it returns a clear compile-time error rather than a silent failure.

### Build and rule lookup

- Compile: `cmake .. -DTENET_ENABLE_YARA=ON`.
- Default rule directories are checked in order: `<exe_dir>/rules/`, `<exe_dir>/../rules/`, `<exe_dir>/../../rules/`, followed by compatibility fallbacks `<cwd>/rules` and `<cwd>/../rules`.
- Add custom rules with `--yara-rules <file_or_dir>` (repeatable) or via MCP `rules_dir`.

### Scan options

| Flag | Purpose |
|---|---|
| `--yara-rules <file_or_dir>` | Extra rule file or directory (repeatable) |
| `--yara-min-entropy <N>` | Skip auto-scanned pages where Shannon entropy < N (default 0 = scan all) |
| `--yara-scan-code` | Also scan the reconstructed instruction-byte buffer (for constants embedded in code) |

```bash
./tenet [options] trace.bin --yara-mem-scan
./tenet [options] trace.bin --yara-mem-scan --yara-rules custom.yar --yara-min-entropy 3.0
./tenet [options] trace.bin --yara-mem-scan --yara-scan-code
```

### Troubleshooting

- **"YaraMemScanPass: no .yar rule files found."** The compiler succeeded but zero `.yar` files were found. Verify the rule lookup directories listed in the error message; pass an explicit `--yara-rules`.
- **"YaraMemScanPass: failed to initialize YARA compiler."** `libyara` returned a compiler error. Check your rule syntax with `yarac` first.
- **"YARA support not compiled in"** (Tauri frontend or MCP). This build used `TENET_ENABLE_YARA=OFF`; rebuild with YARA enabled. The menu item is greyed out rather than hidden so users know the feature exists.

MCP: `yara_mem_scan` tool; Tauri frontend: **Tools → YARA Scan…**

## Tauri frontend and MCP quick reference

| Capability | Tauri frontend entry | MCP tool |
|---|---|---|
| Memory read | Right-click addr → "Open in Hex Dump" | `memread` |
| Write history | **Tools → Memory Write History…** | `mem_write_history` |
| Strings | Strings panel | `strings_scan` |
| Call-site strings | Strings panel (second tab) | `memory_strings` |
| Snapshot | **Tools → Memory Snapshot…** | `memory_snapshot` |
| Pattern / value search | **Tools → Memory / Value Search…** | `mem_search` |
| Entropy | **Tools → Entropy…** | `entropy_analysis` |
| YARA scan | **Tools → YARA Scan…** | `yara_mem_scan` |

## Evidence and limits

- All memory results depend on **recorded writes and reads**. Unaccessed pages remain unknown.
- Recorded reads can recover data from uninstrumented code; data never observed at all is irretrievable unless a v9 `REC_MEMIMG` snapshot covers it (snapshot bytes are marked with the `kSnapshotWriterId` sentinel and represent trace-start state).
- `strings` captures each memory write's post-write snapshot, not a single final state — overwritten values at earlier writes are still discoverable.
- `memory_strings` discovers transient call-site arguments that `strings` can miss due to later coverage.
- Both CLI and the Tauri frontend accept an exact address and size. CLI additionally uses `--entropy-at` for the instant and `--entropy-timeline` for the timeline; MCP `entropy_analysis` paginates backend pass results.
- YARA scans real reconstructed memory, not approximations; it is gated behind an optional build flag and must be troubleshot at the rule/compiler level.
