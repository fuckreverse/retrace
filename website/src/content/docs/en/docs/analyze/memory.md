---
title: Memory, strings and value search
sidebar:
  order: 4
---

Tenet reconstructs memory at a chosen moment, discovers strings, captures snapshots, searches for patterns and values, measures entropy and runs YARA rules. Every result is tied to an instruction ID.

## Time-aware memory read

`memread` reads a memory region at a given point in the timeline; unknown bytes appear as `??`. `mem_history` lists all recorded writes overlapping an address range. These are queries, not passes.

```bash
./tenet trace.bin --memread 0x16fdff200 32 50000
./tenet trace.bin --mem-history 0x16fdff200 32
```

## Strings

| Pass | Method | Best for |
|---|---|---|
| `strings` | Final-snapshot scan | Known strings, ObjC selectors, symbol names |
| `memory_strings` | Time-aware scan at call sites | Transient decrypted/decoded strings |

`memory_strings` inspects registers and stack at call sites for live pointers. It can discover strings that existed only during the call and were overwritten later.

```bash
./tenet trace.bin --strings
./tenet trace.bin --memory-strings --memory-strings-scan-size 512
```

## Memory snapshots

`memory_snapshot` captures a region at a given instruction ID. Combine with `--memory-snapshot-size` to control bytes per region.

```bash
./tenet trace.bin --memory-snapshot 5000 --memory-snapshot-size 128
```

## Value and pattern search

`mem_search` finds byte patterns, exact values, register values and immediates:

```bash
./tenet trace.bin --run-pass mem_search
```

Configure via GUI or MCP: byte patterns with `??` wildcards, exact 8/16/32/64-bit values, register values at selected time, and immediate operand scan. `literal_search` is a deprecated alias.

## Entropy

`entropy` measures Shannon entropy of a memory region at a chosen instruction ID. High entropy is only one classification signal; it does not independently prove encryption. For precise region selection, prefer GUI or MCP `entropy_analysis` over the compatibility CLI form.

## YARA memory scan

`yara_mem_scan` applies YARA rules to memory pages. Provide custom rule files via `--yara-rules` and skip low-entropy pages with `--yara-min-entropy`. Code buffer scanning with `--yara-scan-code`.

```bash
./tenet trace.bin --yara-mem-scan --yara-rules custom.yar --yara-min-entropy 3.0
```

YARA support requires an optional build dependency; it is not available on every installation.

## Evidence and limits

- All memory results depend on recorded writes and reads. Unaccessed pages remain unknown.
- Recorded reads can recover data from uninstrumented code; data not observed at all is irretrievable.
- Final-snapshot strings reflect only the last recorded write. Use `memory_strings` for transient values.
- The GUI/MCP entropy form allows exact address/size control; the CLI compatibility form does not fully expose these.
- YARA scans real reconstructed memory, not approximations.
