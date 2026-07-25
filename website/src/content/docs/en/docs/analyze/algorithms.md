---
title: Algorithm and pattern recognition
sidebar:
  order: 5
---

Algorithm recognition answers "does this execution resemble a known construction?" by combining structural patterns, materialized constants, loop semantics and call-graph context. It is evidence aggregation, not proof.

## Pass chain

```text
pattern (+ constants sub-detector)
     + loop_semantics (requires: loop, xref)
     + function
     + call_graph
          └──> algorithm_summary   (declared dependencies; missing results degrade gracefully)
                    │
                    └──> objc_crypto   (requires: pattern, objc)
```

`algorithm_summary` declares all four in its Pass dependency list, so normal scheduling runs them first. Result synthesis still degrades gracefully if one dependency produces no usable result.

## Pattern scan

`pattern` classifies executed instructions across six categories:

| Category | Signal |
|---|---|
| Crypto | AES / SHA hardware-accelerator mnemonics, S-box lookups, common crypto sequences |
| AntiDebug | ptrace syscalls, anti-debug string constants |
| AntiTamper | Integrity-check signatures |
| Obfuscation | MBA / CFF / opaque-predicate signatures |
| Networking | TLS, HTTP, DNS sequence motifs |
| KeySchedule | Identified via known S-box / K/W constant database matches |

Confidence levels:

| Confidence | When assigned |
|---|---|
| High | YARA rule with `meta: confidence = "high"`; known-constant database match |
| Medium | YARA rule with `meta: confidence = "medium"`; loop-like XOR loop; longer (>= 3 part) movz+movk sequences that don't match any known constant |
| Low | Straightline XOR-dense code (many unique PCs, not a tight loop); YARA rule with `meta: confidence = "low"` |

### XOR loop heuristic

A sliding window of "many EOR instructions" alone is **not** sufficient evidence. The detector also tracks distinct PCs per run: a real loop body re-executes a small fixed set of PCs (Medium confidence "XOR loop"), whereas straight-line code keeps visiting new PCs (Low confidence "XOR-dense code (non-loop)").

### HW crypto detection

PatternCollector pre-classifies loop body PCs into `MC_HW_AES` / `MC_HW_SHA` / `MC_EOR` / `MC_MOVZ` / `MC_MOVK` / `MC_SVC`, then site-aggregates to report hardware-accelerator usage counts.

## Constants: pattern's sub-detector

`--constants` is not a separate pass — it is a sub-detector embedded in `pattern`. A single `PatternCollector` scan tracks in-progress `movz` + `movk` construction sequences (state per destination register):

- Finalized sequences matching a known algorithm constant → High-confidence KeySchedule match with `MaterializedConstant` details (value, reg, num_parts, known_match).
- Longer sequences (>= `constants-min-parts`, default 2) that don't match → Medium-confidence "Constant loading sequence".

```bash
./tenet [options] trace.bin --pattern
./tenet [options] trace.bin --constants --constants-min-parts 3
```

`PatternResult::constants` holds the raw `ConstantMaterializationResult`; `PatternResult::matches` contains one entry per identified constant (KeySchedule category) for uniform downstream consumption.

## Loop semantics

`loop_semantics` classifies each loop body (iteration count >= 2) by sampling 2-3 iterations and analyzing feature flags:

| Feature flag | Detection |
|---|---|
| `has_sbox_pattern` | `LDR` with data-dependent register offset (table lookup) |
| `has_xor_mix` | `EOR` instructions present |
| `has_shift_rotate` | `LSL`, `LSR`, `ASR`, `ROR` |
| `has_addition_chain` | 3+ `ADD`/`SUB` |
| `has_modular_arithmetic` | `MUL`/`UDIV` |
| `sbox_pattern_data_dependent` | S-box's data-flow: load index verified to be produced by a mixing op earlier in the same body |

Classification table:

| Classification | Required features | Typical counts | Confidence |
|---|---|---|---|
| Feistel Round | `add_sub >= 2` + left/right swap pattern | Near classical round count | 0.7–0.85 |
| SPN Round | `has_xor_mix` + `has_sbox_pattern` | 8 / 10 / 12 / 14 / 16 / 32 | 0.55–0.85 |
| ARX | `add_sub >= 1` + `shift_rotate >= 1` + `xor >= 1` | Crypto-like | 0.55–0.7 |
| Accumulator | Simple additive body | N/A | 0.5 |
| Memcpy-like | `load_with_reg_offset_count >= total / 3` and no crypto ops | N/A | 0.6 |
| Counter Loop | 1–2 active regs, one counterlike | N/A | 0.6 |

**Confidence gating**: SPN confidence is 0.8 with `sbox_pattern_data_dependent = true`, drops to 0.55 without it (weaker structural heuristic). Feistel/SPN/ARX each get a small bonus when the iteration count is a known crypto value (8/10/12/14/16/32); unknown counts suppress confidence.

Dependencies: `loop` + `xref`.

```bash
./tenet [options] trace.bin --loop-semantics
```

MCP: `loop_semantics` tool; Tauri frontend: Loop Semantics panel.

## Algorithm summary

`algorithm_summary` synthesizes evidence from four declared dependencies (`pattern`, `loop_semantics`, `function`, `call_graph`). Normal scheduling runs the chain first, while result synthesis consumes whatever usable evidence is available and degrades gracefully.

### Phase breakdown

| Phase | What it consumes |
|---|---|
| 1a | Pattern matches (Crypto category) |
| 1b | Known-constant matches (from `pattern.constants`) |
| 1c | Loop semantics — merges into a *named* accumulator if the loop's structural shape (Feistel/SPN/ARX) matches an already-named candidate's `AlgorithmStructure`; otherwise accumulates under an unnamed structure-keyed bucket |
| 1d | Call-graph hot functions — marks any callee exceeding both absolute (`hot_function_min_calls = 25`) and relative (`hot_function_min_ratio = 20%`) thresholds as **speculative** corroborative hints. Real evidence never gets the speculative flag |

### Evidence accumulation

Different detectors phrase the same algorithm differently (for example, an "AES instruction", an AES constant, or an SPN loop). `normalize_algorithm_name()` maps compatible evidence to the same `AlgorithmFamily` accumulator, so an AES constant, an SPN loop, and a hardware-AES pattern can merge into one candidate.

Every candidate carries:
- `AlgorithmFamily` grouping (including AES, DES, Blowfish, Camellia, TEA, SM4, Serpent, ChaCha, Salsa, SHA families, MD5, SM3, HMAC, Poly1305, SipHash, CRC32, ZUC, ECDSA, Ed25519, Curve25519, GCM, or Unknown).
- AlgorithmStructure (Unknown / Feistel / SPN / ARX) used only for cross-referencing loop_semantics shapes.
- `EvidenceAccumulator` items: text, confidence boost, PC / inst_id range.
- `is_speculative` flag — true only for 1d hot-function entries with *no corroborating real evidence*. `confirmed_candidates()` filters these out.
- `confidence` in [0, 1], sorted descending.

```bash
./tenet [options] trace.bin --algorithm-summary
```

MCP: `algorithm_summary` tool; Tauri frontend: Algorithm Summary panel; TUI: `:algosum`.

## ObjC × Crypto

`objc_crypto` correlates PatternMatch hits with the ObjC call stack at the moment they occur, answering "which ObjC method chain triggers this crypto algorithm?" For each PatternMatch it walks backwards from `start_inst_id` in the ordered ObjC message list, collecting up to 8 frames (or stopping if the gap exceeds 500,000 instructions). Patterns inside an ObjC dispatch are indexed by `class_name` and `selector_name`.

Darwin-only: when `target_os` is neither Darwin nor Unknown (and the header says Android/Linux explicitly), the pass returns an empty result immediately.

Hard dependencies: `pattern` + `objc`.

```bash
./tenet [options] trace.bin --objc --pattern --objc-crypto
```

MCP: `objc_crypto` tool; Tauri frontend: ObjC × Crypto panel.

## CLI / Tauri frontend / TUI / MCP reference

| Capability | CLI | Tauri frontend | TUI | MCP |
|---|---|---|---|---|
| Pattern scan | `--pattern` | Patterns panel | `:pattern` | `pattern_scan` |
| Constants | `--constants --constants-min-parts 3` | Constants panel | — | `constants_scan` |
| Loop semantics | `--loop-semantics` | Loop Semantics | `:loop` | `loop_semantics` |
| Algorithm summary | `--algorithm-summary` | Algorithm Summary | `:algosum` | `algorithm_summary` |
| ObjC × Crypto | `--objc-crypto` | ObjC × Crypto | `:objc` | `objc_crypto` |

## Evidence combination in practice

1. **Pattern + known-constant evidence** pinpoints algorithm family via `movz+movk` constant identification + YARA rule hits.
2. **Loop semantics** confirms round *shape* (Feistel/SPN/ARX). The structural shape alone does not name an algorithm (AES/SM4/Serpent are all SPN); it corroborates candidate families.
3. **Singleton crypto hardware mnemonic** (single AESENC instruction) without constants or loop evidence → weak signal; corroborate via taint/memread.
4. **Speculative hot-function candidates** have no corroborating real evidence — verify by navigating to that PC and manually inspecting, or confirm via taint from a known key.
5. Combination recipe: `--pattern --loop-semantics --algorithm-summary` is the minimal end-to-end command.
6. Adding `--objc-crypto` only matters on Darwin traces with ObjC crypto dispatch.
7. `mem_search` and `entropy` are corroborating evidence not fed into `algorithm_summary` directly — run them separately to confirm address-level details.

## Troubleshooting

### `pattern` reports zero matches

- Verify the build used `TENET_ENABLE_YARA=ON`. Without YARA, mnemonic-based detectors (hardware crypto, constant materialization, XOR loops) still run, but rule-backed patterns are absent.
- Long traces with many small functions may need `--sampling` or `--exclude-range` to keep runtime manageable before pattern can complete.

### `loop_semantics` reports "requires 'loop' and 'xref'"

`--loop-semantics` implicitly registers `loop`, `cfg`, and `xref`. If you manually configured pass dependencies, ensure all three are available. When configuring passes programmatically, register `xref`, `cfg`, `loop`, and `loop_semantics`; the CLI `--loop-semantics` path handles the chain automatically.

### `algorithm_summary` finds candidates I don't recognize

`normalize_algorithm_name()` uses fuzzy substring matching. Shorthand detector names may collide (e.g. "AES-192" vs "AES"). Check the `family` field — `AlgorithmFamily::Unknown` means the name couldn't normalize and it sits in its own bucket. Look at `key_pcs` to confirm manually.

### Speculative hot-function on a known utility (memcpy / allocator)

The hot-function heuristic is intentionally weak: internal defaults require at least 25 calls and 20% of the hottest callee. The ordinary CLI does not currently expose these tuning values, so similarly hot utility functions can still surface. Filter via `confirmed_candidates()` or look for corroborating pattern/constant evidence before treating as crypto.

### ObjC × Crypto returns empty results

- Confirm `target_os` = Darwin or Unknown (the heuristic allows Unknown). Android / Linux traces short-circuit to empty.
- Confirm `--objc --pattern` are registered alongside `--objc-crypto`. Without ObjC messages or patterns, there is nothing to correlate.
- `max_lookback_` = 500,000: if the nearest ObjC message is further back, the pattern is classified as "bare". Increase via C++ `ObjcCryptoPass::set_max_lookback()` if needed.
