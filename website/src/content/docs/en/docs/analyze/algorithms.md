---
title: Algorithm and pattern recognition
sidebar:
  order: 5
---

Algorithm recognition answers "does this execution resemble a known construction?" by combining structural patterns, materialized constants, loop semantics and call-graph context.

## Pass chain

```text
pattern + loop_semantics + function + call_graph ──> algorithm_summary
                                              └──> objc_crypto
```

## Pattern scan

`pattern` classifies executed instructions into crypto, anti-debug, anti-tamper, obfuscation and networking patterns. `constants` (formerly a separate `constant_materialization` pass) extracts `movz` + `movk` chains and known algorithm constants such as AES S-box entries, SHA K/W, ChaCha quarter-round constants and ARIA S-box values.

```bash
./tenet trace.bin --pattern
./tenet trace.bin --constants --constants-min-parts 3
```

## Loop semantics

`loop_semantics` classifies loop bodies:

| Classification | Meaning |
|---|---|
| Feistel | Feistel round structure |
| SPN | Substitution-permutation network |
| ARX | Add-rotate-XOR construction |
| Shift/Rotate | Shift or rotate dominant |
| Accumulator | Value accumulation |
| Memcpy-like | Memory copy or transform |
| Counter Loop | Simple counting iteration |

One loop may carry multiple labels. Classification depends on recorded code; sampling or missing code can reduce confidence.

```bash
./tenet trace.bin --loop-semantics
```

## Algorithm summary

`algorithm_summary` merges patterns, constants, loop evidence and call-graph structure to produce algorithm candidates. Each candidate belongs to a structured `AlgorithmFamily` (AES, SHA256, ChaCha, etc.) and carries:

- Evidence items with sources (pattern, constant, loop, call-graph).
- An `is_speculative` flag marking candidates supported only by weak evidence such as high call frequency. `confirmed_candidates()` filters these out.

This is an **evidence aggregation** pass. It does not prove that the identified algorithm was the only possible one; it reports which known constructions match the observed evidence.

```bash
./tenet trace.bin --algorithm-summary
```

## ObjC × Crypto

`objc_crypto` correlates pattern hits with ObjC call stacks to answer "which ObjC method triggered this crypto operation?" Darwin-only; Android/Linux traces produce an empty result.

```bash
./tenet trace.bin --objc --pattern --objc-crypto
```

## Interpreting results

1. **Pattern + constant evidence** identifies algorithm families.
2. **Loop semantics** confirms round structure (Feistel/SPN/ARX/…).
3. **Algorithm summary** cross-references all evidence for confidence.
4. **Speculative candidates** need further verification—check confirmed candidates first.
5. Results are tied to what was recorded. If the target uses an unrecorded path or an algorithm not in the known-constant table, detection will be incomplete.
