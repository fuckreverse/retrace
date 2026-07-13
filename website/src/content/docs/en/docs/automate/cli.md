---
title: Command-line interface
sidebar:
  order: 2
---

The CLI runs analysis, exports data and produces reports without an interactive session. Every batch analysis mode uses the same pass implementations as the GUI and TUI.

## Batch analysis

```bash
# Structure
./tenet trace.bin --export-cfg func.dot
./tenet trace.bin --call-graph cg.dot
./tenet trace.bin --symbol-annotation

# Taint
./tenet trace.bin --taint 0 --taint-inst 12000
./tenet trace.bin --backward-taint 58000 0
./tenet trace.bin --critical-path --taint 0 --backward-taint 58000 0

# Algorithms
./tenet trace.bin --pattern
./tenet trace.bin --constants
./tenet trace.bin --algorithm-summary
./tenet trace.bin --loop-semantics

# Memory and strings
./tenet trace.bin --strings
./tenet trace.bin --memory-strings
./tenet trace.bin --memread 0x16fdff200 32 50000
./tenet trace.bin --mem-history 0x16fdff200 32
./tenet trace.bin --memory-snapshot 5000

# Platform
./tenet trace.bin --objc
./tenet trace.bin --objc --objc-class NSString
./tenet trace.bin --syscall-intercept

# VM analysis
./tenet trace.bin --vm-abstract
./tenet trace.bin --backward-taint 10000 0 --taint-source-annotation

# Trace tools (instruction-ID ranges)
./tenet trace.bin --trace-fold 10000 50000 --trace-fold-min-iter 3
./tenet trace.bin --trace-diff 10000 20000 30000 40000 --trace-diff-file other.bin
./tenet trace.bin --window-stats 0 100000 --window-stats-size 10000
./tenet trace.bin --reg-timeline 0 --reg-timeline-range 10000 50000
```

## Selecting passes explicitly

```bash
./tenet trace.bin --run-pass function --run-pass xref --run-pass cfg
```

Use `--run-pass` for fine-grained control when the convenience flags do not map to the desired pass set.

## Exclude ranges

```bash
./tenet trace.bin --exclude-range 0x1001000 0x1002000 --exclude-range 0x2001000 0x2002000
```

Exclude ranges filter instructions during analysis. They do not modify the trace file.

## External image

```bash
./tenet trace.bin --image /path/to/binary
```

## Output and reports

Most CLI modes print structured text to stdout. Graph exports (CFG, call graph, dataflow graph) write Graphviz DOT files. Profile supports JSON and CSV. Diff writes JSON. Taint graphs can be exported as JSON with `--backward-taint-graph`.

## Headless considerations

- The CLI reads and writes the same `.tenet/` index as GUI/TUI sessions; it respects the same session lock.
- Long batch runs do not render a UI; they are faster than TUI for large exports.
- Pass results are cached; repeated runs with the same parameters complete quickly.
