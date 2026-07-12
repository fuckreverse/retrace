---
title: Open a trace
sidebar:
  order: 3
---

## Open locally

Launch Tenet Desktop and choose a `.bin` file, or run:

```bash
./tenet /path/to/trace.bin
./tenet --tui /path/to/trace.bin
```

Trace data stays on your Mac; the documentation site receives nothing.

## First-open indexing

The first open scans the record stream and builds a persistent RocksDB index in `<trace-name>.tenet/` beside the trace. It indexes instruction offsets, anchors, register writes, memory history and embedded code. Large traces can take a minute or more. Later opens reuse the index and cached pass results.

Do not routinely delete this directory: it also stores bookmarks, the last cursor position and pass-result blobs. Tenet validates the index against the trace and rebuilds stale data when required.

## Session ownership

Only one Tenet process may open a given trace at a time because all modes share its index and session state. If another GUI, TUI, batch, RPC or MCP process owns it, Tenet reports the owner PID, host, mode and open time. Exit that process; do not delete the lock file. Kernel `flock` releases ownership automatically after a crash.

## Missing code bytes

A trace with `HF_HAS_CODE` normally disassembles without an image. For sampling or legacy traces with missing bytes, provide the matching Mach-O or ELF:

```bash
./tenet trace.bin --image /path/to/binary
```

The image must correspond to the recorded module. Tenet maps runtime PCs using `module_slide` and uses the image only as a code/string fallback.

## Verify the session

After opening, confirm:

1. The instruction timeline has a non-zero count.
2. PCs and module metadata look plausible.
3. Register values change while moving through the timeline.
4. Instructions disassemble, or an external image is configured.
5. Functions and XRefs complete without an evidence warning.

Then continue with [Explore an execution](/en/docs/explore/) or [Analyze a trace](/en/docs/analyze/).
