# Retrace

Retrace is a reverse-engineering toolkit built on [QBDI](https://github.com/QBDI/QBDI)
that records and replays what a binary *actually executed*.

It consists of two cooperating components plus a product website:

| Component | Directory | What it is |
|-----------|-----------|------------|
| **Dashcam** | [`dashcam/`](dashcam/) | The recorder — a high-performance instruction tracer built on QBDI. Compiled as a dylib (iOS) or .so (Android) and injected into the target process via Frida, it captures instruction-level traces (register diffs, memory accesses, syscalls, ObjC messages, C API calls) into compact `.bin` trace files with optional zstd block compression. |
| **Slowmo** | [`slowmo/`](slowmo/) | The analyzer — an offline analysis engine that reads those traces: TUI for interactive browsing, CLI passes for batch analysis (taint, CFG, call graph, crypto / anti-debug pattern detection, algorithm identification, syscall interception), plus a Tauri desktop app ([`slowmo/web/`](slowmo/web/)) for a graphical experience over WebSocket. |
| **Website** | [`website/`](website/) | Astro static site and documentation. |

Dashcam writes, Slowmo reads. The trace binary format they share is
header-defined in [`dashcam/TraceFormat.h`](dashcam/TraceFormat.h)
(documented in [`slowmo/docs/trace-format.md`](slowmo/docs/trace-format.md)).

## Relationship with upstream QBDI

This repo carries **no QBDI source**. Dashcam consumes vanilla upstream
QBDI plus a minimal patch series:

- [`patches/qbdi/`](patches/qbdi/) — the patches (LSE decode fix for Darwin
  AArch64, `QBDI_LOG_FILE` post-mortem logging, iOS build config), pinned to
  an upstream commit recorded in [`patches/qbdi/PIN`](patches/qbdi/PIN)
- [`scripts/prepare-qbdi.sh`](scripts/prepare-qbdi.sh) — clones upstream QBDI
  at the pin, applies the patches, builds the static libraries into the
  `third-party/qbdi/<platform>/` cache
- A CI job re-validates the patch series on every change

## Quick start

```bash
# Slowmo (analyzer) — build & test
cd slowmo
mkdir build && cd build
cmake .. && ninja -j$(nproc)
ctest --output-on-failure

# Dashcam (recorder) — host unit tests (no QBDI needed)
cd ../../dashcam
mkdir build && cd build
cmake .. -G Ninja -DQBDITRACE_BUILD_DYLIB=OFF \
    -DFETCHCONTENT_BASE_DIR=$(pwd)/../../slowmo/_deps
ninja -j$(nproc) && ctest --output-on-failure

# Dashcam — iOS recorder dylib (needs patched QBDI first)
bash scripts/prepare-qbdi.sh ios
bash dashcam/build-dashcam-ios.sh
```

Binary names are kept stable for ABI/compatibility reasons: the recorder
library is still `libqbditrace.{dylib,so}` with the `qbditrace_*` C ABI,
and the analyzer executable is still `tenet`. `Dashcam`/`Slowmo` are the
product-level names for the two components.

See [CLAUDE.md](CLAUDE.md) for the full build matrix (build-directory
conventions, CMake options, trace format contract, CLI reference).

## License

Dashcam and Slowmo inherit the licenses of their components; the trace
format and both tools were developed inside a QBDI fork and carry QBDI's
Apache-2.0 heritage for the recorder's engine dependency. See
[dashcam/README.md](dashcam/README.md) and [slowmo/README.md](slowmo/README.md).
