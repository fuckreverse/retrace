# Retrace QBDI patches

This directory carries the minimal set of fixes Retrace needs on top of
vanilla upstream QBDI. The dashcam recorder's dylib links QBDI **from
source, patched here** — official prebuilt artifacts cannot be used, because
patch 0002 changes code that is compiled into `libQBDI.a`.

## Patch inventory

| Patch | Why it exists |
|-------|---------------|
| `0001-aarch64-lse-decode-fix.patch` | Darwin AArch64 hosts mis-detected as ARMv8.0 (e.g. A11) cannot decode LSE atomics (`casa`) present in Apple's system libraries; QBDI aborts with "Disassembly error". Enables `+lse` for decoding only — inert on genuine v8.0 hardware. |
| `0002-log-file-env-vars.patch` | Post-mortem diagnostics on iOS: `QBDI_LOG_FILE` redirects logs to a file (flushed on abort), `QBDI_LOG_PRIORITY` sets the level. dashcam's crash-site logging relies on `QBDI_LOG_FILE`. |
| `0003-ios-build-config.patch` | iOS cross-build config: deployment target 15.0 → 12.0, pin `-DCMAKE_OSX_ARCHITECTURES=arm64`. |

## Workflow

`patches/qbdi/PIN` records the exact upstream QBDI commit the patches are
rebased on. `scripts/prepare-qbdi.sh` clones vanilla QBDI at that commit,
applies the patch series, and builds the static libraries per platform:

```bash
# host (macOS arm64) — cache at third-party/qbdi/<platform>/
bash scripts/prepare-qbdi.sh ios
bash scripts/prepare-qbdi.sh android   # needs NDK_PATH
```

**Rebasing patches**: fetch upstream, pick the new pin commit, re-apply the
series with `git am -3` (or resolve by hand), regenerate the patch files,
update `PIN`. A CI job applies the series against upstream at `PIN` on every
push to `patches/` so bitrot is caught immediately.

Both fixes are candidates for upstreaming to
[QBDI/QBDI](https://github.com/QBDI/QBDI) — once merged, shrink the series.
