---
title: Record, open, and analyze
sidebar:
  order: 3
---

**Goal:** record an iOS function and run a first analysis.  
**Prerequisite:** a deployed QBDITrace library, a reachable Frida service, and the target's static entry offset.

This tutorial uses iOS; for Android capture, see the corresponding [platform guide](/en/docs/capture/android/).

## Record

```bash
python3 tools/qbditrace/qbditrace_runner.py \
  --target com.example.app \
  --entry 0xEE91EC \
  --output /var/mobile/Documents/trace.bin
```

Use runtime addresses when configuring the C ABI directly. The runner resolves the module and ASLR information for its supported flows.

## Open and navigate

Open the `.bin` file in the standalone Tauri desktop application. Alternatively, run the backend directly to enter the terminal TUI by default:

```bash
./tenet trace.bin
```

The first open builds a persistent index; later opens reuse it. Navigate by instruction ID or PC and compare the register panel before and after a selected instruction.

## Run a first analysis

Start with structure recovery: functions, XRefs, CFG, and call graph. Then choose an output register or memory sink and run backward taint to find contributing sources.

## Expected result

You can move between repeated executions of a PC, inspect register state, and follow the evidence behind a value rather than reading a static path that may never execute.
