# Trace Diff Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Redesign TraceDiffPass to support cross-file comparison with automatic resynchronization, handling billion-instruction traces with <150MB working memory.

**Architecture:** Streaming dual-iterator lockstep comparison with hash-table resynchronization. Pass self-manages trace B lifecycle. On-demand index strategy eliminates unnecessary index builds.

**Tech Stack:** C++20, Catch2 (tests), ImGui (GUI), nlohmann::json (CLI/MCP output)

## Global Constraints

- All files under `tools/tenet/src/` and `tools/tenet/tests/`
- Build with existing `tools/tenet/build/` directory (never create new build dirs)
- Follow existing AnalysisPass interface from `pass_manager.h`
- Use existing test fixtures from `tests/fixtures/trace_fixture.h` and `trace_writer.h`
- Backward compat: `--trace-diff` without `--trace-diff-file` = same-trace mode
- Register names: IDX_FP=29, IDX_LR=30, IDX_SP=31, IDX_NZCV=32, IDX_PC=33
- Spec: `docs/superpowers/specs/2026-06-30-trace-diff-redesign-design.md`

---

### Task 1: Rewrite trace_diff_pass.h
### Task 2: Rewrite trace_diff_pass.cpp
### Task 3: Unit Tests
### Task 4: CLI + batch_analysis
### Task 5: GUI panel
### Task 6: MCP + PassRegistry
