---
title: Getting started
description: Install, record, open, and explore your first trace.
sidebar:
  order: 0
  label: Overview
---

## The path

1. [Install Tenet](./install/) on an Apple Silicon Mac.
2. [Record a trace](../capture/) with QBDITrace or a compatible collector.
3. [Open it in Tenet](./open-a-trace/) and wait for the first index build.
4. [Understand core concepts](./core-concepts/) — instruction IDs, time-aware state, analysis passes.
5. [Explore the execution](../explore/) — navigate, inspect, set breakpoints, follow calls.

## Trace requirements

Tenet accepts format version 4 or newer. The trace should include register diffs and embedded code for the richest analysis. PC-delta (v5) and FPR (v7) recordings are fully supported by `tenet --dump` and all analysis modes.

## What success looks like

The instruction timeline opens, register values change as you navigate, and default structure passes identify executed functions and cross-references. From there, run targeted analysis passes to follow data flow, recognize algorithms, or inspect platform API calls.
