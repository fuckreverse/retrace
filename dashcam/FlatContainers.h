/*
 * qbditrace - high performance instruction tracer built on QBDI
 *
 * FlatContainers.h
 *
 * Lock-free, allocation-light flat containers used on the per-instruction hot
 * path.  Extracted into a standalone header so they can be unit-tested without
 * pulling in the full tracer or QBDI.
 *
 *   WriteRegList       — tiny inline list of GPR/FPR indices written by one insn
 *   FlatPcSet          — open-addressing hash set of uint64_t (PC dedup)
 *   FlatWriteRegCache  — open-addressing hash map PC → WriteRegList
 *
 * All three are designed for contiguous memory layout (cache-friendly), use
 * Fibonacci hashing on 4-byte-aligned AArch64 PC values, and treat key 0 as
 * the empty sentinel (PC 0 is never a valid instruction address).
 */
#ifndef QBDITRACE_FLAT_CONTAINERS_H_
#define QBDITRACE_FLAT_CONTAINERS_H_

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace qbditrace {

/* ──────────────────────────────────────────────────────────────────────────────
 * WriteRegList
 *
 * GPR indices (0..30) and FPR indices (0..31) written by a single AArch64
 * instruction.  AArch64 rarely writes more than 2 GPRs (ldp) or 2 FPRs
 * per opcode, so a small inline array suffices.
 * ────────────────────────────────────────────────────────────────────────── */
struct WriteRegList {
  uint8_t count    = 0;
  uint8_t idx[8]   = {0};      /* GPR write indices */
  uint8_t fpr_count = 0;
  uint8_t fpr_idx[8] = {0};    /* FPR write indices */
};

/* ──────────────────────────────────────────────────────────────────────────────
 * FlatPcSet
 *
 * Per-thread flat open-addressing hash set of uint64_t keys.  Used for CODE
 * record deduplication (emit each distinct PC only once).
 *
 * Sentinel: key 0 = empty.  Linear probing with Fibonacci hash.
 * ────────────────────────────────────────────────────────────────────────── */
struct FlatPcSet {
  static constexpr uint64_t kEmpty   = 0;
  static constexpr size_t   kInitCap = 8192;  /* power of two; ~64 KiB */
  static constexpr double   kMaxLoad = 0.75;

  uint64_t *slots_ = nullptr;
  size_t    cap_   = 0;
  size_t    size_  = 0;

  FlatPcSet() { resize(kInitCap); }

  explicit FlatPcSet(size_t initial_cap) {
    /* Round up to power of two. */
    size_t cap = 16;
    while (cap < initial_cap) cap *= 2;
    resize(cap);
  }

  ~FlatPcSet() { std::free(slots_); }

  /* Non-copyable, movable. */
  FlatPcSet(const FlatPcSet &) = delete;
  FlatPcSet &operator=(const FlatPcSet &) = delete;
  FlatPcSet(FlatPcSet &&o) noexcept
      : slots_(o.slots_), cap_(o.cap_), size_(o.size_) {
    o.slots_ = nullptr; o.cap_ = 0; o.size_ = 0;
  }
  FlatPcSet &operator=(FlatPcSet &&o) noexcept {
    if (this != &o) {
      std::free(slots_);
      slots_ = o.slots_; cap_ = o.cap_; size_ = o.size_;
      o.slots_ = nullptr; o.cap_ = 0; o.size_ = 0;
    }
    return *this;
  }

  size_t size() const { return size_; }
  size_t capacity() const { return cap_; }

  /* Returns true if newly inserted, false if already present. */
  bool insert(uint64_t pc) {
    if (size_ >= (size_t)(cap_ * kMaxLoad)) {
      resize(cap_ * 2);
    }
    size_t mask = cap_ - 1;
    size_t idx = (size_t)((pc >> 2) * 0x9E3779B97F4A7C15ULL) & mask;
    for (;;) {
      uint64_t s = slots_[idx];
      if (s == pc)    return false;   /* already present */
      if (s == kEmpty) {
        slots_[idx] = pc;
        ++size_;
        return true;                  /* newly inserted */
      }
      idx = (idx + 1) & mask;        /* linear probe */
    }
  }

  /* Returns true if the key is present. */
  bool contains(uint64_t pc) const {
    if (!slots_ || cap_ == 0) return false;
    size_t mask = cap_ - 1;
    size_t idx = (size_t)((pc >> 2) * 0x9E3779B97F4A7C15ULL) & mask;
    for (;;) {
      uint64_t s = slots_[idx];
      if (s == pc)    return true;
      if (s == kEmpty) return false;
      idx = (idx + 1) & mask;
    }
  }

private:
  void resize(size_t new_cap) {
    uint64_t *old = slots_;
    size_t old_cap = cap_;
    cap_ = new_cap;
    slots_ = (uint64_t *)std::calloc(cap_, sizeof(uint64_t));
    size_ = 0;
    if (old) {
      for (size_t i = 0; i < old_cap; ++i) {
        if (old[i] != kEmpty) insert(old[i]);
      }
      std::free(old);
    }
  }
};

/* ──────────────────────────────────────────────────────────────────────────────
 * FlatWriteRegCache
 *
 * Per-thread flat open-addressing hash map: PC (uint64_t) → WriteRegList.
 * Used to cache the operand-analysis result per distinct PC, avoiding the
 * global shared_mutex on the hot path.
 *
 * Parallel arrays (keys_[], vals_[]) with Fibonacci hash + linear probing.
 * Sentinel key 0 = empty.
 * ────────────────────────────────────────────────────────────────────────── */
struct FlatWriteRegCache {
  static constexpr uint64_t kEmpty   = 0;
  static constexpr size_t   kInitCap = 8192;  /* power of two; ~144 KiB */
  static constexpr double   kMaxLoad = 0.75;

  uint64_t     *keys_ = nullptr;
  WriteRegList *vals_ = nullptr;
  size_t        cap_  = 0;
  size_t        size_ = 0;

  FlatWriteRegCache() { resize(kInitCap); }

  explicit FlatWriteRegCache(size_t initial_cap) {
    size_t cap = 16;
    while (cap < initial_cap) cap *= 2;
    resize(cap);
  }

  ~FlatWriteRegCache() { std::free(keys_); std::free(vals_); }

  /* Non-copyable, movable. */
  FlatWriteRegCache(const FlatWriteRegCache &) = delete;
  FlatWriteRegCache &operator=(const FlatWriteRegCache &) = delete;
  FlatWriteRegCache(FlatWriteRegCache &&o) noexcept
      : keys_(o.keys_), vals_(o.vals_), cap_(o.cap_), size_(o.size_) {
    o.keys_ = nullptr; o.vals_ = nullptr; o.cap_ = 0; o.size_ = 0;
  }
  FlatWriteRegCache &operator=(FlatWriteRegCache &&o) noexcept {
    if (this != &o) {
      std::free(keys_); std::free(vals_);
      keys_ = o.keys_; vals_ = o.vals_; cap_ = o.cap_; size_ = o.size_;
      o.keys_ = nullptr; o.vals_ = nullptr; o.cap_ = 0; o.size_ = 0;
    }
    return *this;
  }

  size_t size() const { return size_; }
  size_t capacity() const { return cap_; }

  /* Returns pointer to cached WriteRegList, or nullptr if not found. */
  const WriteRegList *find(uint64_t pc) const {
    if (!keys_ || cap_ == 0) return nullptr;
    size_t mask = cap_ - 1;
    size_t idx = (size_t)((pc >> 2) * 0x9E3779B97F4A7C15ULL) & mask;
    for (;;) {
      uint64_t k = keys_[idx];
      if (k == pc)    return &vals_[idx];
      if (k == kEmpty) return nullptr;
      idx = (idx + 1) & mask;
    }
  }

  void insert(uint64_t pc, const WriteRegList &wl) {
    if (size_ >= (size_t)(cap_ * kMaxLoad)) {
      resize(cap_ * 2);
    }
    size_t mask = cap_ - 1;
    size_t idx = (size_t)((pc >> 2) * 0x9E3779B97F4A7C15ULL) & mask;
    while (keys_[idx] != kEmpty && keys_[idx] != pc) {
      idx = (idx + 1) & mask;
    }
    bool is_new = (keys_[idx] == kEmpty);
    keys_[idx] = pc;
    vals_[idx] = wl;
    if (is_new) ++size_;
  }

private:
  void resize(size_t new_cap) {
    uint64_t     *old_keys = keys_;
    WriteRegList *old_vals = vals_;
    size_t old_cap = cap_;
    cap_  = new_cap;
    keys_ = (uint64_t *)std::calloc(cap_, sizeof(uint64_t));
    vals_ = (WriteRegList *)std::calloc(cap_, sizeof(WriteRegList));
    size_ = 0;
    if (old_keys) {
      for (size_t i = 0; i < old_cap; ++i) {
        if (old_keys[i] != kEmpty) insert(old_keys[i], old_vals[i]);
      }
      std::free(old_keys);
      std::free(old_vals);
    }
  }
};

} // namespace qbditrace

#endif /* QBDITRACE_FLAT_CONTAINERS_H_ */
