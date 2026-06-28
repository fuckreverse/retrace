#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <optional>
#include <variant>
#include <vector>
#include <system_error>
#include <functional>

#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Error handling ────────────────────────────────────────────────────────

enum class ErrorCode {
    Ok = 0,
    FileNotFound,
    InvalidMagic,
    VersionMismatch,
    MmapFailed,
    CorruptedRecord,
    IndexCorrupted,
    RocksDBError,
    CapstoneError,
    OutOfRange,
};

struct Error {
    ErrorCode code;
    std::string message;

    Error(ErrorCode c, std::string msg) : code(c), message(std::move(msg)) {}

    static Error file_not_found(std::string_view path) {
        return {ErrorCode::FileNotFound, std::string("File not found: ") + std::string(path)};
    }
    static Error invalid_magic() {
        return {ErrorCode::InvalidMagic, "Invalid trace file magic"};
    }
    static Error version_mismatch(uint32_t got, uint32_t expected) {
        return {ErrorCode::VersionMismatch,
                "Version mismatch: got " + std::to_string(got) +
                ", expected " + std::to_string(expected)};
    }
    static Error mmap_failed(std::string_view detail) {
        return {ErrorCode::MmapFailed, std::string("mmap failed: ") + std::string(detail)};
    }
    static Error rocksdb_error(std::string_view detail) {
        return {ErrorCode::RocksDBError, std::string("RocksDB error: ") + std::string(detail)};
    }
};

/// Simple Result type (C++17 compatible, no std::expected).
/// On success holds a T; on failure holds an Error.
template<typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)), has_value_(true) {}  // NOLINT
    Result(Error err) : error_(std::move(err)), has_value_(false) {} // NOLINT

    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }

    T& operator*() { return value_; }
    const T& operator*() const { return value_; }
    T* operator->() { return &value_; }
    const T* operator->() const { return &value_; }

    const Error& error() const { return error_; }

private:
    union {
        T value_;
        Error error_;
    };
    bool has_value_;

public:
    ~Result() {
        if (has_value_) value_.~T();
        else error_.~Error();
    }
    Result(Result&& o) noexcept : has_value_(o.has_value_) {
        if (has_value_) new (&value_) T(std::move(o.value_));
        else new (&error_) Error(std::move(o.error_));
    }
    Result& operator=(Result&& o) noexcept {
        if (this != &o) {
            this->~Result();
            new (this) Result(std::move(o));
        }
        return *this;
    }
    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;
};

// ─── Trace constants (AArch64) ─────────────────────────────────────────────

constexpr uint32_t TRACE_MAGIC = 0x51424454u;  // "QBDT"
constexpr uint32_t TRACE_VERSION = 4u;
constexpr uint32_t TRACE_VERSION_MAX = 7u;  // highest supported version

constexpr uint8_t AARCH64_GPR_COUNT = 34;  // x0-x28, fp(x29), lr(x30), sp, nzcv, pc
constexpr uint8_t AARCH64_FPR_COUNT = 32;  // v0-v31 (128-bit each)
constexpr uint8_t IDX_FP   = 29;
constexpr uint8_t IDX_LR   = 30;
constexpr uint8_t IDX_SP   = 31;
constexpr uint8_t IDX_NZCV = 32;
constexpr uint8_t IDX_PC   = 33;

// ─── Record kinds (mirrors TraceFormat.h) ──────────────────────────────────

enum class RecordKind : uint8_t {
    Inst   = 0,
    Anchor = 1,
    Thread = 2,
    Event  = 3,
    Svc    = 4,
    Objc   = 5,
    Code   = 6,
};

// ─── FPR value (128-bit vector register) ─────────────────────────────────

struct FprValue {
    uint64_t lo = 0;  // bits  63:0
    uint64_t hi = 0;  // bits 127:64

    bool operator==(const FprValue& o) const { return lo == o.lo && hi == o.hi; }
    bool operator!=(const FprValue& o) const { return !(*this == o); }
};

// ─── Register state ────────────────────────────────────────────────────────

struct RegState {
    uint64_t gpr[AARCH64_GPR_COUNT]{};        // 272 bytes — x0..x28, fp, lr, sp, nzcv, pc
    FprValue fpr[AARCH64_FPR_COUNT]{};        // 512 bytes — v0..v31 (128-bit each)

    uint64_t pc()   const { return gpr[IDX_PC]; }
    uint64_t sp()   const { return gpr[IDX_SP]; }
    uint64_t lr()   const { return gpr[IDX_LR]; }
    uint64_t fp()   const { return gpr[IDX_FP]; }
    uint32_t nzcv() const { return static_cast<uint32_t>(gpr[IDX_NZCV] & 0xF); }

    void set_pc(uint64_t v)   { gpr[IDX_PC] = v; }
    void set_sp(uint64_t v)   { gpr[IDX_SP] = v; }
    void set_lr(uint64_t v)   { gpr[IDX_LR] = v; }
    void set_nzcv(uint32_t v) { gpr[IDX_NZCV] = v & 0xF; }
};

// ─── LRU Cache (zero-allocation, array-backed intrusive linked list) ──────

/// High-performance LRU Cache using a fixed-size array with intrusive
/// doubly-linked list for O(1) promotion/eviction, and ankerl::unordered_dense
/// flat hash map for O(1) lookups. Zero heap allocations after construction.
///
/// Key insight: instead of std::list (one malloc per node), we pre-allocate
/// a contiguous array of nodes. Each node contains prev/next indices forming
/// a doubly-linked list. This eliminates pointer chasing and reduces cache
/// misses on the hot path (InstructionDecoder decode loop).
template<typename Key, typename Value, typename Hash = ankerl::unordered_dense::hash<Key>>
class LRUCache {
public:
    explicit LRUCache(size_t capacity) : capacity_(capacity) {
        nodes_.resize(capacity);
        map_.reserve(capacity);
        // Initialize sentinel: head_ and tail_ are virtual indices
        // We use size_ to track actual occupancy, not a sentinel node.
    }

    std::optional<std::reference_wrapper<const Value>> get(const Key& key) {
        auto it = map_.find(key);
        if (it == map_.end()) return std::nullopt;
        uint32_t idx = it->second;
        promote(idx);
        return std::cref(nodes_[idx].value);
    }

    Value* get_mutable(const Key& key) {
        auto it = map_.find(key);
        if (it == map_.end()) return nullptr;
        uint32_t idx = it->second;
        promote(idx);
        return &nodes_[idx].value;
    }

    /// Read-only lookup WITHOUT promoting the entry to the LRU head.
    /// Safe to call concurrently with other peek() calls under a shared_lock.
    /// Returns nullptr if absent.  The returned pointer stays valid as long as
    /// the entry is not evicted by a concurrent put() on the same cache.
    ///
    /// Use this on read-heavy hot paths (e.g. MemoryModel::read) where the
    /// LRU recency benefit of promote() is outweighed by the contention of an
    /// exclusive lock — peek() enables std::shared_lock parallel readers.
    const Value* peek(const Key& key) const {
        auto it = map_.find(key);
        if (it == map_.end()) return nullptr;
        return &nodes_[it->second].value;
    }

    void put(const Key& key, Value value) {
        auto it = map_.find(key);
        if (it != map_.end()) {
            // Update existing
            uint32_t idx = it->second;
            nodes_[idx].value = std::move(value);
            promote(idx);
            return;
        }

        uint32_t idx;
        if (size_ < capacity_) {
            // Use next free slot
            idx = size_++;
            nodes_[idx].key = key;
            nodes_[idx].value = std::move(value);
            // Link at head
            link_at_head(idx);
        } else {
            // Evict LRU (tail)
            idx = tail_;
            map_.erase(nodes_[idx].key);
            // Unlink from tail
            unlink(idx);
            // Reuse node
            nodes_[idx].key = key;
            nodes_[idx].value = std::move(value);
            // Link at head
            link_at_head(idx);
            generation_.fetch_add(1, std::memory_order_relaxed);
        }
        map_[key] = idx;
    }

    size_t size() const { return size_; }
    size_t capacity() const { return capacity_; }

    /// Monotonically increasing counter bumped on every eviction or erasure.
    /// External caches can snapshot this to detect when their pointers might
    /// be stale (the pointed-to slot may have been reused for a different key).
    uint64_t generation() const { return generation_.load(std::memory_order_relaxed); }

    /// Remove a single entry by key (no-op if not found).
    void erase(const Key& key) {
        auto it = map_.find(key);
        if (it == map_.end()) return;
        uint32_t idx = it->second;
        unlink(idx);
        map_.erase(it);
        size_--;
        generation_.fetch_add(1, std::memory_order_relaxed);
    }

    /// Alias for erase() — invalidate a cached entry.
    void invalidate(const Key& key) { erase(key); }

    void clear() {
        map_.clear();
        size_ = 0;
        head_ = NIL;
        tail_ = NIL;
    }

    void set_capacity(size_t cap) {
        // For simplicity, only allow setting capacity before use or after clear
        if (size_ == 0) {
            capacity_ = cap;
            nodes_.resize(cap);
            map_.reserve(cap);
        }
        // If shrinking with existing data, evict from tail
        while (size_ > cap) {
            uint32_t idx = tail_;
            map_.erase(nodes_[idx].key);
            unlink(idx);
            size_--;
        }
        capacity_ = cap;
    }

private:
    static constexpr uint32_t NIL = UINT32_MAX;

    struct Node {
        Key key{};
        Value value{};
        uint32_t prev = NIL;
        uint32_t next = NIL;
    };

    /// Remove node from its current position in the list.
    void unlink(uint32_t idx) {
        auto& node = nodes_[idx];
        if (node.prev != NIL) {
            nodes_[node.prev].next = node.next;
        } else {
            head_ = node.next;
        }
        if (node.next != NIL) {
            nodes_[node.next].prev = node.prev;
        } else {
            tail_ = node.prev;
        }
        node.prev = NIL;
        node.next = NIL;
    }

    /// Insert node at the head (most recently used).
    void link_at_head(uint32_t idx) {
        auto& node = nodes_[idx];
        node.prev = NIL;
        node.next = head_;
        if (head_ != NIL) {
            nodes_[head_].prev = idx;
        }
        head_ = idx;
        if (tail_ == NIL) {
            tail_ = idx;
        }
    }

    /// Move an existing node to the head (promote on access).
    void promote(uint32_t idx) {
        if (idx == head_) return;  // Already at head
        unlink(idx);
        link_at_head(idx);
    }

    size_t capacity_;
    size_t size_ = 0;
    std::atomic<uint64_t> generation_{0};
    uint32_t head_ = NIL;
    uint32_t tail_ = NIL;
    std::vector<Node> nodes_;
    ankerl::unordered_dense::map<Key, uint32_t, Hash> map_;
};

}  // namespace tenet
