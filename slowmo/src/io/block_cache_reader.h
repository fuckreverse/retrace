#pragma once
/*
 * BlockCacheReader — on-demand decompression with LRU cache for
 * block-compressed trace files (HF_BLOCK_COMPRESSED).
 *
 * Replaces the old "decompress everything to a temp file" approach.
 * The compressed file stays mmap'd (hundreds of MB), and individual 1 MB
 * blocks are decompressed into heap memory on demand.
 *
 * Thread safety:
 *   - All public methods are thread-safe (internal mutex).
 *   - data_at() returns a raw pointer whose lifetime is governed by the
 *     pin/unpin mechanism (see below).
 *
 * Pin / unpin:
 *   Callers that hold pointers across non-trivial scopes must pin the
 *   relevant block(s) to prevent LRU eviction.  Two granularities:
 *     - pin_all() / unpin_all()   — freeze the entire cache (used by
 *       index_builder Phase 0/1, multi-thread shard scans)
 *     - Individual block pinning is implicit: a block whose refcount > 0
 *       is never evicted.
 *
 *   For the common case (record_at → as_inst → read values → done, all
 *   within one function), no explicit pinning is needed: the block stays
 *   in the cache long enough.
 */

#include "TraceFormat.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#if TENET_HAS_ZSTD
#include <zstd.h>
#endif

namespace tenet {

class BlockCacheReader {
public:
    BlockCacheReader() = default;
    ~BlockCacheReader();

    // Non-copyable, movable
    BlockCacheReader(const BlockCacheReader&) = delete;
    BlockCacheReader& operator=(const BlockCacheReader&) = delete;
    BlockCacheReader(BlockCacheReader&& o) noexcept;
    BlockCacheReader& operator=(BlockCacheReader&& o) noexcept;

    /// Initialize from a mmap'd block-compressed file.
    /// `mapped` points to the entire file; `file_size` is its length.
    /// `header_size` is the file header size (536 bytes) — logical offsets
    /// in the block index are relative to the end of the header.
    /// Returns false if the footer/index is corrupt.
    bool init(const uint8_t* mapped, uint64_t file_size, uint64_t header_size,
              size_t max_cached_blocks = 256);

    /// Return a pointer to byte at `logical_offset` (0 = first record byte,
    /// i.e. right after the 536-byte header in the decompressed stream).
    ///
    /// The caller may read up to `kOverlapBytes` contiguous bytes starting
    /// from the returned pointer, even if the read crosses a block boundary.
    /// (Records in the trace are written without regard for block boundaries,
    /// so a single record can straddle two adjacent blocks.)
    ///
    /// The returned pointer is valid until the containing block is evicted
    /// from the cache. Use pin_all()/unpin_all() if you need longer lifetime.
    const uint8_t* data_at(uint64_t logical_offset);

    /// Total decompressed size of the record stream (sum of all block
    /// original_size values).  Equivalent to `file_size - header_size` for
    /// an uncompressed file.
    uint64_t logical_size() const { return logical_size_; }

    /// Whether the block index was recovered by scanning (no valid footer).
    bool was_recovered() const { return recovered_; }

    /// Human-readable recovery summary (empty if not recovered).
    const std::string& recovery_message() const { return recovery_msg_; }

    /// Number of blocks in the index.
    uint32_t block_count() const { return static_cast<uint32_t>(index_.size()); }

    /// Decompress a block and return a contiguous buffer for bulk scanning.
    /// `block_id` must be in [0, block_count()).
    /// `out_data`   → pointer to the decompressed bytes
    /// `out_size`   → decompressed size in bytes
    /// `out_logical_offset` → logical offset of the first byte of this block
    ///                        (relative to the record stream, i.e. after header)
    /// Returns false on decompression error.
    ///
    /// The returned buffer is owned by the caller (via `out_buf`) and remains
    /// valid until `out_buf` is destroyed.  This bypasses the LRU cache
    /// entirely to avoid mutex contention in bulk-scan scenarios.
    bool decompress_block(uint32_t block_id,
                          std::vector<uint8_t>& out_buf,
                          const uint8_t*& out_data,
                          uint32_t& out_size,
                          uint64_t& out_logical_offset) const;

    /// Prevent ALL cached blocks from being evicted.  Must be balanced by
    /// unpin_all().  Nested calls are supported (refcounted).
    void pin_all();
    void unpin_all();

    /// Find the block index for a given logical offset via binary search.
    /// Returns the block_id such that index_[block_id].original_offset
    /// <= logical_offset < index_[block_id+1].original_offset.
    uint32_t find_block(uint64_t logical_offset) const;

    /// Create an independent clone that shares the same mmap and block index
    /// but has its own LRU cache and ZSTD decompression context.
    /// Use this to give each scanning thread its own reader, eliminating
    /// mutex contention on the shared cache.
    std::unique_ptr<BlockCacheReader> clone(size_t max_cached_blocks = 32) const;

private:
    struct CachedBlock {
        uint32_t block_id = UINT32_MAX;  // which block index entry
        std::vector<uint8_t> data;       // decompressed bytes
        std::vector<uint8_t> overlap;    // overlap from next block (for cross-block reads)
        uint32_t access_tick = 0;        // LRU timestamp
        uint32_t pin_count = 0;          // per-block pin (for future use)
    };

    /// Decompress block `block_id` and return a reference to its CachedBlock.
    /// Caller must hold mtx_.
    CachedBlock& ensure_block(uint32_t block_id);

    /// Evict the least-recently-used unpinned block. Caller must hold mtx_.
    void evict_one();

    /// Maximum contiguous bytes that data_at() guarantees beyond the
    /// requested offset.  Must be >= the largest possible trace record.
    /// AArch64 v7 + OLD_VALUE INST record ≈ 22.5 KB; round up to 32 KB.
    static constexpr size_t kOverlapBytes = 32 * 1024;

    /// Decompress block `block_id` into `dst` (append mode) at
    /// `dst_offset`, writing up to `max_bytes` decompressed bytes.
    /// Returns the number of bytes actually written.
    /// Caller must hold mtx_.  Does NOT go through the cache.
    size_t decompress_block_raw(uint32_t block_id,
                                std::vector<uint8_t>& dst,
                                size_t dst_offset,
                                size_t max_bytes);

#if TENET_HAS_ZSTD
    /// Recover block index by scanning zstd frames from header_size to EOF.
    /// Used when the footer/index is missing (e.g. truncated trace).
    /// Returns true if at least one block was recovered.
    bool recover_index();
#endif

    const uint8_t* mapped_ = nullptr;
    uint64_t file_size_ = 0;
    uint64_t header_size_ = 0;

    std::vector<qbditrace::qbditrace_block_entry_t> index_;
    uint64_t logical_size_ = 0;
    bool recovered_ = false;  // true if index was rebuilt from scanning
    std::string recovery_msg_;  // human-readable recovery summary

    // LRU cache
    std::vector<CachedBlock> cache_;
    size_t max_cached_ = 256;
    uint32_t tick_ = 0;

    // Global pin
    uint32_t global_pin_ = 0;

    std::mutex mtx_;

#if TENET_HAS_ZSTD
    ZSTD_DCtx* dctx_ = nullptr;
#endif
};

// ─── Inline implementation ─────────────────────────────────────────────────

inline BlockCacheReader::~BlockCacheReader() {
#if TENET_HAS_ZSTD
    if (dctx_) ZSTD_freeDCtx(dctx_);
#endif
}

inline BlockCacheReader::BlockCacheReader(BlockCacheReader&& o) noexcept
    : mapped_(o.mapped_), file_size_(o.file_size_),
      header_size_(o.header_size_), index_(std::move(o.index_)),
      logical_size_(o.logical_size_), cache_(std::move(o.cache_)),
      max_cached_(o.max_cached_), tick_(o.tick_), global_pin_(o.global_pin_)
{
    o.mapped_ = nullptr;
    o.file_size_ = 0;
#if TENET_HAS_ZSTD
    dctx_ = o.dctx_;
    o.dctx_ = nullptr;
#endif
}

inline BlockCacheReader& BlockCacheReader::operator=(BlockCacheReader&& o) noexcept {
    if (this != &o) {
#if TENET_HAS_ZSTD
        if (dctx_) ZSTD_freeDCtx(dctx_);
        dctx_ = o.dctx_;
        o.dctx_ = nullptr;
#endif
        mapped_ = o.mapped_; o.mapped_ = nullptr;
        file_size_ = o.file_size_; o.file_size_ = 0;
        header_size_ = o.header_size_;
        index_ = std::move(o.index_);
        logical_size_ = o.logical_size_;
        cache_ = std::move(o.cache_);
        max_cached_ = o.max_cached_;
        tick_ = o.tick_;
        global_pin_ = o.global_pin_;
    }
    return *this;
}

inline bool BlockCacheReader::init(const uint8_t* mapped, uint64_t file_size,
                                    uint64_t header_size, size_t max_cached_blocks) {
    mapped_ = mapped;
    file_size_ = file_size;
    header_size_ = header_size;
    max_cached_ = max_cached_blocks;

#if TENET_HAS_ZSTD
    // We need dctx for both normal init and recovery, so create it early.
    dctx_ = ZSTD_createDCtx();
    if (!dctx_) return false;
#endif

    bool footer_ok = false;

    // Try reading footer (last 16 bytes)
    if (file_size >= header_size + sizeof(qbditrace::qbditrace_block_footer_t)) {
        qbditrace::qbditrace_block_footer_t footer;
        std::memcpy(&footer,
                    mapped + file_size - sizeof(footer),
                    sizeof(footer));

        if (footer.magic == QBDITRACE_BLOCK_INDEX_MAGIC &&
            footer.block_count > 0) {
            uint64_t table_size = footer.block_count *
                                  sizeof(qbditrace::qbditrace_block_entry_t);
            if (footer.index_offset + table_size <= file_size - sizeof(footer)) {
                // Footer and index table look valid.
                index_.resize(footer.block_count);
                std::memcpy(index_.data(),
                            mapped + footer.index_offset,
                            table_size);
                footer_ok = true;
            }
        }
    }

    // If footer is missing/corrupt, try to recover by scanning zstd frames.
    if (!footer_ok) {
#if TENET_HAS_ZSTD
        if (!recover_index())
            return false;
#else
        return false;
#endif
    }

    // Compute logical size
    logical_size_ = 0;
    for (auto& e : index_) {
        uint64_t end = e.original_offset + e.original_size;
        if (end > logical_size_) logical_size_ = end;
    }

    // Pre-allocate cache slots
    size_t slots = max_cached_ < index_.size() ? max_cached_ : index_.size();
    cache_.resize(slots);

    return true;
}

#if TENET_HAS_ZSTD
inline bool BlockCacheReader::recover_index() {
    // Scan from right after the header, identifying independent zstd frames.
    // Each block produced by the writer is a self-contained zstd frame
    // (with checksum), so ZSTD_findFrameCompressedSize() can locate them.
    index_.clear();
    uint64_t pos = header_size_;
    uint64_t logical_offset = 0;

    while (pos < file_size_) {
        const uint8_t* frame_start = mapped_ + pos;
        size_t remaining = file_size_ - pos;

        // Check if remaining bytes look like a zstd frame.
        size_t frame_size = ZSTD_findFrameCompressedSize(frame_start, remaining);
        if (ZSTD_isError(frame_size)) {
            // Not a valid frame — this is where the data ends.
            // Could be a partial frame from an interrupted write.
            break;
        }

        // Determine decompressed size.  The writer uses single-shot
        // ZSTD_compress2, which embeds the content size in the frame header.
        unsigned long long content_size = ZSTD_getFrameContentSize(frame_start, remaining);
        if (content_size == ZSTD_CONTENTSIZE_ERROR ||
            content_size == ZSTD_CONTENTSIZE_UNKNOWN) {
            // Can't determine decompressed size — try actually decompressing.
            // Use a generous upper bound (default block = 1 MB, but could be
            // up to ~4 MB with custom settings).
            size_t upper = 4u << 20;
            std::vector<uint8_t> tmp(upper);
            size_t dec = ZSTD_decompressDCtx(dctx_, tmp.data(), upper,
                                             frame_start, frame_size);
            if (ZSTD_isError(dec)) break;
            content_size = dec;
        }

        qbditrace::qbditrace_block_entry_t entry;
        entry.original_offset = logical_offset;
        entry.compressed_offset = pos;
        entry.original_size = static_cast<uint32_t>(content_size);
        entry.compressed_size = static_cast<uint32_t>(frame_size);
        index_.push_back(entry);

        logical_offset += content_size;
        pos += frame_size;
    }

    if (index_.empty())
        return false;

    recovered_ = true;

    // Build a human-readable summary.
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "recovered %zu blocks (%.1f MB logical) from truncated trace",
                  index_.size(), logical_offset / (1024.0 * 1024.0));
    recovery_msg_ = buf;

    return true;
}
#endif

inline uint32_t BlockCacheReader::find_block(uint64_t logical_offset) const {
    // Binary search: find the last block whose original_offset <= logical_offset
    uint32_t lo = 0, hi = static_cast<uint32_t>(index_.size());
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (index_[mid].original_offset <= logical_offset)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo > 0 ? lo - 1 : 0;
}

inline void BlockCacheReader::evict_one() {
    // Find LRU unpinned slot
    uint32_t best = UINT32_MAX;
    uint32_t best_tick = UINT32_MAX;
    for (uint32_t i = 0; i < cache_.size(); i++) {
        if (cache_[i].block_id == UINT32_MAX) continue;  // empty slot
        if (global_pin_ > 0 || cache_[i].pin_count > 0) continue;
        if (cache_[i].access_tick < best_tick) {
            best_tick = cache_[i].access_tick;
            best = i;
        }
    }
    if (best != UINT32_MAX) {
        cache_[best].block_id = UINT32_MAX;
        cache_[best].data.clear();
        cache_[best].data.shrink_to_fit();
        cache_[best].overlap.clear();
        cache_[best].overlap.shrink_to_fit();
    }
}

inline BlockCacheReader::CachedBlock&
BlockCacheReader::ensure_block(uint32_t block_id) {
    // Check if already cached
    for (auto& slot : cache_) {
        if (slot.block_id == block_id) {
            slot.access_tick = ++tick_;
            return slot;
        }
    }

    // Find a free slot or evict
    CachedBlock* target = nullptr;
    for (auto& slot : cache_) {
        if (slot.block_id == UINT32_MAX) {
            target = &slot;
            break;
        }
    }
    if (!target) {
        evict_one();
        for (auto& slot : cache_) {
            if (slot.block_id == UINT32_MAX) {
                target = &slot;
                break;
            }
        }
    }
    if (!target) {
        // All pinned — grow cache by one (emergency)
        cache_.emplace_back();
        target = &cache_.back();
    }

    // Decompress
    auto& entry = index_[block_id];
    target->block_id = block_id;
    target->data.resize(entry.original_size);
    target->access_tick = ++tick_;

#if TENET_HAS_ZSTD
    size_t result = ZSTD_decompressDCtx(
        dctx_,
        target->data.data(), entry.original_size,
        mapped_ + entry.compressed_offset, entry.compressed_size);
    if (ZSTD_isError(result) || result != entry.original_size) {
        // Decompression error — return a zeroed block rather than crashing
        std::memset(target->data.data(), 0, entry.original_size);
    }
#else
    // No zstd — should not reach here, but fill with zeros
    std::memset(target->data.data(), 0, entry.original_size);
#endif

    return *target;
}

inline size_t BlockCacheReader::decompress_block_raw(
    uint32_t block_id, std::vector<uint8_t>& dst,
    size_t dst_offset, size_t max_bytes) {
    auto& entry = index_[block_id];
    size_t to_copy = std::min(max_bytes, static_cast<size_t>(entry.original_size));
#if TENET_HAS_ZSTD
    // Decompress into a temp buffer, then copy the needed prefix.
    // (ZSTD requires decompressing the full frame.)
    std::vector<uint8_t> tmp(entry.original_size);
    size_t res = ZSTD_decompressDCtx(
        dctx_, tmp.data(), entry.original_size,
        mapped_ + entry.compressed_offset, entry.compressed_size);
    if (ZSTD_isError(res) || res != entry.original_size) {
        std::memset(dst.data() + dst_offset, 0, to_copy);
    } else {
        std::memcpy(dst.data() + dst_offset, tmp.data(), to_copy);
    }
#else
    std::memset(dst.data() + dst_offset, 0, to_copy);
#endif
    return to_copy;
}

inline const uint8_t* BlockCacheReader::data_at(uint64_t logical_offset) {
    uint32_t block_id = find_block(logical_offset);

    std::lock_guard<std::mutex> lk(mtx_);
    auto& block = ensure_block(block_id);
    uint64_t offset_in_block = logical_offset - index_[block_id].original_offset;
    uint64_t remaining = block.data.size() - offset_in_block;

    // Fast path: enough contiguous bytes within this block.
    if (remaining >= kOverlapBytes || block_id + 1 >= index_.size()) {
        return block.data.data() + offset_in_block;
    }

    // Slow path: the read may straddle the block boundary.  Build a
    // per-block overlap buffer that covers the tail of this block plus
    // the head of the next block.  The overlap is stored separately from
    // `data` so that existing pointers into `data` remain valid.
    //
    // Layout:  overlap_start_ = max(0, data.size() - kOverlapBytes)
    //          overlap[0..tail] = data[overlap_start_ .. data.size()]
    //          overlap[tail..tail+kOverlapBytes] = next_block[0..kOverlapBytes]
    //
    // Any logical offset mapping to offset_in_block >= overlap_start_ can
    // be served from the overlap buffer.

    if (block.overlap.empty()) {
        // Build the overlap buffer once per cached block.
        size_t block_sz = block.data.size();
        size_t overlap_start = (block_sz >= kOverlapBytes)
                                   ? block_sz - kOverlapBytes : 0;
        size_t tail_bytes = block_sz - overlap_start;
        // Total size: tail of current block + kOverlapBytes from next block.
        size_t total = tail_bytes + kOverlapBytes;
        block.overlap.resize(total);

        // Copy tail of current block.
        std::memcpy(block.overlap.data(),
                    block.data.data() + overlap_start,
                    tail_bytes);

        // Fill head of next block.
        CachedBlock* next_cached = nullptr;
        for (auto& slot : cache_) {
            if (slot.block_id == block_id + 1) {
                next_cached = &slot;
                break;
            }
        }
        if (next_cached) {
            size_t avail = std::min(kOverlapBytes, next_cached->data.size());
            std::memcpy(block.overlap.data() + tail_bytes,
                        next_cached->data.data(), avail);
            if (avail < kOverlapBytes)
                std::memset(block.overlap.data() + tail_bytes + avail, 0,
                            kOverlapBytes - avail);
        } else {
            decompress_block_raw(block_id + 1, block.overlap,
                                 tail_bytes, kOverlapBytes);
        }
    }

    // Map offset_in_block into the overlap buffer.
    size_t block_sz = block.data.size();
    size_t overlap_start = (block_sz >= kOverlapBytes)
                               ? block_sz - kOverlapBytes : 0;
    size_t idx_in_overlap = static_cast<size_t>(offset_in_block) - overlap_start;
    return block.overlap.data() + idx_in_overlap;
}

inline void BlockCacheReader::pin_all() {
    std::lock_guard<std::mutex> lk(mtx_);
    ++global_pin_;
}

inline void BlockCacheReader::unpin_all() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (global_pin_ > 0) --global_pin_;
}

inline std::unique_ptr<BlockCacheReader> BlockCacheReader::clone(size_t max_cached_blocks) const {
    auto c = std::unique_ptr<BlockCacheReader>(new BlockCacheReader());
    c->mapped_ = mapped_;
    c->file_size_ = file_size_;
    c->header_size_ = header_size_;
    c->index_ = index_;  // shared copy of block index (read-only after init)
    c->logical_size_ = logical_size_;
    c->recovered_ = recovered_;
    c->recovery_msg_ = recovery_msg_;
    c->max_cached_ = max_cached_blocks;
    // Pre-allocate cache slots
    size_t slots = max_cached_blocks < index_.size() ? max_cached_blocks : index_.size();
    c->cache_.resize(slots);
#if TENET_HAS_ZSTD
    c->dctx_ = ZSTD_createDCtx();
#endif
    return c;
}

inline bool BlockCacheReader::decompress_block(
    uint32_t block_id,
    std::vector<uint8_t>& out_buf,
    const uint8_t*& out_data,
    uint32_t& out_size,
    uint64_t& out_logical_offset) const
{
    if (block_id >= index_.size()) return false;
    const auto& entry = index_[block_id];
    out_logical_offset = entry.original_offset;
    out_size = entry.original_size;

    // Allocate caller-owned buffer with kOverlapBytes extra for cross-block
    // record reads at the tail.
    size_t alloc = entry.original_size;
    if (block_id + 1 < index_.size())
        alloc += kOverlapBytes;
    out_buf.resize(alloc);

#if TENET_HAS_ZSTD
    // Each call creates its own DCtx so this is fully thread-safe
    // without touching mtx_ at all.
    ZSTD_DCtx* local_dctx = ZSTD_createDCtx();
    if (!local_dctx) return false;

    size_t result = ZSTD_decompressDCtx(
        local_dctx,
        out_buf.data(), entry.original_size,
        mapped_ + entry.compressed_offset, entry.compressed_size);
    if (ZSTD_isError(result) || result != entry.original_size) {
        ZSTD_freeDCtx(local_dctx);
        return false;
    }

    // If there is a next block, decompress its head into the overlap zone
    // so records straddling the block boundary can be read contiguously.
    if (block_id + 1 < index_.size()) {
        const auto& next = index_[block_id + 1];
        // We need at most kOverlapBytes from the next block.
        // Decompress the full next block into a temp buffer, then copy the head.
        std::vector<uint8_t> tmp(next.original_size);
        size_t r2 = ZSTD_decompressDCtx(
            local_dctx,
            tmp.data(), next.original_size,
            mapped_ + next.compressed_offset, next.compressed_size);
        if (!ZSTD_isError(r2) && r2 == next.original_size) {
            size_t to_copy = std::min(kOverlapBytes, static_cast<size_t>(next.original_size));
            std::memcpy(out_buf.data() + entry.original_size, tmp.data(), to_copy);
            if (to_copy < kOverlapBytes)
                std::memset(out_buf.data() + entry.original_size + to_copy, 0,
                            kOverlapBytes - to_copy);
        } else {
            std::memset(out_buf.data() + entry.original_size, 0, kOverlapBytes);
        }
    }

    ZSTD_freeDCtx(local_dctx);
#else
    std::memset(out_buf.data(), 0, alloc);
#endif

    out_data = out_buf.data();
    return true;
}

}  // namespace tenet
