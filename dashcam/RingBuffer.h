/*
 * qbditrace - high performance instruction tracer built on QBDI
 *
 * RingBuffer.h
 *
 * Per-thread write buffering plus a single background writer thread that drains
 * filled chunks to disk in order. The hot path (instruction callback) only ever
 * touches a thread-local buffer with no locking, which is essential for speed.
 *
 * Model:
 *   - Each traced thread owns a `ThreadBuffer` (a large contiguous chunk).
 *   - The callback appends records with `reserve()` (returns a raw pointer) and
 *     never blocks. When the chunk no longer has room for the next record, the
 *     full chunk is handed to the BackgroundWriter and a fresh chunk is taken.
 *   - The BackgroundWriter owns the output file and writes chunks sequentially.
 *     Because we tag each chunk with its owning thread id (via a THREAD record
 *     the producer emits at chunk start), the decoder can demultiplex threads.
 *
 * "Dump to disk" overflow policy: chunks are always flushed, never dropped, so
 * the trace is complete (file may grow large for hot ranges).
 *
 * Compression modes:
 *   - Block-compressed (default when compress=true): records are accumulated
 *     in a staging buffer and flushed as independent zstd frames every 1 MB of
 *     uncompressed data. A block index table + footer are written at file close,
 *     enabling the reader to decompress individual blocks on demand.
 *   - Uncompressed: raw fwrite of each chunk.
 */
#ifndef QBDITRACE_RINGBUFFER_H_
#define QBDITRACE_RINGBUFFER_H_

#include "TraceFormat.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <vector>

#if QBDITRACE_HAVE_ZSTD
#include <zstd.h>
#endif

/* Minimal async-signal-safe stderr logger for IO errors. We avoid fprintf
 * because the writer thread may encounter errors while the process is in an
 * arbitrary state. write(2) to fd 2 is safe from any context. */
namespace qbditrace {
namespace detail {
inline void logIOError(const char *msg) {
  /* Format: "[qbditrace] IO ERROR: <msg>\n" */
  static const char prefix[] = "[qbditrace] IO ERROR: ";
  (void)::write(2, prefix, sizeof(prefix) - 1);
  size_t len = 0;
  while (msg[len]) ++len;
  (void)::write(2, msg, len);
  (void)::write(2, "\n", 1);
}
} // namespace detail
} // namespace qbditrace

namespace qbditrace {

/* A single contiguous buffer chunk produced by one thread. */
struct Chunk {
  uint8_t *data = nullptr;
  size_t capacity = 0;
  size_t used = 0;
  uint64_t thread_id = 0;

  inline size_t room() const { return capacity - used; }
};

/*
 * BackgroundWriter: owns the output FILE* and a queue of filled chunks. A
 * dedicated thread pops chunks and writes them out, then recycles their memory
 * back to a free list to avoid repeated large allocations.
 *
 * When compression is enabled, the writer produces block-compressed output
 * (HF_BLOCK_COMPRESSED): records are accumulated in a staging buffer and
 * flushed as independent zstd frames at 1 MB boundaries.
 */
class BackgroundWriter {
public:
  BackgroundWriter() = default;
  ~BackgroundWriter() { stop(); }

  /* Open output file and start the writer thread. Returns false on error.
   * When `compress` is true, output uses block-compressed format. */
  bool start(const char *path, size_t chunk_bytes, bool compress = false);

  /* Hand a filled chunk to the writer (takes ownership of chunk.data). */
  void submit(Chunk &&c);

  /* Borrow a recycled (or freshly allocated) empty chunk of chunk_bytes. */
  Chunk acquire();

  /* Write raw bytes synchronously through the writer queue ordering.
   * Used for the file header which must precede all chunks. */
  void writeHeaderRaw(const void *buf, size_t len);

  /* Drain the queue, flush, close file, join thread. Idempotent. */
  void stop();

  bool ok() const { return file_ != nullptr; }
  bool compressed() const { return compress_; }

private:
  void loop();
  void recycle(uint8_t *mem);
  /* Write raw bytes to the output file. In block-compressed mode, data is
   * accumulated in a staging buffer and flushed as compressed blocks at
   * QBDITRACE_DEFAULT_BLOCK_SIZE boundaries. */
  void writeBytes(const void *data, size_t len, bool &io_error_reported);

#if QBDITRACE_HAVE_ZSTD
  /* Flush the staging buffer as one compressed block. */
  void flushBlock(bool &io_error_reported);
  /* Write the block index table and footer, then close the file. */
  void finalizeBlocks(bool &io_error_reported);
#endif

  FILE *file_ = nullptr;
  size_t chunk_bytes_ = 0;
  bool compress_ = false;

#if QBDITRACE_HAVE_ZSTD
  ZSTD_CCtx *zctx_ = nullptr;

  /* Block-compressed staging buffer: raw (uncompressed) record bytes are
   * appended here until the buffer reaches QBDITRACE_DEFAULT_BLOCK_SIZE,
   * at which point the buffer is compressed as a single zstd frame and
   * written to disk. */
  uint8_t *stage_buf_ = nullptr;
  size_t stage_used_ = 0;
  size_t stage_capacity_ = 0;

  /* Compressed output buffer (reusable across blocks). */
  uint8_t *zbuf_ = nullptr;
  size_t zbuf_size_ = 0;

  /* Block index: one entry per flushed block. Written to disk at finalize. */
  std::vector<qbditrace_block_entry_t> block_index_;
  uint64_t logical_offset_ = 0;  /* running decompressed byte count */
#endif

  std::mutex mtx_;
  std::condition_variable cv_;
  std::deque<Chunk> queue_;
  std::vector<uint8_t *> free_list_;
  std::thread worker_;
  std::atomic<bool> running_{false};
  bool header_written_ = false;
};

inline bool BackgroundWriter::start(const char *path, size_t chunk_bytes,
                                    bool compress) {
  file_ = std::fopen(path, "wb");
  if (!file_) {
    return false;
  }
  chunk_bytes_ = chunk_bytes;
  compress_ = compress;

#if QBDITRACE_HAVE_ZSTD
  if (compress_) {
    zctx_ = ZSTD_createCCtx();
    if (!zctx_) {
      detail::logIOError("failed to create ZSTD_CCtx");
      std::fclose(file_);
      file_ = nullptr;
      return false;
    }
    /* Level 1: fastest compression; still gets ~3x on trace data. */
    ZSTD_CCtx_setParameter(zctx_, ZSTD_c_compressionLevel, 1);
    ZSTD_CCtx_setParameter(zctx_, ZSTD_c_checksumFlag, 1);

    /* Allocate staging buffer (1 MB = one decompressed block). */
    stage_capacity_ = QBDITRACE_DEFAULT_BLOCK_SIZE;
    stage_buf_ = static_cast<uint8_t *>(std::malloc(stage_capacity_));
    stage_used_ = 0;

    /* Compressed output buffer: worst case = ZSTD_compressBound(block_size). */
    zbuf_size_ = ZSTD_compressBound(stage_capacity_);
    zbuf_ = static_cast<uint8_t *>(std::malloc(zbuf_size_));

    if (!stage_buf_ || !zbuf_) {
      detail::logIOError("failed to allocate block compression buffers");
      std::free(stage_buf_); stage_buf_ = nullptr;
      std::free(zbuf_); zbuf_ = nullptr;
      ZSTD_freeCCtx(zctx_); zctx_ = nullptr;
      std::fclose(file_); file_ = nullptr;
      return false;
    }

    block_index_.clear();
    logical_offset_ = 0;
  }
#else
  if (compress_) {
    detail::logIOError("zstd compression requested but not compiled in");
    compress_ = false;
  }
#endif

  running_.store(true);
  worker_ = std::thread([this] { loop(); });
  return true;
}

inline void BackgroundWriter::writeHeaderRaw(const void *buf, size_t len) {
  /* Header is written before the worker produces any output; do it directly
   * under the lock to keep ordering simple and correct. */
  std::lock_guard<std::mutex> lk(mtx_);
  if (file_ && !header_written_) {
    size_t written = std::fwrite(buf, 1, len, file_);
    if (written != len || std::ferror(file_)) {
      detail::logIOError("failed to write file header (disk full?)");
    }
    std::fflush(file_);
    header_written_ = true;
  }
}

inline Chunk BackgroundWriter::acquire() {
  Chunk c;
  c.capacity = chunk_bytes_;
  c.used = 0;
  {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!free_list_.empty()) {
      c.data = free_list_.back();
      free_list_.pop_back();
    }
  }
  if (!c.data) {
    c.data = static_cast<uint8_t *>(std::malloc(chunk_bytes_));
  }
  if (!c.data) {
    /* Out of memory: hand back a zero-capacity chunk. reserve() detects the
     * null buffer and writes into a scratch sink instead of dereferencing
     * nullptr, so the trace loses records under memory pressure rather than
     * crashing the target. */
    c.capacity = 0;
  }
  return c;
}

inline void BackgroundWriter::submit(Chunk &&c) {
  if (c.used == 0 || c.data == nullptr) {
    /* Nothing to write; recycle immediately. */
    if (c.data) {
      recycle(c.data);
    }
    return;
  }
  {
    std::lock_guard<std::mutex> lk(mtx_);
    queue_.emplace_back(std::move(c));
  }
  cv_.notify_one();
}

inline void BackgroundWriter::recycle(uint8_t *mem) {
  if (!mem) {
    return;
  }
  std::lock_guard<std::mutex> lk(mtx_);
  if (free_list_.size() < 8) {
    free_list_.push_back(mem);
  } else {
    std::free(mem);
  }
}

inline void BackgroundWriter::writeBytes(const void *data, size_t len,
                                          bool &io_error_reported) {
  if (!file_ || !data || len == 0) return;

#if QBDITRACE_HAVE_ZSTD
  if (compress_ && zctx_) {
    /* Block-compressed mode: accumulate in staging buffer, flush at 1 MB. */
    const uint8_t *src = static_cast<const uint8_t *>(data);
    size_t remaining = len;
    while (remaining > 0) {
      size_t room = stage_capacity_ - stage_used_;
      size_t copy = remaining < room ? remaining : room;
      std::memcpy(stage_buf_ + stage_used_, src, copy);
      stage_used_ += copy;
      src += copy;
      remaining -= copy;

      if (stage_used_ >= stage_capacity_) {
        flushBlock(io_error_reported);
      }
    }
    return;
  }
#endif
  /* Uncompressed path. */
  size_t written = std::fwrite(data, 1, len, file_);
  if ((written != len || std::ferror(file_)) && !io_error_reported) {
    detail::logIOError("fwrite failed in writer thread (disk full?)");
    io_error_reported = true;
  }
}

#if QBDITRACE_HAVE_ZSTD
inline void BackgroundWriter::flushBlock(bool &io_error_reported) {
  if (stage_used_ == 0) return;

  /* Record current file position as the block's compressed offset. */
  long pos = std::ftell(file_);
  if (pos < 0) {
    if (!io_error_reported) {
      detail::logIOError("ftell failed in flushBlock");
      io_error_reported = true;
    }
    stage_used_ = 0;
    return;
  }

  /* Compress the entire staging buffer as one independent zstd frame.
   * We use single-shot ZSTD_compress2 (not streaming) since we have the
   * complete block in memory. This produces a self-contained frame. */
  ZSTD_CCtx_reset(zctx_, ZSTD_reset_session_only);
  ZSTD_CCtx_setParameter(zctx_, ZSTD_c_compressionLevel, 1);
  ZSTD_CCtx_setParameter(zctx_, ZSTD_c_checksumFlag, 1);

  size_t comp_size = ZSTD_compress2(zctx_, zbuf_, zbuf_size_,
                                    stage_buf_, stage_used_);
  if (ZSTD_isError(comp_size)) {
    if (!io_error_reported) {
      detail::logIOError("ZSTD_compress2 failed in flushBlock");
      io_error_reported = true;
    }
    stage_used_ = 0;
    return;
  }

  /* Write compressed block to file. */
  size_t written = std::fwrite(zbuf_, 1, comp_size, file_);
  if ((written != comp_size || std::ferror(file_)) && !io_error_reported) {
    detail::logIOError("fwrite failed in flushBlock (disk full?)");
    io_error_reported = true;
  }

  /* Record block index entry. */
  qbditrace_block_entry_t entry;
  entry.original_offset = logical_offset_;
  entry.compressed_offset = static_cast<uint64_t>(pos);
  entry.original_size = static_cast<uint32_t>(stage_used_);
  entry.compressed_size = static_cast<uint32_t>(comp_size);
  block_index_.push_back(entry);

  logical_offset_ += stage_used_;
  stage_used_ = 0;
}

inline void BackgroundWriter::finalizeBlocks(bool &io_error_reported) {
  /* Flush any remaining staged data as a final (possibly smaller) block. */
  flushBlock(io_error_reported);

  if (!file_) return;

  /* Write the block index table. */
  long index_pos = std::ftell(file_);
  if (index_pos < 0) {
    if (!io_error_reported) {
      detail::logIOError("ftell failed before writing block index");
      io_error_reported = true;
    }
    return;
  }

  size_t table_bytes = block_index_.size() * sizeof(qbditrace_block_entry_t);
  if (table_bytes > 0) {
    size_t written = std::fwrite(block_index_.data(), 1, table_bytes, file_);
    if ((written != table_bytes || std::ferror(file_)) && !io_error_reported) {
      detail::logIOError("failed to write block index table");
      io_error_reported = true;
    }
  }

  /* Write the footer (last 16 bytes of file). */
  qbditrace_block_footer_t footer;
  footer.index_offset = static_cast<uint64_t>(index_pos);
  footer.block_count = static_cast<uint32_t>(block_index_.size());
  footer.magic = QBDITRACE_BLOCK_INDEX_MAGIC;
  size_t written = std::fwrite(&footer, 1, sizeof(footer), file_);
  if ((written != sizeof(footer) || std::ferror(file_)) && !io_error_reported) {
    detail::logIOError("failed to write block footer");
    io_error_reported = true;
  }
}
#endif

inline void BackgroundWriter::loop() {
  /* Track whether we have already reported an IO error to avoid flooding
   * stderr with repeated messages for the same disk-full condition. */
  bool io_error_reported = false;
  for (;;) {
    Chunk c;
    {
      std::unique_lock<std::mutex> lk(mtx_);
      cv_.wait(lk, [this] { return !queue_.empty() || !running_.load(); });
      if (queue_.empty()) {
        if (!running_.load()) {
          break;
        }
        continue;
      }
      c = std::move(queue_.front());
      queue_.pop_front();
    }
    if (file_ && c.data && c.used) {
      writeBytes(c.data, c.used, io_error_reported);
    }
    recycle(c.data);
  }
}

inline void BackgroundWriter::stop() {
  if (!running_.exchange(false)) {
    /* Already stopped; ensure file closed. */
    if (file_) {
      std::fclose(file_);
      file_ = nullptr;
    }
    return;
  }
  cv_.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
  /* Drain anything still queued (defensive; loop should have emptied it). */
  bool io_error_reported = false;
  {
    std::lock_guard<std::mutex> lk(mtx_);
    while (!queue_.empty()) {
      Chunk &c = queue_.front();
      if (file_ && c.data && c.used) {
        writeBytes(c.data, c.used, io_error_reported);
      }
      if (c.data) {
        std::free(c.data);
      }
      queue_.pop_front();
    }
    for (uint8_t *m : free_list_) {
      std::free(m);
    }
    free_list_.clear();
  }

#if QBDITRACE_HAVE_ZSTD
  if (compress_ && zctx_ && file_) {
    /* Finalize block-compressed output: flush remaining staged data,
     * write block index table and footer. */
    finalizeBlocks(io_error_reported);
  }
  if (zctx_) {
    ZSTD_freeCCtx(zctx_);
    zctx_ = nullptr;
  }
  if (zbuf_) {
    std::free(zbuf_);
    zbuf_ = nullptr;
  }
  if (stage_buf_) {
    std::free(stage_buf_);
    stage_buf_ = nullptr;
  }
  stage_used_ = 0;
  block_index_.clear();
  logical_offset_ = 0;
#endif

  if (file_) {
    std::fflush(file_);
    std::fclose(file_);
    file_ = nullptr;
  }
  compress_ = false;
  header_written_ = false;
}

/*
 * ThreadBuffer: the producer-side handle held in thread-local storage. Wraps a
 * current Chunk and rotates it through the BackgroundWriter when full.
 */
class ThreadBuffer {
public:
  ThreadBuffer(BackgroundWriter *writer, uint64_t thread_id)
      : writer_(writer), thread_id_(thread_id) {
    cur_ = writer_->acquire();
    cur_.thread_id = thread_id_;
  }

  ~ThreadBuffer() { flush(); }

  /*
   * Reserve `n` contiguous bytes in the current chunk and return a pointer to
   * them. The caller must write exactly `n` bytes. Rotates the chunk if needed.
   * `n` must be <= chunk capacity.
   */
  inline uint8_t *reserve(size_t n) {
    if (cur_.room() < n) {
      rotate();
    }
    /* If the allocator is out of memory the current chunk has no backing buffer
     * (data == nullptr, capacity == 0). Return a throwaway scratch region so the
     * caller can safely write its `n` bytes; the record is silently dropped
     * rather than dereferencing a null pointer and crashing the target. */
    if (cur_.data == nullptr || cur_.capacity == 0) {
      static thread_local uint8_t scratch[512];
      return scratch;
    }
    /* A single record must never exceed the chunk capacity, otherwise the
     * post-rotate chunk still cannot hold it and `used += n` would overrun the
     * heap buffer. The largest record is an ANCHOR (~288B) and the default
     * chunk is >= 64KiB, so this only trips on a pathological configuration.
     * Clamp defensively so a misconfiguration degrades the trace rather than
     * corrupting memory. */
    if (n > cur_.capacity) {
      n = cur_.capacity;
    }
    uint8_t *p = cur_.data + cur_.used;
    cur_.used += n;
    return p;
  }

  /*
   * Guarantee the current chunk has room for at least `n` bytes WITHOUT yet
   * consuming them, rotating to a fresh chunk if necessary. Use this before a
   * sequence of reserve() calls that must all land in the same chunk (e.g. a
   * THREAD marker immediately followed by its first record), so a rotate cannot
   * sneak in between them and orphan the records from their marker.
   */
  inline void ensureRoom(size_t n) {
    if (cur_.room() < n) {
      rotate();
    }
  }

  /* Push the current chunk to the writer (keeps a fresh empty chunk). */
  void flush() {
    if (cur_.data && cur_.used) {
      writer_->submit(std::move(cur_));
      cur_ = writer_->acquire();
      cur_.thread_id = thread_id_;
      /* New chunk after a flush also needs a THREAD marker, otherwise the
       * decoder attributes its records to the previously-seen thread id (it
       * keeps a running cur_thread that only advances on THREAD records). The
       * rotate() path already does this; flush() must too. */
      need_marker_ = true;
    }
  }

  uint64_t threadId() const { return thread_id_; }
  bool needThreadMarker() const { return need_marker_; }
  void markerEmitted() { need_marker_ = false; }

private:
  void rotate() {
    writer_->submit(std::move(cur_));
    cur_ = writer_->acquire();
    cur_.thread_id = thread_id_;
    /* New chunk: decoder needs a THREAD marker to know who owns it. */
    need_marker_ = true;
  }

  BackgroundWriter *writer_;
  uint64_t thread_id_;
  Chunk cur_;
  bool need_marker_ = true;
};

} // namespace qbditrace

#endif /* QBDITRACE_RINGBUFFER_H_ */
