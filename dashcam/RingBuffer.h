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
 */
#ifndef QBDITRACE_RINGBUFFER_H_
#define QBDITRACE_RINGBUFFER_H_

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
 */
class BackgroundWriter {
public:
  BackgroundWriter() = default;
  ~BackgroundWriter() { stop(); }

  /* Open output file and start the writer thread. Returns false on error. */
  bool start(const char *path, size_t chunk_bytes);

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

private:
  void loop();
  void recycle(uint8_t *mem);

  FILE *file_ = nullptr;
  size_t chunk_bytes_ = 0;

  std::mutex mtx_;
  std::condition_variable cv_;
  std::deque<Chunk> queue_;
  std::vector<uint8_t *> free_list_;
  std::thread worker_;
  std::atomic<bool> running_{false};
  bool header_written_ = false;
};

inline bool BackgroundWriter::start(const char *path, size_t chunk_bytes) {
  file_ = std::fopen(path, "wb");
  if (!file_) {
    return false;
  }
  chunk_bytes_ = chunk_bytes;
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
      size_t written = std::fwrite(c.data, 1, c.used, file_);
      if ((written != c.used || std::ferror(file_)) && !io_error_reported) {
        detail::logIOError("fwrite failed in writer thread (disk full?)");
        io_error_reported = true;
      }
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
  {
    std::lock_guard<std::mutex> lk(mtx_);
    while (!queue_.empty()) {
      Chunk &c = queue_.front();
      if (file_ && c.data && c.used) {
        size_t written = std::fwrite(c.data, 1, c.used, file_);
        if (written != c.used || std::ferror(file_)) {
          detail::logIOError("fwrite failed during drain (disk full?)");
        }
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
  if (file_) {
    std::fflush(file_);
    std::fclose(file_);
    file_ = nullptr;
  }
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
