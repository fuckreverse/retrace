#pragma once

#include "common/platform_mmap.h"
#include "common/types.h"
#include <ankerl/unordered_dense.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <utility>

namespace tenet {

/// A read-only mapping from a traced module's runtime PCs back to raw file
/// bytes, used to recover instruction opcodes that are missing from the trace's
/// REC_CODE stream.
///
/// qbditrace drops REC_CODE for instructions executed inside LDXR/STXR
/// (LL/SC) critical sections — emitting them would require a syscall that
/// tears the ARM exclusive reservation. The result is that ~10-20% of PCs in
/// heavily-atomic code show up as "<no code>" in the decoder. Loading the
/// original Mach-O / ELF image lets the decoder disassemble those PCs straight
/// from the on-disk bytes, fully recovering the disassembly, CFG, and taint
/// analyses without re-tracing.
///
/// The image is parsed for executable segments; for each segment we record
/// (runtime_start, runtime_end, file_offset) so a runtime PC maps directly to
/// a file offset without per-query arithmetic beyond a binary search.
class ImageFallback {
public:
    ImageFallback() = default;

    ~ImageFallback() = default;

    // Non-copyable (owns an mmap region).
    ImageFallback(const ImageFallback&) = delete;
    ImageFallback& operator=(const ImageFallback&) = delete;

    // Movable: transfers ownership of the mmap region.
    ImageFallback(ImageFallback&& other) noexcept;
    ImageFallback& operator=(ImageFallback&& other) noexcept;

    /// Load an image file and build the executable-segment map for a module
    /// whose runtime base is `module_base`. Returns false on any parse error
    /// (the fallback simply stays empty and opcode lookups fail gracefully).
    bool load(const std::string& path, uint64_t module_base);

    bool ready() const { return !segments_.empty(); }

    /// Read 4 little-endian instruction bytes at `runtime_pc`.
    /// Returns nullopt if the PC is not inside any executable segment or the
    /// read falls outside the file. Not thread-safe (mmap is read-only so
    /// concurrent reads are fine in practice, but the call is const-logical).
    std::optional<uint32_t> opcode_at(uint64_t runtime_pc) const;

    /// Read up to `len` bytes at `runtime_addr` into `out`.
    /// Returns the number of bytes actually read (0 if the address is not in
    /// any mapped segment). Stops at segment/file boundaries.
    /// Used to recover data (selector strings, constants) from the binary image
    /// when the memory model has no record of it (e.g. data set up by
    /// uninstrumented code).
    size_t read_bytes_at(uint64_t runtime_addr, size_t len, uint8_t* out) const;

    /// Number of executable segments mapped.
    size_t segment_count() const { return segments_.size(); }

private:
    struct Segment {
        uint64_t runtime_start;  // first runtime address covered
        uint64_t runtime_end;    // one past last runtime address
        uint64_t file_offset;    // file offset of runtime_start
    };

    platform::MappedFile mapped_file_;
    std::vector<Segment> segments_;  // sorted by runtime_start
};

/// Stores the raw instruction bytes for each distinct executed PC.
/// Populated from REC_CODE records in the trace file.
///
/// Performance: uses ankerl::unordered_dense::map (open-addressing, contiguous
/// memory) instead of std::unordered_map (per-node heap allocation). For a
/// typical trace with 5-50K unique PCs, this provides 2-3× faster lookups
/// due to better cache locality and elimination of pointer chasing.
class CodeTable {
public:
    CodeTable() = default;

    /// Pre-allocate for expected number of unique PCs.
    void reserve(size_t n) { opcodes_.reserve(n); }

    /// Ingest a CODE record (pc → opcode bytes).
    void insert(uint64_t pc, uint32_t opcode) {
        opcodes_.emplace(pc, opcode);
    }

    /// Attach an image fallback. When opcode_at() misses the trace's CODE
    /// table, it will consult the image before returning nullopt.
    void set_image_fallback(std::shared_ptr<ImageFallback> img) {
        image_ = std::move(img);
    }
    bool has_image_fallback() const { return image_ && image_->ready(); }

    /// Look up the 4-byte opcode at a given PC.
    /// Returns nullopt if that PC was never recorded AND no image fallback
    /// recovers it.
    std::optional<uint32_t> opcode_at(uint64_t pc) const {
        auto it = opcodes_.find(pc);
        if (it != opcodes_.end()) return it->second;
        if (image_) return image_->opcode_at(pc);
        return std::nullopt;
    }

    /// Read a NUL-terminated C string from the binary image at `runtime_addr`.
    /// Returns nullopt if no image fallback is loaded or the address is not in
    /// any mapped segment. Stops at NUL or non-printable characters.
    /// Used to resolve ObjC selector names and other string data that live in
    /// the binary's __TEXT segment but were never read by traced code.
    std::optional<std::string> image_read_cstring(uint64_t runtime_addr,
                                                    size_t max_len = 256) const {
        if (!image_ || !image_->ready()) return std::nullopt;
        uint8_t buf[256];
        if (max_len > sizeof(buf)) max_len = sizeof(buf);
        size_t n = image_->read_bytes_at(runtime_addr, max_len, buf);
        if (n == 0) return std::nullopt;
        std::string result;
        for (size_t i = 0; i < n; ++i) {
            uint8_t c = buf[i];
            if (c == 0) break;
            if (c < 0x20 || c > 0x7e) break;
            result.push_back(static_cast<char>(c));
        }
        if (result.empty()) return std::nullopt;
        return result;
    }

    /// Number of distinct PCs stored from the trace's CODE records (does not
    /// count image-fallback hits).
    size_t size() const { return opcodes_.size(); }

    /// Iterator access for bulk operations.
    auto begin() const { return opcodes_.begin(); }
    auto end()   const { return opcodes_.end(); }

    /// Get all entries as a sorted vector (by PC).
    std::vector<std::pair<uint64_t, uint32_t>> all_entries() const {
        std::vector<std::pair<uint64_t, uint32_t>> result(opcodes_.begin(), opcodes_.end());
        std::sort(result.begin(), result.end());
        return result;
    }

private:
    ankerl::unordered_dense::map<uint64_t, uint32_t> opcodes_;
    std::shared_ptr<ImageFallback> image_;
};

}  // namespace tenet
