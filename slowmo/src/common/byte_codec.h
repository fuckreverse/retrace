#pragma once

// ─── ByteWriter / ByteReader: shared serialization helpers ──────────────────
//
// All tenet analysis passes that persist results to RocksDB blobs use the
// same hand-rolled memcpy+pointer-advance pattern for serialisation.  This
// header replaces ~20 duplicated lambda sets with two small classes.
//
// Usage (write):
//   ByteWriter w;
//   w.u32(MAGIC); w.u32(VERSION); w.u64(n);
//   for (...) { w.u64(pc); w.str(name); }
//   index.save_pass_blob("foo", w.data(), w.size());
//
// Usage (read):
//   ByteReader r(blob.data(), blob.size());
//   if (r.u32() != MAGIC) return false;
//   if (r.u32() != VERSION) return false;
//   uint64_t n = r.u64();
//   for (...) { uint64_t pc = r.u64(); std::string name; r.str(name); }
//   return r.ok();  // false if any read went past end

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tenet {

// ─── ByteWriter ─────────────────────────────────────────────────────────────

class ByteWriter {
public:
    ByteWriter() = default;
    explicit ByteWriter(size_t reserve) { buf_.reserve(reserve); }

    void u8(uint8_t  v) { buf_.append(reinterpret_cast<const char*>(&v), 1); }
    void u16(uint16_t v) { buf_.append(reinterpret_cast<const char*>(&v), 2); }
    void u32(uint32_t v) { buf_.append(reinterpret_cast<const char*>(&v), 4); }
    void u64(uint64_t v) { buf_.append(reinterpret_cast<const char*>(&v), 8); }
    void s32(int32_t  v) { buf_.append(reinterpret_cast<const char*>(&v), 4); }
    void f32(float    v) { buf_.append(reinterpret_cast<const char*>(&v), 4); }

    /// Write raw bytes (no length prefix).
    void bytes(const void* data, size_t len) {
        if (len > 0) buf_.append(reinterpret_cast<const char*>(data), len);
    }

    /// Length-prefixed string (u32 length + raw bytes).
    void str(const std::string& s) {
        u32(static_cast<uint32_t>(s.size()));
        buf_.append(s.data(), s.size());
    }

    /// Length-prefixed string_view (u32 length + raw bytes).
    void str(std::string_view s) {
        u32(static_cast<uint32_t>(s.size()));
        buf_.append(s.data(), s.size());
    }

    /// Optional string: u8 has_value flag, then str if present.
    void opt_str(const std::optional<std::string>& s) {
        if (s.has_value()) { u8(1u); str(*s); }
        else               { u8(0u); }
    }

    /// Optional bytes: u8 has_value flag, then u32 length + raw bytes.
    void opt_bytes(const std::optional<std::vector<uint8_t>>& b) {
        if (b.has_value()) {
            u8(1u);
            u32(static_cast<uint32_t>(b->size()));
            bytes(b->data(), b->size());
        } else {
            u8(0u);
        }
    }

    /// Advance pointer by N bytes (for manual padding).
    void pad(size_t n) { buf_.append(n, '\0'); }

    const std::string& data() const { return buf_; }
    size_t size() const { return buf_.size(); }

    std::string take() && { return std::move(buf_); }

private:
    std::string buf_;
};

// ─── ByteReader ─────────────────────────────────────────────────────────────

class ByteReader {
public:
    ByteReader(const char* data, size_t size)
        : p_(data), end_(data + size) {}

    explicit ByteReader(const std::string& s)
        : p_(s.data()), end_(s.data() + s.size()) {}

    // ── Fixed-size reads ──────────────────────────────────────────────────

    uint8_t  u8()  { uint8_t  v; copy(&v, 1); return v; }
    uint16_t u16() { uint16_t v; copy(&v, 2); return v; }
    uint32_t u32() { uint32_t v; copy(&v, 4); return v; }
    uint64_t u64() { uint64_t v; copy(&v, 8); return v; }
    int32_t  s32() { int32_t  v; copy(&v, 4); return v; }
    float    f32() { float    v; copy(&v, 4); return v; }

    /// Read raw bytes into a buffer.
    void bytes(void* out, size_t len) { copy(out, len); }

    // ── Variable-length reads ─────────────────────────────────────────────

    /// Length-prefixed string (u32 length + raw bytes).
    /// Returns false (and sets ok_=false) if out of bounds.
    bool str(std::string& out) {
        if (!ensure(4)) return false;
        uint32_t len = u32();
        if (!ensure(len)) return false;
        out.assign(p_, len);
        p_ += len;
        return true;
    }

    /// Optional string (u8 flag + optional str).
    bool opt_str(std::optional<std::string>& out) {
        if (!ensure(1)) return false;
        uint8_t has = u8();
        if (!has) { out.reset(); return true; }
        std::string s;
        if (!str(s)) return false;
        out = std::move(s);
        return true;
    }

    /// Optional bytes (u8 flag + optional u32 length + raw bytes).
    bool opt_bytes(std::optional<std::vector<uint8_t>>& out) {
        if (!ensure(1)) return false;
        uint8_t has = u8();
        if (!has) { out.reset(); return true; }
        if (!ensure(4)) return false;
        uint32_t len = u32();
        if (!ensure(len)) return false;
        std::vector<uint8_t> v(len);
        if (len) { std::memcpy(v.data(), p_, len); p_ += len; }
        out = std::move(v);
        return true;
    }

    // ── State queries ─────────────────────────────────────────────────────

    /// True if all reads so far were within bounds.
    bool ok() const { return ok_ && p_ <= end_; }

    /// Remaining bytes (only valid if ok()).
    size_t remaining() const { return ok_ ? static_cast<size_t>(end_ - p_) : 0; }

    /// Skip N bytes (for padding).
    void skip(size_t n) {
        if (ok_ && p_ + n <= end_) { p_ += n; }
        else { ok_ = false; }
    }

private:
    void copy(void* dst, size_t n) {
        if (n == 0) return;
        if (ok_ && p_ + n <= end_) {
            std::memcpy(dst, p_, n);
            p_ += n;
        } else {
            ok_ = false;
            std::memset(dst, 0, n);  // zero-fill on error
        }
    }

    bool ensure(size_t n) {
        if (ok_ && p_ + n <= end_) return true;
        ok_ = false;
        return false;
    }

    const char* p_;
    const char* const end_;
    bool ok_ = true;
};

}  // namespace tenet
