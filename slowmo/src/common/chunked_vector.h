#pragma once

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <iterator>
#include <memory>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace tenet {
// Append-oriented result storage. Fixed chunks avoid vector's doubling/copy
// peak. Once the resident prefix budget is used, chunks live in anonymous
// temporary files. Mappings retain normal C++ object/reference semantics;
// files disappear automatically, and are never a cross-session object format.
template<class T, size_t ChunkBytes = 256 * 1024>
class ChunkedVector {
    static constexpr size_t slots = std::max<size_t>(1, ChunkBytes / sizeof(T));
#ifndef _WIN32
    struct Backing {
        FILE* file = std::tmpfile();
        uint64_t length = 0;
        Backing() { if (!file) throw std::runtime_error("Cannot create analysis spill file"); }
        ~Backing() { std::fclose(file); }
        uint64_t allocate(size_t bytes) {
            const auto page = static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
            const auto offset = (length + page - 1) / page * page;
            if (ftruncate(fileno(file), static_cast<off_t>(offset + bytes)) != 0)
                throw std::runtime_error("Cannot extend analysis spill file");
            length = offset + bytes; return offset;
        }
    };
#endif
    struct Chunk {
        T* data = nullptr; size_t used = 0; bool mapped = false;
        #ifndef _WIN32
        std::shared_ptr<Backing> backing;
        uint64_t file_offset = 0;
        explicit Chunk(bool spill, std::shared_ptr<Backing> store) : mapped(spill), backing(std::move(store)) {
#else
        explicit Chunk(bool spill) : mapped(spill) {
#endif
            const size_t bytes = slots * sizeof(T);
            if (!spill) { data = static_cast<T*>(::operator new(bytes)); return; }
#ifdef _WIN32
            FILE* f = std::tmpfile();
            if (!f) throw std::runtime_error("Cannot create analysis spill file");
            if (_chsize_s(_fileno(f), bytes) == 0) {
                auto h = CreateFileMappingW(reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(f))), nullptr, PAGE_READWRITE, 0, 0, nullptr);
                if (h) { data = static_cast<T*>(MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, bytes)); CloseHandle(h); }
            }
            std::fclose(f);
#else
            file_offset = backing->allocate(bytes);
            void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
                           fileno(backing->file), static_cast<off_t>(file_offset));
            if (p != MAP_FAILED) data = static_cast<T*>(p);
#endif
            if (!data) throw std::runtime_error("Cannot map analysis spill file");
        }
        void cool() {
            if (!mapped) return;
#ifdef _WIN32
            FlushViewOfFile(data, 0);
#else
            // Replace the mapping at the same address to discard process page
            // table entries. Shared dirty pages stay in the file cache; this
            // avoids synchronous disk flushes and preserves stable references.
            (void)mmap(data, slots * sizeof(T), PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_FIXED, fileno(backing->file),
                       static_cast<off_t>(file_offset));
#endif
        }
        ~Chunk() {
            for (size_t i = 0; i < used; ++i) data[i].~T();
            if (!mapped) ::operator delete(data);
#ifdef _WIN32
            else UnmapViewOfFile(data);
#else
            else munmap(data, slots * sizeof(T));
#endif
        }
    };
public:
    using value_type = T;
    using size_type = size_t;
    template<bool Const> class Iter {
        using Owner = std::conditional_t<Const, const ChunkedVector, ChunkedVector>;
        Owner* owner_ = nullptr; size_t pos_ = 0;
    public:
        using iterator_category = std::random_access_iterator_tag;
        using value_type = T; using difference_type = std::ptrdiff_t;
        using reference = std::conditional_t<Const, const T&, T&>;
        using pointer = std::conditional_t<Const, const T*, T*>;
        Iter() = default;
        Iter(Owner* owner, size_t pos) : owner_(owner), pos_(pos) {}
        reference operator*() const { return (*owner_)[pos_]; }
        pointer operator->() const { return &**this; }
        reference operator[](difference_type n) const { return *(*this + n); }
        Iter& operator++() { ++pos_; return *this; } Iter operator++(int) { auto p=*this; ++*this; return p; }
        Iter& operator--() { --pos_; return *this; } Iter operator--(int) { auto p=*this; --*this; return p; }
        Iter& operator+=(difference_type n) { pos_ += n; return *this; }
        Iter& operator-=(difference_type n) { pos_ -= n; return *this; }
        friend Iter operator+(Iter i, difference_type n) { return i += n; }
        friend Iter operator+(difference_type n, Iter i) { return i += n; }
        friend Iter operator-(Iter i, difference_type n) { return i -= n; }
        friend difference_type operator-(Iter a, Iter b) { return difference_type(a.pos_) - difference_type(b.pos_); }
        friend bool operator==(Iter a, Iter b) { return a.pos_ == b.pos_; }
        friend auto operator<=>(Iter a, Iter b) { return a.pos_ <=> b.pos_; }
    };
    using iterator = Iter<false>; using const_iterator = Iter<true>;
    ChunkedVector() = default;
    ChunkedVector(ChunkedVector&& o) noexcept { *this = std::move(o); }
    ChunkedVector& operator=(ChunkedVector&& o) noexcept {
        if (this != &o) { chunks_ = std::move(o.chunks_); size_ = std::exchange(o.size_, 0);
            #ifndef _WIN32
            backing_ = std::move(o.backing_);
#endif
            budget_ = o.budget_; resident_ = std::exchange(o.resident_, 0); spilled_ = std::exchange(o.spilled_, 0); }
        return *this;
    }
    ChunkedVector(const ChunkedVector& o) : budget_(o.budget_) { for (const auto& x : o) push_back(x); }
    ChunkedVector& operator=(const ChunkedVector& o) { if (this != &o) { clear(); for (const auto& x : o) push_back(x); } return *this; }
    ChunkedVector& operator=(std::vector<T>&& o) { clear(); for (auto& x : o) push_back(std::move(x)); return *this; }
    void set_resident_budget(size_t bytes) { if (size_) throw std::logic_error("Configure storage before appending"); budget_ = bytes; }
    void reserve(size_t) {} // no eager N-sized allocation
    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }
    size_t spilled_bytes() const { return spilled_; }
    size_t resident_capacity_bytes() const { return resident_; }
    T& operator[](size_t i) { return chunks_[i / slots]->data[i % slots]; }
    const T& operator[](size_t i) const { return chunks_[i / slots]->data[i % slots]; }
    T& at(size_t i) { if (i >= size_) throw std::out_of_range("result index"); return (*this)[i]; }
    const T& at(size_t i) const { if (i >= size_) throw std::out_of_range("result index"); return (*this)[i]; }
    T& front() { return (*this)[0]; } const T& front() const { return (*this)[0]; }
    T& back() { return (*this)[size_-1]; } const T& back() const { return (*this)[size_-1]; }
    template<class... A> T& emplace_back(A&&... args) {
        if (size_ % slots == 0) {
            if (!chunks_.empty()) chunks_.back()->cool();
            const bool spill = resident_ + slots * sizeof(T) > budget_;
            #ifdef _WIN32
            chunks_.push_back(std::make_unique<Chunk>(spill));
#else
            if (spill && !backing_) backing_ = std::make_shared<Backing>();
            chunks_.push_back(std::make_unique<Chunk>(spill, spill ? backing_ : nullptr));
#endif
            (spill ? spilled_ : resident_) += slots * sizeof(T);
        }
        auto& c = *chunks_.back();
        T* p = new (c.data + c.used) T(std::forward<A>(args)...);
        ++c.used; ++size_; return *p;
    }
    void push_back(const T& x) { emplace_back(x); }
    void push_back(T&& x) { emplace_back(std::move(x)); }
    void clear() { chunks_.clear(); size_ = spilled_ = resident_ = 0;
#ifndef _WIN32
        backing_.reset();
#endif
    }
    template<class It> iterator insert(iterator pos, It first, It last) {
        if (pos != end()) throw std::logic_error("ChunkedVector only supports append insertion");
        const auto start = size_; for (; first != last; ++first) emplace_back(*first);
        return {this, start};
    }
    void pop_back() {
        if (!size_) throw std::out_of_range("empty result");
        auto& c = *chunks_.back(); c.data[--c.used].~T(); --size_;
        if (!c.used) { (c.mapped ? spilled_ : resident_) -= slots * sizeof(T); chunks_.pop_back(); }
    }
    iterator erase(iterator first, iterator last) {
        const auto pos = static_cast<size_t>(first - begin());
        const auto n = static_cast<size_t>(last - first);
        for (size_t i = pos; i + n < size_; ++i) (*this)[i] = std::move((*this)[i + n]);
        for (size_t i = 0; i < n; ++i) pop_back();
        return {this, pos};
    }
    void resize(size_t n) { while (size_ > n) pop_back(); while (size_ < n) emplace_back(); }
    void shrink_to_fit() {}
    // Call during a sequential read to release the preceding mapped chunk.
    void cool_before(size_t index) const {
        if (index && index % slots == 0 && index / slots <= chunks_.size())
            chunks_[index / slots - 1]->cool();
    }
    iterator begin() { return {this, 0}; } iterator end() { return {this, size_}; }
    const_iterator begin() const { return {this, 0}; } const_iterator end() const { return {this, size_}; }
    const_iterator cbegin() const { return begin(); } const_iterator cend() const { return end(); }
private:
#ifndef _WIN32
    std::shared_ptr<Backing> backing_;
#endif
    std::vector<std::unique_ptr<Chunk>> chunks_;
    size_t size_ = 0, budget_ = 8u << 20, resident_ = 0, spilled_ = 0;
};
} // namespace tenet
