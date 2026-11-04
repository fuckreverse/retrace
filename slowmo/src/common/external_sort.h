#pragma once

#include "common/platform_compat.h"
#include "common/platform_file.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <memory>
#include <queue>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace tenet {
struct ScratchDirectory {
    std::filesystem::path path;
    ScratchDirectory() {
        static std::atomic<uint64_t> serial{0};
        path = std::filesystem::temp_directory_path() /
            ("tenet_analysis_" + std::to_string(platform::current_pid()) + "_" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" + std::to_string(serial++));
        if (!std::filesystem::create_directory(path)) throw std::runtime_error("Cannot create analysis scratch directory");
    }
    ~ScratchDirectory() { std::error_code ec; std::filesystem::remove_all(path, ec); }
};

// Bounded run generation and 32-way merge. At most 33 files are open even
// for billion-record inputs. Scratch files are private to this sort instance.
template<class T, class Less = std::less<T>>
class ExternalSorter {
    static_assert(std::is_trivially_copyable_v<T>);
    struct Close { void operator()(FILE* f) const { if (f) std::fclose(f); } };
    using File = std::unique_ptr<FILE, Close>;
public:
    explicit ExternalSorter(size_t bytes, std::function<void()> check = {})
        : scratch(std::make_shared<ScratchDirectory>()), limit_(std::max<size_t>(1, bytes / sizeof(T))), check_(std::move(check)) {
        buffer_.reserve(limit_);
    }
    void add(const T& value) { buffer_.push_back(value); if (buffer_.size() >= limit_) flush(); }
    template<class Fn> void finish(Fn&& consume) {
        flush();
        while (runs_.size() > 32) {
            std::vector<std::filesystem::path> next;
            for (size_t i = 0; i < runs_.size(); i += 32) {
                const auto end = std::min(i + 32, runs_.size());
                std::vector<std::filesystem::path> group(runs_.begin() + i, runs_.begin() + end);
                auto path = next_path(); auto out = open(path, "wb");
                merge(group, [&](const T& v) { write(out.get(), v); });
                if (std::fflush(out.get()) != 0) throw std::runtime_error("External-sort flush failed");
                out.reset();
                for (const auto& p : group) std::filesystem::remove(p);
                next.push_back(std::move(path));
            }
            runs_ = std::move(next);
        }
        merge(runs_, std::forward<Fn>(consume));
        for (const auto& p : runs_) std::filesystem::remove(p);
        runs_.clear();
    }
    std::shared_ptr<ScratchDirectory> scratch;
    size_t runs_written() const { return serial_; }
private:
    File open(const std::filesystem::path& p, const char* mode) {
        File f(platform::open_file(p, mode));
        if (!f) throw std::runtime_error("Cannot open external-sort run");
        return f;
    }
    static void write(FILE* f, const T& v) {
        if (std::fwrite(&v, sizeof(T), 1, f) != 1) throw std::runtime_error("External-sort disk write failed");
    }
    std::filesystem::path next_path() { return scratch->path / ("run_" + std::to_string(serial_++)); }
    void flush() {
        if (buffer_.empty()) return;
        if (check_) check_();
        std::sort(buffer_.begin(), buffer_.end(), Less{});
        auto p = next_path(); auto out = open(p, "wb");
        if (std::fwrite(buffer_.data(), sizeof(T), buffer_.size(), out.get()) != buffer_.size())
            throw std::runtime_error("External-sort run write failed");
        if (std::fflush(out.get()) != 0) throw std::runtime_error("External-sort flush failed");
        runs_.push_back(std::move(p)); buffer_.clear();
    }
    template<class Fn> void merge(const std::vector<std::filesystem::path>& paths, Fn&& consume) {
        struct Item { T value; size_t file; };
        auto later = [](const Item& a, const Item& b) { return Less{}(b.value, a.value); };
        std::priority_queue<Item, std::vector<Item>, decltype(later)> heap(later);
        std::vector<File> files;
        for (const auto& p : paths) {
            files.push_back(open(p, "rb")); T v;
            if (std::fread(&v, sizeof(T), 1, files.back().get()) == 1) heap.push({v, files.size() - 1});
            else if (std::ferror(files.back().get())) throw std::runtime_error("External-sort read failed");
        }
        size_t n = 0;
        while (!heap.empty()) {
            if ((n++ & 65535) == 0 && check_) check_();
            const auto item = heap.top(); heap.pop(); consume(item.value);
            T v;
            if (std::fread(&v, sizeof(T), 1, files[item.file].get()) == 1) heap.push({v, item.file});
            else if (std::ferror(files[item.file].get())) throw std::runtime_error("External-sort read failed");
        }
    }
    size_t limit_, serial_ = 0;
    std::vector<T> buffer_;
    std::vector<std::filesystem::path> runs_;
    std::function<void()> check_;
};
} // namespace tenet
