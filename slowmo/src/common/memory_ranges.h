#pragma once

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <utility>
#include <iterator>
#include <map>

namespace tenet {

// Disjoint byte intervals. Inclusive ends allow the final byte of the address
// space to be represented without wrapping an exclusive end to zero.
// Queries visit only intersecting intervals: O(log M + K).
template <typename T>
class MemoryRanges {
public:
    struct Entry { uint64_t last; T value; };
    bool empty() const { return ranges_.empty(); }
    size_t size() const { return ranges_.size(); }

    void limit(size_t max_intervals) {
        while (ranges_.size() > max_intervals) ranges_.erase(std::prev(ranges_.end()));
    }

    static uint64_t last_byte(uint64_t addr, uint64_t size) {
        return addr + std::min(size - 1, UINT64_MAX - addr);
    }

    template <typename Fn>
    void visit(uint64_t addr, uint64_t size, Fn&& fn) {
        if (!size) return;
        const auto last = last_byte(addr, size);
        auto it = ranges_.upper_bound(addr);
        if (it != ranges_.begin() && std::prev(it)->second.last >= addr) --it;
        for (; it != ranges_.end() && it->first <= last; ++it) {
            fn(std::max(addr, it->first), std::min(last, it->second.last), it->second.value);
        }
    }

    void erase(uint64_t addr, uint64_t size) {
        if (!size) return;
        const auto last = last_byte(addr, size);
        split(addr);
        if (last != UINT64_MAX) split(last + 1);
        ranges_.erase(ranges_.lower_bound(addr), ranges_.upper_bound(last));
    }

    void assign(uint64_t addr, uint64_t size, const T& value) {
        if (!size) return;
        erase(addr, size);
        ranges_.emplace(addr, Entry{last_byte(addr, size), value});
    }

    // Update every byte, including gaps initialized with T{}. Used to merge
    // sink tag masks without overwriting tags belonging to overlapping sinks.
    template <typename Fn>
    void update(uint64_t addr, uint64_t size, Fn&& fn) {
        if (!size) return;
        const auto last = last_byte(addr, size);
        split(addr);
        if (last != UINT64_MAX) split(last + 1);
        auto it = ranges_.lower_bound(addr);
        uint64_t pos = addr;
        while (true) {
            if (it == ranges_.end() || it->first > pos) {
                const auto end = it == ranges_.end() ? last : std::min(last, it->first - 1);
                it = ranges_.emplace(pos, Entry{end, T{}}).first;
            }
            fn(it->second.value);
            const auto end = it->second.last;
            if (end >= last) break;
            pos = end + 1;
            ++it;
        }
    }

private:
    void split(uint64_t addr) {
        auto it = ranges_.upper_bound(addr);
        if (it == ranges_.begin()) return;
        --it;
        if (it->first == addr || it->second.last < addr) return;
        Entry tail = it->second;
        it->second.last = addr - 1;
        ranges_.emplace(addr, std::move(tail));
    }
    std::map<uint64_t, Entry> ranges_;
};

} // namespace tenet
