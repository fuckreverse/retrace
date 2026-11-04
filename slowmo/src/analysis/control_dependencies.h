#pragma once

#include "analysis/pass_manager.h"
#include "common/chunked_vector.h"
#include "core/instruction_decoder.h"
#include "io/index_builder.h"
#include "io/trace_reader.h"
#include <algorithm>
#include <unordered_map>
#include <vector>

namespace tenet {
// Dynamic control dependence, scoped by thread and call depth. The CFG includes
// observed edges plus both encoded successors of conditional branches. Missing
// paths join a virtual exit and are explicitly reported as uncertain, rather
// than inventing a reconvergence point.
class ControlDependencies {
    struct Node {
        uint64_t pc;
        std::vector<uint32_t> succ, pred;
        uint32_t join = UINT32_MAX;
        bool branch = false, call = false, ret = false;
    };
public:
    ChunkedVector<uint64_t> parents;
    uint64_t unresolved_joins = 0;
    bool branch(uint64_t pc) const {
        auto i = ids_.find(pc); return i != ids_.end() && nodes_[i->second].branch;
    }
    explicit ControlDependencies(PassContext& ctx) {
        parents.set_resident_budget(ctx.memory_budget_bytes() / 4);
        auto node = [&](uint64_t pc) {
            auto [i, fresh] = ids_.try_emplace(pc, static_cast<uint32_t>(nodes_.size()));
            if (fresh) {
                Node n; n.pc = pc;
                auto d = ctx.decoder().decode(pc, ctx.code_table());
                if (d && d->decoded) {
                    const auto mn = d->mnemonic_sv();
                    n.branch = (mn.starts_with("b.") || mn == "cbz" || mn == "cbnz" || mn == "tbz" || mn == "tbnz" || mn == "br");
                    n.call = mn == "bl" || mn == "blr"; n.ret = mn == "ret";
                }
                nodes_.push_back(std::move(n));
            }
            return i->second;
        };
        auto edge = [&](uint32_t a, uint32_t b) {
            auto& s = nodes_[a].succ;
            if (std::find(s.begin(), s.end(), b) == s.end()) { s.push_back(b); nodes_[b].pred.push_back(a); }
        };
        std::unordered_map<uint64_t, uint32_t> last;
        uint64_t iid = 0;
        auto tr = ctx.reader().create_thread_reader(2);
        for (auto it = ctx.reader().begin(tr); it != ctx.reader().end(tr); ++it) {
            const auto r = *it; if (r.kind != RecordKind::Inst) continue;
            if ((iid & 65535) == 0 && (ctx.cancelled() || ctx.memory_pressure())) throw std::runtime_error("control index cancelled or memory limit exceeded");
            const auto tid = ctx.index().thread_at(iid++);
            const auto n = node(r.as_inst().pc);
            if (auto p = last.find(tid); p != last.end()) edge(p->second, n);
            last[tid] = n;
            auto op = ctx.code_table().opcode_at(r.as_inst().pc);
            if (!op || !nodes_[n].branch) continue;
            const uint32_t word = *op;
            unsigned bits = 0, shift = 0;
            if ((word & 0xff000010u) == 0x54000000u) { bits = 19; shift = 5; }
            else if ((word & 0x7e000000u) == 0x34000000u) { bits = 19; shift = 5; }
            else if ((word & 0x7e000000u) == 0x36000000u) { bits = 14; shift = 5; }
            if (bits) {
                int64_t imm = (word >> shift) & ((uint32_t(1) << bits) - 1);
                if (imm & (int64_t(1) << (bits - 1))) imm -= int64_t(1) << bits;
                const auto target = node(r.as_inst().pc + imm * 4);
                const auto fallthrough = node(r.as_inst().pc + 4);
                edge(n, target); edge(n, fallthrough);
            }
        }
        const uint32_t exit = static_cast<uint32_t>(nodes_.size());
        nodes_.push_back(Node{UINT64_MAX});
        for (uint32_t n = 0; n < exit; ++n) if (nodes_[n].succ.empty()) edge(n, exit);
        for (auto [tid, n] : last) edge(n, exit);
        // Cooper dominators on the reversed graph = forward postdominators.
        std::vector<uint32_t> order, rank(nodes_.size(), UINT32_MAX), dom(nodes_.size(), UINT32_MAX);
        std::vector<bool> seen(nodes_.size(), false);
        std::vector<std::pair<uint32_t, size_t>> stack{{exit, 0}}; seen[exit] = true;
        while (!stack.empty()) {
            auto& f = stack.back();
            if (f.second < nodes_[f.first].pred.size()) {
                auto c = nodes_[f.first].pred[f.second++];
                if (!seen[c]) { seen[c] = true; stack.push_back({c, 0}); }
            } else { order.push_back(f.first); stack.pop_back(); }
        }
        std::reverse(order.begin(), order.end());
        for (uint32_t i = 0; i < order.size(); ++i) rank[order[i]] = i;
        dom[exit] = exit;
        auto intersect = [&](uint32_t a, uint32_t b) {
            while (a != b) {
                while (rank[a] > rank[b]) a = dom[a];
                while (rank[b] > rank[a]) b = dom[b];
            }
            return a;
        };
        bool changed = true;
        while (changed) {
            if (ctx.cancelled()) throw std::runtime_error("control index cancelled");
            changed = false;
            for (size_t i = 1; i < order.size(); ++i) {
                auto n = order[i]; uint32_t next = UINT32_MAX;
                for (auto s : nodes_[n].succ) if (dom[s] != UINT32_MAX)
                    next = next == UINT32_MAX ? s : intersect(next, s);
                if (next != UINT32_MAX && next != dom[n]) { dom[n] = next; changed = true; }
            }
        }
        for (uint32_t n = 0; n < exit; ++n) if (nodes_[n].branch) {
            nodes_[n].join = dom[n];
            if (dom[n] == UINT32_MAX || dom[n] == exit) ++unresolved_joins;
        }
        struct Frame { uint32_t branch, join, depth; uint64_t id; };
        struct Thread { uint32_t depth = 0; uint64_t pending_call = UINT64_MAX; std::vector<Frame> frames; };
        std::unordered_map<uint64_t, Thread> threads;
        iid = 0;
        for (auto it = ctx.reader().begin(tr); it != ctx.reader().end(tr); ++it) {
            const auto r = *it; if (r.kind != RecordKind::Inst) continue;
            if ((iid & 65535) == 0 && ctx.cancelled()) throw std::runtime_error("control index cancelled");
            auto& t = threads[ctx.index().thread_at(iid)];
            const auto n = ids_.at(r.as_inst().pc);
            if (t.pending_call != UINT64_MAX) {
                if (r.as_inst().pc != t.pending_call) ++t.depth;
                t.pending_call = UINT64_MAX;
            }
            for (size_t i = 0; i < t.frames.size(); ++i) if (t.frames[i].join == n && t.frames[i].depth == t.depth) {
                t.frames.resize(i); break;
            }
            parents.push_back(t.frames.empty() ? UINT64_MAX : t.frames.back().id);
            if (nodes_[n].branch) {
                // Iterations replace the previous instance of the same guard;
                // recursion at another call depth remains a separate scope.
                for (size_t i = 0; i < t.frames.size(); ++i) if (t.frames[i].branch == n && t.frames[i].depth == t.depth) {
                    t.frames.resize(i); break;
                }
                t.frames.push_back({n, nodes_[n].join, t.depth, iid});
            }
            if (nodes_[n].call) t.pending_call = r.as_inst().pc + 4;
            if (nodes_[n].ret && t.depth) {
                --t.depth;
                while (!t.frames.empty() && t.frames.back().depth > t.depth) t.frames.pop_back();
            }
            ++iid;
        }
    }
private:
    std::unordered_map<uint64_t, uint32_t> ids_;
    std::vector<Node> nodes_;
};
} // namespace tenet
