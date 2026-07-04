#include "analysis/passes/profile/dataflow_graph_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <map>

namespace tenet {

// ─── DataflowGraphResult serialization helpers ────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x44464752 ("DFGR")
//   u32  version = 2
//   u64  num_nodes
//   for each DataflowNode:
//     u64  inst_id, pc
//     u32  mnemonic_len; u8[] mnemonic
//     u32  num_regs_read; u8[] regs_read
//     u32  num_regs_written; u8[] regs_written
//   u64  num_edges
//   for each DFGEdge:
//     u64  from_inst_id, to_inst_id
//     u8   via_reg
//     u64  via_mem_addr
//   (adjacency index rebuilt after deserialization)
//
// Version history:
//   v1: register-only edges (via_mem_addr always 0).
//   v2: adds memory dependency edges (store → load, via_mem_addr != 0).
//       Wire format is unchanged (via_mem_addr was always serialized); the
//       version bump exists purely so older v1 blobs — produced before
//       memory edges existed — are invalidated and the pass re-runs to
//       pick up the new edges, rather than silently serving stale results.

namespace {

static constexpr uint32_t DFGR_BLOB_MAGIC   = 0x44464752u;  // "DFGR"
static constexpr uint32_t DFGR_BLOB_VERSION = 2u;

std::string dataflow_graph_serialize(const DataflowGraphResult& res) {
    size_t total = 4 + 4 + 8;  // magic, version, num_nodes
    for (const auto& n : res.nodes) {
        total += 8 + 8;  // inst_id, pc
        total += 4 + n.mnemonic.size();
        total += 4 + n.regs_read.size();
        total += 4 + n.regs_written.size();
    }
    total += 8;  // num_edges
    total += res.edges.size() * (8 + 8 + 1 + 8);  // from, to, reg, mem_addr

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u8  = [&](uint8_t  v) { *reinterpret_cast<uint8_t*>(p) = v; p += 1; };
    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };

    write_u32(DFGR_BLOB_MAGIC);
    write_u32(DFGR_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.nodes.size()));

    for (const auto& n : res.nodes) {
        write_u64(n.inst_id);
        write_u64(n.pc);
        write_u32(static_cast<uint32_t>(n.mnemonic.size()));
        std::memcpy(p, n.mnemonic.data(), n.mnemonic.size()); p += n.mnemonic.size();
        write_u32(static_cast<uint32_t>(n.regs_read.size()));
        std::memcpy(p, n.regs_read.data(), n.regs_read.size()); p += n.regs_read.size();
        write_u32(static_cast<uint32_t>(n.regs_written.size()));
        std::memcpy(p, n.regs_written.data(), n.regs_written.size()); p += n.regs_written.size();
    }

    write_u64(static_cast<uint64_t>(res.edges.size()));
    for (const auto& e : res.edges) {
        write_u64(e.from_inst_id);
        write_u64(e.to_inst_id);
        write_u8(e.via_reg);
        write_u64(e.via_mem_addr);
    }

    return buf;
}

bool dataflow_graph_deserialize(const std::string& blob, DataflowGraphResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u8  = [&]() -> uint8_t  { uint8_t  v = *reinterpret_cast<const uint8_t*>(p); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };

    if (read_u32() != DFGR_BLOB_MAGIC)   return false;
    if (read_u32() != DFGR_BLOB_VERSION) return false;

    uint64_t n_nodes = read_u64();
    out.nodes.reserve(static_cast<size_t>(n_nodes));

    for (uint64_t i = 0; i < n_nodes; i++) {
        DataflowNode n;
        if (p + 8 + 8 > end) return false;
        n.inst_id = read_u64();
        n.pc      = read_u64();
        if (p + 4 > end) return false;
        uint32_t mnem_len = read_u32();
        if (p + mnem_len > end) return false;
        n.mnemonic.assign(p, mnem_len); p += mnem_len;
        if (p + 4 > end) return false;
        uint32_t nr = read_u32();
        if (p + nr > end) return false;
        n.regs_read.assign(reinterpret_cast<const uint8_t*>(p),
                           reinterpret_cast<const uint8_t*>(p) + nr);
        p += nr;
        if (p + 4 > end) return false;
        uint32_t nw = read_u32();
        if (p + nw > end) return false;
        n.regs_written.assign(reinterpret_cast<const uint8_t*>(p),
                              reinterpret_cast<const uint8_t*>(p) + nw);
        p += nw;

        size_t node_idx = out.nodes.size();
        out.inst_to_node[n.inst_id] = node_idx;
        out.nodes.push_back(std::move(n));
    }

    if (p + 8 > end) return false;
    uint64_t n_edges = read_u64();
    out.edges.reserve(static_cast<size_t>(n_edges));
    for (uint64_t i = 0; i < n_edges; i++) {
        if (p + 8 + 8 + 1 + 8 > end) return false;
        DFGEdge e;
        e.from_inst_id = read_u64();
        e.to_inst_id   = read_u64();
        e.via_reg      = read_u8();
        e.via_mem_addr = read_u64();
        out.edges.push_back(e);
    }

    // Rebuild adjacency index
    out.build_adjacency();

    return true;
}

}  // anonymous namespace (dataflow_graph serialization)

// ─── Register name helper (AArch64) ───────────────────────────────────────

static std::string reg_name(uint8_t idx) {
    if (idx <= 28) return fmt::format("x{}", idx);
    if (idx == IDX_FP)   return "fp";
    if (idx == IDX_LR)   return "lr";
    if (idx == IDX_SP)   return "sp";
    if (idx == IDX_NZCV) return "nzcv";
    if (idx == IDX_PC)   return "pc";
    return fmt::format("r{}", idx);
}

// ─── Query helpers ────────────────────────────────────────────────────────

std::vector<DFGEdge> DataflowGraphResult::producers_of(uint64_t inst_id) const {
    std::vector<DFGEdge> result;
    auto it = incoming_edge_idx_.find(inst_id);
    if (it == incoming_edge_idx_.end()) return result;
    result.reserve(it->second.size());
    for (size_t idx : it->second) {
        result.push_back(edges[idx]);
    }
    return result;
}

std::vector<DFGEdge> DataflowGraphResult::consumers_of(uint64_t inst_id) const {
    std::vector<DFGEdge> result;
    auto it = outgoing_edge_idx_.find(inst_id);
    if (it == outgoing_edge_idx_.end()) return result;
    result.reserve(it->second.size());
    for (size_t idx : it->second) {
        result.push_back(edges[idx]);
    }
    return result;
}

// ─── DOT export ───────────────────────────────────────────────────────────

std::string DataflowGraphResult::to_dot() const {
    std::string out;
    out += "digraph dataflow {\n";
    out += "    rankdir=TB;\n";
    out += "    node [shape=box, style=filled, fillcolor=\"#e8e8e8\", "
           "fontname=\"Courier\", fontsize=10];\n";
    out += "    edge [fontname=\"Courier\", fontsize=9];\n\n";

    // Emit nodes
    for (const auto& node : nodes) {
        auto label = fmt::format("{} @ 0x{:X}", node.mnemonic, node.pc);
        out += fmt::format("    n{} [label=\"#{}: {}\"];\n",
                           node.inst_id, node.inst_id, label);
    }

    out += "\n";

    // Emit edges. Memory edges (via_mem_addr != 0) are distinguished from
    // register edges both by label and by a dashed/colored style, since
    // via_reg == 0 is ambiguous with the legitimate register x0.
    for (const auto& edge : edges) {
        if (edge.via_mem_addr != 0) {
            out += fmt::format(
                "    n{} -> n{} [label=\"mem:0x{:X}\", style=dashed, color=\"#3070c0\"];\n",
                edge.from_inst_id, edge.to_inst_id, edge.via_mem_addr);
        } else {
            out += fmt::format("    n{} -> n{} [label=\"{}\"];\n",
                               edge.from_inst_id, edge.to_inst_id,
                               reg_name(edge.via_reg));
        }
    }

    out += "}\n";
    return out;
}

// ─── JSON export ──────────────────────────────────────────────────────────

/// Escape a string for JSON output (handles quotes and backslashes).
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"')       out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\t') out += "\\t";
        else                out += c;
    }
    return out;
}

std::string DataflowGraphResult::to_json() const {
    std::string out;
    out += "{\n";

    // Nodes
    out += "  \"nodes\": [\n";
    for (size_t i = 0; i < nodes.size(); ++i) {
        const auto& node = nodes[i];
        out += fmt::format("    {{\"inst_id\": {}, \"pc\": {}, \"mnemonic\": \"{}\", ",
                           node.inst_id, node.pc, json_escape(node.mnemonic));

        out += "\"regs_read\": [";
        for (size_t r = 0; r < node.regs_read.size(); ++r) {
            if (r > 0) out += ", ";
            out += fmt::format("\"{}\"", reg_name(node.regs_read[r]));
        }
        out += "], \"regs_written\": [";
        for (size_t r = 0; r < node.regs_written.size(); ++r) {
            if (r > 0) out += ", ";
            out += fmt::format("\"{}\"", reg_name(node.regs_written[r]));
        }
        out += "]}";
        if (i + 1 < nodes.size()) out += ",";
        out += "\n";
    }
    out += "  ],\n";

    // Edges. Memory edges (via_mem_addr != 0) carry a "via_mem" field instead
    // of "reg", since via_reg == 0 is ambiguous with the legitimate x0.
    out += "  \"edges\": [\n";
    for (size_t i = 0; i < edges.size(); ++i) {
        const auto& edge = edges[i];
        if (edge.via_mem_addr != 0) {
            out += fmt::format(
                "    {{\"from_inst_id\": {}, \"to_inst_id\": {}, \"via_mem\": \"0x{:X}\"}}",
                edge.from_inst_id, edge.to_inst_id, edge.via_mem_addr);
        } else {
            out += fmt::format("    {{\"from_inst_id\": {}, \"to_inst_id\": {}, \"reg\": \"{}\"}}",
                               edge.from_inst_id, edge.to_inst_id,
                               reg_name(edge.via_reg));
        }
        if (i + 1 < edges.size()) out += ",";
        out += "\n";
    }
    out += "  ]\n";

    out += "}\n";
    return out;
}

// ─── Pass implementation ──────────────────────────────────────────────────

PassResult DataflowGraphPass::run(PassContext& ctx) {
    auto& reader     = ctx.reader();
    auto& index      = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder    = ctx.decoder();
    const auto& range = ctx.range();

    // Determine effective analysis range by intersecting config with context range
    uint64_t start = std::max(config_.start_inst_id, range.start_inst_id);
    uint64_t end   = std::min(config_.end_inst_id, range.end_inst_id);

    // ─── Fast path: load from persisted cache ─────────────────────────────
    // Only cache when using the full trace with default config range.
    bool is_default_range = (config_.start_inst_id == 0 && config_.end_inst_id == UINT64_MAX);
    if (ctx.range().is_full_trace() && is_default_range) {
        std::string blob;
        if (index.load_pass_blob("dataflow_graph", blob)) {
            DataflowGraphResult cached;
            if (dataflow_graph_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Dataflow graph: {} nodes, {} edges (from cache)",
                    cached.nodes.size(), cached.edges.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }
    end = std::min(end, index.inst_count());
    if (end == 0) end = index.inst_count();

    if (start >= end) {
        return PassResult::failed(
            fmt::format("Empty analysis range: start={} >= end={}", start, end));
    }

    DataflowGraphResult result;

    // last_writer[reg] = inst_id of the instruction that most recently wrote `reg`.
    // We use UINT64_MAX as the sentinel meaning "no writer seen yet".
    constexpr uint64_t NO_WRITER = UINT64_MAX;
    std::array<uint64_t, AARCH64_GPR_COUNT> last_writer;
    last_writer.fill(NO_WRITER);

    // ─── Memory dependency tracking ────────────────────────────────────────
    // Tracks live (non-fully-shadowed) store intervals as start_addr →
    // {end_addr, inst_id}, ordered by start address. On each load, we find
    // the interval with the greatest inst_id whose byte range overlaps the
    // load (same overlap test as BackwardTaintPass:
    //   store_start < load_end && load_start < store_end
    // ) and add a single edge from that instruction — the most recent write
    // is the effective source of the loaded bytes. On each store, any
    // existing interval fully covered by the new write is dropped (its bytes
    // can never be observed again) to keep the map small.
    struct MemWriteEntry {
        uint64_t end_addr;
        uint64_t inst_id;
    };
    std::map<uint64_t, MemWriteEntry> mem_writes;  // start_addr → {end_addr, inst_id}

    uint64_t nodes_added = 0;
    uint64_t total = end - start;

    // Seek directly to start position using index (avoid scanning prefix)
    uint64_t start_offset = 0;
    uint64_t scan_inst_id = 0;
    if (start > 0) {
        auto [off, pc] = index.offset_of_with_pc(start, reader);
        start_offset = off;
        scan_inst_id = start;
    }

    auto it_begin = (start > 0) ? TraceReader::Iterator(&reader, start_offset) : reader.begin();
    uint64_t inst_id = scan_inst_id;

    for (auto it = it_begin; it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        if (ctx.cancelled()) {
            break;
        }

        // Enforce max_nodes to keep graph sizes practical
        if (nodes_added >= config_.max_nodes) {
            break;
        }

        auto inst = rec.as_inst();
        auto opcode = code_table.opcode_at(inst.pc);
        if (!opcode) {
            inst_id++;
            continue;
        }

        auto decoded = decoder.decode(inst.pc, *opcode);
        if (!decoded) {
            inst_id++;
            continue;
        }

        // Build the node
        DataflowNode node;
        node.inst_id = inst_id;
        node.pc = inst.pc;
        node.mnemonic = std::string(decoded->mnemonic_sv());
        node.regs_read.assign(decoded->regs_read.begin(),
                              decoded->regs_read.begin() + decoded->regs_read_count);
        node.regs_written.assign(decoded->regs_written.begin(),
                                 decoded->regs_written.begin() + decoded->regs_written_count);

        size_t node_idx = result.nodes.size();
        result.inst_to_node[inst_id] = node_idx;

        // Create edges for each register read: last_writer[reg] → this inst
        for (uint8_t i = 0; i < decoded->regs_read_count; ++i) {
            uint8_t reg = decoded->regs_read[i];
            if (reg >= AARCH64_GPR_COUNT) continue;

            uint64_t writer = last_writer[reg];
            if (writer != NO_WRITER) {
                // Only create an edge if the producer is also in the graph
                if (result.inst_to_node.count(writer) > 0) {
                    DFGEdge edge;
                    edge.from_inst_id = writer;
                    edge.to_inst_id   = inst_id;
                    edge.via_reg      = reg;
                    result.edges.push_back(edge);
                }
            }
        }

        // Update last_writer for each register written
        for (uint8_t i = 0; i < decoded->regs_written_count; ++i) {
            uint8_t reg = decoded->regs_written[i];
            if (reg >= AARCH64_GPR_COUNT) continue;
            last_writer[reg] = inst_id;
        }

        // ─── Memory dependency edges (store → load) ─────────────────────
        // Uses the trace's recorded mem_access entries (actual runtime
        // addresses), not statically-inferred operands, so this is precise
        // even for register-indexed/indirect addressing. See mem_writes
        // declaration above for the resolution semantics.
        if (inst.mem_access_count > 0) {
            for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
                auto mem = inst.mem_access(m);
                bool is_write = (mem.type & 0x02) != 0;
                if (is_write || mem.addr == 0 || mem.size == 0) continue;

                uint64_t load_start = mem.addr;
                uint64_t load_end   = mem.addr + mem.size;

                // Scan backward from the first store starting at/after
                // load_end; once a store starts at or before load_start, no
                // earlier (smaller start_addr) store can overlap further
                // right, so it's safe to stop after examining it.
                uint64_t best_writer = NO_WRITER;
                auto it_mw = mem_writes.upper_bound(load_end);
                while (it_mw != mem_writes.begin()) {
                    --it_mw;
                    uint64_t store_start = it_mw->first;
                    uint64_t store_end   = it_mw->second.end_addr;
                    bool overlaps = store_start < load_end && load_start < store_end;
                    if (overlaps &&
                        (best_writer == NO_WRITER || it_mw->second.inst_id > best_writer)) {
                        best_writer = it_mw->second.inst_id;
                    }
                    if (store_start <= load_start) break;  // no earlier store can start later
                }

                if (best_writer != NO_WRITER && result.inst_to_node.count(best_writer) > 0) {
                    DFGEdge edge;
                    edge.from_inst_id = best_writer;
                    edge.to_inst_id   = inst_id;
                    edge.via_reg      = 0;
                    edge.via_mem_addr = mem.addr;
                    result.edges.push_back(edge);
                }
            }

            // Writes: record this instruction as the latest writer for the
            // touched byte range, dropping any pre-existing entries that are
            // now fully shadowed (their bytes can no longer be observed by
            // any future load) to keep the map small.
            for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
                auto mem = inst.mem_access(m);
                bool is_write = (mem.type & 0x02) != 0;
                if (!is_write || mem.addr == 0 || mem.size == 0) continue;

                uint64_t store_start = mem.addr;
                uint64_t store_end   = mem.addr + mem.size;

                auto it_lo = mem_writes.lower_bound(store_start);
                for (auto it_e = it_lo; it_e != mem_writes.end() && it_e->first < store_end; ) {
                    if (it_e->second.end_addr <= store_end) {
                        it_e = mem_writes.erase(it_e);
                    } else {
                        ++it_e;
                    }
                }

                mem_writes[store_start] = MemWriteEntry{store_end, inst_id};
            }
        }

        result.nodes.push_back(std::move(node));
        nodes_added++;
        inst_id++;

        // Report progress periodically
        if (nodes_added % 1000 == 0) {
            float pct = (total > 0)
                ? static_cast<float>(inst_id - start) / static_cast<float>(total)
                : 1.0f;
            ctx.progress(std::min(pct, 1.0f),
                         fmt::format("Dataflow graph: {} nodes, {} edges",
                                     result.nodes.size(), result.edges.size()));
        }
    }

    ctx.progress(1.0f,
                 fmt::format("Dataflow graph: {} nodes, {} edges",
                             result.nodes.size(), result.edges.size()));

    // Build O(1) adjacency index for producer/consumer queries.
    result.build_adjacency();

    // ─── Persist to cache ─────────────────────────────────────────────────
    if (ctx.range().is_full_trace() && is_default_range) {
        std::string blob = dataflow_graph_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("dataflow_graph", blob.data(), blob.size());
        }
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet
