#include "analysis/passes/profile/dataflow_graph_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include "common/byte_codec.h"
#include "common/memory_ranges.h"
#include <fmt/core.h>
#include <algorithm>
#include <array>
#include <map>

namespace tenet {

// ─── DataflowGraphResult serialization helpers ────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x44464752 ("DFGR")
//   u32  version = 3
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
//   v3: resolves every live byte-range producer; invalidates earlier incomplete graphs.
//   v2: adds memory dependency edges (store → load, via_mem_addr != 0).
//       Wire format is unchanged (via_mem_addr was always serialized); the
//       version bump exists purely so older v1 blobs — produced before
//       memory edges existed — are invalidated and the pass re-runs to
//       pick up the new edges, rather than silently serving stale results.

namespace {

static constexpr uint32_t DFGR_BLOB_MAGIC   = 0x44464752u;  // "DFGR"
static constexpr uint32_t DFGR_BLOB_VERSION = 3u;

std::string dataflow_graph_serialize(const DataflowGraphResult& res) {
    ByteWriter w;
    w.u32(DFGR_BLOB_MAGIC);
    w.u32(DFGR_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.nodes.size()));

    for (const auto& n : res.nodes) {
        w.u64(n.inst_id);
        w.u64(n.pc);
        w.u32(static_cast<uint32_t>(n.mnemonic.size()));
        w.bytes(n.mnemonic.data(), n.mnemonic.size());
        w.u32(static_cast<uint32_t>(n.regs_read.size()));
        w.bytes(n.regs_read.data(), n.regs_read.size());
        w.u32(static_cast<uint32_t>(n.regs_written.size()));
        w.bytes(n.regs_written.data(), n.regs_written.size());
    }

    w.u64(static_cast<uint64_t>(res.edges.size()));
    for (const auto& e : res.edges) {
        w.u64(e.from_inst_id);
        w.u64(e.to_inst_id);
        w.u8(e.via_reg);
        w.u64(e.via_mem_addr);
    }

    return std::move(w).take();
}

bool dataflow_graph_deserialize(const std::string& blob, DataflowGraphResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != DFGR_BLOB_MAGIC)   return false;
    if (r.u32() != DFGR_BLOB_VERSION) return false;

    uint64_t n_nodes = r.u64();
    out.nodes.reserve(static_cast<size_t>(n_nodes));

    for (uint64_t i = 0; i < n_nodes; i++) {
        DataflowNode n;
        n.inst_id = r.u64();
        n.pc      = r.u64();
        uint32_t mnem_len = r.u32();
        if (!r.ok() || r.remaining() < mnem_len) return false;
        n.mnemonic.resize(mnem_len);
        r.bytes(n.mnemonic.data(), mnem_len);
        uint32_t nr = r.u32();
        if (!r.ok()) return false;
        n.regs_read.resize(nr);
        r.bytes(n.regs_read.data(), nr);
        uint32_t nw = r.u32();
        if (!r.ok()) return false;
        n.regs_written.resize(nw);
        r.bytes(n.regs_written.data(), nw);
        if (!r.ok()) return false;

        size_t node_idx = out.nodes.size();
        out.inst_to_node[n.inst_id] = node_idx;
        out.nodes.push_back(std::move(n));
    }

    uint64_t n_edges = r.u64();
    if (!r.ok()) return false;
    out.edges.reserve(static_cast<size_t>(n_edges));
    for (uint64_t i = 0; i < n_edges; i++) {
        DFGEdge e;
        e.from_inst_id = r.u64();
        e.to_inst_id   = r.u64();
        e.via_reg      = r.u8();
        e.via_mem_addr = r.u64();
        out.edges.push_back(e);
    }
    if (!r.ok()) return false;

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

    out += fmt::format("  \"truncated\": {},\n", truncated);

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
    if (ctx.cancelled()) return PassResult::failed("cancelled by user");
    auto& reader     = ctx.reader();
    auto& index      = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder    = ctx.decoder();
    const auto& range = ctx.range();

    // Determine effective analysis range by intersecting config with context range
    uint64_t start = std::max(config_.start_inst_id, range.start_inst_id);
    uint64_t end   = std::min(config_.end_inst_id, range.end_inst_id);

    // ─── Fast path: load from persisted cache ─────────────────────────────
    // Only cache complete full-trace results with the default configuration.
    bool cacheable_config = (config_.start_inst_id == 0 && config_.end_inst_id == UINT64_MAX
                             && config_.max_nodes == DataflowGraphConfig{}.max_nodes);
    if (ctx.range().is_full_trace() && cacheable_config) {
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

    // Latest writer for each disjoint byte range. Partial overwrites split
    // intervals; a load can depend on multiple live producers.
    MemoryRanges<uint64_t> mem_writes;

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

        if (ctx.cancelled()) return PassResult::failed("cancelled by user");

        // Enforce max_nodes to keep graph sizes practical
        if (nodes_added >= config_.max_nodes) {
            result.truncated = true;
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

                ankerl::unordered_dense::set<uint64_t> producers;
                mem_writes.visit(mem.addr, mem.size,
                    [&](uint64_t, uint64_t, uint64_t writer) {
                        if (producers.insert(writer).second) {
                            DFGEdge edge;
                            edge.from_inst_id = writer;
                            edge.to_inst_id = inst_id;
                            edge.via_mem_addr = mem.addr;
                            result.edges.push_back(edge);
                        }
                    });
            }

            // Writes: record this instruction as the latest writer for the
            // touched byte range, dropping any pre-existing entries that are
            // now fully shadowed (their bytes can no longer be observed by
            // any future load) to keep the map small.
            for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
                auto mem = inst.mem_access(m);
                bool is_write = (mem.type & 0x02) != 0;
                if (!is_write || mem.addr == 0 || mem.size == 0) continue;

                mem_writes.assign(mem.addr, mem.size, inst_id);
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

    if (ctx.cancelled()) return PassResult::failed("cancelled by user");

    // ─── Persist to cache ─────────────────────────────────────────────────
    if (ctx.range().is_full_trace() && cacheable_config && !result.truncated) {
        std::string blob = dataflow_graph_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("dataflow_graph", blob.data(), blob.size());
        }
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet
