// slowmo/src/ws/ws_handlers_hotpath.cpp
//
// Performance-critical WebSocket handlers that run synchronously on the uWS
// event loop thread (no async dispatch): FetchRows, GetRegs, ReadMemory.
#include "ws/tenet_ws_service.h"
#include "common/types.h"
#include "common/instruction_row.h"
#include "core/register_file.h"
#include "core/memory_model.h"
#include "ws/ws_protocol.h"

// uWebSockets includes (only in .cpp, not in header)
#include <App.h>

// FlatBuffers generated header
#include "tenet_ws_generated.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace tenet {

using namespace tenet::ws;  // FlatBuffers namespace

// Per-socket user data (uWS template parameter) — mirrors tenet_ws_service.cpp.
struct PerSocketData {};

namespace {

/// Wrap a finished payload FlatBuffer in a ws::Envelope and send it over the
/// WebSocket connection.
void send_envelope(void* ws, uint32_t msg_id, MessageType type,
                    flatbuffers::FlatBufferBuilder& fbb) {
    auto bytes = build_ws_envelope_bytes(msg_id, type, fbb);
    auto sv = std::string_view(bytes.data(), bytes.size());
    static_cast<uWS::WebSocket<false, true, PerSocketData>*>(ws)->send(sv, uWS::BINARY);
}

}  // namespace

// ─── FetchRows ──────────────────────────────────────────────────────────────

void TenetWSService::handle_fetch_rows(void* ws, uint32_t msg_id,
                                        const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "FetchRows: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<FetchRowsRequest>(payload);
    uint64_t start = req->start_id();
    uint32_t count = std::min(req->count(), 1024u);  // cap at 1024 rows/request

    flatbuffers::FlatBufferBuilder fbb(static_cast<size_t>(count) * 128 + 64);

    std::vector<flatbuffers::Offset<InstructionRowMsg>> row_offsets;
    row_offsets.reserve(count);

    uint64_t total = service_.total_inst();
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t id = start + i;
        if (id >= total) break;

        auto row = service_.fetch_row(id);
        auto mnemonic = fbb.CreateString(row.mnemonic);
        auto operands = fbb.CreateString(row.operands);
        row_offsets.push_back(CreateInstructionRowMsg(
            fbb, row.inst_id, row.pc, row.static_pc,
            mnemonic, operands,
            row.nzcv, row.reg_diff_count, row.mem_access_count,
            row.has_bookmark));
    }

    auto rows_vec = fbb.CreateVector(row_offsets);
    auto resp = CreateFetchRowsResponse(fbb, rows_vec, total, service_.current_inst());
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_FetchRowsResp, fbb);
}

// ─── GetRegs ────────────────────────────────────────────────────────────────

void TenetWSService::handle_get_regs(void* ws, uint32_t msg_id,
                                      const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "GetRegs: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<GetRegsRequest>(payload);
    uint64_t inst_id = req->inst_id();
    uint8_t when = req->when();          // 0 = before, 1 = after
    bool include_fpr = req->include_fpr();

    RegState state = (when == 0) ? service_.regfile().state_before(inst_id)
                                  : service_.regfile().state_after(inst_id);

    flatbuffers::FlatBufferBuilder fbb(512);

    auto gpr_vec = fbb.CreateVector(state.gpr, AARCH64_GPR_COUNT);

    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> fpr_vec = 0;
    if (include_fpr) {
        // Pack v0-v31 as 512 raw bytes (16 bytes each: lo then hi, little-endian).
        std::vector<uint8_t> fpr_bytes(AARCH64_FPR_COUNT * 16);
        for (uint8_t i = 0; i < AARCH64_FPR_COUNT; ++i) {
            std::memcpy(&fpr_bytes[i * 16 + 0], &state.fpr[i].lo, 8);
            std::memcpy(&fpr_bytes[i * 16 + 8], &state.fpr[i].hi, 8);
        }
        fpr_vec = fbb.CreateVector(fpr_bytes);
    }

    GetRegsResponseBuilder builder(fbb);
    builder.add_inst_id(inst_id);
    builder.add_gpr(gpr_vec);
    if (include_fpr) {
        builder.add_fpr(fpr_vec);
    }
    auto resp = builder.Finish();
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_GetRegsResp, fbb);
}

// ─── ReadMemory ─────────────────────────────────────────────────────────────

void TenetWSService::handle_read_memory(void* ws, uint32_t msg_id,
                                         const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "ReadMemory: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<ReadMemoryRequest>(payload);
    uint64_t addr = req->addr();
    uint64_t inst_id = req->inst_id();
    // Cap at 1 MiB per request to bound allocation/serialization cost on the
    // event loop thread (mirrors FetchRows' 1024-row cap).
    size_t size = std::min<uint32_t>(req->size(), 1u * 1024 * 1024);

    auto result = service_.memory().read_region(addr, size, inst_id);

    // Pack `known` as a bitmask (1 bit per byte, LSB-first within each byte).
    std::vector<uint8_t> known_bits((result.known.size() + 7) / 8, 0);
    for (size_t i = 0; i < result.known.size(); ++i) {
        if (result.known[i]) {
            known_bits[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
        }
    }

    flatbuffers::FlatBufferBuilder fbb(result.data.size() + known_bits.size() + 64);
    auto data_vec = fbb.CreateVector(result.data);
    auto known_vec = fbb.CreateVector(known_bits);

    auto resp = CreateReadMemoryResponse(fbb, addr, inst_id, data_vec, known_vec);
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_ReadMemoryResp, fbb);
}

}  // namespace tenet
