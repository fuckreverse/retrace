#pragma once

#include "tenet_ws_generated.h"

#include <flatbuffers/flatbuffer_builder.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <utility>

namespace tenet {

inline std::string build_ws_envelope_bytes(uint32_t msg_id,
                                           ws::MessageType type,
                                           const uint8_t* payload,
                                           size_t payload_size) {
    flatbuffers::FlatBufferBuilder env_fbb(payload_size + 64);
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> payload_vec = 0;
    if (payload != nullptr && payload_size != 0) {
        payload_vec = env_fbb.CreateVector(payload, payload_size);
    }
    auto env = ws::CreateEnvelope(env_fbb, msg_id, type, payload_vec);
    env_fbb.Finish(env);
    return {
        reinterpret_cast<const char*>(env_fbb.GetBufferPointer()),
        env_fbb.GetSize(),
    };
}

inline std::string build_ws_envelope_bytes(uint32_t msg_id,
                                           ws::MessageType type,
                                           const flatbuffers::FlatBufferBuilder& payload_builder) {
    return build_ws_envelope_bytes(
        msg_id,
        type,
        payload_builder.GetBufferPointer(),
        payload_builder.GetSize());
}

inline std::string build_ws_error_envelope_bytes(uint32_t msg_id,
                                                 uint32_t code,
                                                 std::string_view message) {
    flatbuffers::FlatBufferBuilder payload_fbb(message.size() + 64);
    auto err = ws::CreateErrorResponse(
        payload_fbb,
        code,
        payload_fbb.CreateString(message.data(), message.size()));
    payload_fbb.Finish(err);
    return build_ws_envelope_bytes(msg_id, ws::MessageType_ErrorResp, payload_fbb);
}

template <typename Fn>
inline std::string build_ws_reply_or_error(uint32_t msg_id,
                                           uint32_t code,
                                           std::string_view context,
                                           Fn&& build_reply) {
    try {
        return std::forward<Fn>(build_reply)();
    } catch (const std::exception& e) {
        std::string message(context);
        if (!message.empty()) message += ": ";
        message += e.what();
        return build_ws_error_envelope_bytes(msg_id, code, message);
    } catch (...) {
        std::string message(context);
        if (!message.empty()) message += ": ";
        message += "unknown exception";
        return build_ws_error_envelope_bytes(msg_id, code, message);
    }
}

}  // namespace tenet
