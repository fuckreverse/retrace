#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace tenet {
namespace mcpws {

constexpr size_t kMaxTextPayload = 1024 * 1024;

struct PathInstanceResult {
    bool ok = false;
    std::string instance;
    std::string error;
};

PathInstanceResult extract_ws_instance_from_path(std::string_view path);

bool is_loopback_address(std::string_view addr);
bool is_valid_utf8(std::string_view text);
bool is_valid_websocket_key(std::string_view sec_websocket_key);
std::string websocket_accept_key(std::string_view sec_websocket_key);

enum class WsOpcode : uint8_t {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
};

enum class WsDecodeStatus {
    Ok,
    NeedMoreData,
    ProtocolError,
    UnsupportedFrame,
    PayloadTooLarge,
};

struct WsFrame {
    WsOpcode opcode = WsOpcode::Text;
    bool fin = true;
    std::string payload;
};

struct WsDecodeResult {
    WsDecodeStatus status = WsDecodeStatus::NeedMoreData;
    WsFrame frame;
    size_t consumed = 0;
    std::string error;
};

WsDecodeResult decode_client_frame(std::string_view buffer,
                                   size_t max_text_payload = kMaxTextPayload);

std::string encode_server_text_frame(std::string_view payload);
std::string encode_server_control_frame(WsOpcode opcode, std::string_view payload = {});
std::string encode_server_close_frame(uint16_t code, std::string_view reason = {});

}  // namespace mcpws
}  // namespace tenet
