#include <catch2/catch_test_macros.hpp>

#include "io/mcp/mcp_websocket.h"

#include <cstdint>
#include <string>

using namespace tenet::mcpws;

namespace {

bool is_loopback_address_for_test(std::string_view addr) {
    return tenet::mcpws::is_loopback_address(addr);
}

}  // namespace

namespace {

std::string make_masked_client_frame(uint8_t opcode,
                                     bool fin,
                                     const std::string& payload,
                                     uint32_t masking_key = 0x11223344u) {
    std::string out;
    out.reserve(payload.size() + 32);

    uint8_t b0 = static_cast<uint8_t>((fin ? 0x80 : 0x00) | (opcode & 0x0F));
    out.push_back(static_cast<char>(b0));

    const size_t len = payload.size();
    if (len <= 125) {
        out.push_back(static_cast<char>(0x80 | static_cast<uint8_t>(len)));
    } else if (len <= 0xFFFF) {
        out.push_back(static_cast<char>(0x80 | 126));
        out.push_back(static_cast<char>((len >> 8) & 0xFF));
        out.push_back(static_cast<char>(len & 0xFF));
    } else {
        out.push_back(static_cast<char>(0x80 | 127));
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<char>((static_cast<uint64_t>(len) >> (i * 8)) & 0xFF));
        }
    }

    uint8_t key[4] = {
        static_cast<uint8_t>((masking_key >> 24) & 0xFF),
        static_cast<uint8_t>((masking_key >> 16) & 0xFF),
        static_cast<uint8_t>((masking_key >> 8) & 0xFF),
        static_cast<uint8_t>(masking_key & 0xFF),
    };
    out.append(reinterpret_cast<const char*>(key), 4);

    for (size_t i = 0; i < payload.size(); ++i) {
        out.push_back(static_cast<char>(static_cast<uint8_t>(payload[i]) ^ key[i % 4]));
    }

    return out;
}

uint64_t be64_from_8(const std::string& s, size_t off) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<uint8_t>(s[off + i]);
    }
    return v;
}

}  // namespace

TEST_CASE("mcp websocket: RFC6455 accept key sample", "[unit][mcp][websocket]") {
    const std::string sample_key = "dGhlIHNhbXBsZSBub25jZQ==";
    REQUIRE(websocket_accept_key(sample_key) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    REQUIRE(is_valid_websocket_key(sample_key));
    REQUIRE_FALSE(is_valid_websocket_key("bad-key"));
}

TEST_CASE("mcp websocket: path extraction and URL decode", "[unit][mcp][websocket]") {
    {
        auto r = extract_ws_instance_from_path("/ws/tenet-123");
        REQUIRE(r.ok);
        REQUIRE(r.instance == "tenet-123");
    }
    {
        auto r = extract_ws_instance_from_path("/ws/ida%2Fsession%201");
        REQUIRE(r.ok);
        REQUIRE(r.instance == "ida/session 1");
    }

    REQUIRE_FALSE(extract_ws_instance_from_path("/ws").ok);
    REQUIRE_FALSE(extract_ws_instance_from_path("/ws/").ok);
    REQUIRE_FALSE(extract_ws_instance_from_path("/ws/a/b").ok);
    REQUIRE_FALSE(extract_ws_instance_from_path("/mcp").ok);
    REQUIRE_FALSE(extract_ws_instance_from_path("/ws/%ZZ").ok);

    auto plus = extract_ws_instance_from_path("/ws/abc+def");
    REQUIRE(plus.ok);
    REQUIRE(plus.instance == "abc+def");
}

TEST_CASE("mcp websocket: decode masked text frame boundaries", "[unit][mcp][websocket]") {
    auto check_payload = [](const std::string& payload) {
        std::string frame = make_masked_client_frame(0x1, true, payload);
        auto r = decode_client_frame(frame, kMaxTextPayload);
        REQUIRE(r.status == WsDecodeStatus::Ok);
        REQUIRE(r.frame.opcode == WsOpcode::Text);
        REQUIRE(r.frame.fin);
        REQUIRE(r.frame.payload == payload);
        REQUIRE(r.consumed == frame.size());
    };

    check_payload("hello");
    check_payload(std::string(125, 'a'));
    check_payload(std::string(126, 'b'));
    check_payload(std::string(65535, 'c'));
    check_payload(std::string(65536, 'd'));
}

TEST_CASE("mcp websocket: decode partial frame reports need more", "[unit][mcp][websocket]") {
    std::string frame = make_masked_client_frame(0x1, true, "hello world");
    frame.resize(frame.size() - 3);

    auto r = decode_client_frame(frame, kMaxTextPayload);
    REQUIRE(r.status == WsDecodeStatus::NeedMoreData);
}

TEST_CASE("mcp websocket: encode server text frames", "[unit][mcp][websocket]") {
    {
        std::string encoded = encode_server_text_frame("hi");
        REQUIRE(encoded.size() == 4);
        REQUIRE(static_cast<uint8_t>(encoded[0]) == 0x81);
        REQUIRE(static_cast<uint8_t>(encoded[1]) == 0x02);
        REQUIRE(encoded.substr(2) == "hi");
    }

    {
        std::string payload(126, 'x');
        std::string encoded = encode_server_text_frame(payload);
        REQUIRE(static_cast<uint8_t>(encoded[0]) == 0x81);
        REQUIRE(static_cast<uint8_t>(encoded[1]) == 126);
        const uint16_t len =
            (static_cast<uint8_t>(encoded[2]) << 8) | static_cast<uint8_t>(encoded[3]);
        REQUIRE(len == 126);
        REQUIRE(encoded.substr(4) == payload);
    }

    {
        std::string payload(65536, 'y');
        std::string encoded = encode_server_text_frame(payload);
        REQUIRE(static_cast<uint8_t>(encoded[0]) == 0x81);
        REQUIRE(static_cast<uint8_t>(encoded[1]) == 127);
        REQUIRE(be64_from_8(encoded, 2) == payload.size());
        REQUIRE(encoded.substr(10) == payload);
    }
}

TEST_CASE("mcp websocket: ping close and protocol errors", "[unit][mcp][websocket]") {
    SECTION("ping and close frames decode") {
        auto ping = decode_client_frame(make_masked_client_frame(0x9, true, "abc"), kMaxTextPayload);
        REQUIRE(ping.status == WsDecodeStatus::Ok);
        REQUIRE(ping.frame.opcode == WsOpcode::Ping);
        REQUIRE(ping.frame.payload == "abc");

        auto close = decode_client_frame(make_masked_client_frame(0x8, true, "\x03\xE8", 0xAABBCCDDu), kMaxTextPayload);
        REQUIRE(close.status == WsDecodeStatus::Ok);
        REQUIRE(close.frame.opcode == WsOpcode::Close);

        auto close_bad = decode_client_frame(make_masked_client_frame(0x8, true, "\xFF", 0xAABBCCDDu), kMaxTextPayload);
        REQUIRE(close_bad.status == WsDecodeStatus::ProtocolError);
    }

    SECTION("unmasked frame is rejected") {
        std::string bad;
        bad.push_back(static_cast<char>(0x81));
        bad.push_back(static_cast<char>(0x05));
        bad += "hello";
        auto r = decode_client_frame(bad, kMaxTextPayload);
        REQUIRE(r.status == WsDecodeStatus::ProtocolError);
    }

    SECTION("binary and fragmented frames are rejected") {
        auto binary = decode_client_frame(make_masked_client_frame(0x2, true, "abc"), kMaxTextPayload);
        REQUIRE(binary.status == WsDecodeStatus::UnsupportedFrame);

        auto fragmented = decode_client_frame(make_masked_client_frame(0x1, false, "abc"), kMaxTextPayload);
        REQUIRE(fragmented.status == WsDecodeStatus::UnsupportedFrame);
    }

    SECTION("invalid control frame is rejected") {
        auto ping_fragmented = decode_client_frame(make_masked_client_frame(0x9, false, "a"), kMaxTextPayload);
        REQUIRE(ping_fragmented.status == WsDecodeStatus::ProtocolError);

        auto ping_big = decode_client_frame(make_masked_client_frame(0x9, true, std::string(126, 'p')), kMaxTextPayload);
        REQUIRE(ping_big.status == WsDecodeStatus::ProtocolError);
    }
}

TEST_CASE("mcp websocket: text payload limit", "[unit][mcp][websocket]") {
    std::string max_payload(kMaxTextPayload, 'm');
    auto ok = decode_client_frame(make_masked_client_frame(0x1, true, max_payload), kMaxTextPayload);
    REQUIRE(ok.status == WsDecodeStatus::Ok);

    std::string too_large(kMaxTextPayload + 1, 'n');
    auto big = decode_client_frame(make_masked_client_frame(0x1, true, too_large), kMaxTextPayload);
    REQUIRE(big.status == WsDecodeStatus::PayloadTooLarge);
}

TEST_CASE("mcp websocket: invalid utf8 text frame is rejected", "[unit][mcp][websocket]") {
    std::string invalid_utf8("\xC3\x28", 2);
    auto decoded = decode_client_frame(make_masked_client_frame(0x1, true, invalid_utf8), kMaxTextPayload);
    REQUIRE(decoded.status == WsDecodeStatus::ProtocolError);
    REQUIRE(decoded.error.find("UTF-8") != std::string::npos);
}

TEST_CASE("mcp websocket: loopback helper accepts only local peers", "[unit][mcp][websocket]") {
    REQUIRE(is_loopback_address_for_test("127.0.0.1:10444"));
    REQUIRE(is_loopback_address_for_test("127.9.8.7:42"));
    REQUIRE(is_loopback_address_for_test("[::1]:10444"));
    REQUIRE(is_loopback_address_for_test("::1"));
    REQUIRE_FALSE(is_loopback_address_for_test("192.168.1.10:10444"));
    REQUIRE_FALSE(is_loopback_address_for_test("[2001:db8::1]:10444"));
    REQUIRE_FALSE(is_loopback_address_for_test("garbage"));
}
