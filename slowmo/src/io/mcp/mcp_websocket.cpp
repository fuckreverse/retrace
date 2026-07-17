#include "mcp_websocket.h"

#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <string_view>

namespace tenet {
namespace mcpws {
namespace {

constexpr std::string_view kWsPrefix = "/ws/";
constexpr std::string_view kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

bool is_hex(char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

uint8_t hex_val(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + (c - 'a'));
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(10 + (c - 'A'));
    return 0;
}

bool url_decode_component(std::string_view in, std::string& out) {
    out.clear();
    out.reserve(in.size());

    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '%') {
            if (i + 2 >= in.size()) return false;
            if (!is_hex(in[i + 1]) || !is_hex(in[i + 2])) return false;
            uint8_t b = static_cast<uint8_t>((hex_val(in[i + 1]) << 4) | hex_val(in[i + 2]));
            out.push_back(static_cast<char>(b));
            i += 2;
            continue;
        }
        out.push_back(c);
    }

    return true;
}

bool is_valid_ipv4_octet(std::string_view part) {
    if (part.empty() || part.size() > 3) return false;
    int value = 0;
    for (char c : part) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + (c - '0');
        if (value > 255) return false;
    }
    return true;
}

bool is_loopback_ipv4(std::string_view host) {
    size_t start = 0;
    int octet_index = 0;
    int first_octet = -1;
    while (start <= host.size()) {
        size_t end = host.find('.', start);
        if (end == std::string_view::npos) end = host.size();
        std::string_view part = host.substr(start, end - start);
        if (!is_valid_ipv4_octet(part)) return false;
        int value = 0;
        for (char c : part) {
            value = value * 10 + (c - '0');
        }
        if (octet_index == 0) {
            first_octet = value;
        }
        ++octet_index;
        if (end == host.size()) break;
        start = end + 1;
    }
    return octet_index == 4 && first_octet == 127;
}

std::string_view extract_host(std::string_view addr) {
    if (addr.empty()) return {};
    if (addr.front() == '[') {
        size_t close = addr.find(']');
        if (close == std::string_view::npos) return {};
        return addr.substr(1, close - 1);
    }

    size_t first_colon = addr.find(':');
    if (first_colon == std::string_view::npos) {
        return addr;
    }
    if (addr.find(':', first_colon + 1) == std::string_view::npos) {
        return addr.substr(0, first_colon);
    }
    return addr;
}

std::string base64_encode(std::string_view input) {
    static constexpr char kBase64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= input.size()) {
        uint32_t v = (static_cast<uint32_t>(static_cast<uint8_t>(input[i])) << 16) |
                     (static_cast<uint32_t>(static_cast<uint8_t>(input[i + 1])) << 8) |
                     static_cast<uint32_t>(static_cast<uint8_t>(input[i + 2]));
        out.push_back(kBase64[(v >> 18) & 0x3F]);
        out.push_back(kBase64[(v >> 12) & 0x3F]);
        out.push_back(kBase64[(v >> 6) & 0x3F]);
        out.push_back(kBase64[v & 0x3F]);
        i += 3;
    }

    size_t rem = input.size() - i;
    if (rem == 1) {
        uint32_t v = static_cast<uint32_t>(static_cast<uint8_t>(input[i])) << 16;
        out.push_back(kBase64[(v >> 18) & 0x3F]);
        out.push_back(kBase64[(v >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        uint32_t v = (static_cast<uint32_t>(static_cast<uint8_t>(input[i])) << 16) |
                     (static_cast<uint32_t>(static_cast<uint8_t>(input[i + 1])) << 8);
        out.push_back(kBase64[(v >> 18) & 0x3F]);
        out.push_back(kBase64[(v >> 12) & 0x3F]);
        out.push_back(kBase64[(v >> 6) & 0x3F]);
        out.push_back('=');
    }

    return out;
}

inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

std::array<uint8_t, 20> sha1_bytes(std::string_view data) {
    uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8u;
    size_t total = data.size() + 1 + 8;
    size_t pad_zeros = (64 - (total % 64)) % 64;
    total += pad_zeros;

    std::string msg;
    msg.reserve(total);
    msg.append(data.data(), data.size());
    msg.push_back(static_cast<char>(0x80));
    msg.append(pad_zeros, '\0');

    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<char>((bit_len >> (i * 8)) & 0xFF));
    }

    uint32_t h0 = 0x67452301u;
    uint32_t h1 = 0xEFCDAB89u;
    uint32_t h2 = 0x98BADCFEu;
    uint32_t h3 = 0x10325476u;
    uint32_t h4 = 0xC3D2E1F0u;

    uint32_t w[80] = {};
    for (size_t off = 0; off < msg.size(); off += 64) {
        for (int i = 0; i < 16; ++i) {
            size_t p = off + static_cast<size_t>(i) * 4;
            w[i] = (static_cast<uint32_t>(static_cast<uint8_t>(msg[p])) << 24) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(msg[p + 1])) << 16) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(msg[p + 2])) << 8) |
                   static_cast<uint32_t>(static_cast<uint8_t>(msg[p + 3]));
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        for (int i = 0; i < 80; ++i) {
            uint32_t f;
            uint32_t k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    std::array<uint8_t, 20> out{};
    auto put_be32 = [&](size_t idx, uint32_t v) {
        out[idx] = static_cast<uint8_t>((v >> 24) & 0xFF);
        out[idx + 1] = static_cast<uint8_t>((v >> 16) & 0xFF);
        out[idx + 2] = static_cast<uint8_t>((v >> 8) & 0xFF);
        out[idx + 3] = static_cast<uint8_t>(v & 0xFF);
    };
    put_be32(0, h0);
    put_be32(4, h1);
    put_be32(8, h2);
    put_be32(12, h3);
    put_be32(16, h4);
    return out;
}

bool control_opcode(WsOpcode op) {
    return op == WsOpcode::Close || op == WsOpcode::Ping || op == WsOpcode::Pong;
}

void append_u16_be(std::string& out, uint16_t v) {
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>(v & 0xFF));
}

void append_u64_be(std::string& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<char>((v >> (i * 8)) & 0xFF));
    }
}

}  // namespace

bool is_loopback_address(std::string_view addr) {
    std::string_view host = extract_host(addr);
    if (host.empty()) return false;
    if (host == "::1") return true;
    return is_loopback_ipv4(host);
}

bool is_valid_utf8(std::string_view text) {
    size_t i = 0;
    while (i < text.size()) {
        uint8_t c = static_cast<uint8_t>(text[i]);
        if (c <= 0x7F) {
            ++i;
            continue;
        }

        size_t needed = 0;
        uint32_t codepoint = 0;
        if ((c & 0xE0u) == 0xC0u) {
            needed = 1;
            codepoint = c & 0x1Fu;
            if (codepoint < 0x02u) return false;
        } else if ((c & 0xF0u) == 0xE0u) {
            needed = 2;
            codepoint = c & 0x0Fu;
        } else if ((c & 0xF8u) == 0xF0u) {
            needed = 3;
            codepoint = c & 0x07u;
            if (codepoint > 0x04u) return false;
        } else {
            return false;
        }

        if (i + needed >= text.size()) return false;
        for (size_t j = 1; j <= needed; ++j) {
            uint8_t cc = static_cast<uint8_t>(text[i + j]);
            if ((cc & 0xC0u) != 0x80u) return false;
            codepoint = (codepoint << 6) | (cc & 0x3Fu);
        }

        if ((needed == 2 && codepoint < 0x800u) ||
            (needed == 3 && codepoint < 0x10000u) ||
            (codepoint >= 0xD800u && codepoint <= 0xDFFFu) ||
            codepoint > 0x10FFFFu) {
            return false;
        }

        i += needed + 1;
    }
    return true;
}

PathInstanceResult extract_ws_instance_from_path(std::string_view path) {
    PathInstanceResult out;

    size_t qpos = path.find('?');
    if (qpos != std::string_view::npos) {
        path = path.substr(0, qpos);
    }

    if (path.size() <= kWsPrefix.size()) {
        out.error = "missing instance id";
        return out;
    }
    if (path.compare(0, kWsPrefix.size(), kWsPrefix) != 0) {
        out.error = "invalid websocket path";
        return out;
    }

    std::string_view encoded = path.substr(kWsPrefix.size());
    if (encoded.empty()) {
        out.error = "missing instance id";
        return out;
    }
    if (encoded.find('/') != std::string_view::npos) {
        out.error = "invalid instance path";
        return out;
    }

    std::string decoded;
    if (!url_decode_component(encoded, decoded)) {
        out.error = "invalid URL encoding in instance id";
        return out;
    }
    if (decoded.empty()) {
        out.error = "missing instance id";
        return out;
    }

    out.ok = true;
    out.instance = std::move(decoded);
    return out;
}

bool is_valid_websocket_key(std::string_view sec_websocket_key) {
    if (sec_websocket_key.empty()) return false;
    if (sec_websocket_key.find_first_of("\r\n") != std::string_view::npos) return false;

    std::string trimmed(sec_websocket_key);
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.back()))) {
        trimmed.pop_back();
    }
    size_t lead = 0;
    while (lead < trimmed.size() && std::isspace(static_cast<unsigned char>(trimmed[lead]))) {
        ++lead;
    }
    if (lead > 0) trimmed.erase(0, lead);

    if (trimmed.size() != 24) return false;
    if (trimmed[22] != '=' || trimmed[23] != '=') return false;

    for (size_t i = 0; i < trimmed.size() - 2; ++i) {
        char c = trimmed[i];
        bool ok = (c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == '+' || c == '/';
        if (!ok) return false;
    }
    return true;
}

std::string websocket_accept_key(std::string_view sec_websocket_key) {
    std::string key(sec_websocket_key);
    while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back()))) {
        key.pop_back();
    }
    size_t lead = 0;
    while (lead < key.size() && std::isspace(static_cast<unsigned char>(key[lead]))) {
        ++lead;
    }
    if (lead > 0) key.erase(0, lead);

    std::string input = key;
    input.append(kWsGuid.data(), kWsGuid.size());

    const auto sha = sha1_bytes(input);
    return base64_encode(std::string_view(reinterpret_cast<const char*>(sha.data()), sha.size()));
}

WsDecodeResult decode_client_frame(std::string_view buffer, size_t max_text_payload) {
    WsDecodeResult out;

    if (buffer.size() < 2) {
        out.status = WsDecodeStatus::NeedMoreData;
        return out;
    }

    const uint8_t b0 = static_cast<uint8_t>(buffer[0]);
    const uint8_t b1 = static_cast<uint8_t>(buffer[1]);

    const bool fin = (b0 & 0x80) != 0;
    const bool rsv = (b0 & 0x70) != 0;
    if (rsv) {
        out.status = WsDecodeStatus::ProtocolError;
        out.error = "RSV bits must be zero";
        return out;
    }

    const WsOpcode opcode = static_cast<WsOpcode>(b0 & 0x0F);
    const bool masked = (b1 & 0x80) != 0;
    if (!masked) {
        out.status = WsDecodeStatus::ProtocolError;
        out.error = "client frames must be masked";
        return out;
    }

    uint64_t payload_len = static_cast<uint64_t>(b1 & 0x7F);
    size_t pos = 2;

    if (payload_len == 126) {
        if (buffer.size() < pos + 2) {
            out.status = WsDecodeStatus::NeedMoreData;
            return out;
        }
        payload_len =
            (static_cast<uint64_t>(static_cast<uint8_t>(buffer[pos])) << 8) |
            static_cast<uint64_t>(static_cast<uint8_t>(buffer[pos + 1]));
        pos += 2;
    } else if (payload_len == 127) {
        if (buffer.size() < pos + 8) {
            out.status = WsDecodeStatus::NeedMoreData;
            return out;
        }
        payload_len = 0;
        for (int i = 0; i < 8; ++i) {
            payload_len = (payload_len << 8) | static_cast<uint64_t>(static_cast<uint8_t>(buffer[pos + i]));
        }
        pos += 8;
        if ((payload_len >> 63) != 0) {
            out.status = WsDecodeStatus::ProtocolError;
            out.error = "most significant bit of 64-bit payload length must be zero";
            return out;
        }
    }

    const bool is_control = control_opcode(opcode);
    if (is_control) {
        if (!fin) {
            out.status = WsDecodeStatus::ProtocolError;
            out.error = "control frames must not be fragmented";
            return out;
        }
        if (payload_len > 125) {
            out.status = WsDecodeStatus::ProtocolError;
            out.error = "control frame payload too large";
            return out;
        }
        if (opcode == WsOpcode::Close && payload_len == 1) {
            out.status = WsDecodeStatus::ProtocolError;
            out.error = "close frame payload length 1 is invalid";
            return out;
        }
    }

    if (!fin || opcode == WsOpcode::Continuation) {
        out.status = WsDecodeStatus::UnsupportedFrame;
        out.error = "fragmented frames are not supported";
        return out;
    }

    if (opcode == WsOpcode::Binary) {
        out.status = WsDecodeStatus::UnsupportedFrame;
        out.error = "binary frames are not supported";
        return out;
    }

    if (opcode != WsOpcode::Text && opcode != WsOpcode::Ping &&
        opcode != WsOpcode::Pong && opcode != WsOpcode::Close) {
        out.status = WsDecodeStatus::UnsupportedFrame;
        out.error = "unsupported opcode";
        return out;
    }

    if (opcode == WsOpcode::Text && payload_len > max_text_payload) {
        out.status = WsDecodeStatus::PayloadTooLarge;
        out.error = "text frame payload exceeds limit";
        return out;
    }

    if (payload_len > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) - pos - 4) {
        out.status = WsDecodeStatus::ProtocolError;
        out.error = "payload length overflows";
        return out;
    }

    if (buffer.size() < pos + 4) {
        out.status = WsDecodeStatus::NeedMoreData;
        return out;
    }

    uint8_t mask[4] = {
        static_cast<uint8_t>(buffer[pos]),
        static_cast<uint8_t>(buffer[pos + 1]),
        static_cast<uint8_t>(buffer[pos + 2]),
        static_cast<uint8_t>(buffer[pos + 3]),
    };
    pos += 4;

    size_t need = static_cast<size_t>(payload_len);
    if (buffer.size() < pos + need) {
        out.status = WsDecodeStatus::NeedMoreData;
        return out;
    }

    out.frame.opcode = opcode;
    out.frame.fin = fin;
    out.frame.payload.resize(need);
    for (size_t i = 0; i < need; ++i) {
        out.frame.payload[i] = static_cast<char>(
            static_cast<uint8_t>(buffer[pos + i]) ^ mask[i % 4]);
    }

    if (opcode == WsOpcode::Text && !is_valid_utf8(out.frame.payload)) {
        out.status = WsDecodeStatus::ProtocolError;
        out.error = "text payload is not valid UTF-8";
        return out;
    }

    out.consumed = pos + need;
    out.status = WsDecodeStatus::Ok;
    return out;
}

std::string encode_server_control_frame(WsOpcode opcode, std::string_view payload) {
    std::string out;

    if (!control_opcode(opcode)) {
        return out;
    }
    if (payload.size() > 125) {
        return out;
    }

    out.reserve(payload.size() + 2);
    out.push_back(static_cast<char>(0x80 | static_cast<uint8_t>(opcode)));
    out.push_back(static_cast<char>(payload.size()));
    out.append(payload.data(), payload.size());
    return out;
}

std::string encode_server_text_frame(std::string_view payload) {
    std::string out;
    out.reserve(payload.size() + 16);

    out.push_back(static_cast<char>(0x80 | static_cast<uint8_t>(WsOpcode::Text)));

    const uint64_t len = static_cast<uint64_t>(payload.size());
    if (len <= 125) {
        out.push_back(static_cast<char>(len));
    } else if (len <= 0xFFFF) {
        out.push_back(static_cast<char>(126));
        append_u16_be(out, static_cast<uint16_t>(len));
    } else {
        out.push_back(static_cast<char>(127));
        append_u64_be(out, len);
    }

    out.append(payload.data(), payload.size());
    return out;
}

std::string encode_server_close_frame(uint16_t code, std::string_view reason) {
    std::string payload;
    payload.reserve(2 + reason.size());
    append_u16_be(payload, code);
    if (!reason.empty()) {
        payload.append(reason.data(), reason.size());
        if (payload.size() > 125) {
            payload.resize(125);
        }
    }
    return encode_server_control_frame(WsOpcode::Close, payload);
}

}  // namespace mcpws
}  // namespace tenet
