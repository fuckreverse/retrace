import base64
import hashlib
import json
import pathlib
import socket
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tenet.ida.websocket import LocalWebSocketClient, WebSocketError, WebSocketProtocolError


def _recv_http_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("socket closed")
        data += chunk
    return data.decode("iso-8859-1")


def _ws_accept(key):
    return base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
    ).decode("ascii")


def _read_exact(sock, size):
    out = bytearray()
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            raise RuntimeError("socket closed")
        out.extend(chunk)
    return bytes(out)


def _read_client_frame(sock):
    head = _read_exact(sock, 2)
    b0 = head[0]
    b1 = head[1]

    fin = (b0 & 0x80) != 0
    opcode = b0 & 0x0F
    masked = (b1 & 0x80) != 0
    length = b1 & 0x7F

    if length == 126:
        length = int.from_bytes(_read_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(_read_exact(sock, 8), "big")

    mask_key = b""
    if masked:
        mask_key = _read_exact(sock, 4)

    payload = bytearray(_read_exact(sock, length))
    if masked:
        for i in range(length):
            payload[i] ^= mask_key[i % 4]

    return {
        "fin": fin,
        "opcode": opcode,
        "masked": masked,
        "payload": bytes(payload),
        "raw_len": length,
    }


def _make_server_frame(opcode, payload=b"", fin=True, rsv=0, mask=None):
    first = (0x80 if fin else 0x00) | ((rsv & 0x7) << 4) | (opcode & 0x0F)
    out = bytearray([first])
    length = len(payload)
    mask_bit = 0x80 if mask is not None else 0x00
    if length <= 125:
        out.append(mask_bit | length)
    elif length <= 0xFFFF:
        out.append(mask_bit | 126)
        out.extend(length.to_bytes(2, "big"))
    else:
        out.append(mask_bit | 127)
        out.extend(length.to_bytes(8, "big"))
    if mask is not None:
        out.extend(mask)
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(length))
    out.extend(payload)
    return bytes(out)


def _make_server_text_frame(text):
    return _make_server_frame(0x1, text.encode("utf-8"))


class _BrokenSendSocket(object):
    def __init__(self):
        self.shutdown_calls = 0
        self.close_calls = 0

    def sendall(self, _frame):
        raise BrokenPipeError("peer disappeared")

    def shutdown(self, _how):
        self.shutdown_calls += 1

    def close(self):
        self.close_calls += 1


class WebSocketClientTests(unittest.TestCase):
    def _with_socketpair(self, server_fn):
        client_sock, server_sock = socket.socketpair()
        self.addCleanup(lambda: client_sock.close())
        self.addCleanup(lambda: server_sock.close())

        server_done = threading.Event()
        server_exc = []

        def _server_wrapper():
            try:
                server_fn(server_sock)
            except Exception as exc:
                server_exc.append(exc)
            finally:
                server_done.set()

        thread = threading.Thread(target=_server_wrapper)
        thread.start()

        def _create_connection(addr, timeout):
            return client_sock

        return thread, server_done, server_exc, _create_connection

    def test_handshake_invalid_accept_rejected(self):
        def server(sock):
            headers = _recv_http_headers(sock)
            self.assertIn("Upgrade: websocket", headers)
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: invalid\r\n"
                "\r\n"
            )
            sock.sendall(response.encode("ascii"))

        thread, done, excs, create_connection = self._with_socketpair(server)
        with mock.patch("socket.create_connection", side_effect=create_connection):
            client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
            with self.assertRaises(WebSocketProtocolError):
                client.connect()
            client.close()

        done.wait(timeout=1.0)
        thread.join(timeout=1.0)
        self.assertFalse(excs)

    def test_masked_client_frames_and_extended_lengths(self):
        requests = []

        def server(sock):
            headers = _recv_http_headers(sock)
            key_line = [line for line in headers.split("\r\n") if line.lower().startswith("sec-websocket-key:")][0]
            key = key_line.split(":", 1)[1].strip()
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {0}\r\n"
                "\r\n"
            ).format(_ws_accept(key))
            sock.sendall(response.encode("ascii"))

            for _ in range(2):
                requests.append(_read_client_frame(sock))

        thread, done, excs, create_connection = self._with_socketpair(server)

        with mock.patch("socket.create_connection", side_effect=create_connection):
            client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
            client.connect()
            client.send_notification("n1", {"pad": "x" * 130})
            client.send_notification("n2", {"pad": "y" * 70000})
            client.close()

        done.wait(timeout=2.0)
        thread.join(timeout=2.0)
        self.assertFalse(excs)
        self.assertEqual(2, len(requests))
        self.assertTrue(requests[0]["masked"])
        self.assertTrue(requests[1]["masked"])

        payload1 = json.loads(requests[0]["payload"].decode("utf-8"))
        payload2 = json.loads(requests[1]["payload"].decode("utf-8"))
        self.assertEqual("n1", payload1["method"])
        self.assertEqual("n2", payload2["method"])

    def test_handshake_can_buffer_first_server_frame(self):
        notifications = []
        received = threading.Event()

        def server(sock):
            headers = _recv_http_headers(sock)
            key_line = [line for line in headers.split("\r\n") if line.lower().startswith("sec-websocket-key:")][0]
            key = key_line.split(":", 1)[1].strip()
            note = {
                "jsonrpc": "2.0",
                "method": "tenet/connected",
                "params": {"instance": "buffered"},
            }
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {0}\r\n"
                "\r\n"
            ).format(_ws_accept(key)).encode("ascii") + _make_server_text_frame(json.dumps(note))
            sock.sendall(response)
            _read_client_frame(sock)

        thread, done, excs, create_connection = self._with_socketpair(server)

        with mock.patch("socket.create_connection", side_effect=create_connection):
            client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")

            def _on_notification(msg):
                notifications.append(msg)
                received.set()

            client.add_notification_handler(_on_notification)
            client.connect()
            self.assertTrue(received.wait(timeout=1.0))
            client.close()

        done.wait(timeout=2.0)
        thread.join(timeout=2.0)
        self.assertFalse(excs)
        self.assertEqual("tenet/connected", notifications[0]["method"])

    def test_fragmented_recv_and_request_response_matching(self):
        notifications = []

        def server(sock):
            headers = _recv_http_headers(sock)
            key_line = [line for line in headers.split("\r\n") if line.lower().startswith("sec-websocket-key:")][0]
            key = key_line.split(":", 1)[1].strip()
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {0}\r\n"
                "\r\n"
            ).format(_ws_accept(key))
            sock.sendall(response.encode("ascii"))

            req = _read_client_frame(sock)
            payload = json.loads(req["payload"].decode("utf-8"))
            request_id = payload["id"]

            note = {
                "jsonrpc": "2.0",
                "method": "tenet/connected",
                "params": {"instance": "x"},
            }
            note_frame = _make_server_text_frame(json.dumps(note))
            sock.sendall(note_frame[:3])
            sock.sendall(note_frame[3:])

            rsp = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": "{\"ok\":true}"}],
                    "isError": False,
                },
            }
            rsp_frame = _make_server_text_frame(json.dumps(rsp))
            sock.sendall(rsp_frame[:2])
            sock.sendall(rsp_frame[2:9])
            sock.sendall(rsp_frame[9:])

            _read_client_frame(sock)  # close frame from client

        thread, done, excs, create_connection = self._with_socketpair(server)

        with mock.patch("socket.create_connection", side_effect=create_connection):
            client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
            client.add_notification_handler(lambda msg: notifications.append(msg))
            client.connect()
            resp = client.call_jsonrpc("tools/call", params={"name": "trace_info", "arguments": {}}, timeout=2.0)
            self.assertEqual("2.0", resp["jsonrpc"])
            self.assertIn("result", resp)
            client.close()

        done.wait(timeout=2.0)
        thread.join(timeout=2.0)
        self.assertFalse(excs)
        self.assertTrue(notifications)
        self.assertEqual("tenet/connected", notifications[0]["method"])

    def test_peer_close_fails_pending_requests_and_marks_disconnected(self):
        def server(sock):
            headers = _recv_http_headers(sock)
            key_line = [line for line in headers.split("\r\n") if line.lower().startswith("sec-websocket-key:")][0]
            key = key_line.split(":", 1)[1].strip()
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {0}\r\n"
                "\r\n"
            ).format(_ws_accept(key))
            sock.sendall(response.encode("ascii"))
            _read_client_frame(sock)
            sock.close()

        thread, done, excs, create_connection = self._with_socketpair(server)
        with mock.patch("socket.create_connection", side_effect=create_connection):
            client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
            client.connect()
            with self.assertRaisesRegex(WebSocketError, "reader stopped|closed"):
                client.call_jsonrpc("tools/call", params={"name": "trace_info", "arguments": {}}, timeout=1.0)
            self.assertFalse(client.is_connected)
            with self.assertRaisesRegex(WebSocketError, "not connected"):
                client.send_notification("tenet/ping", {})
            client.close()

        done.wait(timeout=2.0)
        thread.join(timeout=2.0)
        self.assertFalse(excs)

    def test_send_oserror_raises_websocket_error_and_disconnects(self):
        disconnects = []
        client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
        client.set_disconnect_handler(lambda reason: disconnects.append(reason))
        client._sock = _BrokenSendSocket()

        with self.assertRaisesRegex(WebSocketError, "peer disappeared"):
            client._send_frame(0x1, b"{}")

        self.assertFalse(client.is_connected)
        self.assertEqual(1, len(disconnects))
        self.assertIn("peer disappeared", disconnects[0])
        client.close()
        client.close()

    def test_handshake_requires_upgrade_header(self):
        def server(sock):
            _recv_http_headers(sock)
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: invalid\r\n"
                "\r\n"
            )
            sock.sendall(response.encode("ascii"))

        thread, done, excs, create_connection = self._with_socketpair(server)
        with mock.patch("socket.create_connection", side_effect=create_connection):
            client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
            with self.assertRaisesRegex(WebSocketProtocolError, "Upgrade"):
                client.connect()
            client.close()

        done.wait(timeout=1.0)
        thread.join(timeout=1.0)
        self.assertFalse(excs)

    def test_handshake_requires_connection_upgrade_token(self):
        def server(sock):
            headers = _recv_http_headers(sock)
            key_line = [line for line in headers.split("\r\n") if line.lower().startswith("sec-websocket-key:")][0]
            key = key_line.split(":", 1)[1].strip()
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: WebSocket\r\n"
                "Connection: keep-alive\r\n"
                "Sec-WebSocket-Accept: {0}\r\n"
                "\r\n"
            ).format(_ws_accept(key))
            sock.sendall(response.encode("ascii"))

        thread, done, excs, create_connection = self._with_socketpair(server)
        with mock.patch("socket.create_connection", side_effect=create_connection):
            client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
            with self.assertRaisesRegex(WebSocketProtocolError, "Connection"):
                client.connect()
            client.close()

        done.wait(timeout=1.0)
        thread.join(timeout=1.0)
        self.assertFalse(excs)

    def test_reader_rejects_rsv_bits_and_masked_server_frames(self):
        for frame, needle in (
            (_make_server_frame(0x1, b"{}", rsv=1), "RSV"),
            (_make_server_frame(0x1, b"{}", mask=b"\x01\x02\x03\x04"), "masked"),
        ):
            client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
            with self.assertRaisesRegex(WebSocketProtocolError, needle):
                client._decode_server_frame(bytearray(frame))

    def test_reader_rejects_fragmented_control_and_binary_frames(self):
        client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
        with self.assertRaisesRegex(WebSocketProtocolError, "fragmented"):
            client._decode_server_frame(bytearray(_make_server_frame(0x9, b"x", fin=False)))
        with self.assertRaisesRegex(WebSocketProtocolError, "Binary"):
            client._decode_server_frame(bytearray(_make_server_frame(0x2, b"x")))

    def test_reader_rejects_fragmented_text_and_unexpected_continuation(self):
        client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
        with self.assertRaisesRegex(WebSocketProtocolError, "Fragmented"):
            client._handle_frame(0x1, False, b"part")
        with self.assertRaisesRegex(WebSocketProtocolError, "continuation"):
            client._handle_frame(0x0, True, b"part")

    def test_reader_rejects_invalid_control_payload_lengths(self):
        client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
        with self.assertRaisesRegex(WebSocketProtocolError, "payload exceeds 125"):
            client._decode_server_frame(bytearray(_make_server_frame(0x9, b"x" * 126)))
        with self.assertRaisesRegex(WebSocketProtocolError, "length 1"):
            client._handle_frame(0x8, True, b"\x03")

    def test_reader_rejects_invalid_64bit_length_msb(self):
        client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
        frame = bytearray([0x81, 0x7F])
        frame.extend((1 << 63).to_bytes(8, "big"))
        with self.assertRaisesRegex(WebSocketProtocolError, "most significant bit"):
            client._decode_server_frame(frame)

    def test_reader_rejects_payload_exceeding_limit(self):
        client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test", max_payload=8)
        with self.assertRaisesRegex(WebSocketProtocolError, "exceeds limit"):
            client._decode_server_frame(bytearray(_make_server_frame(0x1, b"0123456789")))

    def test_close_frame_validates_code_and_reason_utf8(self):
        client = LocalWebSocketClient("ws://127.0.0.1:10444/ws/test")
        with self.assertRaisesRegex(WebSocketProtocolError, "close code"):
            client._handle_frame(0x8, True, b"\x03\xed")
        with self.assertRaisesRegex(WebSocketProtocolError, "UTF-8"):
            client._handle_frame(0x8, True, b"\x03\xe8\xc3\x28")


if __name__ == "__main__":
    unittest.main()
