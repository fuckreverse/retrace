import base64
import hashlib
import json
import os
import socket
import threading
from urllib.parse import urlparse


_VALID_CLOSE_CODES = set([1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014])


class WebSocketError(Exception):
    pass


class WebSocketProtocolError(WebSocketError):
    pass


class _PendingCall(object):
    def __init__(self):
        self.event = threading.Event()
        self.response = None
        self.error = None


class LocalWebSocketClient(object):
    """Minimal RFC6455 client for ws://127.0.0.1 / localhost only."""

    def __init__(self, url, timeout=5.0, max_payload=1024 * 1024):
        parsed = urlparse(url)
        if parsed.scheme != "ws":
            raise ValueError("Only ws:// URLs are supported")
        host = parsed.hostname or ""
        if host not in ("127.0.0.1", "localhost"):
            raise ValueError("Only localhost WebSocket endpoints are allowed")

        self._url = url
        self._host = host
        self._port = parsed.port or 80
        self._path = parsed.path or "/"
        if parsed.query:
            self._path += "?" + parsed.query

        self._timeout = timeout
        self._max_payload = max_payload

        self._sock = None
        self._reader_thread = None
        self._stop_event = threading.Event()

        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending_cond = threading.Condition(self._pending_lock)
        self._pending = {}

        self._next_id = 1
        self._id_lock = threading.Lock()

        self._notification_handlers = []
        self._notification_lock = threading.Lock()

        self._fragment_opcode = None
        self._fragment_payload = bytearray()
        self._handshake_buffer = bytearray()
        self._close_sent = False
        self._disconnect_handler = None
        self._disconnect_reason = None

    @property
    def is_connected(self):
        with self._state_lock:
            return self._sock is not None

    def add_notification_handler(self, handler):
        with self._notification_lock:
            self._notification_handlers.append(handler)

    def set_disconnect_handler(self, handler):
        self._disconnect_handler = handler

    def connect(self):
        if self.is_connected:
            return

        self._close_sent = False
        self._fragment_opcode = None
        self._fragment_payload = bytearray()
        self._handshake_buffer = bytearray()

        sock = socket.create_connection((self._host, self._port), self._timeout)
        sock.settimeout(0.5)
        self._perform_handshake(sock)
        with self._state_lock:
            self._sock = sock
            self._disconnect_reason = None
            self._stop_event.clear()
            self._reader_thread = threading.Thread(target=self._reader_loop, name="tenet-ida-ws", daemon=True)
            reader_thread = self._reader_thread
        reader_thread.start()

    def close(self):
        with self._state_lock:
            reader_thread = self._reader_thread
            send_close = self._sock is not None and not self._close_sent
            if send_close:
                self._close_sent = True

        if send_close:
            try:
                self._send_frame(0x8, b"\x03\xe8")
            except Exception:
                pass

        self._transition_disconnected("WebSocket closed", notify=False)

        if reader_thread is not None and reader_thread is not threading.current_thread():
            reader_thread.join(timeout=1.0)
            with self._state_lock:
                if self._reader_thread is reader_thread:
                    self._reader_thread = None
        elif reader_thread is threading.current_thread():
            with self._state_lock:
                if self._reader_thread is reader_thread:
                    self._reader_thread = None

    def call_jsonrpc(self, method, params=None, timeout=5.0):
        if self._sock is None:
            raise WebSocketError("WebSocket is not connected")

        with self._id_lock:
            request_id = self._next_id
            self._next_id += 1

        req = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        pending = _PendingCall()
        with self._pending_cond:
            self._pending[request_id] = pending

        self._send_text(json.dumps(req))

        if not pending.event.wait(timeout):
            with self._pending_cond:
                self._pending.pop(request_id, None)
            raise TimeoutError("JSON-RPC request timed out")

        if pending.error:
            raise WebSocketError(pending.error)

        return pending.response

    def send_notification(self, method, params=None):
        if self._sock is None:
            raise WebSocketError("WebSocket is not connected")
        req = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        self._send_text(json.dumps(req))

    def _perform_handshake(self, sock):
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET {path} HTTP/1.1\r\n"
            "Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: {key}\r\n"
            "\r\n"
        ).format(path=self._path, host=self._host, port=self._port, key=key)
        sock.sendall(request.encode("ascii"))

        response, remaining = self._recv_http_headers(sock)
        self._handshake_buffer = bytearray(remaining)
        lines = response.split("\r\n")
        if not lines or not lines[0].startswith("HTTP/1.1 101"):
            raise WebSocketProtocolError("WebSocket handshake failed: expected HTTP 101")

        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        upgrade = headers.get("upgrade", "")
        upgrade_tokens = [token.strip().lower() for token in upgrade.split(",") if token.strip()]
        if "websocket" not in upgrade_tokens:
            raise WebSocketProtocolError("WebSocket handshake missing Upgrade: websocket")

        connection = headers.get("connection", "")
        connection_tokens = [token.strip().lower() for token in connection.split(",") if token.strip()]
        if "upgrade" not in connection_tokens:
            raise WebSocketProtocolError("WebSocket handshake missing Connection: Upgrade")

        accept = headers.get("sec-websocket-accept", "")
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if accept != expected:
            raise WebSocketProtocolError("Invalid Sec-WebSocket-Accept in handshake")

    def _recv_http_headers(self, sock):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                raise WebSocketProtocolError("Connection closed during handshake")
            data += chunk
            if len(data) > 65536:
                raise WebSocketProtocolError("HTTP headers too large")
        header_bytes, remaining = data.split(b"\r\n\r\n", 1)
        return header_bytes.decode("iso-8859-1"), remaining

    def _send_text(self, text):
        payload = text.encode("utf-8")
        self._send_frame(0x1, payload)

    def _send_frame(self, opcode, payload):
        frame = self._encode_client_frame(opcode, payload)
        with self._send_lock:
            with self._state_lock:
                sock = self._sock
            if sock is None:
                raise WebSocketError("WebSocket is not connected")
            try:
                sock.sendall(frame)
            except OSError as exc:
                self._transition_disconnected("WebSocket send failed: %s" % exc)
                raise WebSocketError("WebSocket send failed: %s" % exc)

    def _encode_client_frame(self, opcode, payload):
        first = 0x80 | (opcode & 0x0F)
        out = bytearray([first])

        length = len(payload)
        if length <= 125:
            out.append(0x80 | length)
        elif length <= 0xFFFF:
            out.append(0x80 | 126)
            out.extend(length.to_bytes(2, "big"))
        else:
            out.append(0x80 | 127)
            out.extend(length.to_bytes(8, "big"))

        mask = os.urandom(4)
        out.extend(mask)
        masked = bytearray(length)
        for i in range(length):
            masked[i] = payload[i] ^ mask[i % 4]
        out.extend(masked)
        return bytes(out)

    def _reader_loop(self):
        buffer = bytearray(self._handshake_buffer)
        self._handshake_buffer = bytearray()

        try:
            while not self._stop_event.is_set():
                while buffer:
                    frame = self._decode_server_frame(buffer)
                    if frame is None:
                        break
                    consumed, opcode, fin, payload = frame
                    del buffer[:consumed]
                    if not self._handle_frame(opcode, fin, payload):
                        return

                sock = self._sock
                if sock is None:
                    break
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                if not chunk:
                    break

                buffer.extend(chunk)
        finally:
            self._transition_disconnected("WebSocket reader stopped", clear_reader=True)

    def _decode_server_frame(self, buffer):
        if len(buffer) < 2:
            return None

        b0 = buffer[0]
        b1 = buffer[1]
        fin = (b0 & 0x80) != 0
        if (b0 & 0x70) != 0:
            raise WebSocketProtocolError("RSV bits must be zero")

        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        if masked:
            raise WebSocketProtocolError("Server frames must not be masked")

        is_control = opcode >= 0x8
        if is_control and not fin:
            raise WebSocketProtocolError("Control frames must not be fragmented")
        if opcode == 0x2:
            raise WebSocketProtocolError("Binary frames are not supported")
        if opcode in (0x0, 0x1):
            if not fin:
                raise WebSocketProtocolError("Fragmented data frames are not supported")
        elif opcode not in (0x8, 0x9, 0xA):
            raise WebSocketProtocolError("Unsupported frame opcode: %d" % opcode)

        length = b1 & 0x7F
        pos = 2

        if length == 126:
            if len(buffer) < pos + 2:
                return None
            length = int.from_bytes(buffer[pos:pos + 2], "big")
            pos += 2
        elif length == 127:
            if len(buffer) < pos + 8:
                return None
            length = int.from_bytes(buffer[pos:pos + 8], "big")
            if (length >> 63) != 0:
                raise WebSocketProtocolError("The most significant bit of 64-bit payload length must be zero")
            pos += 8

        if is_control and length > 125:
            raise WebSocketProtocolError("Control frame payload exceeds 125 bytes")
        if length > self._max_payload:
            raise WebSocketProtocolError("Frame payload exceeds limit")

        end = pos + length
        if len(buffer) < end:
            return None

        payload = bytes(buffer[pos:end])
        return end, opcode, fin, payload

    def _handle_frame(self, opcode, fin, payload):
        if opcode == 0x9:  # ping
            self._send_frame(0xA, payload)
            return True

        if opcode == 0xA:  # pong
            return True

        if opcode == 0x8:  # close
            if len(payload) == 1:
                raise WebSocketProtocolError("Close frame payload length 1 is invalid")
            if len(payload) >= 2:
                code = int.from_bytes(payload[:2], "big")
                valid_range = code >= 3000 and code <= 4999
                if code < 1000 or code in (1004, 1005, 1006, 1015) or (code > 1014 and not valid_range) or (code not in _VALID_CLOSE_CODES and not valid_range and code < 3000):
                    raise WebSocketProtocolError("Invalid close code: %d" % code)
                if len(payload) > 2:
                    try:
                        payload[2:].decode("utf-8")
                    except UnicodeDecodeError:
                        raise WebSocketProtocolError("Close reason is not valid UTF-8")
            if not self._close_sent:
                self._close_sent = True
                try:
                    self._send_frame(0x8, payload[:125])
                except Exception:
                    pass
            self._stop_event.set()
            return False

        if opcode == 0x1:  # text
            if not fin:
                raise WebSocketProtocolError("Fragmented data frames are not supported")
            return self._dispatch_text(payload)

        if opcode == 0x0:  # continuation
            raise WebSocketProtocolError("Unexpected continuation frame")

        if opcode == 0x2:
            raise WebSocketProtocolError("Binary frames are not supported")

        raise WebSocketProtocolError("Unsupported frame opcode: %d" % opcode)

    def _dispatch_text(self, payload):
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise WebSocketProtocolError("Text frame is not valid UTF-8")

        try:
            message = json.loads(text)
        except Exception:
            message = text

        if isinstance(message, dict) and "id" in message:
            self._complete_pending(message)
            return True

        if isinstance(message, dict) and message.get("jsonrpc") == "2.0":
            self._notify_handlers(message)
            return True

        # Ignore non JSON-RPC server chatter but keep the socket alive.
        return True

    def _complete_pending(self, message):
        request_id = message.get("id")
        with self._pending_cond:
            pending = self._pending.pop(request_id, None)
            if pending is None:
                return
            if "error" in message:
                pending.error = message["error"]
            else:
                pending.response = message
            pending.event.set()
            self._pending_cond.notify_all()

    def _notify_handlers(self, message):
        with self._notification_lock:
            handlers = list(self._notification_handlers)

        for handler in handlers:
            try:
                handler(message)
            except Exception:
                continue

    def _transition_disconnected(self, reason, notify=True, clear_reader=False):
        callback = None
        with self._state_lock:
            sock = self._sock
            self._sock = None
            self._stop_event.set()
            if clear_reader:
                self._reader_thread = None
            if self._disconnect_reason is None:
                self._disconnect_reason = reason
                if notify:
                    callback = self._disconnect_handler

        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

        self._fail_all_pending(reason)

        if callback is not None:
            try:
                callback(reason)
            except Exception:
                pass

    def _fail_all_pending(self, reason):
        with self._pending_cond:
            pending_items = list(self._pending.values())
            self._pending.clear()
            for pending in pending_items:
                pending.error = reason
                pending.event.set()
            self._pending_cond.notify_all()
