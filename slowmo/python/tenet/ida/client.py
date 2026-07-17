import json
from urllib import parse
from urllib import request

from .websocket import LocalWebSocketClient, WebSocketError


class TenetClientError(Exception):
    pass


class TenetClient(object):
    def __init__(self, host="127.0.0.1", port=10444, timeout=5.0):
        self._host = host
        self._port = int(port)
        self._timeout = timeout

        self._instance = None
        self._instance_info = None
        self._ws = None
        self._disconnect_handlers = []

    @property
    def instance(self):
        return self._instance

    @property
    def instance_info(self):
        return self._instance_info

    @property
    def connected(self):
        return self._ws is not None and self._ws.is_connected

    def discover_instances(self):
        rpc = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_instances",
                "arguments": {},
            },
        }

        body = json.dumps(rpc).encode("utf-8")
        url = "http://{0}:{1}/mcp".format(self._host, self._port)
        req = request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")

        try:
            with request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8")
        except Exception as exc:
            raise TenetClientError("Failed to discover instances: %s" % exc)

        try:
            data = json.loads(raw)
        except Exception as exc:
            raise TenetClientError("Hub response is not valid JSON: %s" % exc)

        if "error" in data:
            raise TenetClientError("Hub returned JSON-RPC error: %r" % data["error"])

        result = data.get("result", {})
        content = result.get("content", [])
        if not content:
            return []

        text = content[0].get("text", "")
        payload = json.loads(text)
        return payload.get("instances", [])

    def auto_select_instance(self, ida_input_path):
        instances = self.discover_instances()
        if not instances:
            raise TenetClientError("No tenet instances discovered")

        ida_base = ""
        if ida_input_path:
            ida_base = ida_input_path.rsplit("/", 1)[-1]

        best = None

        # Prefer module_name basename match.
        if ida_base:
            for inst in instances:
                module = inst.get("module_name") or ""
                module_base = module.rsplit("/", 1)[-1]
                if module_base == ida_base:
                    best = inst
                    break

        # Fallback: trace_file basename match.
        if best is None and ida_base:
            for inst in instances:
                trace = inst.get("trace_file") or ""
                trace_base = trace.rsplit("/", 1)[-1]
                if trace_base == ida_base:
                    best = inst
                    break

        # Final fallback: first instance.
        if best is None:
            best = instances[0]

        self._instance_info = best
        self._instance = best.get("id")
        return best

    def add_disconnect_handler(self, handler):
        self._disconnect_handlers.append(handler)

    def connect(self, instance=None):
        if instance is not None:
            self._instance = instance
        if not self._instance:
            raise TenetClientError("Instance is not selected")

        quoted = parse.quote(self._instance, safe="")
        ws_url = "ws://{0}:{1}/ws/{2}".format(self._host, self._port, quoted)

        ws = LocalWebSocketClient(ws_url, timeout=self._timeout)
        ws.add_notification_handler(self._on_notification)
        ws.set_disconnect_handler(self._on_disconnect)
        try:
            ws.connect()
        except Exception:
            ws.close()
            raise
        self._ws = ws

    def close(self):
        if self._ws is not None:
            self._ws.close()
            self._ws = None

    def _on_notification(self, message):
        # Keep a hook for future plugin UI feedback; currently no-op.
        _ = message

    def _on_disconnect(self, reason):
        for handler in list(self._disconnect_handlers):
            try:
                handler(reason)
            except Exception:
                continue

    def call_tool(self, name, arguments=None, timeout=5.0):
        if self._ws is None or not self._ws.is_connected:
            raise TenetClientError("WebSocket is not connected")

        params = {
            "name": name,
            "arguments": arguments or {},
        }

        try:
            response = self._ws.call_jsonrpc("tools/call", params=params, timeout=timeout)
        except (WebSocketError, OSError) as exc:
            raise TenetClientError("tools/call failed: %s" % exc)

        if response.get("jsonrpc") != "2.0":
            raise TenetClientError("Invalid JSON-RPC version in response")

        if "error" in response:
            raise TenetClientError("JSON-RPC error: %r" % response["error"])

        result = response.get("result", {})
        if result.get("isError"):
            text = ""
            content = result.get("content", [])
            if content:
                text = content[0].get("text", "")
            raise TenetClientError("Tool %s returned error: %s" % (name, text))

        content = result.get("content", [])
        if not content:
            return {}

        text = content[0].get("text", "")
        if not text:
            return {}

        return json.loads(text)

    def trace_info(self):
        return self.call_tool("trace_info", {})

    def search_pc(self, pc_hex, offset=0, limit=100, nearest_to_inst_id=None):
        args = {
            "pc": pc_hex,
            "offset": int(offset),
            "limit": int(limit),
        }
        if nearest_to_inst_id is not None:
            args["nearest_to_inst_id"] = int(nearest_to_inst_id)
        return self.call_tool("search_pc", args)

    def disasm(self, start_inst_id, count=20, show_regs=False, show_mem=False):
        args = {
            "start_inst_id": int(start_inst_id),
            "count": int(count),
            "show_regs": bool(show_regs),
            "show_mem": bool(show_mem),
        }
        return self.call_tool("disasm", args)

    def get_regs(self, inst_id):
        return self.call_tool("get_regs", {"inst_id": int(inst_id)})

    def get_cursor(self):
        return self.call_tool("get_cursor", {})

    def navigate(self, inst_id):
        return self.call_tool("navigate", {"inst_id": int(inst_id)})

    def set_image_base(self, image_base):
        if isinstance(image_base, int):
            image_base = "0x{0:X}".format(image_base)
        return self.call_tool("set_image_base", {"image_base": image_base})
