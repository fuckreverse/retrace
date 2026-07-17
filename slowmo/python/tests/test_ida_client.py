import io
import json
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tenet.ida.client import TenetClient, TenetClientError
from tenet.ida.websocket import WebSocketError


class _FakeHttpResponse(object):
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeWs(object):
    created_urls = []

    def __init__(self, url, timeout=5.0):
        self.url = url
        self.timeout = timeout
        self.connected = False
        self.calls = []
        self.responses = []
        self.notifications = []
        self.disconnect_handler = None
        _FakeWs.created_urls.append(url)

    def connect(self):
        self.connected = True

    def close(self):
        self.connected = False

    @property
    def is_connected(self):
        return self.connected

    def add_notification_handler(self, handler):
        self.notifications.append(handler)

    def set_disconnect_handler(self, handler):
        self.disconnect_handler = handler

    def call_jsonrpc(self, method, params=None, timeout=5.0):
        if not self.connected:
            raise WebSocketError("WebSocket is not connected")
        self.calls.append((method, params, timeout))
        if self.responses:
            return self.responses.pop(0)
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "{}"}],
                "isError": False,
            },
        }


def _make_list_instances_payload(instances):
    tool_result = {
        "instances": instances,
    }
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": json.dumps(tool_result)}],
            "isError": False,
        },
    }
    return json.dumps(rpc).encode("utf-8")


class TenetClientTests(unittest.TestCase):
    def test_discovery_auto_select_prefers_module_basename(self):
        instances = [
            {"id": "i1", "module_name": "/tmp/other", "trace_file": "/tmp/t1.bin"},
            {"id": "i2", "module_name": "/opt/bin/myapp", "trace_file": "/tmp/t2.bin"},
        ]

        payload = _make_list_instances_payload(instances)
        with mock.patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            client = TenetClient()
            selected = client.auto_select_instance("/Users/me/myapp")
            self.assertEqual("i2", selected["id"])

    def test_discovery_fallback_trace_basename(self):
        instances = [
            {"id": "i1", "module_name": "modA", "trace_file": "/tmp/first.bin"},
            {"id": "i2", "module_name": "modB", "trace_file": "/tmp/target.trace"},
        ]

        payload = _make_list_instances_payload(instances)
        with mock.patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            client = TenetClient()
            selected = client.auto_select_instance("/Users/me/target.trace")
            self.assertEqual("i2", selected["id"])

    def test_connect_uses_url_quoted_instance(self):
        instances = [{"id": "ida/session 1", "module_name": "x", "trace_file": "x"}]
        payload = _make_list_instances_payload(instances)

        _FakeWs.created_urls = []
        with mock.patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            with mock.patch("tenet.ida.client.LocalWebSocketClient", _FakeWs):
                client = TenetClient()
                client.auto_select_instance("")
                client.connect()
                self.assertTrue(_FakeWs.created_urls)
                self.assertIn("/ws/ida%2Fsession%201", _FakeWs.created_urls[0])

    def test_call_tool_requires_jsonrpc_2_0(self):
        instances = [{"id": "iid", "module_name": "x", "trace_file": "x"}]
        payload = _make_list_instances_payload(instances)

        with mock.patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            with mock.patch("tenet.ida.client.LocalWebSocketClient", _FakeWs):
                client = TenetClient()
                client.auto_select_instance("")
                client.connect()

                client._ws.responses.append({
                    "jsonrpc": "1.0",
                    "id": 1,
                    "result": {"content": [], "isError": False},
                })

                with self.assertRaises(TenetClientError):
                    client.call_tool("trace_info", {})

    def test_call_tool_and_convenience_methods(self):
        instances = [{"id": "iid", "module_name": "x", "trace_file": "x"}]
        payload = _make_list_instances_payload(instances)

        with mock.patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            with mock.patch("tenet.ida.client.LocalWebSocketClient", _FakeWs):
                client = TenetClient()
                client.auto_select_instance("")
                client.connect()

                client._on_notification({"jsonrpc": "2.0", "method": "tenet/connected", "params": {"instance": "iid"}})

                client._ws.responses.append({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "content": [{"type": "text", "text": "{\"inst_id\": 7, \"pc\": \"0x1000\"}"}],
                        "isError": False,
                    },
                })

                out = client.navigate(7)
                self.assertEqual(7, out["inst_id"])

                method, params, _timeout = client._ws.calls[-1]
                self.assertEqual("tools/call", method)
                self.assertEqual("navigate", params["name"])
                self.assertEqual(7, params["arguments"]["inst_id"])

    def test_connected_property_tracks_socket_state(self):
        instances = [{"id": "iid", "module_name": "x", "trace_file": "x"}]
        payload = _make_list_instances_payload(instances)

        with mock.patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            with mock.patch("tenet.ida.client.LocalWebSocketClient", _FakeWs):
                client = TenetClient()
                client.auto_select_instance("")
                client.connect()
                self.assertTrue(client.connected)

                client._ws.connected = False
                with self.assertRaisesRegex(TenetClientError, "WebSocket is not connected"):
                    client.call_tool("trace_info", {})
                self.assertFalse(client.connected)

    def test_set_image_base_wraps_tool_call(self):
        instances = [{"id": "iid", "module_name": "x", "trace_file": "x"}]
        payload = _make_list_instances_payload(instances)

        with mock.patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            with mock.patch("tenet.ida.client.LocalWebSocketClient", _FakeWs):
                client = TenetClient()
                client.auto_select_instance("")
                client.connect()

                client._ws.responses.append({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "result": {
                        "content": [{"type": "text", "text": "{\"ok\": true, \"new_image_base\": \"0x180000000\"}"}],
                        "isError": False,
                    },
                })

                out = client.set_image_base(0x180000000)
                self.assertTrue(out["ok"])
                method, params, _timeout = client._ws.calls[-1]
                self.assertEqual("tools/call", method)
                self.assertEqual("set_image_base", params["name"])
                self.assertEqual("0x180000000", params["arguments"]["image_base"])

                client._ws.responses.append({
                    "jsonrpc": "2.0",
                    "id": 4,
                    "result": {
                        "content": [{"type": "text", "text": "{\"ok\": true, \"new_image_base\": \"0x1000\"}"}],
                        "isError": False,
                    },
                })

                client.set_image_base("0x1000")
                _method, params, _timeout = client._ws.calls[-1]
                self.assertEqual("0x1000", params["arguments"]["image_base"])

    def test_search_pc_supports_nearest_to_inst_id(self):
        instances = [{"id": "iid", "module_name": "x", "trace_file": "x"}]
        payload = _make_list_instances_payload(instances)

        with mock.patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            with mock.patch("tenet.ida.client.LocalWebSocketClient", _FakeWs):
                client = TenetClient()
                client.auto_select_instance("")
                client.connect()

                client._ws.responses.append({
                    "jsonrpc": "2.0",
                    "id": 5,
                    "result": {
                        "content": [{"type": "text", "text": "{\"inst_ids\": [1, 3], \"nearest_inst_id\": 3}"}],
                        "isError": False,
                    },
                })

                out = client.search_pc("0x401000", nearest_to_inst_id=77)
                self.assertEqual(3, out["nearest_inst_id"])
                method, params, _timeout = client._ws.calls[-1]
                self.assertEqual("tools/call", method)
                self.assertEqual("search_pc", params["name"])
                self.assertEqual("0x401000", params["arguments"]["pc"])
                self.assertEqual(77, params["arguments"]["nearest_to_inst_id"])
                self.assertEqual(0, params["arguments"]["offset"])
                self.assertEqual(100, params["arguments"]["limit"])


if __name__ == "__main__":
    unittest.main()
