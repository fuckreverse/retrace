import pathlib
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


class _FakeKernwin(object):
    MFF_FAST = 0
    AST_ENABLE_ALWAYS = 0
    SETMENU_APP = 0

    def __init__(self):
        self.execute_sync_calls = []
        self.msg_calls = []
        self.warning_calls = []

    def execute_sync(self, fn, flags):
        self.execute_sync_calls.append((fn, flags))
        return fn()

    def msg(self, text):
        self.msg_calls.append(text)

    def warning(self, text):
        self.warning_calls.append(text)

    def register_action(self, desc):
        return True

    def attach_action_to_menu(self, *args, **kwargs):
        return True

    def detach_action_from_menu(self, *args, **kwargs):
        return True

    def unregister_action(self, *args, **kwargs):
        return True

    class action_handler_t(object):
        def __init__(self, *args, **kwargs):
            pass

    class action_desc_t(object):
        def __init__(self, *args, **kwargs):
            pass


class _FakeIdaIdaapi(object):
    PLUGIN_KEEP = 0
    PLUGIN_OK = 0
    PLUGIN_SKIP = -1

    class plugin_t(object):
        pass


class _FakeIdaNalt(object):
    @staticmethod
    def get_input_file_path():
        return "/tmp/input.bin"


class _FakeClient(object):
    def __init__(self, call_order, name="client", set_image_base_exc=None):
        self.image_base_calls = []
        self.call_order = call_order
        self.name = name
        self.close_calls = 0
        self.set_image_base_exc = set_image_base_exc

    def set_image_base(self, image_base):
        self.image_base_calls.append(image_base)
        self.call_order.append(("set_image_base", image_base, self.name))
        if self.set_image_base_exc is not None:
            raise self.set_image_base_exc
        return {"ok": True}

    def add_disconnect_handler(self, handler):
        self.disconnect_handler = handler

    def close(self):
        self.close_calls += 1
        self.call_order.append(("close", self.name))
        return None


class _FakeAdapter(object):
    def __init__(self, _kernwin):
        self.calls = []

    def get_image_base(self):
        self.calls.append("get_image_base")
        return 0x180000000


class _FakeNavigationSync(object):
    created = []

    def __init__(self, adapter, client, poll_interval=0.25):
        self.adapter = adapter
        self.client = client
        self.poll_interval = poll_interval
        client.call_order.append(("navigation_sync_init", poll_interval, client.name))
        _FakeNavigationSync.created.append(self)

    def start(self):
        return None

    def stop(self):
        return None


class _FailingNavigationSync(object):
    def __init__(self, adapter, client, poll_interval=0.25):
        client.call_order.append(("navigation_sync_init", poll_interval, client.name))
        raise RuntimeError("sync init failed")


class _DeferredThread(object):
    created = []

    def __init__(self, target=None, daemon=None, name=None):
        self._target = target
        self.daemon = daemon
        self.name = name
        self.started = False

    def start(self):
        self.started = True
        _DeferredThread.created.append(self)

    def run_now(self):
        if self._target is not None:
            self._target()


class PluginConnectTests(unittest.TestCase):
    def setUp(self):
        self.fake_kernwin = _FakeKernwin()
        self.call_order = []
        self.fake_client = _FakeClient(self.call_order)
        _FakeNavigationSync.created = []
        _DeferredThread.created = []

        fake_adapter_module = types.SimpleNamespace(IdaAdapter=_FakeAdapter)
        fake_client_module = types.SimpleNamespace(TenetClient=object)
        fake_sync_module = types.SimpleNamespace(NavigationSync=_FakeNavigationSync)

        self.module_patcher = mock.patch.dict(
            sys.modules,
            {
                "ida_idaapi": _FakeIdaIdaapi(),
                "ida_kernwin": self.fake_kernwin,
                "ida_nalt": _FakeIdaNalt(),
                "tenet.ida.adapter": fake_adapter_module,
                "tenet.ida.client": fake_client_module,
                "tenet.ida.sync": fake_sync_module,
            },
            clear=False,
        )
        self.module_patcher.start()
        self.addCleanup(self.module_patcher.stop)

        sys.modules.pop("tenet.ida.plugin", None)
        import tenet.ida.plugin as plugin

        self.plugin = plugin
        with self.plugin._STATE.lock:
            self.plugin._disconnect_locked()

    def tearDown(self):
        with self.plugin._STATE.lock:
            self.plugin._disconnect_locked()
        sys.modules.pop("tenet.ida.plugin", None)

    def test_run_network_task_routes_ui_success_exception_to_on_error(self):
        observed = []

        def task():
            return "ok"

        def on_success(_result):
            raise RuntimeError("ui exploded")

        def on_error(exc):
            observed.append(str(exc))

        with mock.patch.object(self.plugin.threading, "Thread", _DeferredThread):
            self.plugin._run_network_task(task, on_success=on_success, on_error=on_error)
            self.assertEqual(1, len(_DeferredThread.created))
            _DeferredThread.created[0].run_now()

        self.assertEqual(["ui exploded"], observed)
        self.assertEqual([], self.fake_kernwin.warning_calls)

    def test_connect_sets_image_base_before_navigation_sync(self):
        with mock.patch.object(self.plugin, "_make_client_and_connect", return_value=(self.fake_client, {"id": "iid"})):
            self.plugin._action_connect()

        with self.plugin._STATE.lock:
            sync = self.plugin._STATE.sync
            client = self.plugin._STATE.client

        self.assertIs(client, self.fake_client)
        self.assertIsNotNone(sync)
        self.assertEqual([0x180000000], self.fake_client.image_base_calls)
        self.assertEqual(["get_image_base"], sync.adapter.calls)
        self.assertEqual(0.25, sync.poll_interval)
        self.assertEqual(
            [("set_image_base", 0x180000000, "client"), ("navigation_sync_init", 0.25, "client")],
            self.call_order,
        )

    def test_disconnect_before_connect_success_keeps_state_empty(self):
        with mock.patch.object(self.plugin.threading, "Thread", _DeferredThread):
            with mock.patch.object(self.plugin, "_make_client_and_connect", return_value=(self.fake_client, {"id": "iid"})):
                self.plugin._action_connect()
                self.assertEqual(1, len(_DeferredThread.created))

                with self.plugin._STATE.lock:
                    self.assertTrue(self.plugin._STATE.connecting)

                self.plugin._action_disconnect()
                _DeferredThread.created[0].run_now()

        with self.plugin._STATE.lock:
            self.assertIsNone(self.plugin._STATE.client)
            self.assertIsNone(self.plugin._STATE.sync)
            self.assertFalse(self.plugin._STATE.connecting)

        self.assertEqual(1, self.fake_client.close_calls)

    def test_disconnect_handler_cleans_plugin_state(self):
        with mock.patch.object(self.plugin, "_make_client_and_connect", return_value=(self.fake_client, {"id": "iid"})):
            self.plugin._action_connect()

        with self.plugin._STATE.lock:
            self.assertIs(self.plugin._STATE.client, self.fake_client)
            self.assertIsNotNone(self.plugin._STATE.sync)

        self.fake_client.disconnect_handler("worker disconnected")

        with self.plugin._STATE.lock:
            self.assertIsNone(self.plugin._STATE.client)
            self.assertIsNone(self.plugin._STATE.sync)
            self.assertFalse(self.plugin._STATE.sync_enabled)

        self.assertTrue(any("Disconnected from tenet: worker disconnected" in msg for msg in self.fake_kernwin.warning_calls))

    def test_repeated_connect_is_blocked_while_request_in_flight(self):
        with mock.patch.object(self.plugin.threading, "Thread", _DeferredThread):
            with mock.patch.object(self.plugin, "_make_client_and_connect", return_value=(self.fake_client, {"id": "iid"})):
                self.plugin._action_connect()
                self.plugin._action_connect()
                self.assertEqual(1, len(_DeferredThread.created))
                _DeferredThread.created[0].run_now()

        with self.plugin._STATE.lock:
            self.assertIs(self.plugin._STATE.client, self.fake_client)
            self.assertFalse(self.plugin._STATE.connecting)

        self.assertTrue(any("connect already in progress" in msg for msg in self.fake_kernwin.msg_calls))

    def test_term_before_connect_success_marks_plugin_terminated(self):
        with mock.patch.object(self.plugin.threading, "Thread", _DeferredThread):
            with mock.patch.object(self.plugin, "_make_client_and_connect", return_value=(self.fake_client, {"id": "iid"})):
                self.plugin._action_connect()
                self.assertEqual(1, len(_DeferredThread.created))

                plugin_entry = self.plugin.TenetIdaPlugin()
                plugin_entry.term()
                _DeferredThread.created[0].run_now()

        with self.plugin._STATE.lock:
            self.assertTrue(self.plugin._STATE.terminated)
            self.assertIsNone(self.plugin._STATE.client)
            self.assertIsNone(self.plugin._STATE.sync)

        self.assertEqual(1, self.fake_client.close_calls)

    def test_stale_connect_result_closes_old_client_after_reconnect(self):
        client_one = _FakeClient(self.call_order, name="client-one")
        client_two = _FakeClient(self.call_order, name="client-two")

        with mock.patch.object(self.plugin.threading, "Thread", _DeferredThread):
            with mock.patch.object(
                self.plugin,
                "_make_client_and_connect",
                side_effect=[(client_one, {"id": "iid-1"}), (client_two, {"id": "iid-2"})],
            ):
                self.plugin._action_connect()
                first = _DeferredThread.created[0]
                self.plugin._action_disconnect()
                self.plugin._action_connect()
                self.assertEqual(2, len(_DeferredThread.created))
                second = _DeferredThread.created[1]

                first.run_now()
                second.run_now()

        with self.plugin._STATE.lock:
            self.assertIs(self.plugin._STATE.client, client_two)
            self.assertFalse(self.plugin._STATE.connecting)

        self.assertEqual(1, client_one.close_calls)
        self.assertEqual(0, client_two.close_calls)

    def test_connect_set_image_base_failure_closes_client_and_can_reconnect(self):
        failing_client = _FakeClient(
            self.call_order,
            name="bad-client",
            set_image_base_exc=RuntimeError("set_image_base failed"),
        )
        good_client = _FakeClient(self.call_order, name="good-client")

        with mock.patch.object(self.plugin.threading, "Thread", _DeferredThread):
            with mock.patch.object(
                self.plugin,
                "_make_client_and_connect",
                side_effect=[(failing_client, {"id": "bad"}), (good_client, {"id": "good"})],
            ):
                self.plugin._action_connect()
                _DeferredThread.created[0].run_now()

                with self.plugin._STATE.lock:
                    self.assertIsNone(self.plugin._STATE.client)
                    self.assertIsNone(self.plugin._STATE.sync)
                    self.assertFalse(self.plugin._STATE.connecting)

                self.plugin._action_connect()
                _DeferredThread.created[1].run_now()

        with self.plugin._STATE.lock:
            self.assertIs(self.plugin._STATE.client, good_client)
            self.assertFalse(self.plugin._STATE.connecting)

        self.assertEqual(1, failing_client.close_calls)
        self.assertEqual(0, good_client.close_calls)
        self.assertEqual(1, len(self.fake_kernwin.warning_calls))
        self.assertIn("set_image_base failed", self.fake_kernwin.warning_calls[0])

    def test_connect_sync_init_failure_closes_client_and_can_reconnect(self):
        failing_client = _FakeClient(self.call_order, name="bad-sync-client")
        good_client = _FakeClient(self.call_order, name="good-sync-client")

        with mock.patch.object(self.plugin.threading, "Thread", _DeferredThread):
            with mock.patch.object(self.plugin, "NavigationSync", _FailingNavigationSync):
                with mock.patch.object(
                    self.plugin,
                    "_make_client_and_connect",
                    side_effect=[(failing_client, {"id": "bad"}), (good_client, {"id": "good"})],
                ):
                    self.plugin._action_connect()
                    _DeferredThread.created[0].run_now()

                    with self.plugin._STATE.lock:
                        self.assertIsNone(self.plugin._STATE.client)
                        self.assertIsNone(self.plugin._STATE.sync)
                        self.assertFalse(self.plugin._STATE.connecting)

            with mock.patch.object(
                self.plugin,
                "_make_client_and_connect",
                return_value=(good_client, {"id": "good"}),
            ):
                self.plugin._action_connect()
                _DeferredThread.created[1].run_now()

        with self.plugin._STATE.lock:
            self.assertIs(self.plugin._STATE.client, good_client)
            self.assertFalse(self.plugin._STATE.connecting)

        self.assertEqual(1, failing_client.close_calls)
        self.assertEqual(0, good_client.close_calls)
        self.assertEqual(1, len(self.fake_kernwin.warning_calls))
        self.assertIn("sync init failed", self.fake_kernwin.warning_calls[0])

    def test_stale_connect_error_is_ignored_after_disconnect(self):
        with mock.patch.object(self.plugin.threading, "Thread", _DeferredThread):
            with mock.patch.object(self.plugin, "_make_client_and_connect", side_effect=RuntimeError("boom")):
                self.plugin._action_connect()
                self.assertEqual(1, len(_DeferredThread.created))
                self.plugin._action_disconnect()
                _DeferredThread.created[0].run_now()

        self.assertEqual([], self.fake_kernwin.warning_calls)
        with self.plugin._STATE.lock:
            self.assertFalse(self.plugin._STATE.connecting)
            self.assertIsNone(self.plugin._STATE.client)


if __name__ == "__main__":
    unittest.main()
