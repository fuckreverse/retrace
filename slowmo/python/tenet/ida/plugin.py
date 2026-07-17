import threading

from .adapter import IdaAdapter
from .client import TenetClient
from .sync import NavigationSync


PLUGIN_NAME = "Tenet IDA Bridge"
ACTION_CONNECT = "tenet:ida:connect"
ACTION_DISCONNECT = "tenet:ida:disconnect"
ACTION_TOGGLE_SYNC = "tenet:ida:toggle_sync"
ACTION_SHOW_REGS = "tenet:ida:show_regs"


try:
    import ida_idaapi
    import ida_kernwin
    import ida_nalt
except Exception:  # pragma: no cover - guarded for non-IDA imports
    ida_idaapi = None
    ida_kernwin = None
    ida_nalt = None


class _BridgeState(object):
    def __init__(self):
        self.client = None
        self.sync = None
        self.sync_enabled = False
        self.connecting = False
        self.terminated = False
        self.generation = 0
        self.lock = threading.Lock()


_STATE = _BridgeState()


def _log(text):
    if ida_kernwin is not None:
        ida_kernwin.msg("[tenet-ida] %s\n" % text)


def _warn(text):
    if ida_kernwin is not None:
        ida_kernwin.warning("[tenet-ida] %s" % text)


def _ui_warn(text):
    if ida_kernwin is None:
        return

    def _warn_sync():
        _warn(text)
        return 1

    ida_kernwin.execute_sync(_warn_sync, ida_kernwin.MFF_FAST)



def _make_client_and_connect():
    input_path = ""
    if ida_nalt is not None:
        try:
            input_path = ida_nalt.get_input_file_path() or ""
        except Exception:
            input_path = ""

    client = TenetClient(host="127.0.0.1", port=10444, timeout=5.0)
    selected = client.auto_select_instance(input_path)
    client.connect()
    return client, selected


def _disconnect_locked(terminated=False):
    _STATE.generation += 1
    _STATE.connecting = False
    _STATE.terminated = terminated

    if _STATE.sync is not None:
        _STATE.sync.stop()
        _STATE.sync = None
    if _STATE.client is not None:
        _STATE.client.close()
        _STATE.client = None
    _STATE.sync_enabled = False


def _run_network_task(task, on_success=None, on_error=None):
    if ida_kernwin is None:
        return

    def dispatch_error(exc):
        if on_error is not None:
            def apply_error():
                on_error(exc)
                return 1

            ida_kernwin.execute_sync(apply_error, ida_kernwin.MFF_FAST)
        else:
            _ui_warn(str(exc))

    def worker():
        try:
            result = task()
        except Exception as exc:
            dispatch_error(exc)
            return

        if on_success is None:
            return

        try:
            def apply_result():
                on_success(result)
                return 1

            ida_kernwin.execute_sync(apply_result, ida_kernwin.MFF_FAST)
        except Exception as exc:
            dispatch_error(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()


def _action_connect():
    if ida_kernwin is None:
        return

    with _STATE.lock:
        if _STATE.terminated:
            _warn("Plugin is terminated")
            return
        if _STATE.client is not None:
            _log("already connected")
            return
        if _STATE.connecting:
            _log("connect already in progress")
            return
        _STATE.connecting = True
        _STATE.generation += 1
        token = _STATE.generation

    def task():
        return _make_client_and_connect()

    def on_success(result):
        client, selected = result

        with _STATE.lock:
            stale = (
                token != _STATE.generation
                or _STATE.terminated
                or not _STATE.connecting
                or _STATE.client is not None
            )
        if stale:
            client.close()
            return

        try:
            adapter = IdaAdapter(ida_kernwin)
            image_base = adapter.get_image_base()
            client.set_image_base(image_base)
            sync = NavigationSync(adapter, client, poll_interval=0.25)
        except Exception:
            client.close()
            raise

        def handle_disconnect(reason):
            if ida_kernwin is None:
                return

            def apply_disconnect():
                with _STATE.lock:
                    if _STATE.client is not client or token != _STATE.generation or _STATE.terminated:
                        return 1
                    _disconnect_locked()
                _warn("Disconnected from tenet: %s" % reason)
                return 1

            ida_kernwin.execute_sync(apply_disconnect, ida_kernwin.MFF_FAST)

        client.add_disconnect_handler(handle_disconnect)

        with _STATE.lock:
            stale = (
                token != _STATE.generation
                or _STATE.terminated
                or not _STATE.connecting
                or _STATE.client is not None
            )
            if stale:
                _STATE.connecting = False
            else:
                _STATE.client = client
                _STATE.sync = sync
                _STATE.sync_enabled = False
                _STATE.connecting = False

        if stale:
            client.close()
            return

        _log("connected to instance %s" % selected.get("id", ""))

    def on_error(exc):
        with _STATE.lock:
            stale = token != _STATE.generation or _STATE.terminated
            if not stale and _STATE.connecting:
                _STATE.connecting = False
        if stale:
            return
        _ui_warn(str(exc))

    _run_network_task(task, on_success=on_success, on_error=on_error)


def _action_disconnect():
    if ida_kernwin is None:
        return

    with _STATE.lock:
        if _STATE.client is None and not _STATE.connecting:
            _log("not connected")
            return
        _disconnect_locked()
    _log("disconnected")


def _action_toggle_sync():
    if ida_kernwin is None:
        return

    with _STATE.lock:
        sync = _STATE.sync
        if sync is None:
            _warn("Connect first")
            return

        if _STATE.sync_enabled:
            sync.stop()
            _STATE.sync_enabled = False
            _log("sync disabled")
            return

        sync.start()
        _STATE.sync_enabled = True
        _log("sync enabled")


def _action_show_regs():
    if ida_kernwin is None:
        return

    with _STATE.lock:
        client = _STATE.client

    if client is None:
        _warn("Connect first")
        return

    def task():
        cursor = client.get_cursor()
        regs = client.get_regs(cursor.get("inst_id"))
        return cursor, regs

    def on_success(result):
        cursor, regs_payload = result
        regs = regs_payload.get("regs", {})
        inst_id = cursor.get("inst_id")
        pc = cursor.get("pc")
        summary = "inst_id=%s pc=%s x0=%s x1=%s sp=%s" % (
            inst_id,
            pc,
            regs.get("x0", "?"),
            regs.get("x1", "?"),
            regs.get("sp", "?"),
        )
        _log(summary)

    _run_network_task(task, on_success=on_success)


def _register_action(action_name, label, callback):
    if ida_kernwin is None:
        return

    class _SimpleActionHandler(ida_kernwin.action_handler_t):
        def __init__(self, cb):
            super(_SimpleActionHandler, self).__init__()
            self._cb = cb

        def activate(self, ctx):
            self._cb()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    desc = ida_kernwin.action_desc_t(
        action_name,
        label,
        _SimpleActionHandler(callback),
        None,
        "",
        0,
    )
    ida_kernwin.register_action(desc)


def _attach_actions_to_menu():
    if ida_kernwin is None:
        return

    ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_CONNECT, ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_DISCONNECT, ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_TOGGLE_SYNC, ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_SHOW_REGS, ida_kernwin.SETMENU_APP)


def _detach_actions_from_menu():
    if ida_kernwin is None:
        return

    for action in (ACTION_CONNECT, ACTION_DISCONNECT, ACTION_TOGGLE_SYNC, ACTION_SHOW_REGS):
        ida_kernwin.detach_action_from_menu("Edit/Plugins/", action)
        ida_kernwin.unregister_action(action)


if ida_idaapi is not None:
    class TenetIdaPlugin(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_KEEP
        comment = "tenet hub websocket bridge"
        help = "Connect IDA to tenet MCP Hub"
        wanted_name = PLUGIN_NAME
        wanted_hotkey = ""

        def init(self):
            try:
                _register_action(ACTION_CONNECT, "Tenet: Connect", _action_connect)
                _register_action(ACTION_DISCONNECT, "Tenet: Disconnect", _action_disconnect)
                _register_action(ACTION_TOGGLE_SYNC, "Tenet: Toggle Sync", _action_toggle_sync)
                _register_action(ACTION_SHOW_REGS, "Tenet: Show Current Registers", _action_show_regs)
                _attach_actions_to_menu()
                _log("plugin loaded")
                return ida_idaapi.PLUGIN_OK
            except Exception as exc:
                _warn("init failed: %s" % exc)
                return ida_idaapi.PLUGIN_SKIP

        def run(self, arg):
            _action_connect()

        def term(self):
            with _STATE.lock:
                _disconnect_locked(terminated=True)
            _detach_actions_from_menu()
            _log("plugin unloaded")


    def PLUGIN_ENTRY():
        return TenetIdaPlugin()
else:
    def PLUGIN_ENTRY():  # pragma: no cover
        return None
