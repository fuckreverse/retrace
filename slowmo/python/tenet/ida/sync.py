import threading


class NavigationSync(object):
    def __init__(self, ida_adapter, tenet_client, poll_interval=0.25):
        self._ida = ida_adapter
        self._tenet = tenet_client
        self._poll_interval = poll_interval

        self._running = False
        self._thread = None
        self._stop_event = threading.Event()

        self._last_tenet_inst = None
        self._last_tenet_pc = None
        self._last_ida_ea = None

        self._suppress_ida_to_tenet_once = False
        self._suppress_tenet_to_ida_once = False

        self._state_lock = threading.Lock()

    def start(self):
        with self._state_lock:
            if self._running:
                return
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._loop, name="tenet-ida-sync", daemon=True)
            self._thread.start()

    def stop(self):
        with self._state_lock:
            if not self._running:
                return
            self._running = False
            self._stop_event.set()
            thread = self._thread
            self._thread = None

        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    def tick_once(self):
        self._sync_tenet_to_ida()
        self._sync_ida_to_tenet()

    def process_once(self):
        self.tick_once()

    def _loop(self):
        while not self._stop_event.wait(self._poll_interval):
            try:
                self.tick_once()
            except Exception:
                if not getattr(self._tenet, "connected", True):
                    with self._state_lock:
                        self._running = False
                        self._thread = None
                        self._stop_event.set()
                    return
                continue

    def _sync_tenet_to_ida(self):
        if self._suppress_tenet_to_ida_once:
            self._suppress_tenet_to_ida_once = False
            return

        cursor = self._tenet.get_cursor()
        inst_id = cursor.get("inst_id")
        pc = cursor.get("pc")
        if inst_id is None or not pc:
            return

        if inst_id == self._last_tenet_inst and pc == self._last_tenet_pc:
            return

        self._last_tenet_inst = inst_id
        self._last_tenet_pc = pc

        ea = int(pc, 16)
        current_ea = self._ida.current_ea()
        if current_ea == ea:
            self._last_ida_ea = current_ea
            return

        self._suppress_ida_to_tenet_once = True
        self._ida.jumpto(ea)
        self._last_ida_ea = ea

    def _sync_ida_to_tenet(self):
        if self._suppress_ida_to_tenet_once:
            self._suppress_ida_to_tenet_once = False
            return

        current_ea = self._ida.current_ea()
        if current_ea is None:
            return

        if current_ea == self._last_ida_ea:
            return

        self._last_ida_ea = current_ea
        pc_hex = "0x{0:X}".format(int(current_ea))

        target = self._find_nearest_inst(pc_hex)
        if target is None:
            return

        if target == self._last_tenet_inst:
            return

        self._suppress_tenet_to_ida_once = True
        nav = self._tenet.navigate(target)
        self._last_tenet_inst = nav.get("inst_id")
        self._last_tenet_pc = nav.get("pc")

    def _find_nearest_inst(self, pc_hex):
        nearest = self._last_tenet_inst
        result = self._tenet.search_pc(pc_hex, nearest_to_inst_id=nearest)
        target = result.get("nearest_inst_id")
        if target is not None:
            try:
                return int(target)
            except (TypeError, ValueError):
                return None

        inst_ids = result.get("inst_ids", [])
        if not inst_ids:
            return None
        return inst_ids[0]
