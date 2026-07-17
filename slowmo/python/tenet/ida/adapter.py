try:
    import ida_kernwin as _default_ida_kernwin
except Exception:  # pragma: no cover - import guarded for non-IDA use
    _default_ida_kernwin = None

try:
    import ida_nalt as _default_ida_nalt
except Exception:  # pragma: no cover - import guarded for non-IDA use
    _default_ida_nalt = None

try:
    import idaapi as _default_idaapi
except Exception:  # pragma: no cover - import guarded for non-IDA use
    _default_idaapi = None


class IdaAdapter(object):
    """Thin adapter for IDA APIs, designed for main-thread-safe calls."""

    def __init__(self, ida_kernwin=None, ida_nalt=None, idaapi=None):
        self._ida_kernwin = ida_kernwin or _default_ida_kernwin
        self._ida_nalt = ida_nalt or _default_ida_nalt
        self._idaapi = idaapi or _default_idaapi
        if self._ida_kernwin is None:
            raise RuntimeError("IDA APIs are unavailable")

    def execute_sync(self, fn, flags=None):
        if flags is None:
            flags = self._ida_kernwin.MFF_FAST
        return self._ida_kernwin.execute_sync(fn, flags)

    def current_ea(self):
        holder = {"ea": None}

        def _read():
            holder["ea"] = self._ida_kernwin.get_screen_ea()
            return 1

        self.execute_sync(_read)
        return holder["ea"]

    def jumpto(self, ea):
        def _jump():
            self._ida_kernwin.jumpto(ea)
            return 1

        self.execute_sync(_jump)

    def get_image_base(self):
        holder = {"image_base": None}

        def _read():
            if self._ida_nalt is not None and hasattr(self._ida_nalt, "get_imagebase"):
                holder["image_base"] = self._ida_nalt.get_imagebase()
                return 1
            if self._idaapi is not None and hasattr(self._idaapi, "get_imagebase"):
                holder["image_base"] = self._idaapi.get_imagebase()
                return 1
            raise RuntimeError("IDA image base API is unavailable")

        self.execute_sync(_read)
        return holder["image_base"]

    def msg(self, text):
        def _msg():
            self._ida_kernwin.msg(text)
            return 1

        self.execute_sync(_msg)

    def warning(self, text):
        def _warning():
            self._ida_kernwin.warning(text)
            return 1

        self.execute_sync(_warning)
