"""
tenet Python bindings
=====================

Provides a high-level Python interface to the tenet trace analysis engine.

Quickstart
----------
    import tenet

    t = tenet.Trace("trace.bin")
    print(f"Instructions: {t.inst_count}")

    # Read registers at instruction 1000
    state = t.regs(1000)
    print(f"x0 = 0x{state['x0']:X}")

    # Read memory at a specific point in time
    data = t.read_mem(0x100000, 16, at=1000)

    # Run the xref pass and find all executions of a PC
    xref = t.pass_xref()
    ids = xref.inst_ids_at(0xdeadbeef)

    # Run taint analysis from x0
    taint = t.pass_taint(source_reg=0)
    print(f"Taint steps: {len(taint.steps)}")

    # Pipe into a custom analysis via the loopback RPC interface
    t.start_rpc()          # starts a TCP listener on 127.0.0.1
    t.stop_rpc()
"""

import subprocess
import sys
import os
import json
import socket
import struct
import tempfile
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any, Iterator


__version__ = "0.1.0"
__all__ = ["Trace", "TraceError", "RpcClient"]


class TraceError(Exception):
    """Raised when the tenet binary returns an error."""
    pass


def _find_tenet_binary() -> Optional[str]:
    """Locate the tenet binary: check PATH, then common build paths."""
    # 1. Explicit env override
    env_path = os.environ.get("TENET_BIN")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2. PATH
    import shutil
    found = shutil.which("tenet")
    if found:
        return found

    # 3. Relative to this file (development layout)
    this_dir = Path(__file__).parent.parent.parent  # tools/tenet/python → tools/tenet
    for candidate in [
        this_dir / "build" / "tenet",
        this_dir / "build-no-triton" / "tenet",
    ]:
        if candidate.is_file():
            return str(candidate)

    return None


class RegState:
    """Snapshot of AArch64 register state at a given instruction."""
    _REG_NAMES = [
        "x0","x1","x2","x3","x4","x5","x6","x7",
        "x8","x9","x10","x11","x12","x13","x14","x15",
        "x16","x17","x18","x19","x20","x21","x22","x23",
        "x24","x25","x26","x27","x28","fp","lr","sp","nzcv","pc"
    ]

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def __getitem__(self, key: str) -> int:
        val = self._data.get(key, "0x0")
        return int(val, 16) if isinstance(val, str) else val

    def __repr__(self) -> str:
        pc = self["pc"]
        x0 = self["x0"]
        return f"<RegState pc=0x{pc:X} x0=0x{x0:X}>"

    @property
    def pc(self) -> int:     return self["pc"]
    @property
    def sp(self) -> int:     return self["sp"]
    @property
    def lr(self) -> int:     return self["lr"]
    @property
    def fp(self) -> int:     return self["fp"]
    @property
    def x0(self) -> int:     return self["x0"]
    @property
    def x1(self) -> int:     return self["x1"]
    @property
    def x2(self) -> int:     return self["x2"]
    @property
    def x3(self) -> int:     return self["x3"]

    def all(self) -> Dict[str, int]:
        return {k: int(v, 16) if isinstance(v, str) else v for k, v in self._data.items()}


class MemRegion:
    """Memory snapshot at a point in time."""

    def __init__(self, addr: int, data: List[int], known: List[bool]):
        self.addr  = addr
        self.data  = bytes(data)
        self.known = known

    def __getitem__(self, offset: int) -> Optional[int]:
        if not self.known[offset]:
            return None
        return self.data[offset]

    def hex(self) -> str:
        return self.data.hex()

    def hexdump(self, width: int = 16) -> str:
        lines = []
        for off in range(0, len(self.data), width):
            chunk = self.data[off:off + width]
            hex_part = " ".join(f"{b:02x}" if self.known[off + i] else ".."
                                for i, b in enumerate(chunk))
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  0x{self.addr + off:08X}  {hex_part:<{width*3}}  {asc_part}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        known_count = sum(1 for k in self.known if k)
        return f"<MemRegion addr=0x{self.addr:X} size={len(self.data)} known={known_count}>"


class TaintResult:
    """Result of a forward taint analysis pass."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    @property
    def tainted_regs(self) -> List[str]:
        return self._data.get("tainted_regs_final", [])

    @property
    def steps(self) -> List[Dict[str, Any]]:
        return self._data.get("steps", [])

    @property
    def instructions_processed(self) -> int:
        return self._data.get("statistics", {}).get("instructions_processed", 0)

    def __repr__(self) -> str:
        return (f"<TaintResult steps={len(self.steps)} "
                f"tainted_regs={self.tainted_regs}>")


class RpcClient:
    """
    Thin JSON-RPC 2.0 client over TCP.

    Used by Trace.start_rpc() but can also be used standalone::

        client = RpcClient("127.0.0.1", 10445)
        result = client.call("get_regs", {"inst_id": 100})
        print(result)
    """

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._seq  = 0
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

    def connect(self, timeout: float = 5.0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((self._host, self._port))
        self._sock = sock

    def close(self):
        if self._sock:
            try: self._sock.close()
            except: pass
            self._sock = None

    def call(self, method: str, params: Optional[Dict] = None) -> Any:
        if self._sock is None:
            self.connect()
        with self._lock:
            self._seq += 1
            req = {"jsonrpc": "2.0", "id": self._seq,
                   "method": method, "params": params or {}}
            payload = json.dumps(req) + "\n"
            self._sock.sendall(payload.encode())
            # Read response line
            resp_bytes = b""
            while b"\n" not in resp_bytes:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise TraceError("RPC connection closed")
                resp_bytes += chunk
            resp = json.loads(resp_bytes.split(b"\n")[0])
            if "error" in resp:
                raise TraceError(f"RPC error {resp['error']['code']}: {resp['error']['message']}")
            return resp.get("result")

    # ── Convenience wrappers ──────────────────────────────────────────────

    def ping(self) -> bool:
        return self.call("ping", {}).get("pong", False)

    def get_regs(self, inst_id: int) -> RegState:
        data = self.call("get_regs", {"inst_id": inst_id})
        return RegState(data.get("regs", {}))

    def get_reg(self, inst_id: int, reg_name: str) -> int:
        data = self.call("get_reg", {"inst_id": inst_id, "reg_name": reg_name})
        return int(data["value"], 16)

    def read_mem(self, addr: int, size: int, inst_id: int) -> MemRegion:
        data = self.call("read_mem", {"addr": hex(addr), "size": size, "inst_id": inst_id})
        return MemRegion(addr, data["data"], data["known"])

    def get_range(self, start: int, end: int) -> List[Dict[str, Any]]:
        data = self.call("get_range", {"start": start, "end": end})
        return data.get("rows", [])

    def get_xref(self, pc: int) -> List[int]:
        data = self.call("get_xref", {"pc": hex(pc)})
        return data.get("inst_ids", [])

    def get_stats(self) -> Dict[str, Any]:
        return self.call("get_stats", {})

    def get_taint(self) -> TaintResult:
        data = self.call("get_taint", {})
        return TaintResult(data)

    def get_cfg(self) -> str:
        data = self.call("get_cfg", {})
        return data.get("dot", "")

    def get_call_graph(self) -> Dict[str, Any]:
        return self.call("get_call_graph", {})

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


class Trace:
    """
    High-level interface to a tenet trace file.

    Uses the tenet binary in subprocess mode for complex passes,
    and the RPC interface for interactive queries.

    Parameters
    ----------
    path : str or Path
        Path to the .bin trace file.
    tenet_bin : str, optional
        Path to the tenet binary. If None, searches PATH and build directories.
    """

    def __init__(self, path, tenet_bin: Optional[str] = None):
        self._path = str(path)
        self._bin  = tenet_bin or _find_tenet_binary()
        if not self._bin:
            raise TraceError(
                "tenet binary not found. Set TENET_BIN env var or pass tenet_bin=.")
        self._rpc: Optional[RpcClient] = None
        self._rpc_proc = None
        self._stats_cache: Optional[Dict[str, Any]] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start_rpc(self, host: str = "127.0.0.1", port: int = 0) -> RpcClient:
        """
        Start a tenet process in RPC server mode and return a connected client.

        The tenet process runs in the background and listens on the requested
        TCP loopback endpoint. Port 0 selects an available local port.
        Call stop_rpc() or use the Trace as a context manager to clean up.
        """
        if self._rpc is not None:
            return self._rpc

        if not 0 <= port <= 65535:
            raise ValueError("RPC port must be in range 0..65535")
        if port == 0:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind((host, 0))
                port = probe.getsockname()[1]
            finally:
                probe.close()

        endpoint = f"{host}:{port}"
        cmd = [self._bin, "--rpc", endpoint, self._path]
        self._rpc_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        import time
        deadline = time.time() + 10.0
        client = RpcClient(host, port)
        while time.time() < deadline:
            if self._rpc_proc.poll() is not None:
                raise TraceError(
                    f"tenet RPC server exited early (rc={self._rpc_proc.returncode})")
            try:
                client.connect(timeout=0.2)
                self._rpc = client
                return client
            except OSError:
                client.close()
                time.sleep(0.05)

        self.stop_rpc()
        raise TraceError(f"timed out connecting to tenet RPC server at {endpoint}")

    def stop_rpc(self):
        """Stop the RPC server and disconnect the client."""
        if self._rpc:
            self._rpc.close()
            self._rpc = None
        if self._rpc_proc:
            self._rpc_proc.terminate()
            try: self._rpc_proc.wait(timeout=3)
            except: self._rpc_proc.kill()
            self._rpc_proc = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop_rpc()

    # ── Stats ─────────────────────────────────────────────────────────────

    @property
    def inst_count(self) -> int:
        return self._get_stats().get("inst_count", 0)

    @property
    def module_name(self) -> str:
        return self._get_stats().get("module_name", "")

    @property
    def module_base(self) -> int:
        v = self._get_stats().get("module_base", "0x0")
        return int(v, 16) if isinstance(v, str) else v

    @property
    def module_slide(self) -> int:
        v = self._get_stats().get("module_slide", "0x0")
        return int(v, 16) if isinstance(v, str) else v

    def _get_stats(self) -> Dict[str, Any]:
        if self._stats_cache is not None:
            return self._stats_cache
        if self._rpc:
            self._stats_cache = self._rpc.get_stats()
            return self._stats_cache
        # Fallback: run tenet --batch mode and parse output
        result = self._run(["--stats"])
        try:
            self._stats_cache = json.loads(result)
        except:
            self._stats_cache = {}
        return self._stats_cache

    # ── Register access ───────────────────────────────────────────────────

    def regs(self, inst_id: int) -> RegState:
        """Get register state before instruction `inst_id`."""
        if self._rpc:
            return self._rpc.get_regs(inst_id)
        # Fallback via batch mode
        data = json.loads(self._run(["--regs", str(inst_id)]))
        return RegState(data.get("regs", {}))

    def reg(self, inst_id: int, reg_name: str) -> int:
        """Get a single register value before instruction `inst_id`."""
        if self._rpc:
            return self._rpc.get_reg(inst_id, reg_name)
        state = self.regs(inst_id)
        return state[reg_name]

    # ── Memory access ─────────────────────────────────────────────────────

    def read_mem(self, addr: int, size: int, at: Optional[int] = None) -> MemRegion:
        """Read `size` bytes at `addr` as they were at time `at` (inst_id)."""
        inst_id = at if at is not None else self.inst_count
        if self._rpc:
            return self._rpc.read_mem(addr, size, inst_id)
        data = json.loads(self._run(["--read-mem",
                                     hex(addr), str(size), str(inst_id)]))
        return MemRegion(addr, data.get("data", []), data.get("known", []))

    # ── Instruction range ─────────────────────────────────────────────────

    def instructions(self, start: int = 0,
                      end: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return a list of instruction records for the given range."""
        if end is None:
            end = min(start + 100, self.inst_count)
        if self._rpc:
            return self._rpc.get_range(start, end)
        data = json.loads(self._run(["--range", str(start), str(end)]))
        return data.get("rows", [])

    # ── Pass execution ────────────────────────────────────────────────────

    def pass_taint(self, source_reg: int = 0,
                   source_inst_id: int = 0) -> TaintResult:
        """Run forward taint analysis from `source_reg` at `source_inst_id`."""
        if self._rpc:
            return self._rpc.get_taint()
        data = json.loads(self._run(["--taint", str(source_reg)]))
        return TaintResult(data)

    def pass_xref(self) -> "XrefProxy":
        """Run and return the XRef (PC-to-inst_id) index."""
        return XrefProxy(self)

    def pass_cfg(self) -> str:
        """Run and return the CFG as a Graphviz DOT string."""
        if self._rpc:
            return self._rpc.get_cfg()
        return self._run(["--export-cfg", "/dev/stdout"])

    def pass_call_graph(self) -> Dict[str, Any]:
        """Run and return the call graph as nodes+edges dict."""
        if self._rpc:
            return self._rpc.get_call_graph()
        data_str = self._run(["--call-graph", "/dev/stdout"])
        return json.loads(data_str)

    def pass_strings(self) -> List[Dict[str, Any]]:
        """Run and return the strings pass result."""
        raw = self._run(["--strings"])
        try:
            return json.loads(raw).get("strings", [])
        except:
            return []

    def pass_yara_mem_scan(self) -> List[Dict[str, Any]]:
        """Run and return YARA memory scan results."""
        raw = self._run(["--yara-mem-scan"])
        try:
            return json.loads(raw).get("matches", [])
        except:
            return []

    # ── Iteration ─────────────────────────────────────────────────────────

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        """Iterate over all instruction rows (fetches in chunks of 1000)."""
        chunk_size = 1000
        start = 0
        total = self.inst_count
        while start < total:
            end = min(start + chunk_size, total)
            rows = self.instructions(start, end)
            yield from rows
            start = end

    def __len__(self) -> int:
        return self.inst_count

    def __repr__(self) -> str:
        return (f"<Trace '{os.path.basename(self._path)}' "
                f"insts={self.inst_count} module='{self.module_name}'>")

    # ── Internal ─────────────────────────────────────────────────────────

    def _run(self, extra_args: List[str]) -> str:
        """Run tenet with the given arguments on this trace file."""
        cmd = [self._bin] + extra_args + [self._path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                raise TraceError(
                    f"tenet failed (rc={result.returncode}):\n{result.stderr[:2000]}")
            return result.stdout
        except subprocess.TimeoutExpired:
            raise TraceError("tenet timed out after 120s")


class XrefProxy:
    """Proxy object for the XRef pass result."""

    def __init__(self, trace: "Trace"):
        self._trace = trace
        self._cache: Dict[int, List[int]] = {}

    def inst_ids_at(self, pc: int) -> List[int]:
        """Return all inst_ids that executed at `pc`."""
        if pc not in self._cache:
            if self._trace._rpc:
                self._cache[pc] = self._trace._rpc.get_xref(pc)
            else:
                data = json.loads(self._trace._run(["--xref", hex(pc)]))
                self._cache[pc] = data.get("inst_ids", [])
        return self._cache[pc]

    def exec_count(self, pc: int) -> int:
        return len(self.inst_ids_at(pc))

    def __repr__(self) -> str:
        return "<XrefProxy>"
