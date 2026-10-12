#!/usr/bin/env python3
"""Exercise the bundled desktop backend with a real generated trace."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

import flatbuffers
import websocket

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "slowmo/build"
SUFFIX = ".exe" if sys.platform == "win32" else ""
FLATC_ROOT = ROOT / "slowmo/_deps/flatbuffers-build"
flatc = next(FLATC_ROOT.rglob("flatc" + SUFFIX))
generated = BUILD / "generated/python"
subprocess.run([str(flatc), "--python", "-o", str(generated),
                str(ROOT / "slowmo/src/ws/schema/tenet_ws.fbs")], check=True)
sys.path.insert(0, str(generated))
from tenet.ws import Envelope, GetTraceInfoResponse, MessageType


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


sidecar = next(p for p in (ROOT / "slowmo/web/src-tauri/binaries").glob("tenet-*")
               if p.is_file() and (not SUFFIX or p.suffix == SUFFIX))
generator = BUILD / "tests" / ("gen_test_traces" + SUFFIX)
with tempfile.TemporaryDirectory(prefix="ws-release-", dir=BUILD) as folder:
    folder = Path(folder)
    subprocess.run([str(generator), "--case", "ut_minimal", "--outdir", str(folder)], check=True)
    trace = folder / "ut_minimal.trace"
    port, http_port = free_port(), free_port()
    while http_port == port:
        http_port = free_port()
    connection = None
    with (folder / "backend.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen([str(sidecar), "--ws-port", str(port), str(trace),
                                    "--mcp-http", f"127.0.0.1:{http_port}"],
                                   stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 60
            while connection is None:
                if process.poll() is not None:
                    raise RuntimeError(f"Backend exited: {process.returncode}")
                try:
                    connection = websocket.create_connection(f"ws://127.0.0.1:{port}/", timeout=2)
                except (OSError, websocket.WebSocketException):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Desktop WebSocket did not start")
                    time.sleep(0.1)

            builder = flatbuffers.Builder(64)
            Envelope.Start(builder)
            Envelope.AddMsgId(builder, 42)
            Envelope.AddType(builder, MessageType.MessageType.GetTraceInfoReq)
            builder.Finish(Envelope.End(builder))
            connection.send_binary(bytes(builder.Output()))
            connection.settimeout(10)
            while True:
                raw = connection.recv()
                response = Envelope.Envelope.GetRootAs(raw, 0)
                if response.MsgId() != 42:
                    continue
                if response.Type() != MessageType.MessageType.GetTraceInfoResp:
                    raise RuntimeError(f"Unexpected response type: {response.Type()}")
                payload = bytes(response.Payload(i) for i in range(response.PayloadLength()))
                info = GetTraceInfoResponse.GetTraceInfoResponse.GetRootAs(payload, 0)
                if info.TotalInst() != 1 or info.ModuleName() != b"ut_minimal":
                    raise RuntimeError("Desktop backend did not return the real trace data")
                print("Real trace WebSocket OK: module=ut_minimal, instructions=1")
                break
        finally:
            if connection is not None:
                connection.close()
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.flush()
            print((folder / "backend.log").read_text(encoding="utf-8", errors="replace"))
