# TenetWSService — High-Performance WebSocket Service for Web/Electron Frontends

## Overview

`TenetWSService` is a high-performance WebSocket server built on **uWebSockets** with **FlatBuffers** binary serialization. It exposes the full `TenetService` API to Web/Electron frontends, replacing MCP for human-UI communication while MCP remains the AI Agent interface.

**Design goals:**

- 60fps-capable hot-path data delivery (instruction rows, registers, memory)
- Server-push for async events (pass completion, navigation sync, bookmark changes)
- Zero-copy reads via FlatBuffers (no JSON parse/stringify overhead)
- Single `.fbs` schema shared between C++ server and TypeScript client

## Architecture

```
Web/Electron Frontend
        ↕  WebSocket Binary (FlatBuffers frames)
TenetWSService (uWS event loop thread)
        ↕  C++ direct call (in-process, ~ns)
TenetService
        ↕
Analysis / Core / IO layers
```

`TenetWSService` is a `TenetServiceObserver`. When pass completion, navigation, or bookmark events fire, it pushes `Evt*` messages to all connected clients via `uWS::Loop::defer()` (thread-safe posting to the uWS event loop).

## Dependencies

| Dependency | Version | Method | Notes |
|---|---|---|---|
| uWebSockets | latest | FetchContent (git) | Header-only; depends on uSockets (bundled) |
| FlatBuffers | 24.x | FetchContent (git) | Header-only runtime + `flatc` build tool |

Both are header-only at runtime. `flatc` is only needed at build time to compile `.fbs` schemas into C++ headers. uSockets ships inside uWebSockets. zlib is already available (via zstd dependency chain). OpenSSL/TLS is NOT required (localhost-only WebSocket, no `wss://`).

## Message Protocol

### Envelope

Every WebSocket binary frame contains a single FlatBuffers `Envelope`:

```fbs
namespace tenet.ws;

enum MessageType : uint16 {
    // ── Requests (client → server) ──────────────────────────
    FetchRowsReq = 1,
    GetRegsReq = 2,
    ReadMemoryReq = 3,
    NavigateReq = 10,
    NavBackReq = 11,
    NavForwardReq = 12,
    ToggleBookmarkReq = 13,
    GetBookmarksReq = 14,
    GetTraceInfoReq = 15,
    SearchForwardReq = 20,
    SearchClearReq = 21,
    GetSearchResultsReq = 22,
    RunPassReq = 30,
    RunDefaultPassesReq = 31,
    ClearAnalysisReq = 32,
    GetPassStateReq = 33,
    GetPassResultReq = 34,
    GetPassCatalogReq = 35,
    GetCallStackReq = 40,
    GetLastWriterReq = 41,
    GetWriteHistoryReq = 42,
    GetFunctionsReq = 43,

    // ── Responses (server → client) ─────────────────────────
    FetchRowsResp = 101,
    GetRegsResp = 102,
    ReadMemoryResp = 103,
    NavigateResp = 110,
    NavBackResp = 111,
    NavForwardResp = 112,
    ToggleBookmarkResp = 113,
    GetBookmarksResp = 114,
    GetTraceInfoResp = 115,
    SearchForwardResp = 120,
    SearchClearResp = 121,
    GetSearchResultsResp = 122,
    RunPassResp = 130,
    RunDefaultPassesResp = 131,
    ClearAnalysisResp = 132,
    GetPassStateResp = 133,
    GetPassResultResp = 134,
    GetPassCatalogResp = 135,
    GetCallStackResp = 140,
    GetLastWriterResp = 141,
    GetWriteHistoryResp = 142,
    GetFunctionsResp = 143,

    // ── Server push events (server → client, msg_id=0) ──────
    EvtNavigation = 200,
    EvtPassCompleted = 201,
    EvtPassProgress = 202,
    EvtBookmarkChanged = 203,

    // ── Error ───────────────────────────────────────────────
    ErrorResp = 255,
}

table Envelope {
    msg_id: uint32;          // Client-generated request ID; 0 for server push
    type: MessageType;
    payload: [ubyte];        // Nested FlatBuffers message (type-specific)
}

root_type Envelope;
```

### Request-Response Pairing

Client sends `Envelope(msg_id=N, type=FetchRowsReq, payload=...)`. Server replies `Envelope(msg_id=N, type=FetchRowsResp, payload=...)`. Client can pipeline multiple requests without waiting for responses. `msg_id=0` is reserved for server-initiated push events.

### Error Handling

On error, server sends `Envelope(msg_id=N, type=ErrorResp, payload=ErrorResponse{code, message})`.

```fbs
table ErrorResponse {
    code: uint32;           // 1=invalid_request, 2=pass_failed, 3=not_found, 4=internal
    message: string;
}
```

## Message Definitions

### Hot Path — 60fps Sensitive

#### FetchRows (批量拉取指令行)

```fbs
table FetchRowsRequest {
    start_id: uint64;
    count: uint32;           // max 1024
}

table InstructionRowMsg {
    inst_id: uint64;
    pc: uint64;
    static_pc: uint64;
    mnemonic: string;
    operands: string;
    nzcv: uint8;
    reg_diff_count: uint8;
    mem_access_count: uint8;
    has_bookmark: bool;
}

table FetchRowsResponse {
    rows: [InstructionRowMsg];
    total_inst: uint64;
    current_inst: uint64;    // piggyback cursor position for sync
}
```

#### GetRegs (寄存器状态)

```fbs
table GetRegsRequest {
    inst_id: uint64;
    when: uint8 = 0;        // 0=before, 1=after
    include_fpr: bool = false;
}

table GetRegsResponse {
    inst_id: uint64;
    gpr: [uint64];           // 34 values: x0-x28, fp, lr, sp, nzcv, pc
    fpr: [ubyte];            // 512 bytes raw (32 × 128-bit), empty if not requested
}
```

#### ReadMemory (内存读取)

```fbs
table ReadMemoryRequest {
    addr: uint64;
    size: uint32;            // max 65536
    inst_id: uint64;
}

table ReadMemoryResponse {
    addr: uint64;
    inst_id: uint64;
    data: [ubyte];           // raw bytes
    known: [ubyte];          // bitmask: bit i = byte i is known (packed, ceil(size/8) bytes)
}
```

### Navigation

```fbs
table NavigateRequest { inst_id: uint64; }
table NavigateResponse { inst_id: uint64; }  // actual position after clamping

table NavBackResponse { inst_id: uint64; ok: bool; }
table NavForwardResponse { inst_id: uint64; ok: bool; }

table ToggleBookmarkRequest { inst_id: uint64; }
table ToggleBookmarkResponse { bookmarks: [uint64]; }  // full list after toggle

table GetBookmarksResponse { bookmarks: [uint64]; }
```

### Trace Info

```fbs
table GetTraceInfoResponse {
    total_inst: uint64;
    current_inst: uint64;
    module_name: string;
    module_base: uint64;
    module_slide: uint64;
    trace_path: string;
    format_version: uint32;
    target_os: uint8;        // 0=Unknown, 1=iOS, 2=Android, 3=Linux
    has_fpr: bool;
    has_code: bool;
    num_gpr: uint32;
}
```

### Search

```fbs
table SearchForwardRequest {
    query: string;
    from_inst: uint64;
}

table SearchForwardResponse {
    results: [uint64];       // matching inst_ids (max 10000)
    count: uint32;
}

table GetSearchResultsResponse {
    results: [uint64];
    current: uint32;
    active: bool;
}
```

### Pass Management

```fbs
enum PassState : uint8 {
    NotRun = 0,
    Running = 1,
    Completed = 2,
    Failed = 3,
    Cancelled = 4,
}

table RunPassRequest {
    name: string;
    // Config fields for specific passes (optional):
    taint_regs: [uint8];     // register indices for taint source
    taint_inst_id: uint64;   // starting instruction for taint
}

table RunPassResponse {
    name: string;
    ok: bool;
    message: string;
}

table GetPassStateRequest { name: string; }
table GetPassStateResponse {
    name: string;
    state: PassState;
    progress: float;         // 0.0-1.0
    message: string;
}

table PassCatalogEntry {
    name: string;
    display_name: string;
    category: string;
    state: PassState;
}
table GetPassCatalogResponse {
    passes: [PassCatalogEntry];
}
```

### Pass Results

Pass results are serialized per-type. The client specifies which pass and optionally a sub-query (pagination, filtering).

```fbs
table GetPassResultRequest {
    name: string;            // pass name (e.g. "cfg", "taint", "function")
    format: string;          // "json" for structured, "dot" for graph export
    offset: uint32 = 0;     // pagination
    limit: uint32 = 1000;
}

table GetPassResultResponse {
    name: string;
    format: string;
    data: [ubyte];           // JSON or DOT bytes (pass results are complex/varied,
                             // JSON is acceptable here since this is not hot-path)
    has_more: bool;
    next_offset: uint32;
}
```

**Rationale for JSON in pass results:** Pass result types (CFG, Taint, CallGraph, etc.) are structurally diverse — ~25 different result types each with unique fields, nested arrays, maps, and bitmaps. Defining FlatBuffers tables for each would be enormous schema bloat with minimal performance benefit (pass results are fetched once after analysis completes, not per-frame). The existing MCP tools already have well-tested JSON serialization for every pass result type. We reuse that: `GetPassResultResponse::data` contains UTF-8 JSON bytes using the same format as MCP tools.

### Call Stack & Memory Queries

```fbs
table GetCallStackRequest { inst_id: uint64; }
table CallStackEntry {
    depth: uint32;
    call_inst_id: uint64;
    return_inst_id: uint64;
    call_site_pc: uint64;
    target_pc: uint64;
    function_name: string;
}
table GetCallStackResponse {
    entries: [CallStackEntry];
    current_function: string;
}

table GetLastWriterRequest {
    addr: uint64;
    size: uint32;
    before_inst: uint64;
}
table GetLastWriterResponse {
    writer_inst_id: uint64;  // 0 if no writer found
}

table GetWriteHistoryRequest {
    addr: uint64;
    size: uint32;
    offset: uint32 = 0;
    limit: uint32 = 100;
}
table GetWriteHistoryResponse {
    writers: [uint64];       // inst_ids that wrote to this address
    has_more: bool;
    next_offset: uint32;
}

table FunctionEntry {
    entry_pc: uint64;
    name: string;
    total_calls: uint32;
    total_instructions: uint64;
}
table GetFunctionsResponse {
    functions: [FunctionEntry];
}
```

### Server Push Events

```fbs
table EvtNavigationMsg { inst_id: uint64; }

table EvtPassCompletedMsg {
    name: string;
    ok: bool;
    summary: string;
}

table EvtPassProgressMsg {
    name: string;
    progress: float;         // 0.0-1.0
    message: string;
}

table EvtBookmarkChangedMsg { bookmarks: [uint64]; }
```

## Threading Model

```
┌─────────────────────────────────────┐
│ uWS Event Loop Thread              │
│                                     │
│  on_message(ws, data) {             │
│    decode Envelope                  │
│    if (hot_path) {                  │
│      // sync: ~1-100µs             │
│      result = service.fetch_row()   │
│      ws.send(encode(result))        │
│    } else if (heavy) {              │
│      // async: post to worker       │
│      worker_pool.submit([=] {       │
│        result = service.run_pass()  │
│        loop->defer([=] {            │
│          ws.send(encode(result))    │
│        });                          │
│      });                            │
│    }                                │
│  }                                  │
│                                     │
│  // Observer callbacks via defer()  │
│  on_pass_completed(name) {          │
│    loop->defer([=] {                │
│      broadcast(EvtPassCompleted)    │
│    });                              │
│  }                                  │
└─────────────────────────────────────┘
         │
         ├── Worker Thread 1 (RunPass, Search, ...)
         ├── Worker Thread 2
         └── Worker Thread N
```

**Hot-path classification** (sync, in event loop): `FetchRows`, `GetRegs`, `ReadMemory`, `Navigate`, `NavBack`, `NavForward`, `ToggleBookmark`, `GetBookmarks`, `GetTraceInfo`, `GetCallStack`, `GetLastWriter`.

**Heavy-path classification** (async, worker thread): `RunPass`, `RunDefaultPasses`, `SearchForward`, `GetPassResult` (when format="json" and result is large), `GetWriteHistory`, `GetFunctions`.

## File Structure

```
tools/tenet/src/ws/
├── schema/
│   ├── tenet_ws.fbs           # All FlatBuffers schema definitions
│   └── CMakeLists.txt         # flatc code generation rules
├── tenet_ws_service.h         # TenetWSService class declaration
├── tenet_ws_service.cpp        # Implementation
└── ws_handlers.cpp            # Message handler dispatch table
```

## CMake Integration

```cmake
# In tools/tenet/CMakeLists.txt:

# ── uWebSockets ──
FetchContent_Declare(uwebsockets
    GIT_REPOSITORY https://github.com/uNetworking/uWebSockets.git
    GIT_TAG        v20.73.0)
FetchContent_MakeAvailable(uwebsockets)

# ── FlatBuffers ──
FetchContent_Declare(flatbuffers
    GIT_REPOSITORY https://github.com/google/flatbuffers.git
    GIT_TAG        v24.3.25
    CMAKE_ARGS -DFLATBUFFERS_BUILD_TESTS=OFF)
FetchContent_MakeAvailable(flatbuffers)

# ── Schema compilation ──
# flatc generates tenet_ws_generated.h from tenet_ws.fbs
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tenet_ws_generated.h
    COMMAND flatc --cpp -o ${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/ws/schema/tenet_ws.fbs
    DEPENDS src/ws/schema/tenet_ws.fbs flatc)

# Add to tenet_lib sources
target_sources(tenet_lib PRIVATE
    src/ws/tenet_ws_service.cpp
    src/ws/ws_handlers.cpp)
```

## TenetWSService API

```cpp
class TenetWSService : public TenetServiceObserver {
public:
    explicit TenetWSService(TenetService& service);
    ~TenetWSService();

    /// Start the WebSocket server on the given port.
    /// Spawns the uWS event loop thread.  Returns actual port (useful when port=0).
    uint16_t start(uint16_t port = 9090);

    /// Stop the server and join the event loop thread.
    void stop();

    /// True if the server is listening.
    bool running() const;

    /// Actual listening port.
    uint16_t port() const;

    // ── TenetServiceObserver ────────────────────────────────────
    void on_pass_completed(std::string_view name) override;
    void on_navigation(uint64_t inst_id) override;
    void on_bookmark_changed() override;

private:
    void event_loop_main(uint16_t port);
    void handle_message(uWS::WebSocket<false>* ws,
                        std::string_view data);
    void broadcast(const uint8_t* buf, size_t len);

    TenetService& service_;
    std::thread loop_thread_;
    struct uWS::Loop* loop_ = nullptr;
    std::atomic<bool> running_{false};
    std::atomic<uint16_t> port_{0};

    // Connected clients (accessed only from event loop thread)
    std::vector<uWS::WebSocket<false>*> clients_;
};
```

## Startup Integration

In `main.cpp`, `TenetWSService` is started alongside `TenetMcpService` when requested:

```cpp
// --ws-port flag (or auto-start from GUI settings)
if (opts.ws_port > 0) {
    TenetWSService ws(service);
    auto actual_port = ws.start(opts.ws_port);
    fmt::print(stderr, "[ws] listening on ws://127.0.0.1:{}\n", actual_port);
}
```

GUI can also auto-start it (like it does for MCP):
```cpp
if (service_ && !ws_service_) {
    ws_service_ = std::make_unique<TenetWSService>(*service_);
    ws_service_->start(9090);
}
```

## Performance Characteristics

| Operation | Latency (expected) | Bandwidth |
|---|---|---|
| FetchRows (200 rows) | ~50-200µs serialize + ~50µs network | ~20KB/frame |
| GetRegs | ~5µs serialize | ~300 bytes |
| ReadMemory (4KB) | ~10µs | ~4.1KB |
| Navigate | ~1µs | ~20 bytes |
| Server push event | ~1µs via defer() | ~50 bytes |

Compared to MCP JSON-RPC: FetchRows JSON is ~150KB for 200 rows (hex strings, field names, nesting). FlatBuffers binary is ~20KB — **~7x smaller**, with zero parse overhead on the client side (direct memory access via generated accessors).

## Future Considerations

- **Compression**: uWebSockets supports per-message deflate (`PERMESSAGE_DEFLATE`). Can be enabled for pass results (large JSON payloads) while keeping hot-path frames uncompressed.
- **Multi-trace**: If tenet supports opening multiple traces simultaneously, each trace gets its own `TenetWSService` instance on a different port (matching the MCP hub/worker pattern).
- **TypeScript client SDK**: `flatc --ts schema/tenet_ws.fbs` generates TypeScript bindings. A thin `TenetClient` class wraps the WebSocket + FlatBuffers encode/decode + request-response promise matching.
