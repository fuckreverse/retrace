# TenetWSService Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a high-performance WebSocket service (`TenetWSService`) using uWebSockets + FlatBuffers that exposes the full TenetService API to Web/Electron frontends.

**Architecture:** `TenetWSService` runs a uWS event loop on a dedicated thread, serializes hot-path data (instruction rows, registers, memory) via FlatBuffers zero-copy binary frames, and implements `TenetServiceObserver` to push async events (pass completion, navigation sync) to all connected clients. Heavy operations (RunPass, Search) are dispatched to worker threads and responses are posted back via `uWS::Loop::defer()`.

**Tech Stack:** C++20, uWebSockets v20.73.0, FlatBuffers v25.2.10, CMake/Ninja

## Global Constraints

- Build targets: `tenet_lib` (backend + WS service), `tenet_gui_lib` (GUI), `tenet` (executable)
- **Never** create new `build-xxx` directories or delete `_deps/`
- All new WS files under `src/ws/` directory
- FlatBuffers schema files under `src/ws/schema/`
- `FETCHCONTENT_BASE_DIR` remains `tools/tenet/_deps/`
- uWebSockets is plain `ws://` only — no TLS/OpenSSL
- Existing tests (`ctest`) must stay green after every task
- CMake option `TENET_ENABLE_WS=ON/OFF` controls inclusion (default ON)

---

### Task 1: Add uWebSockets + FlatBuffers Dependencies to CMake

**Files:**
- Modify: `tools/tenet/CMakeLists.txt` (add FetchContent blocks + library targets)

**Interfaces:**
- Produces: CMake targets `uwebsockets` (INTERFACE), `usockets` (STATIC), `flatbuffers::flatbuffers`, and `flatc` (build tool)

uWebSockets has no official CMake. We manually create targets for uSockets (compiled C library) and uWebSockets (header-only C++ wrapper). FlatBuffers has proper CMake support via FetchContent.

- [ ] **Step 1: Add FlatBuffers FetchContent**

In `tools/tenet/CMakeLists.txt`, after the `nlohmann_json` block (around line 292), add:

```cmake
# ── FlatBuffers (binary serialization for WS service) ────────────────────────
if(TENET_ENABLE_WS)
    FetchContent_Declare(
        flatbuffers
        GIT_REPOSITORY https://github.com/google/flatbuffers.git
        GIT_TAG        v25.2.10
        GIT_SHALLOW    TRUE
    )
    set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_INSTALL OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_BUILD_SHAREDLIB OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_BUILD_FLATC ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(flatbuffers)
endif()
```

- [ ] **Step 2: Add uWebSockets + uSockets FetchContent**

After FlatBuffers, add:

```cmake
# ── uWebSockets + uSockets (WebSocket transport for WS service) ──────────────
if(TENET_ENABLE_WS)
    FetchContent_Declare(
        uwebsockets
        GIT_REPOSITORY https://github.com/uNetworking/uWebSockets.git
        GIT_TAG        v20.73.0
        GIT_SHALLOW    TRUE
    )
    FetchContent_Declare(
        usockets
        GIT_REPOSITORY https://github.com/uNetworking/uSockets.git
        GIT_TAG        v0.8.9
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(uwebsockets usockets)

    # uSockets — build as a static C library (no SSL, no libuv)
    file(GLOB USOCKETS_SRCS
        ${usockets_SOURCE_DIR}/src/*.c
        ${usockets_SOURCE_DIR}/src/eventing/epoll_kqueue.c
        ${usockets_SOURCE_DIR}/src/crypto/openssl.c
    )
    # Remove SSL source if present (we don't need TLS)
    list(FILTER USOCKETS_SRCS EXCLUDE REGEX ".*ssl\\.c$")

    add_library(usockets STATIC ${USOCKETS_SRCS})
    target_include_directories(usockets PUBLIC ${usockets_SOURCE_DIR}/src)
    target_compile_definitions(usockets PUBLIC LIBUS_NO_SSL=1)
    # Link zlib for permessage-deflate (already available via zstd dep chain)
    find_package(ZLIB REQUIRED)
    target_link_libraries(usockets PUBLIC ZLIB::ZLIB)

    # uWebSockets — header-only C++ wrapper
    add_library(uwebsockets INTERFACE)
    target_include_directories(uwebsockets INTERFACE ${uwebsockets_SOURCE_DIR}/src)
    target_link_libraries(uwebsockets INTERFACE usockets)
endif()
```

- [ ] **Step 3: Add `TENET_ENABLE_WS` option**

Near the top of CMakeLists.txt where other options are declared (around the `option(TENET_ENABLE_TRITON ...)` block), add:

```cmake
option(TENET_ENABLE_WS "Build WebSocket service (uWebSockets + FlatBuffers)" ON)
```

- [ ] **Step 4: Build to verify dependencies resolve**

```bash
cd tools/tenet/build
cmake .. && ninja -j$(nproc)
```

This will trigger FetchContent to clone uwebsockets, usockets, and flatbuffers. On first run this takes network time. Expected: compiles clean. uSockets may need minor source file adjustments — check the actual file layout in `_deps/usockets-src/src/` and adjust the `file(GLOB)` if needed.

- [ ] **Step 5: Verify flatc is built**

```bash
ls tools/tenet/build/_deps/flatbuffers-build/flatc
# or
find tools/tenet/build -name flatc -type f
```

Expected: `flatc` binary exists.

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/CMakeLists.txt
git commit -m "build: add uWebSockets + FlatBuffers dependencies for WS service

FetchContent integration for uWebSockets v20.73.0 (header-only +
uSockets static lib, no TLS) and FlatBuffers v25.2.10 (runtime +
flatc compiler).  Guarded by TENET_ENABLE_WS option (default ON)."
```

---

### Task 2: Create FlatBuffers Schema and Code Generation

**Files:**
- Create: `tools/tenet/src/ws/schema/tenet_ws.fbs`
- Modify: `tools/tenet/CMakeLists.txt` (add flatc custom command)

**Interfaces:**
- Consumes: `flatc` and `flatbuffers::flatbuffers` from Task 1
- Produces: `tenet_ws_generated.h` (auto-generated FlatBuffers C++ header)

- [ ] **Step 1: Create the FlatBuffers schema file**

Create `tools/tenet/src/ws/schema/tenet_ws.fbs` with the full protocol definition from the spec. This is a large file — it defines the `Envelope`, all `MessageType` enums, and all request/response tables.

```fbs
// tools/tenet/src/ws/schema/tenet_ws.fbs
//
// FlatBuffers schema for TenetWSService binary WebSocket protocol.
// Compiled by flatc into tenet_ws_generated.h (C++) and tenet_ws_generated.ts (TypeScript).

namespace tenet.ws;

// ─── Message Type Enum ──────────────────────────────────────────────────────

enum MessageType : uint16 {
    // Requests (client → server)
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

    // Responses (server → client)
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

    // Server push (server → client, msg_id=0)
    EvtNavigation = 200,
    EvtPassCompleted = 201,
    EvtPassProgress = 202,
    EvtBookmarkChanged = 203,

    // Error
    ErrorResp = 255,
}

enum PassState : uint8 {
    NotRun = 0,
    Running = 1,
    Completed = 2,
    Failed = 3,
    Cancelled = 4,
}

// ─── Envelope ───────────────────────────────────────────────────────────────

table Envelope {
    msg_id: uint32;
    type: MessageType;
    payload: [ubyte];            // Nested FlatBuffers message (type-specific, manually parsed)
}

root_type Envelope;

// ─── Hot Path ───────────────────────────────────────────────────────────────

table FetchRowsRequest {
    start_id: uint64;
    count: uint32;
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
    current_inst: uint64;
}

table GetRegsRequest {
    inst_id: uint64;
    when: uint8 = 0;
    include_fpr: bool = false;
}

table GetRegsResponse {
    inst_id: uint64;
    gpr: [uint64];
    fpr: [ubyte];
}

table ReadMemoryRequest {
    addr: uint64;
    size: uint32;
    inst_id: uint64;
}

table ReadMemoryResponse {
    addr: uint64;
    inst_id: uint64;
    data: [ubyte];
    known: [ubyte];
}

// ─── Navigation ─────────────────────────────────────────────────────────────

table NavigateRequest { inst_id: uint64; }
table NavigateResponse { inst_id: uint64; }

table NavBackResponse { inst_id: uint64; ok: bool; }
table NavForwardResponse { inst_id: uint64; ok: bool; }

table ToggleBookmarkRequest { inst_id: uint64; }
table ToggleBookmarkResponse { bookmarks: [uint64]; }

table GetBookmarksResponse { bookmarks: [uint64]; }

// ─── Trace Info ─────────────────────────────────────────────────────────────

table GetTraceInfoResponse {
    total_inst: uint64;
    current_inst: uint64;
    module_name: string;
    module_base: uint64;
    module_slide: uint64;
    trace_path: string;
    format_version: uint32;
    target_os: uint8;
    has_fpr: bool;
    has_code: bool;
    num_gpr: uint32;
}

// ─── Search ─────────────────────────────────────────────────────────────────

table SearchForwardRequest {
    query: string;
    from_inst: uint64;
}

table SearchForwardResponse {
    results: [uint64];
    count: uint32;
}

table GetSearchResultsResponse {
    results: [uint64];
    current: uint32;
    active: bool;
}

// ─── Pass Management ────────────────────────────────────────────────────────

table RunPassRequest {
    name: string;
    taint_regs: [uint8];
    taint_inst_id: uint64;
}

table RunPassResponse {
    name: string;
    ok: bool;
    message: string;
}

table RunDefaultPassesResponse {
    ok: bool;
    message: string;
}

table ClearAnalysisResponse { ok: bool; }

table GetPassStateRequest { name: string; }
table GetPassStateResponse {
    name: string;
    state: PassState;
    progress: float;
    message: string;
}

table GetPassResultRequest {
    name: string;
    format: string;
    offset: uint32 = 0;
    limit: uint32 = 1000;
}

table GetPassResultResponse {
    name: string;
    format: string;
    data: [ubyte];
    has_more: bool;
    next_offset: uint32;
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

// ─── Call Stack & Memory ────────────────────────────────────────────────────

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
    writer_inst_id: uint64;
}

table GetWriteHistoryRequest {
    addr: uint64;
    size: uint32;
    offset: uint32 = 0;
    limit: uint32 = 100;
}

table GetWriteHistoryResponse {
    writers: [uint64];
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

// ─── Server Push Events ─────────────────────────────────────────────────────

table EvtNavigationMsg { inst_id: uint64; }

table EvtPassCompletedMsg {
    name: string;
    ok: bool;
    summary: string;
}

table EvtPassProgressMsg {
    name: string;
    progress: float;
    message: string;
}

table EvtBookmarkChangedMsg { bookmarks: [uint64]; }

// ─── Error ──────────────────────────────────────────────────────────────────

table ErrorResponse {
    code: uint32;
    message: string;
}
```

- [ ] **Step 2: Add flatc code generation to CMakeLists.txt**

After the FlatBuffers FetchContent block, add:

```cmake
if(TENET_ENABLE_WS)
    # Generate C++ headers from FlatBuffers schema
    set(FBS_SCHEMA ${CMAKE_CURRENT_SOURCE_DIR}/src/ws/schema/tenet_ws.fbs)
    set(FBS_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
    file(MAKE_DIRECTORY ${FBS_GENERATED_DIR})

    add_custom_command(
        OUTPUT ${FBS_GENERATED_DIR}/tenet_ws_generated.h
        COMMAND flatc --cpp --gen-object-api
                -o ${FBS_GENERATED_DIR}
                ${FBS_SCHEMA}
        DEPENDS ${FBS_SCHEMA} flatc
        COMMENT "Compiling FlatBuffers schema: tenet_ws.fbs"
    )

    add_custom_target(tenet_ws_schema DEPENDS ${FBS_GENERATED_DIR}/tenet_ws_generated.h)
endif()
```

- [ ] **Step 3: Build to verify schema compiles**

```bash
cd tools/tenet/build && cmake .. && ninja tenet_ws_schema
```

Expected: `tenet_ws_generated.h` appears in `build/generated/`.

- [ ] **Step 4: Verify the generated header is valid C++**

Create a quick smoke test — a small `.cpp` that `#include`s the generated header and instantiates a `FetchRowsRequestT`:

```cpp
// Temporary test — delete after verification
#include "tenet_ws_generated.h"
int main() {
    tenet::ws::FetchRowsRequestT req;
    req.start_id = 42;
    req.count = 100;
    return 0;
}
```

Compile with: `c++ -std=c++17 -I<flatbuffers_include> -I<generated_dir> test_fbs.cpp -o /dev/null`

- [ ] **Step 5: Commit**

```bash
git add tools/tenet/src/ws/schema/tenet_ws.fbs tools/tenet/CMakeLists.txt
git commit -m "build: add FlatBuffers schema and code generation for WS protocol

tenet_ws.fbs defines the complete binary WS protocol: Envelope,
40+ message types (hot-path rows/regs/memory, navigation, pass
management, search, server push events).  flatc generates
tenet_ws_generated.h at build time."
```

---

### Task 3: Implement TenetWSService Core (Start/Stop + Message Dispatch)

**Files:**
- Create: `tools/tenet/src/ws/tenet_ws_service.h`
- Create: `tools/tenet/src/ws/tenet_ws_service.cpp`
- Modify: `tools/tenet/CMakeLists.txt` (add to `tenet_lib` sources + link deps)

**Interfaces:**
- Consumes: `TenetService` (from `src/service/tenet_service.h`), `uwebsockets` and `flatbuffers` targets from Task 1, `tenet_ws_generated.h` from Task 2
- Produces: `TenetWSService` class with `start(port)`, `stop()`, message dispatch skeleton, observer push

This task creates the server skeleton: uWS event loop lifecycle, WebSocket open/close/message callbacks, and a dispatch switch that routes `Envelope.type` to handler functions. The actual handler implementations come in Tasks 4-6.

- [ ] **Step 1: Create `src/ws/tenet_ws_service.h`**

```cpp
// tools/tenet/src/ws/tenet_ws_service.h
#pragma once

#include "service/tenet_service.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// Forward declarations (avoid including uWS in the header)
struct us_listen_socket_t;

namespace tenet {

/// High-performance WebSocket service using uWebSockets + FlatBuffers.
/// Exposes the full TenetService API over binary WebSocket frames.
class TenetWSService : public TenetServiceObserver {
public:
    explicit TenetWSService(TenetService& service);
    ~TenetWSService() override;

    TenetWSService(const TenetWSService&) = delete;
    TenetWSService& operator=(const TenetWSService&) = delete;

    /// Start the WebSocket server.  Spawns the uWS event loop thread.
    /// Returns the actual listening port (useful when port=0 for OS-assigned).
    uint16_t start(uint16_t port = 9090);

    /// Stop the server and join the event loop thread.
    void stop();

    bool running() const { return running_.load(); }
    uint16_t port() const { return port_.load(); }

    // ── TenetServiceObserver ────────────────────────────────────
    void on_pass_completed(std::string_view name) override;
    void on_navigation(uint64_t inst_id) override;
    void on_bookmark_changed() override;

private:
    void event_loop_main(uint16_t port);
    void handle_message(void* ws, const uint8_t* data, size_t len);
    void broadcast(const uint8_t* buf, size_t len);
    void send_error(void* ws, uint32_t msg_id, uint32_t code,
                    const std::string& message);

    // ── Handler methods (implemented in ws_handlers.cpp) ────────
    void handle_fetch_rows(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_regs(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_read_memory(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_navigate(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_nav_back(void* ws, uint32_t msg_id);
    void handle_nav_forward(void* ws, uint32_t msg_id);
    void handle_toggle_bookmark(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_bookmarks(void* ws, uint32_t msg_id);
    void handle_get_trace_info(void* ws, uint32_t msg_id);
    void handle_search_forward(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_search_clear(void* ws, uint32_t msg_id);
    void handle_get_search_results(void* ws, uint32_t msg_id);
    void handle_run_pass(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_run_default_passes(void* ws, uint32_t msg_id);
    void handle_clear_analysis(void* ws, uint32_t msg_id);
    void handle_get_pass_state(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_pass_result(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_pass_catalog(void* ws, uint32_t msg_id);
    void handle_get_call_stack(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_last_writer(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_write_history(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_functions(void* ws, uint32_t msg_id);

    TenetService& service_;
    std::thread loop_thread_;
    std::atomic<bool> running_{false};
    std::atomic<uint16_t> port_{0};

    // uWS internals (opaque here; cast in .cpp)
    void* loop_ = nullptr;           // uWS::Loop*
    us_listen_socket_t* listen_socket_ = nullptr;

    // Connected clients — accessed ONLY from the event loop thread.
    std::vector<void*> clients_;     // uWS::WebSocket<false>* pointers
};

}  // namespace tenet
```

- [ ] **Step 2: Create `src/ws/tenet_ws_service.cpp` with lifecycle + dispatch**

```cpp
// tools/tenet/src/ws/tenet_ws_service.cpp
#include "ws/tenet_ws_service.h"
#include "common/logger.h"

// uWebSockets includes (only in .cpp, not in header)
#include <uWebSockets/App.h>

// FlatBuffers generated header
#include "tenet_ws_generated.h"

#include <fmt/format.h>

namespace tenet {

using namespace tenet::ws;  // FlatBuffers namespace

// ─── Construction / Destruction ─────────────────────────────────────────────

TenetWSService::TenetWSService(TenetService& service)
    : service_(service) {
    service_.add_observer(this);
}

TenetWSService::~TenetWSService() {
    stop();
    service_.remove_observer(this);
}

// ─── Start / Stop ───────────────────────────────────────────────────────────

uint16_t TenetWSService::start(uint16_t port) {
    if (running_.load()) return port_.load();

    std::promise<uint16_t> port_promise;
    auto port_future = port_promise.get_future();

    loop_thread_ = std::thread([this, port, p = std::move(port_promise)]() mutable {
        event_loop_main(port);
        // If event_loop_main exits without setting the promise (error),
        // set it to 0 to unblock the caller.
        try { p.set_value(0); } catch (...) {}
    });

    // Wait for the actual port (or 0 on failure).
    // Note: we need a different mechanism — use an atomic + cv instead.
    // For now, spin briefly.
    while (!running_.load() && loop_thread_.joinable()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return port_.load();
}

void TenetWSService::stop() {
    if (!running_.load()) return;
    running_.store(false);

    // Close the listen socket from the event loop thread
    if (loop_) {
        auto* loop = static_cast<uWS::Loop*>(loop_);
        loop->defer([this]() {
            if (listen_socket_) {
                us_listen_socket_close(0, listen_socket_);
                listen_socket_ = nullptr;
            }
            // Close all client connections
            // (uWS will clean up once all sockets are closed)
        });
    }

    if (loop_thread_.joinable()) {
        loop_thread_.join();
    }
    loop_ = nullptr;
}

// ─── Event Loop ─────────────────────────────────────────────────────────────

void TenetWSService::event_loop_main(uint16_t port) {
    uWS::App app;

    app.ws<void*>("/*", {
        .compression = uWS::DISABLED,
        .maxPayloadLength = 16 * 1024 * 1024,  // 16 MB
        .maxBackpressure = 64 * 1024 * 1024,    // 64 MB

        .open = [this](auto* ws) {
            clients_.push_back(ws);
            LOG_INFO_M(log::Module::Mcp, "[ws] client connected (total: {})",
                       clients_.size());
        },

        .message = [this](auto* ws, std::string_view data, uWS::OpCode op) {
            if (op != uWS::BINARY) return;  // ignore text frames
            handle_message(ws,
                           reinterpret_cast<const uint8_t*>(data.data()),
                           data.size());
        },

        .close = [this](auto* ws, int /*code*/, std::string_view /*msg*/) {
            clients_.erase(
                std::remove(clients_.begin(), clients_.end(), ws),
                clients_.end());
            LOG_INFO_M(log::Module::Mcp, "[ws] client disconnected (total: {})",
                       clients_.size());
        },
    });

    app.listen(port, [this, port](us_listen_socket_t* socket) {
        if (socket) {
            listen_socket_ = socket;
            port_.store(us_socket_local_port(0,
                reinterpret_cast<us_socket_t*>(socket)));
            running_.store(true);
            LOG_INFO_M(log::Module::Mcp, "[ws] listening on ws://127.0.0.1:{}",
                       port_.load());
        } else {
            LOG_INFO_M(log::Module::Mcp, "[ws] failed to listen on port {}", port);
        }
    });

    loop_ = uWS::Loop::get();
    app.run();  // blocks until all sockets closed
    running_.store(false);
}

// ─── Message Dispatch ───────────────────────────────────────────────────────

void TenetWSService::handle_message(void* ws, const uint8_t* data, size_t len) {
    auto* env = flatbuffers::GetRoot<Envelope>(data);
    if (!env) {
        send_error(ws, 0, 1, "invalid envelope");
        return;
    }

    auto msg_id = env->msg_id();
    auto type = env->type();
    auto* payload = env->payload();
    const uint8_t* payload_data = payload ? payload->data() : nullptr;
    size_t payload_len = payload ? payload->size() : 0;

    switch (type) {
    // Hot path
    case MessageType_FetchRowsReq:
        handle_fetch_rows(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetRegsReq:
        handle_get_regs(ws, msg_id, payload_data, payload_len); break;
    case MessageType_ReadMemoryReq:
        handle_read_memory(ws, msg_id, payload_data, payload_len); break;

    // Navigation
    case MessageType_NavigateReq:
        handle_navigate(ws, msg_id, payload_data, payload_len); break;
    case MessageType_NavBackReq:
        handle_nav_back(ws, msg_id); break;
    case MessageType_NavForwardReq:
        handle_nav_forward(ws, msg_id); break;
    case MessageType_ToggleBookmarkReq:
        handle_toggle_bookmark(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetBookmarksReq:
        handle_get_bookmarks(ws, msg_id); break;
    case MessageType_GetTraceInfoReq:
        handle_get_trace_info(ws, msg_id); break;

    // Search
    case MessageType_SearchForwardReq:
        handle_search_forward(ws, msg_id, payload_data, payload_len); break;
    case MessageType_SearchClearReq:
        handle_search_clear(ws, msg_id); break;
    case MessageType_GetSearchResultsReq:
        handle_get_search_results(ws, msg_id); break;

    // Pass management
    case MessageType_RunPassReq:
        handle_run_pass(ws, msg_id, payload_data, payload_len); break;
    case MessageType_RunDefaultPassesReq:
        handle_run_default_passes(ws, msg_id); break;
    case MessageType_ClearAnalysisReq:
        handle_clear_analysis(ws, msg_id); break;
    case MessageType_GetPassStateReq:
        handle_get_pass_state(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetPassResultReq:
        handle_get_pass_result(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetPassCatalogReq:
        handle_get_pass_catalog(ws, msg_id); break;

    // Data queries
    case MessageType_GetCallStackReq:
        handle_get_call_stack(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetLastWriterReq:
        handle_get_last_writer(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetWriteHistoryReq:
        handle_get_write_history(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetFunctionsReq:
        handle_get_functions(ws, msg_id); break;

    default:
        send_error(ws, msg_id, 1,
                   fmt::format("unknown message type: {}", static_cast<int>(type)));
        break;
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

void TenetWSService::broadcast(const uint8_t* buf, size_t len) {
    auto sv = std::string_view(reinterpret_cast<const char*>(buf), len);
    for (auto* client : clients_) {
        static_cast<uWS::WebSocket<false, true, void*>*>(client)->send(
            sv, uWS::BINARY);
    }
}

void TenetWSService::send_error(void* ws, uint32_t msg_id, uint32_t code,
                                 const std::string& message) {
    flatbuffers::FlatBufferBuilder fbb(256);
    auto err = CreateErrorResponse(fbb, code, fbb.CreateString(message));
    fbb.Finish(err);

    flatbuffers::FlatBufferBuilder env_fbb(256 + fbb.GetSize());
    auto payload_vec = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
    auto env = CreateEnvelope(env_fbb, msg_id, MessageType_ErrorResp, payload_vec);
    env_fbb.Finish(env);

    auto sv = std::string_view(
        reinterpret_cast<const char*>(env_fbb.GetBufferPointer()),
        env_fbb.GetSize());
    static_cast<uWS::WebSocket<false, true, void*>*>(ws)->send(sv, uWS::BINARY);
}

// ─── Observer Callbacks (called from any thread) ────────────────────────────

void TenetWSService::on_navigation(uint64_t inst_id) {
    if (!running_.load() || !loop_) return;
    static_cast<uWS::Loop*>(loop_)->defer([this, inst_id]() {
        flatbuffers::FlatBufferBuilder fbb(64);
        auto evt = CreateEvtNavigationMsg(fbb, inst_id);
        fbb.Finish(evt);

        flatbuffers::FlatBufferBuilder env_fbb(64 + fbb.GetSize());
        auto pv = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
        auto env = CreateEnvelope(env_fbb, 0, MessageType_EvtNavigation, pv);
        env_fbb.Finish(env);
        broadcast(env_fbb.GetBufferPointer(), env_fbb.GetSize());
    });
}

void TenetWSService::on_pass_completed(std::string_view name) {
    if (!running_.load() || !loop_) return;
    std::string name_copy(name);
    static_cast<uWS::Loop*>(loop_)->defer([this, name_copy]() {
        flatbuffers::FlatBufferBuilder fbb(256);
        auto evt = CreateEvtPassCompletedMsg(fbb, fbb.CreateString(name_copy),
                                              true, 0);
        fbb.Finish(evt);

        flatbuffers::FlatBufferBuilder env_fbb(256 + fbb.GetSize());
        auto pv = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
        auto env = CreateEnvelope(env_fbb, 0, MessageType_EvtPassCompleted, pv);
        env_fbb.Finish(env);
        broadcast(env_fbb.GetBufferPointer(), env_fbb.GetSize());
    });
}

void TenetWSService::on_bookmark_changed() {
    if (!running_.load() || !loop_) return;
    static_cast<uWS::Loop*>(loop_)->defer([this]() {
        auto& bm = service_.bookmarks();
        flatbuffers::FlatBufferBuilder fbb(64 + bm.size() * 8);
        auto bm_vec = fbb.CreateVector(bm.data(), bm.size());
        auto evt = CreateEvtBookmarkChangedMsg(fbb, bm_vec);
        fbb.Finish(evt);

        flatbuffers::FlatBufferBuilder env_fbb(64 + fbb.GetSize());
        auto pv = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
        auto env = CreateEnvelope(env_fbb, 0, MessageType_EvtBookmarkChanged, pv);
        env_fbb.Finish(env);
        broadcast(env_fbb.GetBufferPointer(), env_fbb.GetSize());
    });
}

}  // namespace tenet
```

- [ ] **Step 3: Add to CMakeLists.txt**

In the `tenet_lib` source list, inside an `if(TENET_ENABLE_WS)` guard:

```cmake
if(TENET_ENABLE_WS)
    target_sources(tenet_lib PRIVATE
        src/ws/tenet_ws_service.cpp
    )
    target_link_libraries(tenet_lib PUBLIC uwebsockets flatbuffers)
    target_include_directories(tenet_lib PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/generated)
    add_dependencies(tenet_lib tenet_ws_schema)
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_WS=1)
endif()
```

Also add a `#define` guard so code can conditionally use WS:

```cmake
if(NOT TENET_ENABLE_WS)
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_WS=0)
endif()
```

- [ ] **Step 4: Build**

```bash
cd tools/tenet/build && cmake .. && ninja -j$(nproc)
```

This will fail because the `handle_*` methods are declared but not defined. Create stub implementations that call `send_error(ws, msg_id, 4, "not implemented")` for all handlers to get it to compile.

- [ ] **Step 5: Create `src/ws/ws_handlers_stub.cpp` with stubs**

```cpp
// tools/tenet/src/ws/ws_handlers_stub.cpp
// Stub implementations — replaced by real handlers in Tasks 4-6
#include "ws/tenet_ws_service.h"

namespace tenet {

void TenetWSService::handle_fetch_rows(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: FetchRows");
}
// ... (one stub per handler method)

}  // namespace tenet
```

Add to CMakeLists: `src/ws/ws_handlers_stub.cpp`.

- [ ] **Step 6: Build and run tests**

```bash
cd tools/tenet/build && ninja -j$(nproc) && ctest --output-on-failure
```

Expected: Compiles. All existing tests pass. WS service is defined but not yet launched from main.

- [ ] **Step 7: Commit**

```bash
git add tools/tenet/src/ws/ tools/tenet/CMakeLists.txt
git commit -m "feat(ws): TenetWSService skeleton — uWS lifecycle + dispatch + observer push

uWebSockets event loop on dedicated thread, FlatBuffers envelope
dispatch to handler stubs, TenetServiceObserver push for navigation/
pass/bookmark events via uWS::Loop::defer().  Guarded by TENET_HAS_WS."
```

---

### Task 4: Implement Hot-Path Handlers (FetchRows, GetRegs, ReadMemory)

**Files:**
- Create: `tools/tenet/src/ws/ws_handlers_hotpath.cpp`
- Modify: `tools/tenet/CMakeLists.txt` (replace stub, add source)

**Interfaces:**
- Consumes: `TenetWSService` from Task 3, `TenetService::fetch_row()`, `RegisterFile::state_before/after()`, `MemoryModel::read_region()`
- Produces: Working FetchRows, GetRegs, ReadMemory handlers

These are the performance-critical handlers that must run synchronously in the uWS event loop thread (no async dispatch).

- [ ] **Step 1: Implement `handle_fetch_rows`**

```cpp
void TenetWSService::handle_fetch_rows(void* ws, uint32_t msg_id,
                                        const uint8_t* payload, size_t len) {
    auto* req = flatbuffers::GetRoot<FetchRowsRequest>(payload);
    uint64_t start = req->start_id();
    uint32_t count = std::min(req->count(), 1024u);  // cap at 1024

    flatbuffers::FlatBufferBuilder fbb(count * 128);

    std::vector<flatbuffers::Offset<InstructionRowMsg>> row_offsets;
    row_offsets.reserve(count);

    for (uint32_t i = 0; i < count; ++i) {
        uint64_t id = start + i;
        if (id >= service_.total_inst()) break;

        auto row = service_.fetch_row(id);
        auto mnemonic = fbb.CreateString(row.mnemonic);
        auto operands = fbb.CreateString(row.operands);
        row_offsets.push_back(CreateInstructionRowMsg(
            fbb, row.inst_id, row.pc, row.static_pc,
            mnemonic, operands,
            row.nzcv, row.reg_diff_count, row.mem_access_count,
            row.has_bookmark));
    }

    auto rows_vec = fbb.CreateVector(row_offsets);
    auto resp = CreateFetchRowsResponse(fbb, rows_vec,
                                         service_.total_inst(),
                                         service_.current_inst());
    fbb.Finish(resp);

    // Wrap in envelope
    flatbuffers::FlatBufferBuilder env_fbb(fbb.GetSize() + 64);
    auto pv = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
    auto env = CreateEnvelope(env_fbb, msg_id, MessageType_FetchRowsResp, pv);
    env_fbb.Finish(env);

    auto sv = std::string_view(reinterpret_cast<const char*>(env_fbb.GetBufferPointer()),
                                env_fbb.GetSize());
    static_cast<uWS::WebSocket<false, true, void*>*>(ws)->send(sv, uWS::BINARY);
}
```

- [ ] **Step 2: Implement `handle_get_regs`**

Use `service_.regfile().state_before(inst_id)` or `state_after()` based on `req->when()`. Serialize 34 GPR values as a `[uint64]` vector. If `include_fpr`, also serialize 512 bytes of FPR data.

- [ ] **Step 3: Implement `handle_read_memory`**

Use `service_.memory().read_region(addr, size, inst_id)`. Serialize `data` as `[ubyte]` and pack `known` as a bitmask.

- [ ] **Step 4: Build and test**

```bash
cd tools/tenet/build && ninja -j$(nproc)
```

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(ws): hot-path handlers — FetchRows, GetRegs, ReadMemory

Synchronous handlers in the uWS event loop for 60fps data delivery.
FetchRows capped at 1024 rows/request. GetRegs returns 34 GPR +
optional 512B FPR. ReadMemory returns raw bytes + known bitmask."
```

---

### Task 5: Implement Navigation + Bookmark + TraceInfo + Search Handlers

**Files:**
- Create: `tools/tenet/src/ws/ws_handlers_nav.cpp`

**Interfaces:**
- Consumes: `TenetService` navigation/bookmark/search API
- Produces: All navigation, bookmark, trace info, and search handlers

These are all synchronous, low-latency operations.

- [ ] **Step 1: Implement navigation handlers**

`handle_navigate`, `handle_nav_back`, `handle_nav_forward` — call `service_.navigate_to()` etc., respond with updated `inst_id`.

- [ ] **Step 2: Implement bookmark handlers**

`handle_toggle_bookmark`, `handle_get_bookmarks` — call `service_.toggle_bookmark()` / `service_.bookmarks()`.

- [ ] **Step 3: Implement trace info handler**

`handle_get_trace_info` — read from `service_.reader().header()` for module_name, slide, etc.

- [ ] **Step 4: Implement search handlers**

`handle_search_forward` — this is a **heavy** operation. Dispatch to a worker thread:

```cpp
void TenetWSService::handle_search_forward(void* ws, uint32_t msg_id,
                                            const uint8_t* payload, size_t len) {
    auto* req = flatbuffers::GetRoot<SearchForwardRequest>(payload);
    std::string query = req->query()->str();
    uint64_t from = req->from_inst();

    // Heavy: dispatch to a worker thread
    std::thread([this, ws, msg_id, query, from]() {
        service_.search_forward(query, from);
        auto* loop = static_cast<uWS::Loop*>(loop_);
        loop->defer([this, ws, msg_id]() {
            // Back on event loop thread — safe to send
            auto& results = service_.search_results();
            flatbuffers::FlatBufferBuilder fbb(results.size() * 8 + 64);
            auto rv = fbb.CreateVector(results.data(), results.size());
            auto resp = CreateSearchForwardResponse(fbb, rv, results.size());
            fbb.Finish(resp);
            // ... wrap in envelope and send
        });
    }).detach();
}
```

`handle_search_clear`, `handle_get_search_results` — synchronous.

- [ ] **Step 5: Build and commit**

---

### Task 6: Implement Pass Management + Data Query Handlers

**Files:**
- Create: `tools/tenet/src/ws/ws_handlers_analysis.cpp`

**Interfaces:**
- Consumes: `TenetService` pass API, `PassManager`, `FunctionResult`, `MemoryModel`
- Produces: All pass and data query handlers

- [ ] **Step 1: Implement pass management handlers**

`handle_run_pass` (async worker), `handle_run_default_passes` (async worker), `handle_clear_analysis` (sync), `handle_get_pass_state` (sync), `handle_get_pass_catalog` (sync).

- [ ] **Step 2: Implement `handle_get_pass_result`**

This reuses MCP's JSON serialization for pass results. The response's `data` field contains UTF-8 JSON bytes:

```cpp
void TenetWSService::handle_get_pass_result(void* ws, uint32_t msg_id,
                                             const uint8_t* payload, size_t len) {
    auto* req = flatbuffers::GetRoot<GetPassResultRequest>(payload);
    std::string name = req->name()->str();
    // Use MCP's existing serialization helpers to get JSON
    // ... serialize to JSON string, put bytes in response
}
```

- [ ] **Step 3: Implement data query handlers**

`handle_get_call_stack` — use `FunctionResult::call_stack_at()`.
`handle_get_last_writer` — use `service_.memory().last_writer()`.
`handle_get_write_history` — use `service_.memory().write_history()`.
`handle_get_functions` — use `FunctionResult::functions`.

- [ ] **Step 4: Remove stub file, update CMake**

Replace `ws_handlers_stub.cpp` with the three new handler files in CMakeLists.

- [ ] **Step 5: Build and commit**

---

### Task 7: Wire into main.cpp + CLI Option + GUI Auto-Start

**Files:**
- Modify: `tools/tenet/src/main.cpp` — add `--ws-port` option and WS startup
- Modify: `tools/tenet/src/cli_options.h` — add `ws_port` field
- Modify: `tools/tenet/src/gui/gui_app.h` — add `ws_service_` member
- Modify: `tools/tenet/src/gui/gui_app.mm` or `popups.cpp` — WS auto-start from GUI

**Interfaces:**
- Consumes: `TenetWSService` from Tasks 3-6
- Produces: Launchable WS server from CLI and GUI

- [ ] **Step 1: Add CLI option**

In `cli_options.h`, add `uint16_t ws_port = 0;` (0 = disabled).

In CLI parsing (wherever `--mcp-http` is parsed), add:
```
--ws-port PORT     Start WebSocket service on PORT (default: disabled)
```

- [ ] **Step 2: Start WS in main.cpp**

```cpp
#if TENET_HAS_WS
    std::unique_ptr<TenetWSService> ws_service;
    if (opts.ws_port > 0) {
        ws_service = std::make_unique<TenetWSService>(service);
        auto actual = ws_service->start(opts.ws_port);
        fmt::print(stderr, "[ws] listening on ws://127.0.0.1:{}\n", actual);
    }
#endif
```

- [ ] **Step 3: Add GUI auto-start option**

Add `ws_service_` member to `GuiApp`. In the settings/MCP panel, add a "WebSocket" section with start/stop button (similar to MCP panel).

- [ ] **Step 4: Build, test, verify**

```bash
cd tools/tenet/build && ninja -j$(nproc) && ctest --output-on-failure
```

Launch: `./tenet --ws-port 9090 trace.bin` and verify WebSocket is listening.

- [ ] **Step 5: Commit**

---

### Task 8: Integration Test + Documentation

**Files:**
- Create: `tools/tenet/tests/integration/test_ws_service.cpp`
- Modify: `tools/tenet/docs/ARCHITECTURE.md`
- Modify: `CLAUDE.md` (project root)

**Interfaces:**
- Consumes: `TenetWSService` from Tasks 3-7
- Produces: Integration test + updated documentation

- [ ] **Step 1: Write integration test**

A Catch2 test that starts `TenetWSService` on port 0, connects via a raw TCP socket, performs the WebSocket handshake, sends a `FetchRows` request, and verifies the response.

- [ ] **Step 2: Update docs**

Add WS service to architecture docs and CLAUDE.md CLI usage section.

- [ ] **Step 3: Build all configurations**

```bash
# With WS
cd tools/tenet/build && cmake .. -DTENET_ENABLE_WS=ON && ninja -j$(nproc)
# Without WS
cmake .. -DTENET_ENABLE_WS=OFF && ninja -j$(nproc)
```

- [ ] **Step 4: Final commit**

```bash
git commit -m "feat(ws): integration test + documentation for TenetWSService"
```
