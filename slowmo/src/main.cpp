#include "cli_options.h"
#include "io/trace_reader.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "io/trace_lock.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "tui/tui_app.h"
#include "service/tenet_service.h"
#if TENET_HAS_WS
#include "ws/tenet_ws_service.h"
#endif
#include "io/recent_files.h"
#include "batch_analysis.h"

#include "common/logger.h"
#include "common/progress_manager.h"
#include "common/Profiling.h"

#include <fmt/core.h>
#include <fmt/color.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>

#if !defined(_WIN32)
#include <sys/resource.h>
#endif

using namespace tenet;


// ─── Usage ─────────────────────────────────────────────────────────────────

// print_usage() moved to cli_options.cpp

// ─── Main ──────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    // ─── Raise file descriptor limit ────────────────────────────────────
    // RocksDB's parallel SST ingest + CompactRange on large traces can open
    // thousands of files simultaneously.  macOS defaults to 256 for GUI apps.
#if !defined(_WIN32)
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            rl.rlim_cur = std::min<rlim_t>(rl.rlim_max, 65536);
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }
#endif

    // ─── Initialize logging ─────────────────────────────────────────────
    tenet::log::init();

    // ─── Parse CLI arguments ────────────────────────────────────────────
    auto opts = tenet::parse_args(argc, argv);
    if (opts.parse_status != 0)
        return opts.parse_status == 2 ? 0 : 1;

    bool has_analysis_option = opts.has_analysis_option();


    // ─── Open trace file ────────────────────────────────────────────────
    // In MCP mode, stdout is reserved for JSON-RPC — all human-readable
    // progress/info output goes to stderr instead.
    FILE* info_out = opts.opt_mcp ? stderr : stdout;

    fmt::print(info_out, "Opening trace: {}\n", opts.trace_path);
    LOG_INFO("opening trace: {}", opts.trace_path);
    auto t_open = TENET_TIMER_START();

    auto reader_result = TraceReader::open(opts.trace_path);
    if (!reader_result) {
        fmt::print(stderr, "Error: {}\n", reader_result.error().message);
        return 1;
    }
auto& reader = *reader_result;
LOG_INFO("trace opened in {:.1f}ms  size={:.2f}MB",
TENET_TIMER_MS(t_open),
reader.file_size() / (1024.0 * 1024.0));

// ─── Acquire exclusive trace session lock ────────────────────────────
// Only one tenet instance (TUI/batch/RPC/MCP — any mode) may hold a
// given trace open at a time: concurrent instances would race on the same
// RocksDB index directory and on interactive navigation/bookmark state.
// See io/trace_lock.h for why this uses flock() rather than a PID check
// (crash-safe: the kernel releases the lock automatically on process exit,
// no matter how the process terminates).
std::string session_mode = "batch";
if (opts.opt_mcp_hub)        session_mode = "mcp-hub";
else if (opts.opt_mcp_http)  session_mode = "mcp-http";
else if (opts.opt_mcp)       session_mode = "mcp";
else if (opts.opt_rpc)       session_mode = "rpc";
else if (opts.opt_streaming) session_mode = "streaming";
else if (has_analysis_option) session_mode = "batch-analysis";
else if (opts.batch_mode)    session_mode = "tui-batch";
else                          session_mode = "tui";

TraceLockHolderInfo lock_holder;
auto trace_lock = TraceFileLock::try_acquire(
    TraceIndex::index_dir_for(reader),
    std::filesystem::absolute(opts.trace_path).string(),
    session_mode, &lock_holder);

if (!trace_lock && lock_holder.pid != 0) {
    // A live holder was identified (flock() denied us the lock) — refuse
    // to proceed. Do NOT attempt to clean up, wait, or retry: an existing
    // instance is actively using this trace.
    fmt::print(stderr,
        "Error: trace '{}' is already open in another tenet instance\n"
        "  pid:        {}\n"
        "  host:       {}\n"
        "  mode:       {}\n"
        "  opened at:  {}\n"
        "\n"
        "Close that instance before opening this trace again.\n",
        opts.trace_path, lock_holder.pid, lock_holder.host,
        lock_holder.mode, lock_holder.opened_at);
    return 1;
}
// If trace_lock is empty but lock_holder.pid == 0, acquisition hit a soft
// I/O error (see trace_lock.cpp) — proceed without a lock rather than
// blocking normal usage on lock-file infrastructure problems.

    const auto& hdr = reader.header();
    fmt::print(info_out, "  Magic:     0x{:08X}\n", hdr.magic);
    fmt::print(info_out, "  Version:   {}\n", hdr.version);
    fmt::print(info_out, "  Arch:      {}\n", hdr.arch == 1 ? "AArch64" : "x86_64");
    fmt::print(info_out, "  GPR count: {}\n", hdr.num_gpr);
    fmt::print(info_out, "  Module:    {}\n", hdr.module_name);
    fmt::print(info_out, "  Base:      0x{:016X}\n", hdr.module_base);
    fmt::print(info_out, "  Slide:     0x{:016X}\n", hdr.module_slide);
    fmt::print(info_out, "  Range:     0x{:016X} - 0x{:016X}\n", hdr.trace_start, hdr.trace_end);
    fmt::print(info_out, "  File size: {:.2f} MB\n", reader.file_size() / (1024.0 * 1024.0));
    fmt::print(info_out, "  Flags:     mem={} nzcv={} diff={} code={}\n",
               hdr.has_mem(), hdr.has_nzcv(), hdr.reg_diff(), hdr.has_code());
    fmt::print(info_out, "\n");
    LOG_DEBUG("trace header: arch={} gpr={} module={} slide=0x{:X}",
              hdr.arch == 1 ? "AArch64" : "x86_64",
              hdr.num_gpr, hdr.module_name, hdr.module_slide);

    // ─── Dump mode (no RocksDB index) ───────────────────────────────────
    if (opts.opt_dump) {
        auto result = dump_trace(reader, opts.dump_options, std::cout);
        if (!result) {
            fmt::print(stderr, "Error: {}\n", result.error().message);
            return 1;
        }
        fmt::print(stderr, "Dumped {} records ({} INST)\n",
                   result->records, result->inst_records);
        return 0;
    }

    // ─── Build/load index ───────────────────────────────────────────────
    fmt::print(info_out, "Building index...\n");
    LOG_INFO("building/loading RocksDB index");
    auto cli_progress = ProgressManager::global().subscribe([info_out](const ProgressTask& task) {
        if (task.kind != "index" || task.state != ProgressState::Running) return;
        fmt::print(info_out, "\r  {:5.1f}%  {}   ", task.progress * 100.0f, task.message);
        fflush(info_out);
    });
    ProgressManager::global().start("index", "index", "Build trace index",
                                    reader.file_size(), "scan");
    auto t_index = TENET_TIMER_START();

    auto index_result = TraceIndex::open_or_build(reader,
        [info_out, t_start = std::chrono::steady_clock::now(),
         last_bytes = uint64_t(0), last_time = std::chrono::steady_clock::now(),
         cur_speed = 0.0]
        (uint64_t processed, uint64_t total) mutable {
            if (total == 0) return;

            // Phase 2 sentinel: processed > total means compaction step.
            // Display "Compacting index (N/3)..." instead of a percentage.
            if (processed > total) {
                uint64_t step = processed - total;  // 1, 2, or 3
                // Keep overall progress monotonic: scanning owns [0, 0.9],
                // compaction owns [0.9, 1.0].
                ProgressManager::global().update_fraction(
                    "index", 0.9f + static_cast<float>(step) / 30.0f,
                    "compact", fmt::format("Compacting index ({}/3)", step));
                return;
            }

            auto now = std::chrono::steady_clock::now();
            double elapsed_total = std::chrono::duration<double>(now - t_start).count();
            // Update speed every 200ms to avoid flicker
            double dt = std::chrono::duration<double>(now - last_time).count();
            if (dt >= 0.2 || processed == total) {
                uint64_t delta = processed - last_bytes;
                cur_speed = static_cast<double>(delta) / dt;
                last_bytes = processed;
                last_time = now;
            }
            double pct = 100.0 * processed / total;
            // Format speed with appropriate unit
            const char* unit = "B/s";
            double display_speed = cur_speed;
            if (display_speed >= 1e9) { display_speed /= 1e9; unit = "GB/s"; }
            else if (display_speed >= 1e6) { display_speed /= 1e6; unit = "MB/s"; }
            else if (display_speed >= 1e3) { display_speed /= 1e3; unit = "KB/s"; }
            ProgressManager::global().update_fraction(
                "index", static_cast<float>(processed) / static_cast<float>(total) * 0.9f,
                "scan", elapsed_total > 0.1 && cur_speed > 0
                    ? fmt::format("Indexing {:.1f}% [{:.1f} {}]", pct, display_speed, unit)
                    : fmt::format("Indexing {:.1f}%", pct));
        });

    if (!index_result) {
        ProgressManager::global().fail("index", index_result.error().message);
        fmt::print(stderr, "\nError building index: {}\n", index_result.error().message);
        return 1;
    }
    auto& index = *index_result;
    ProgressManager::global().complete("index", "Index ready");
    fmt::print(info_out, "\r  Done. {} instructions, {} anchors, built in {:.2f}s\n",
               index.stats().inst_count, index.stats().anchor_count,
               index.stats().build_seconds);
    LOG_INFO("index ready: {} instructions, {} anchors  ({:.1f}ms total)",
             index.stats().inst_count, index.stats().anchor_count,
             TENET_TIMER_MS(t_index));

    // ─── Integrity check ──────────────────────────────────────────────────
    {
        auto integrity = index.verify_integrity(reader);
        if (!integrity.ok) {
            fmt::print(stderr, "\n[WARNING] Index integrity check failed: {}\n",
                       integrity.error);
            fmt::print(stderr, "  The index may be corrupted and will be rebuilt.\n");
            // Integrity failure is non-fatal here: the index was already loaded
            // and is most likely still usable (hash mismatch is a soft warning).
            // A full rebuild would be triggered on the next open_or_build call.
        } else {
            LOG_DEBUG("index integrity OK");
        }
    }

    if (opts.show_index_stats) {
        fmt::print(info_out, "  Code records: {}\n", index.stats().code_count);
        fmt::print(info_out, "  Event records: {}\n", index.stats().event_count);
        fmt::print(info_out, "  Total records: {}\n", index.stats().total_records);
        fmt::print(info_out, "\n");
    }

    // ─── Populate CodeTable from index (P1.9: zero extra file I/O) ──────
    // The index build already extracted all CODE records into the code_bytes CF
    // during the same single pass. load_code_table() reads from RocksDB instead
    // of scanning the trace file a second time.
    CodeTable code_table;
    fmt::print(info_out, "Loading code table...\n");
    {
        TENET_SCOPE_TIMER("code_table_load");
        uint64_t loaded = index.load_code_table(code_table);
        if (loaded == 0) {
            // Fallback: old index (schema < v5) without CODE_BYTES CF.
            // Re-scan the trace file to populate the table.
            fmt::print(info_out, "  (index has no code_bytes CF, falling back to trace scan)\n");
            for (auto it = reader.begin(); it != reader.end(); ++it) {
                auto rec = *it;
                if (rec.kind == RecordKind::Code) {
                    auto code = rec.as_code();
                    if (code.size == 4) {
                        uint32_t opcode = 0;
                        std::memcpy(&opcode, code.bytes, 4);
                        code_table.insert(code.pc, opcode);
                    }
                }
            }
        }
    }
    fmt::print(info_out, "  Loaded {} distinct PCs\n\n", code_table.size());
    LOG_DEBUG("code table: {} distinct PCs", code_table.size());

    // ─── Record this trace in the recent-files list ──────────────────────
    {
        auto recent = RecentFiles::load();
        // Use absolute path for portability (resolve symlinks / relative paths)
        std::string abs_path = std::filesystem::absolute(opts.trace_path).string();
        recent.push(abs_path, hdr.module_name, index.stats().inst_count);
        recent.save();
    }

    // ─── Load image fallback (optional) ─────────────────────────────
    if (!opts.image_path.empty()) {
        auto img = std::make_shared<ImageFallback>();
        if (img->load(opts.image_path, hdr.module_base)) {
            code_table.set_image_fallback(img);
            fmt::print(info_out, "  Image fallback: {} segments loaded from {}\n",
                       img->segment_count(), opts.image_path);
        } else {
            fmt::print(stderr, "  Warning: failed to load image fallback: {}\n", opts.image_path);
        }
    }

    // ─── Initialize decoder ─────────────────────────────────────────────
    InstructionDecoder decoder;
    {
        auto t = TENET_TIMER_START();
        if (!decoder.init()) {
            fmt::print(stderr, "Error: failed to initialize Capstone\n");
            return 1;
        }
        LOG_DEBUG("Capstone decoder initialized in {:.1f}ms", TENET_TIMER_MS(t));
    }

    // ─── Initialize RegisterFile and MemoryModel ──────────────────────────
    RegisterFile regfile(reader, index);
    // Eagerly build the dense checkpoint array so state_before()/state_after()
    // queries work immediately for all modes (TUI/batch/service), even before
    // any analysis triggers PassManager::init_infra(). init_infra()'s
    // CheckpointManager::ensure_checkpoints() sees has_checkpoints() == true
    // and skips the rebuild.
    regfile.build_checkpoints();
    // Use RocksDB-backed MemoryModel for full memory read/write indexing.
    // This enables resolving pointer dereferences (e.g. ObjC selector strings,
    // NSData bytes) that were written by uninstrumented shared-cache code.
    MemoryModel memory(reader, index,
                       index.raw_db(), index.mem_write_cf(), index.mem_read_cf());
    LOG_DEBUG("RegisterFile + MemoryModel ready");

    // RAII guard: on scope exit, invalidate MemoryModel's thread-local
    // iterators and close the RocksDB DB (joining all background compaction
    // threads) BEFORE MemoryModel's mutexes are destroyed.
    //
    // Without this, ~MemoryModel()'s pthread_mutex_destroy() can collide with
    // RocksDB BG threads' own pthread_mutex_destroy() calls on macOS's global
    // os_unfair_lock, triggering _os_unfair_lock_corruption_abort (SIGKILL).
    //
    // Destruction order at function exit: guard → memory → regfile → ...
    // → index_result.  guard runs first, closing RocksDB; then memory's
    // mutexes are destroyed with no BG threads running.
    struct RocksDbShutdownGuard {
        MemoryModel* memory;
        TraceIndex* index;
        ~RocksDbShutdownGuard() {
            if (memory) memory->invalidate_thread_iterators();
            if (index) index->close();
        }
    } shutdown_guard{&memory, &index};


    // Create TenetService — shared by all paths (batch, TUI, service).
    TenetService service(reader, index, code_table, decoder, regfile, memory, opts.trace_path);

    // ─── Start WebSocket service (if requested) ────────────────────────────
#if TENET_HAS_WS
    std::unique_ptr<TenetWSService> ws_service;
    if (opts.ws_port > 0) {
        ws_service = std::make_unique<TenetWSService>(service);
        auto actual = ws_service->start(opts.ws_port);
        if (actual > 0) {
            fmt::print(info_out, "WebSocket service listening on ws://127.0.0.1:{}\n", actual);
        } else {
            fmt::print(stderr, "Warning: WebSocket service failed to start on port {}\n",
                       opts.ws_port);
        }
    }
#endif

    // ─── Run analysis options (batch mode) ─────────────────────────────────
    if (has_analysis_option) {
        return tenet::run_batch_analysis(opts, service);
    }

    // ─── Run interactive TUI or batch mode ───────────────────────────────
    if (opts.batch_mode) {
        TuiApp app(service);
        return app.batch_mode(opts.start_id, opts.display_count, opts.show_regs, opts.show_mem);
    }

    // TUI is the only native interactive frontend. The graphical frontend is
    // the separate Tauri application in tools/tenet/web/.
    TuiApp app(service);
    return app.run();
}
