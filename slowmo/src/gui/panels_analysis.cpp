// panels_analysis.cpp — analysis control panel + all run_*_analysis triggers
// + ensure_pass_manager + clear_analysis.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal). This is the only GUI
// translation unit that pulls in every analysis pass header.

#include "gui/gui_app.h"
#include "analysis/pass_registry.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/slice_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/thread_pass.h"
#include "analysis/passes/constant_materialization_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/symbol_annotation_pass.h"
#include "analysis/passes/objc_crypto_pass.h"
#include "analysis/passes/memory_string_pass.h"
#include "analysis/passes/syscall_intercept_pass.h"
#include "analysis/passes/cache_sim_pass.h"
#include "analysis/passes/trace_fold_pass.h"
#include "analysis/passes/vm_abstract_pass.h"
#include "analysis/passes/vm_hints_json.h"

#include <imgui.h>
#include "gui/icons/IconsFontAwesome6.h"

#include <fmt/core.h>

#include <cstring>
#include <mutex>
#include <thread>

namespace tenet {

// ─── Analysis helpers ───────────────────────────────────────────────────────

void GuiApp::ensure_pass_manager() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }
}

// ─── Async analysis infrastructure ──────────────────────────────────────────
//
// All pass execution (startup + manual triggers) runs on background threads.
// The UI thread never blocks on require().  Results are delivered back to the
// UI thread via pending_apply_ — a queue of lambdas drained at the top of each
// frame.  This guarantees that all result-pointer writes happen on the UI
// thread, eliminating the data races of the old detached-thread design.

void GuiApp::start_analysis_worker() {
    analysis_worker_stop_.store(false, std::memory_order_release);
    analysis_worker_thread_ = std::thread(&GuiApp::analysis_worker_loop, this);
}

void GuiApp::stop_analysis_worker() {
    // ── Step 1: cancel all in-flight passes immediately ─────────────────────
    // This signals every PassContext::cancelled() to return true, causing
    // long-running passes (xref, objc, etc.) to abort early rather than running
    // to completion.  Without this the join below can block for 10+ seconds.
    if (pass_manager_) {
        pass_manager_->cancel_all();
    }

    // ── Step 2: stop the serial worker queue ────────────────────────────────
    analysis_worker_stop_.store(true, std::memory_order_release);
    analysis_queue_cv_.notify_all();
    if (analysis_worker_thread_.joinable()) {
        analysis_worker_thread_.join();
    }

    // ── Step 3: join the startup analysis thread ────────────────────────────
    // startup_analysis_thread_ runs run_all(N) which itself spawns N worker
    // threads; those threads are joined internally before run_all returns.
    if (startup_analysis_thread_.joinable()) {
        startup_analysis_thread_.join();
    }

    // ── Step 4: wait for all detached enqueue_async() threads ───────────────
    // These are fully independent threads (detached).  We track them via
    // detached_thread_count_; wait here until every one has exited so that
    // no thread accesses TraceIndex / PassManager after they are destroyed.
    {
        std::unique_lock<std::mutex> lk(detached_thread_mutex_);
        detached_thread_cv_.wait(lk, [this] {
            return detached_thread_count_.load(std::memory_order_acquire) == 0;
        });
    }
}

void GuiApp::analysis_worker_loop() {
    while (true) {
        AnalysisTask task;
        {
            std::unique_lock<std::mutex> lk(analysis_queue_mutex_);
            analysis_queue_cv_.wait(lk, [this] {
                return analysis_worker_stop_.load(std::memory_order_acquire)
                    || !analysis_queue_.empty();
            });
            if (analysis_worker_stop_.load(std::memory_order_acquire)
                && analysis_queue_.empty())
                return;
            task = std::move(analysis_queue_.front());
            analysis_queue_.pop_front();
        }

        // Execute the task on this worker thread.
        task.work();

        // Decrement the active-analysis counter.
        if (active_analysis_count_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            analysis_running_.store(false, std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> lk(analysis_mutex_);
                analysis_status_.clear();
            }
        }
    }
}

void GuiApp::enqueue_async(std::string pass_name, std::function<void()> work) {
    active_analysis_count_.fetch_add(1, std::memory_order_acq_rel);
    analysis_running_.store(true, std::memory_order_relaxed);

    // Track this detached thread so stop_analysis_worker() can wait for it.
    detached_thread_count_.fetch_add(1, std::memory_order_acq_rel);

    // Launch on a dedicated detached thread instead of the single worker queue.
    // This prevents a slow pass (e.g. ObjcPass) from blocking all subsequent
    // manual triggers.  The worker thread is still available for other purposes
    // (e.g. future priority tasks), but manual pass execution no longer
    // serializes through it.
    std::thread([this, p = std::move(pass_name), w = std::move(work)]() mutable {
        w();

        if (active_analysis_count_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            analysis_running_.store(false, std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> lk(analysis_mutex_);
                analysis_status_.clear();
            }
        }

        // Decrement the detached-thread counter and notify stop_analysis_worker()
        // in case it is waiting for this thread to finish.
        if (detached_thread_count_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            detached_thread_cv_.notify_all();
        }
    }).detach();
}

void GuiApp::post_apply(std::function<void()> fn) {
    std::lock_guard<std::mutex> lk(pending_apply_mutex_);
    pending_apply_.push_back(std::move(fn));
}

void GuiApp::apply_pending_results() {
    std::vector<std::function<void()>> local;
    {
        std::lock_guard<std::mutex> lk(pending_apply_mutex_);
        local.swap(pending_apply_);
    }
    results_applied_this_frame_ = !local.empty();
    for (auto& fn : local) {
        fn();
    }
}

const PassResult* GuiApp::completed_result(std::string_view name) {
    if (!pass_manager_) return nullptr;
    if (pass_manager_->state(name) != PassManager::PassState::Completed)
        return nullptr;
    // Fast path: require() returns immediately for completed passes.
    return &pass_manager_->require(name);
}

void GuiApp::apply_pass_result_pointers(std::string_view name) {
    auto* raw = completed_result(name);
    if (!raw || !raw->ok()) return;

    if (name == "function") {
        function_result_ = &raw->get<FunctionResult>();
        show_callstack_   = true;
        show_functions_   = true;
        goto_candidates_dirty_ = true;
        // Functions panel is the primary tab of dock_left_sidebar — already
        // active, so no FocusWindow needed.  CallStack is intentionally NOT
        // auto-focused to avoid being disruptive.
        return;
    }
    if (name == "xref") {
        xref_result_  = &raw->get<XrefResult>();
        xref_cursor_  = 0;
        return;
    }
    if (name == "strings") {
        string_result_  = &raw->get<StringResult>();
        show_strings_   = true;
        string_cursor_  = 0;
        string_filter_.clear();
        std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
        // Strings shares dock_center_main with Instructions (default active).
        // Queue FocusWindow so Strings tab becomes visible.
        pending_focus_windows_.push_back("Strings");
        return;
    }
    if (name == "thread") {
        thread_result_ = &raw->get<ThreadResult>();
        show_threads_  = true;
        // Threads shares dock_left_sidebar with Functions (default active).
        // Do NOT auto-focus Threads — Functions is the primary view.
        return;
    }
    if (name == "loop") {
        loop_result_ = &raw->get<LoopResult>();
        show_loops_  = true;
        return;
    }
    if (name == "call_graph") {
        call_graph_result_ = &raw->get<CallGraphResult>();
        show_call_graph_   = true;
        pending_focus_windows_.push_back("Call Graph");
        return;
    }
    if (name == "cfg") {
        cfg_result_ = &raw->get<CFGResult>();
        show_cfg_   = true;
        // CFG shares dock_center_main with Instructions.
        // Do NOT auto-focus — Instructions is the primary disasm view.
        return;
    }
    if (name == "constant_materialization") {
        constant_result_ = &raw->get<ConstantMaterializationResult>();
        show_constant_   = true;
        pending_focus_windows_.push_back("Constants");
        return;
    }
    if (name == "pattern") {
        pattern_result_ = &raw->get<PatternResult>();
        show_pattern_   = true;
        pending_focus_windows_.push_back("Patterns");
        return;
    }
    if (name == "loop_semantics") {
        loop_semantics_result_ = &raw->get<LoopSemanticsResult>();
        show_loop_semantics_   = true;
        return;
    }
    if (name == "algorithm_summary") {
        algorithm_summary_result_ = &raw->get<AlgorithmSummaryResult>();
        show_algorithm_summary_   = true;
        pending_focus_windows_.push_back("Algorithm Summary");
        return;
    }
    if (name == "symbol_annotation") {
        annotation_result_ = &raw->get<AnnotationResult>();
        return;
    }
    if (name == "objc") {
        objc_result_ = &raw->get<ObjcResult>();
        show_objc_   = true;
        pending_focus_windows_.push_back("ObjC Messages");
        return;
    }
    if (name == "taint") {
        taint_result_ = &raw->get<TaintResult>();
        show_taint_   = true;
        return;
    }
    if (name == "backward_taint") {
        backward_taint_result_ = &raw->get<BackwardTaintResult>();
        show_backward_taint_   = true;
        return;
    }
    if (name == "slice") {
        slice_result_ = &raw->get<SliceResult>();
        show_slice_   = true;
        return;
    }
    if (name == "objc_crypto") {
        objc_crypto_result_ = &raw->get<ObjcCryptoResult>();
        show_objc_crypto_   = true;
        pending_focus_windows_.push_back("ObjC Crypto");
        return;
    }
    if (name == "memory_strings") {
        mem_string_result_ = &raw->get<MemoryStringResult>();
        show_mem_strings_  = true;
        pending_focus_windows_.push_back("Memory Strings");
        return;
    }
    if (name == "syscall_intercept") {
        syscall_result_          = &raw->get<SyscallInterceptResult>();
        show_syscall_intercept_  = true;
        pending_focus_windows_.push_back("API Intercepts");
        return;
    }
    if (name == "cache_sim") {
        cache_sim_result_ = &raw->get<CacheSimResult>();
        show_cache_sim_   = true;
        pending_focus_windows_.push_back("Cache Sim");
        return;
    }
    if (name == "trace_fold") {
        trace_fold_result_ = &raw->get<TraceFoldResult>();
        show_trace_fold_   = true;
        pending_focus_windows_.push_back("Trace Fold");
        return;
    }
    if (name == "vm_abstract") {
        vm_abstract_result_ = &raw->get<VMAbstractResult>();
        show_vm_abstract_   = true;
        vm_handler_cursor_  = 0;
        vm_step_cursor_     = 0;
        pending_focus_windows_.push_back("VM Abstract\xef\x83\x90##VMPanel");
        return;
    }
}

// ─── Startup Analysis ───────────────────────────────────────────────────────
// Runs the default pass set in parallel via run_all(N).  Results are applied
// on the UI thread after completion.

void GuiApp::run_startup_analysis() {
    if (analysis_running_.exchange(true)) return;

    ensure_pass_manager();

    // Pre-register all default passes so the UI can show them and
    // run_all can schedule them with full dependency resolution.
    tenet::register_default_passes(*pass_manager_);
    pass_manager_->reset_cancel();

    active_analysis_count_.fetch_add(1, std::memory_order_acq_rel);
    analysis_running_.store(true, std::memory_order_relaxed);

    startup_analysis_thread_ = std::thread([this]() {
        // Run all registered passes in parallel using the dynamic
        // ready-queue scheduler (LLVM New PM style).  This gives
        // true multi-core parallelism for independent passes.
        size_t n = std::max(2u, std::thread::hardware_concurrency());
        pass_manager_->run_all(n);

        // Apply all results on the UI thread.
        post_apply([this]() {
            for (auto name : tenet::default_ui_pass_names()) {
                apply_pass_result_pointers(name);
            }
        });

        if (active_analysis_count_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            analysis_running_.store(false, std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> lk(analysis_mutex_);
                analysis_status_.clear();
            }
        }
    });
}

// ─── Manual analysis triggers (all async, non-blocking) ─────────────────────

void GuiApp::run_taint_analysis() {
    ensure_pass_manager();

    // If already completed, apply immediately (fast path, no thread needed).
    if (pass_manager_->state("taint") == PassManager::PassState::Completed) {
        apply_pass_result_pointers("taint");
        show_slice_ = false;
        show_backward_taint_ = false;
        return;
    }
    if (pass_manager_->state("taint") == PassManager::PassState::Running)
        return;  // already in progress

    // Build config on the UI thread (reads current_inst_, reader_, etc.).
    TaintConfig config;
    config.taint_from_memory = true;
    config.track_memory_sinks = true;
    config.propagate_arithmetic = true;
    config.propagate_moves = true;
    config.max_instructions = 100000;

    auto [offset_ts, seed_pc_ts] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_ts = reader_.record_at(offset_ts, seed_pc_ts);
    if (rec_ts.kind == RecordKind::Inst) {
        auto inst = rec_ts.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.add_source_reg(diff.index);
        }
    }

    // Register the pass on the UI thread (modifies the PassManager registry).
    pass_manager_->register_pass(std::make_unique<TaintPass>(config));

    // Enqueue async execution.
    enqueue_async("taint", [this]() {
        auto& r = pass_manager_->require("taint");
        bool ok = r.ok();
        post_apply([this, ok]() {
            if (ok) {
                apply_pass_result_pointers("taint");
                show_slice_ = false;
                show_backward_taint_ = false;
            }
        });
    });
}

void GuiApp::run_backward_taint_analysis() {
    ensure_pass_manager();

    if (pass_manager_->state("backward_taint") == PassManager::PassState::Completed) {
        apply_pass_result_pointers("backward_taint");
        show_taint_ = false;
        show_slice_ = false;
        return;
    }
    if (pass_manager_->state("backward_taint") == PassManager::PassState::Running)
        return;

    BackwardTaintConfig config;
    config.sink_inst_id = current_inst_;
    config.propagate_through_memory = true;
    config.max_steps = 500000;
    config.max_tainted_insts = 50000;

    auto [offset_sk, seed_pc_sk] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_sk = reader_.record_at(offset_sk, seed_pc_sk);
    if (rec_sk.kind == RecordKind::Inst) {
        auto inst = rec_sk.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.add_sink_reg(diff.index);
        }
    }

    if (config.sink_regs == 0) {
        config.add_sink_reg(0);
    }

    pass_manager_->register_pass(std::make_unique<BackwardTaintPass>(std::move(config)));

    enqueue_async("backward_taint", [this]() {
        auto& r = pass_manager_->require("backward_taint");
        bool ok = r.ok();
        post_apply([this, ok]() {
            if (ok) {
                apply_pass_result_pointers("backward_taint");
                show_taint_ = false;
                show_slice_ = false;
            }
        });
    });
}

void GuiApp::run_slice_analysis() {
    ensure_pass_manager();

    // Slice depends on taint — the PassManager handles the dependency
    // via require("taint") inside SlicePass::run().  We just need to
    // make sure taint is registered.  If taint was already completed,
    // apply its result; otherwise it will run as a dependency.
    if (pass_manager_->state("taint") == PassManager::PassState::NotRun) {
        // Register taint with default config (will be triggered by slice's require()).
        // We use run_taint_analysis() to register + enqueue it.
        run_taint_analysis();
    }

    if (pass_manager_->state("slice") == PassManager::PassState::Completed) {
        apply_pass_result_pointers("slice");
        show_taint_ = false;
        show_backward_taint_ = false;
        return;
    }
    if (pass_manager_->state("slice") == PassManager::PassState::Running)
        return;

    uint8_t target_reg = 0;
    auto [offset_sl, seed_pc_sl] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_sl = reader_.record_at(offset_sl, seed_pc_sl);
    if (rec_sl.kind == RecordKind::Inst) {
        auto inst = rec_sl.as_inst();
        if (inst.reg_diff_count > 0) {
            target_reg = inst.reg_diff(0).index;
        }
    }

    pass_manager_->register_pass(
        std::make_unique<SlicePass>(current_inst_, target_reg));

    enqueue_async("slice", [this]() {
        auto& r = pass_manager_->require("slice");
        bool ok = r.ok();
        post_apply([this, ok]() {
            if (ok) {
                apply_pass_result_pointers("slice");
                show_taint_ = false;
                show_backward_taint_ = false;
            }
        });
    });
}

void GuiApp::run_call_graph_analysis() {
    ensure_pass_manager();

    // CallGraph depends on function — register it if not present.
    if (pass_manager_->state("function") == PassManager::PassState::NotRun) {
        run_pass_by_name("function");
    }

    run_pass_by_name("call_graph");
}

// ─── CFG Layout Analysis ─────────────────────────────────────────────────────

void GuiApp::run_cfg_layout() {
    ensure_pass_manager();

    // Register passes (idempotent — skips if already registered).
    tenet::register_pass_by_name(*pass_manager_, "xref");
    tenet::register_pass_by_name(*pass_manager_, "cfg");

    // If both are already completed, apply immediately.
    if (pass_manager_->state("cfg") == PassManager::PassState::Completed) {
        apply_pass_result_pointers("xref");
        apply_pass_result_pointers("cfg");
        show_cfg_ = true;
        cfg_current_func_pc_ = 0;
        cfg_func_result_.reset();
        cfg_func_layout_.reset();
        cfg_layout_result_ = nullptr;
        return;
    }

    enqueue_async("cfg", [this]() {
        auto& xref_res = pass_manager_->require("xref");
        auto& cfg_res  = pass_manager_->require("cfg");
        bool xref_ok = xref_res.ok();
        bool cfg_ok  = cfg_res.ok();

        post_apply([this, xref_ok, cfg_ok]() {
            if (xref_ok) apply_pass_result_pointers("xref");
            if (cfg_ok)  apply_pass_result_pointers("cfg");
            show_cfg_ = true;
            // Force per-function CFG rebuild on next render frame.
            cfg_current_func_pc_ = 0;
            cfg_func_result_.reset();
            cfg_func_layout_.reset();
            cfg_layout_result_ = nullptr;
        });
    });
}

// ─── Generic pass runner ───────────────────────────────────────────────────
// Runs any catalog pass by name, deriving a config from the current cursor.
// Used by the "All Passes" section of the Analysis panel so that every pass
// is reachable from the GUI — even those without a dedicated button.

void GuiApp::run_pass_by_name(std::string_view name) {
    ensure_pass_manager();
    if (!tenet::is_known_pass(name)) {
        last_pass_status_ = fmt::format("unknown pass '{}'", name);
        return;
    }

    // Build a PassRunCtx from the current cursor (must be on UI thread).
    tenet::PassRunCtx ctx;
    ctx.current_inst = current_inst_;
    ctx.total_inst   = total_inst_;
    auto [offset, seed_pc] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec = reader_.record_at(offset, seed_pc);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        ctx.current_reg = (inst.reg_diff_count > 0) ? inst.reg_diff(0).index : 0;
    }

    // Register the pass (and its dependencies) on the UI thread.
    if (!tenet::register_pass_by_name(*pass_manager_, name, ctx)) {
        last_pass_status_ = fmt::format("'{}' could not be registered", name);
        return;
    }

    // Fast path: already completed → apply immediately.
    if (pass_manager_->state(name) == PassManager::PassState::Completed) {
        auto& raw = pass_manager_->require(name);
        last_pass_status_ = fmt::format("{}: {}", name,
                                        tenet::summarize_pass_result(name, raw));
        apply_pass_result_pointers(name);
        return;
    }
    if (pass_manager_->state(name) == PassManager::PassState::Running)
        return;  // already in progress

    std::string name_str(name);

    // Enqueue async execution.
    enqueue_async(name_str, [this, name_str]() {
        auto& raw = pass_manager_->require(name_str);
        std::string summary = tenet::summarize_pass_result(name_str, raw);
        bool ok = raw.ok();
        post_apply([this, name_str, summary, ok]() {
            last_pass_status_ = fmt::format("{}: {}", name_str, summary);
            if (ok) apply_pass_result_pointers(name_str);
        });
    });
}

// ─── VM Abstract: hints-gated runner ────────────────────────────────────────
//
// VM dispatcher auto-detection is a pure heuristic (loop iteration count +
// indirect-branch shape) with a very high false-positive/false-negative rate
// on real traces. The GUI requires the user to load a static-analysis hints
// JSON file (produced by IDA/Ghidra, or the same schema as the MCP
// `vm_abstract` tool's hints_file) before running the pass — unless they
// explicitly check "run without hints (unreliable)".
void GuiApp::run_vm_abstract_with_hints() {
    ensure_pass_manager();

    std::string hints_path(vm_hints_path_buf_);

    if (hints_path.empty() && !vm_auto_detect_opt_in_) {
        vm_hints_status_ =
            "Load a static-analysis hints JSON file first (dispatcher_pc, "
            "handler_entry_pcs, ...), or check \"run without hints\" to use "
            "the unreliable heuristic auto-detection.";
        last_pass_status_ = "vm_abstract: hints required";
        return;
    }

    // Build the VMConfig up front so we can validate hints before touching
    // any pass-manager state.
    VMConfig vm_cfg;
    if (!hints_path.empty()) {
        if (!load_vm_hints_from_json(hints_path, vm_cfg)) {
            vm_hints_status_ = fmt::format("Failed to load hints file: {}", hints_path);
            last_pass_status_ = "vm_abstract: invalid hints file";
            return;
        }
    }
    vm_cfg.auto_detect = vm_auto_detect_opt_in_;
    if (!vm_cfg.has_any_static_hint() && !vm_auto_detect_opt_in_) {
        vm_hints_status_ = "Hints file has no usable hints, and auto-detect is not enabled.";
        last_pass_status_ = "vm_abstract: hints required";
        return;
    }

    // Always invalidate any previous result so new hints actually take
    // effect. NOTE: register_pass_by_name()/pm_has_pass() is idempotent by
    // NAME regardless of NotRun/Completed state, so it would incorrectly
    // skip re-registration here — construct + register the pass directly
    // instead (dependencies still go through register_pass_by_name, which
    // is safe for them since their config never changes).
    if (pass_manager_->state("vm_abstract") == PassManager::PassState::Running) {
        pass_manager_->cancel("vm_abstract");
    }
    pass_manager_->invalidate_and_clear_blob("vm_abstract");
    vm_abstract_result_ = nullptr;

    tenet::register_pass_by_name(*pass_manager_, "xref");
    tenet::register_pass_by_name(*pass_manager_, "cfg");
    tenet::register_pass_by_name(*pass_manager_, "loop");
    pass_manager_->register_pass(std::make_unique<VMAbstractPass>(std::move(vm_cfg)));

    vm_hints_status_ = hints_path.empty()
        ? "Running with auto-detect (unreliable) — no hints loaded."
        : fmt::format("Hints loaded from {}", hints_path);

    enqueue_async("vm_abstract", [this]() {
        auto& raw = pass_manager_->require("vm_abstract");
        std::string summary = tenet::summarize_pass_result("vm_abstract", raw);
        bool ok = raw.ok();
        post_apply([this, summary, ok]() {
            last_pass_status_ = fmt::format("vm_abstract: {}", summary);
            if (ok) apply_pass_result_pointers("vm_abstract");
        });
    });
}

void GuiApp::force_rerun_pass(std::string_view name) {
    ensure_pass_manager();

    // Cancel if currently running.
    if (pass_manager_->state(name) == PassManager::PassState::Running) {
        pass_manager_->cancel(name);
    }

    // Wipe in-memory result + RocksDB blob so the next run does a full recompute.
    pass_manager_->invalidate_and_clear_blob(name);

    // Clear the cached result pointer on the UI side for the three cached passes.
    if (name == "xref") {
        xref_result_ = nullptr;
    } else if (name == "function") {
        function_result_ = nullptr;
        sparkline_cache_ = {};
    } else if (name == "constant_materialization") {
        constant_result_ = nullptr;
    }

    // Re-register (may already be registered) and enqueue.
    tenet::PassRunCtx ctx;
    ctx.current_inst = current_inst_;
    ctx.total_inst   = total_inst_;
    tenet::register_pass_by_name(*pass_manager_, name, ctx);

    std::string name_str(name);
    enqueue_async(name_str, [this, name_str]() {
        auto& raw = pass_manager_->require(name_str);
        std::string summary = tenet::summarize_pass_result(name_str, raw);
        bool ok = raw.ok();
        post_apply([this, name_str, summary, ok]() {
            last_pass_status_ = fmt::format("{}: {}", name_str, summary);
            if (ok) apply_pass_result_pointers(name_str);
        });
    });
}

void GuiApp::clear_analysis() {
    // Cancel any in-flight analysis.
    if (pass_manager_) {
        pass_manager_->cancel_all();
    }

    // Clear the task queue.
    {
        std::lock_guard<std::mutex> lk(analysis_queue_mutex_);
        analysis_queue_.clear();
    }

    taint_result_ = nullptr;
    slice_result_ = nullptr;
    backward_taint_result_ = nullptr;
    function_result_ = nullptr;
    xref_result_ = nullptr;
    string_result_ = nullptr;
    call_graph_result_ = nullptr;
    loop_result_ = nullptr;
    thread_result_ = nullptr;
    cfg_result_        = nullptr;
    cfg_layout_result_ = nullptr;
    cfg_func_result_.reset();
    cfg_func_layout_.reset();
    cfg_current_func_pc_ = 0;
    constant_result_          = nullptr;
    show_constant_            = false;
    std::memset(constant_filter_buf_, 0, sizeof(constant_filter_buf_));
    constant_filter_.clear();
    pattern_result_           = nullptr;
    show_pattern_             = false;
    std::memset(pattern_filter_buf_, 0, sizeof(pattern_filter_buf_));
    pattern_filter_.clear();
    loop_semantics_result_    = nullptr;
    show_loop_semantics_      = false;
    algorithm_summary_result_ = nullptr;
    show_algorithm_summary_   = false;
    call_graph_result_        = nullptr;
    show_call_graph_          = false;
    std::memset(call_graph_filter_buf_, 0, sizeof(call_graph_filter_buf_));
    call_graph_filter_.clear();
    annotation_result_        = nullptr;
    objc_result_ = nullptr;
    show_objc_   = false;
    std::memset(objc_class_filter_buf_, 0, sizeof(objc_class_filter_buf_));
    std::memset(objc_sel_filter_buf_, 0, sizeof(objc_sel_filter_buf_));
    objc_class_filter_.clear();
    objc_sel_filter_.clear();
    objc_msg_cursor_ = 0;
    objc_crypto_result_ = nullptr;
    show_objc_crypto_   = false;
    std::memset(objc_crypto_filter_buf_, 0, sizeof(objc_crypto_filter_buf_));
    objc_crypto_filter_.clear();
    objc_crypto_cursor_ = 0;
    mem_string_result_ = nullptr;
    show_mem_strings_  = false;
    std::memset(mem_string_filter_buf_, 0, sizeof(mem_string_filter_buf_));
    mem_string_filter_.clear();
    syscall_result_         = nullptr;
    show_syscall_intercept_ = false;
    std::memset(syscall_filter_buf_, 0, sizeof(syscall_filter_buf_));
    syscall_filter_.clear();
    syscall_cursor_ = 0;
    cache_sim_result_ = nullptr;
    show_cache_sim_   = false;
    trace_fold_result_ = nullptr;
    show_trace_fold_   = false;
    vm_abstract_result_ = nullptr;
    show_vm_abstract_   = false;
    vm_handler_cursor_  = 0;
    vm_step_cursor_     = 0;
    show_taint_ = false;
    show_threads_ = false;
    show_slice_ = false;
    show_backward_taint_ = false;
    show_callstack_ = false;
    show_functions_ = false;
    show_strings_ = false;
    show_loops_ = false;
    xref_cursor_ = 0;
    string_cursor_ = 0;
    string_filter_.clear();
    std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
    function_filter_.clear();
    std::memset(function_filter_buf_, 0, sizeof(function_filter_buf_));
    taint_sorted_ids_.clear();
    taint_sorted_ids_dirty_ = true;
    goto_candidates_.clear();
    goto_candidates_dirty_ = true;
    goto_selected_candidate_ = -1;
    if (pass_manager_) {
        pass_manager_->invalidate_all();
    }
    active_analysis_count_.store(0, std::memory_order_relaxed);
    analysis_running_.store(false, std::memory_order_relaxed);
}

// ─── Analysis Panel ─────────────────────────────────────────────────────────
// Flat list of ALL catalog passes with per-pass Run / Stop / Rerun controls.

void GuiApp::render_analysis_panel() {
    if (!ImGui::Begin("Analysis", &show_analysis_)) {
        ImGui::End();
        return;
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();
    float panel_w = ImGui::GetContentRegionAvail().x;
    bool running = analysis_running_.load();

    // ── Banner ──────────────────────────────────────────────────────
    {
        ImVec2 banner_p0 = ImGui::GetCursorScreenPos();
        float banner_h = ImGui::GetFrameHeightWithSpacing();
        draw->AddRectFilled(banner_p0,
            ImVec2(banner_p0.x + panel_w, banner_p0.y + banner_h),
            running ? IM_COL32(140, 110, 0, 60) : IM_COL32(20, 80, 30, 40));

        if (running) {
            static const char* spinner[] = {
                "\xe2\xa3\xbe","\xe2\xa3\xbd","\xe2\xa3\xbb","\xe2\xa2\xbf",
                "\xe2\xa1\xbf","\xe2\xa3\x9f","\xe2\xa3\xaf","\xe2\xa3\xb7"
            };
            static int spin_frame = 0;
            spin_frame = (spin_frame + 1) % 8;
            ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.2f, 1.0f),
                " %s  Analyzing...", spinner[spin_frame]);

            // Stop All button (right-aligned)
            float btn_w = ImGui::CalcTextSize(" Stop All ").x + 20.0f;
            ImGui::SameLine(panel_w - btn_w);
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.50f, 0.10f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.65f, 0.15f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.75f, 0.20f, 0.20f, 1.0f));
            if (ImGui::SmallButton(ICON_FA_STOP " Stop All")) {
                if (pass_manager_) pass_manager_->cancel_all();
            }
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Cancel all in-flight passes");
        } else {
            ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f),
                " " ICON_FA_CHECK "  Analysis ready");

            // Clear All button (right-aligned)
            float btn_w = ImGui::CalcTextSize(" Clear All ").x + 20.0f;
            ImGui::SameLine(panel_w - btn_w);
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.10f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.60f, 0.15f, 0.15f, 1.0f));
            if (ImGui::SmallButton(ICON_FA_XMARK " Clear All")) {
                clear_analysis();
            }
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Clear all analysis results and overlays");
        }
    }

    ImGui::Dummy(ImVec2(0, 2));

    // ── Status line (last manual pass result) ───────────────────────
    if (!last_pass_status_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.85f, 1.0f, 1.0f));
        ImGui::TextWrapped("%s", last_pass_status_.c_str());
        ImGui::PopStyleColor();
        ImGui::Dummy(ImVec2(0, 2));
    }

    // ── Category header helper ──────────────────────────────────────
    auto section_header = [&](const char* title, ImVec4 color) {
        ImVec2 hp = ImGui::GetCursorScreenPos();
        float h = ImGui::GetTextLineHeightWithSpacing();
        draw->AddRectFilled(hp, ImVec2(hp.x + panel_w, hp.y + h),
                            ImGui::ColorConvertFloat4ToU32(
                                ImVec4(color.x*0.4f, color.y*0.4f, color.z*0.4f, 0.55f)));
        draw->AddRectFilled(hp, ImVec2(hp.x + 3.0f, hp.y + h),
                            ImGui::ColorConvertFloat4ToU32(color));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 6.0f);
        ImGui::TextColored(color, "%s", title);
    };

    // ── Category colors ─────────────────────────────────────────────
    auto category_color = [](tenet::PassCategory c) -> ImVec4 {
        switch (c) {
            case tenet::PassCategory::Structure:   return {0.35f, 0.62f, 1.0f, 1.0f};
            case tenet::PassCategory::Taint:       return {0.20f, 0.82f, 0.35f, 1.0f};
            case tenet::PassCategory::Crypto:      return {0.90f, 0.70f, 0.20f, 1.0f};
            case tenet::PassCategory::Memory:      return {0.75f, 0.55f, 1.0f, 1.0f};
            case tenet::PassCategory::PlatformApi:  return {1.0f, 0.55f, 0.40f, 1.0f};
            case tenet::PassCategory::Profile:     return {0.55f, 0.80f, 0.75f, 1.0f};
            case tenet::PassCategory::Misc:        return {0.55f, 0.55f, 0.62f, 1.0f};
        }
        return {0.55f, 0.55f, 0.62f, 1.0f};
    };

    auto category_label = [](tenet::PassCategory c) -> const char* {
        switch (c) {
            case tenet::PassCategory::Structure:   return "  Structure";
            case tenet::PassCategory::Taint:       return "  Taint";
            case tenet::PassCategory::Crypto:      return "  Crypto / Pattern";
            case tenet::PassCategory::Memory:      return "  Memory / String";
            case tenet::PassCategory::PlatformApi:  return "  ObjC / Platform API";
            case tenet::PassCategory::Profile:     return "  Profile / Trace";
            case tenet::PassCategory::Misc:        return "  Misc";
        }
        return "  Misc";
    };

    // ── Flat pass list (all catalog entries) ────────────────────────
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 2));

    int cur_cat = -1;
    for (const auto& entry : tenet::pass_catalog()) {
        int ci = static_cast<int>(entry.category);
        if (ci != cur_cat) {
            cur_cat = ci;
            if (ci != 0) ImGui::Dummy(ImVec2(0, 2));
            section_header(category_label(entry.category),
                           category_color(entry.category));
        }

        // Determine pass state
        auto st = PassManager::PassState::NotRun;
        float pct = 0.0f;
        if (pass_manager_) {
            st = pass_manager_->state(entry.name);
            pct = pass_manager_->progress_of(entry.name);
        }

        // State icon
        const char* icon;
        ImVec4 icon_color;
        switch (st) {
            case PassManager::PassState::Running:
                icon = ICON_FA_PLAY;
                icon_color = ImVec4(1.0f, 0.9f, 0.2f, 1.0f);
                break;
            case PassManager::PassState::Completed:
                icon = ICON_FA_CHECK;
                icon_color = ImVec4(0.35f, 0.90f, 0.45f, 1.0f);
                break;
            case PassManager::PassState::Failed:
                icon = ICON_FA_XMARK;
                icon_color = ImVec4(0.90f, 0.30f, 0.30f, 1.0f);
                break;
            default:  // NotRun
                icon = "\xc2\xb7";  // · (middle dot)
                icon_color = ImVec4(0.40f, 0.42f, 0.48f, 1.0f);
                break;
        }

        ImGui::TextColored(icon_color, "%s", icon);
        ImGui::SameLine(0, 4);

        // Display name
        ImGui::TextUnformatted(std::string(entry.display_name).c_str());
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s\n(pass: %s%s)", entry.description.data(),
                              entry.name.data(),
                              entry.default_for_ui == tenet::PassDefault::Yes
                                  ? ", auto" : "");

        // ── Right-side controls ─────────────────────────────────────
        // Lay out from right to left: [▶ Run] or [■ Stop] + [↺ Rerun]
        // We use a fixed region at the right edge of the panel.

        if (st == PassManager::PassState::Running) {
            // Progress bar + percentage
            float bar_w = 60.0f;
            float stop_btn_w = ImGui::CalcTextSize(" " ICON_FA_STOP " ").x + 12.0f;
            ImGui::SameLine(panel_w - bar_w - 50 - stop_btn_w);
            ImGui::ProgressBar(pct, ImVec2(bar_w, ImGui::GetFrameHeight() * 0.6f), "");
            ImGui::SameLine(0, 4);
            ImGui::TextDisabled("%d%%", (int)(pct * 100));

            // Stop button
            ImGui::SameLine(0, 6);
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.50f, 0.10f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.65f, 0.15f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.75f, 0.20f, 0.20f, 1.0f));
            std::string stop_label = fmt::format(ICON_FA_STOP "##stop_{}", entry.name);
            if (ImGui::SmallButton(stop_label.c_str())) {
                if (pass_manager_) pass_manager_->cancel(entry.name);
            }
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Cancel %s", entry.display_name.data());

            // Progress message on next line
            if (pass_manager_) {
                auto msg = pass_manager_->progress_msg_of(entry.name);
                if (!msg.empty()) {
                    ImGui::Indent(16.0f);
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.55f, 0.65f, 1.0f));
                    ImGui::TextWrapped("%s", msg.c_str());
                    ImGui::PopStyleColor();
                    ImGui::Unindent(16.0f);
                }
            }

        } else if (st == PassManager::PassState::Completed) {
            // Summary text
            auto* raw = completed_result(entry.name);
            if (raw) {
                std::string summary = tenet::summarize_pass_result(entry.name, *raw);
                if (!summary.empty() && summary != "ok") {
                    ImGui::SameLine(0, 8);
                    ImGui::TextDisabled("%s", summary.c_str());
                }
            }

            // Rerun button
            float rerun_w = ImGui::CalcTextSize(" " ICON_FA_ARROW_ROTATE_LEFT " ").x + 12.0f;
            ImGui::SameLine(panel_w - rerun_w);
            std::string rerun_label = fmt::format(ICON_FA_ARROW_ROTATE_LEFT "##rerun_{}", entry.name);
            if (ImGui::SmallButton(rerun_label.c_str())) {
                force_rerun_pass(entry.name);
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Force re-run %s (discard cache)", entry.display_name.data());

        } else if (st == PassManager::PassState::Failed) {
            // Error indicator + Run button to retry
            ImGui::SameLine(0, 8);
            ImGui::TextDisabled("failed");

            float run_w = ImGui::CalcTextSize(" " ICON_FA_PLAY " ").x + 12.0f;
            ImGui::SameLine(panel_w - run_w);
            std::string run_label = fmt::format(ICON_FA_PLAY "##run_{}", entry.name);
            if (ImGui::SmallButton(run_label.c_str())) {
                force_rerun_pass(entry.name);
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Retry %s", entry.display_name.data());

        } else {
            // NotRun — show Run button
            float run_w = ImGui::CalcTextSize(" " ICON_FA_PLAY " ").x + 12.0f;
            ImGui::SameLine(panel_w - run_w);
            std::string run_label = fmt::format(ICON_FA_PLAY "##run_{}", entry.name);
            if (ImGui::SmallButton(run_label.c_str())) {
                run_pass_by_name(entry.name);
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Run %s", entry.display_name.data());
        }
    }

    ImGui::PopStyleVar();  // ItemSpacing
    ImGui::End();
}

}  // namespace tenet
