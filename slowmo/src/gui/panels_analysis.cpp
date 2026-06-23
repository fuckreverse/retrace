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

#include <imgui.h>

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
        // Functions panel is the primary tab of dock_left_sidebar — it is
        // already the active tab, so no FocusWindow needed here.
        // CallStack is behind Analysis in dock_center_bottom; register it
        // so we can make it visible without forcing a full focus steal.
        // (We intentionally do NOT focus CallStack automatically — it would
        //  be disruptive.  Functions is the primary view the user wants.)
    } else if (name == "xref") {
        xref_result_  = &raw->get<XrefResult>();
        xref_cursor_  = 0;
    } else if (name == "strings") {
        string_result_  = &raw->get<StringResult>();
        show_strings_   = true;
        string_cursor_  = 0;
        string_filter_.clear();
        std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
        // Strings shares dock_center_main with Instructions (default active).
        // Queue a FocusWindow so the Strings tab becomes visible, but only
        // if the user has not already selected a different tab manually.
        pending_focus_windows_.push_back("Strings");
    } else if (name == "thread") {
        thread_result_ = &raw->get<ThreadResult>();
        show_threads_  = true;
        // Threads shares dock_left_sidebar with Functions (default active).
        // Do NOT auto-focus Threads — Functions is the primary view.
    } else if (name == "loop") {
        loop_result_ = &raw->get<LoopResult>();
        show_loops_  = true;
    } else if (name == "call_graph") {
        call_graph_result_ = &raw->get<CallGraphResult>();
        show_call_graph_   = true;
        pending_focus_windows_.push_back("Call Graph");
    } else if (name == "cfg") {
        cfg_result_ = &raw->get<CFGResult>();
        show_cfg_   = true;
        // CFG shares dock_center_main with Instructions.
        // Do NOT auto-focus CFG — Instructions is the primary disasm view.
    } else if (name == "constant_materialization") {
        constant_result_ = &raw->get<ConstantMaterializationResult>();
        show_constant_   = true;
        pending_focus_windows_.push_back("Constants");
    } else if (name == "pattern") {
        pattern_result_ = &raw->get<PatternResult>();
        show_pattern_   = true;
        pending_focus_windows_.push_back("Patterns");
    } else if (name == "loop_semantics") {
        loop_semantics_result_ = &raw->get<LoopSemanticsResult>();
        show_loop_semantics_   = true;
    } else if (name == "algorithm_summary") {
        algorithm_summary_result_ = &raw->get<AlgorithmSummaryResult>();
        show_algorithm_summary_   = true;
        pending_focus_windows_.push_back("Algorithm Summary");
    } else if (name == "symbol_annotation") {
        annotation_result_ = &raw->get<AnnotationResult>();
    } else if (name == "objc") {
        objc_result_ = &raw->get<ObjcResult>();
        show_objc_   = true;
        pending_focus_windows_.push_back("ObjC Messages");
    } else if (name == "taint") {
        taint_result_ = &raw->get<TaintResult>();
        show_taint_   = true;
    } else if (name == "backward_taint") {
        backward_taint_result_ = &raw->get<BackwardTaintResult>();
        show_backward_taint_   = true;
    } else if (name == "slice") {
        slice_result_ = &raw->get<SliceResult>();
        show_slice_   = true;
    } else if (name == "objc_crypto") {
        objc_crypto_result_ = &raw->get<ObjcCryptoResult>();
        show_objc_crypto_   = true;
        pending_focus_windows_.push_back("ObjC Crypto");
    } else if (name == "memory_strings") {
        mem_string_result_ = &raw->get<MemoryStringResult>();
        show_mem_strings_  = true;
        pending_focus_windows_.push_back("Memory Strings");
    } else if (name == "syscall_intercept") {
        syscall_result_          = &raw->get<SyscallInterceptResult>();
        show_syscall_intercept_  = true;
        pending_focus_windows_.push_back("API Intercepts");
    } else if (name == "cache_sim") {
        cache_sim_result_ = &raw->get<CacheSimResult>();
        show_cache_sim_   = true;
        pending_focus_windows_.push_back("Cache Sim");
    } else if (name == "trace_fold") {
        trace_fold_result_ = &raw->get<TraceFoldResult>();
        show_trace_fold_   = true;
        pending_focus_windows_.push_back("Trace Fold");
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

void GuiApp::render_analysis_panel() {
    if (!ImGui::Begin("Analysis", &show_analysis_)) {
        ImGui::End();
        return;
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();
    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Pass Progress ───────────────────────────────────────────────
    // Live view of every registered pass: state icon + progress bar +
    // message.  Includes a Stop button for cancellation.
    if (pass_manager_) {
        bool running = analysis_running_.load();
        auto all = pass_manager_->all_passes();

        if (running || !all.empty()) {
            // Banner with spinner + Stop button
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
            } else {
                ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f),
                    " \xe2\x9c\x93  Analysis ready");
            }

            // Stop button (right-aligned in the banner)
            if (running) {
                float btn_w = ImGui::CalcTextSize(" Stop ").x + 20.0f;
                ImGui::SameLine(panel_w - btn_w);
                ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.50f, 0.10f, 0.10f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.65f, 0.15f, 0.15f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.75f, 0.20f, 0.20f, 1.0f));
                if (ImGui::SmallButton("\xe2\x8f\xb9 Stop")) {  // ⏹
                    pass_manager_->cancel_all();
                }
                ImGui::PopStyleColor(3);
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Cancel all in-flight passes");
            }
        }

        // Per-pass progress list
        for (auto name : all) {
            auto st = pass_manager_->state(name);
            float pct = pass_manager_->progress_of(name);

            // Look up display name from catalog
            std::string_view display = name;
            if (auto* cat = tenet::find_pass_catalog_entry(name))
                display = cat->display_name;

            // State icon + name
            const char* icon;
            ImVec4 icon_color;
            if (st == PassManager::PassState::Running) {
                icon = "\xe2\x96\xb6";  // ▶
                icon_color = ImVec4(1.0f, 0.9f, 0.2f, 1.0f);
            } else if (st == PassManager::PassState::Completed) {
                icon = "\xe2\x9c\x93";  // ✓
                icon_color = ImVec4(0.35f, 0.90f, 0.45f, 1.0f);
            } else if (st == PassManager::PassState::Failed) {
                icon = "\xe2\x9c\x97";  // ✗
                icon_color = ImVec4(0.90f, 0.30f, 0.30f, 1.0f);
            } else {
                icon = "\xe2\x8f\xb3";  // ⏳
                icon_color = ImVec4(0.45f, 0.50f, 0.60f, 1.0f);
            }

            ImGui::TextColored(icon_color, "%s", icon);
            ImGui::SameLine(0, 4);
            ImGui::TextUnformatted(std::string(display).c_str());

            // Progress bar or status on the right
            if (st == PassManager::PassState::Running) {
                // Progress bar
                float bar_w = 80.0f;
                ImGui::SameLine(panel_w - bar_w - 50);
                ImGui::ProgressBar(pct, ImVec2(bar_w, ImGui::GetFrameHeight() * 0.6f), "");
                // Percentage text
                ImGui::SameLine(0, 4);
                ImGui::TextDisabled("%d%%", (int)(pct * 100));
                // Progress message on next line (indented)
                auto msg = pass_manager_->progress_msg_of(name);
                if (!msg.empty()) {
                    ImGui::Indent(16.0f);
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.55f, 0.65f, 1.0f));
                    ImGui::TextWrapped("%s", msg.c_str());
                    ImGui::PopStyleColor();
                    ImGui::Unindent(16.0f);
                }
            } else if (st == PassManager::PassState::Completed) {
                // Show summary
                auto* raw = completed_result(name);
                if (raw) {
                    std::string summary = tenet::summarize_pass_result(name, *raw);
                    if (!summary.empty() && summary != "ok") {
                        ImGui::SameLine(panel_w - ImGui::CalcTextSize(summary.c_str()).x - 8);
                        ImGui::TextDisabled("%s", summary.c_str());
                    }
                }
            } else if (st == PassManager::PassState::Failed) {
                // Per-pass cancel button for running passes
                ImGui::SameLine(panel_w - 30);
                if (ImGui::SmallButton(fmt::format("x##{}", name).c_str())) {
                    pass_manager_->cancel(name);
                }
            }
        }
    }

    ImGui::Dummy(ImVec2(0, 3));

    // ── Section helper ──────────────────────────────────────────────
    auto section_header = [&](const char* title, ImVec4 color) {
        ImVec2 hp = ImGui::GetCursorScreenPos();
        draw->AddRectFilled(hp, ImVec2(hp.x + panel_w, hp.y + ImGui::GetFrameHeight()),
                            ImGui::ColorConvertFloat4ToU32(
                                ImVec4(color.x*0.4f, color.y*0.4f, color.z*0.4f, 0.55f)));
        draw->AddRectFilled(hp, ImVec2(hp.x + 3.0f, hp.y + ImGui::GetFrameHeight()),
                            ImGui::ColorConvertFloat4ToU32(color));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 6.0f);
        ImGui::TextColored(color, "%s", title);
    };

    // ── GROUP 1: Taint analysis ─────────────────────────────────────
    section_header("  Taint Analysis", ImVec4(0.20f, 0.82f, 0.35f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 3));

    // Forward taint
    {
        bool active = show_taint_ && taint_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f, 0.35f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.10f, 0.45f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.12f, 0.55f, 0.18f, 1.0f));
        }
        if (ImGui::Button("Run Taint##fwd")) {
            run_taint_analysis();
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Forward taint from selected register\nAnalysis > Taint to choose source");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.25f, 0.85f, 0.35f, 1.0f), "\xe2\x9c\x93");
            ImGui::SameLine(0, 4);
            ImGui::Text("%llu tainted", (unsigned long long)taint_result_->tainted_inst_count());
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrtaint")) {
                show_taint_ = false;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear taint overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // Backward taint
    {
        bool active = show_backward_taint_ && backward_taint_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.35f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.10f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.55f, 0.12f, 0.12f, 1.0f));
        }
        if (ImGui::Button("Run BackTaint")) {
            run_backward_taint_analysis();
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Backward taint from current instruction");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.90f, 0.25f, 0.25f, 1.0f), "\xe2\x9c\x93 active");
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrbt")) {
                show_backward_taint_ = false;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear backward-taint overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // Slice
    {
        bool active = show_slice_ && slice_result_;
        if (ImGui::Button("Run Slice##slc")) {
            run_slice_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Program slice for current instruction");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.80f, 0.25f, 0.80f, 1.0f), "\xe2\x9c\x93 active");
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrslc")) { show_slice_ = false; }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear slice overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    ImGui::Dummy(ImVec2(0, 4));

    // ── GROUP 2: Code Structure ─────────────────────────────────────
    section_header("  Code Structure", ImVec4(0.35f, 0.62f, 1.0f, 1.0f));

    // Functions
    {
        bool active = (function_result_ != nullptr);
        if (ImGui::Button("Run Functions##fn")) {
            run_pass_by_name("function");
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Discover call/return pairs, build function list");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.4f, 0.75f, 1.0f, 1.0f),
                "\xe2\x9c\x93 %zu functions", function_result_->functions.size());
            ImGui::SameLine();
            if (ImGui::SmallButton("\xe2\x86\xba##rerun_fn")) {  // ↺
                force_rerun_pass("function");
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Force re-run (discard disk cache)");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    // Loops
    {
        bool active = show_loops_ && loop_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.35f, 0.18f, 0.02f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.25f, 0.03f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.55f, 0.30f, 0.04f, 1.0f));
        }
        if (ImGui::Button("Run Loops##lp")) {
            run_pass_by_name("loop");
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Detect loops (back-edges in CFG)");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(1.0f, 0.62f, 0.12f, 1.0f),
                "\xe2\x9c\x93 %zu loops", loop_result_->loops.size());
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrlp")) { show_loops_ = false; }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear loop overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // XRef
    {
        bool active = (xref_result_ != nullptr);
        if (ImGui::Button("Run XRef##xref")) {
            run_pass_by_name("xref");
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Build cross-reference index (PC → inst_ids)");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.65f, 0.75f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
            ImGui::SameLine();
            if (ImGui::SmallButton("\xe2\x86\xba##rerun_xref")) {  // ↺
                force_rerun_pass("xref");
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Force re-run (discard disk cache)");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    // CFG
    {
        bool active = (cfg_result_ != nullptr);
        if (ImGui::Button("Run CFG##cfg")) {
            run_cfg_layout();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Compute control-flow graph + layout for CFG view");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.55f, 0.80f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    ImGui::Dummy(ImVec2(0, 4));

    // ── GROUP 3: String & Call Graph ───────────────────────────────
    section_header("  Strings / Calls", ImVec4(0.75f, 0.55f, 1.0f, 1.0f));

    {
        bool has_str = (string_result_ != nullptr);
        if (ImGui::Button("Run Strings##str")) {
            run_pass_by_name("strings");
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Find string accesses in the trace");
        ImGui::SameLine();
        if (has_str) {
            ImGui::TextColored(ImVec4(0.78f, 0.62f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    {
        bool has_cg = (call_graph_result_ != nullptr);
        if (ImGui::Button("Run CallGraph##cg")) {
            run_call_graph_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Build call graph across functions");
        ImGui::SameLine();
        if (has_cg) {
            ImGui::TextColored(ImVec4(0.78f, 0.62f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    ImGui::Dummy(ImVec2(0, 6));

    // ── GROUP 4: All Passes (full catalog) ─────────────────────────────
    // Every pass in the registry is reachable here, so nothing is
    // "GUI-only" or hidden. Default passes show ✓ once run at startup.
    section_header("  All Passes", ImVec4(0.55f, 0.55f, 0.62f, 1.0f));
    {
        static bool show_all = false;
        ImGui::Checkbox("Show full catalog", &show_all);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Expand to run any of the %d passes (incl. those without a dedicated button).",
                              (int)tenet::pass_catalog().size());

        if (!last_pass_status_.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.85f, 1.0f, 1.0f));
            ImGui::TextWrapped("%s", last_pass_status_.c_str());
            ImGui::PopStyleColor();
        }

        if (show_all) {
            const char* cat_names[] = {
                "Structure", "Taint", "Crypto/Pattern", "Memory/String",
                "ObjC/Syscall", "Profile/Trace", "Misc"
            };
            auto cat_to_idx = [](tenet::PassCategory c) -> int {
                switch (c) {
                    case tenet::PassCategory::Structure:  return 0;
                    case tenet::PassCategory::Taint:      return 1;
                    case tenet::PassCategory::Crypto:     return 2;
                    case tenet::PassCategory::Memory:     return 3;
                    case tenet::PassCategory::ObjcSyscall:return 4;
                    case tenet::PassCategory::Profile:    return 5;
                    case tenet::PassCategory::Misc:       return 6;
                }
                return 6;
            };

            // Passes that persist results to the RocksDB blob cache.
            // These get an extra ↺ button to force re-computation.
            static constexpr std::string_view kBlobCachedPasses[] = {
                "xref", "function", "constant_materialization"
            };
            auto has_blob_cache = [](std::string_view name) {
                for (auto n : kBlobCachedPasses) if (n == name) return true;
                return false;
            };

            int cur_cat = -1;
            for (const auto& e : tenet::pass_catalog()) {
                int ci = cat_to_idx(e.category);
                if (ci != cur_cat) {
                    cur_cat = ci;
                    ImGui::Dummy(ImVec2(0, 2));
                    ImGui::TextDisabled("%s", cat_names[ci]);
                }
                // Status indicator: ✓ if completed, · if not run.
                bool done = pass_manager_ &&
                            pass_manager_->state(e.name) ==
                                PassManager::PassState::Completed;
                std::string label = fmt::format("{}##cat", e.display_name);
                if (done) {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.10f, 0.30f, 0.16f, 1.0f));
                }
                if (ImGui::SmallButton(label.c_str())) {
                    run_pass_by_name(e.name);
                }
                if (done) ImGui::PopStyleColor();
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s\n(pass: %s%s)", e.description.data(),
                                      e.name.data(),
                                      e.default_for_ui == tenet::PassDefault::Yes
                                          ? ", default" : "");
                // For blob-cached passes that completed, show a ↺ re-run button.
                if (done && has_blob_cache(e.name)) {
                    ImGui::SameLine(0, 2);
                    std::string rerun_label = fmt::format("\xe2\x86\xba##rerun_cat_{}", e.name);
                    if (ImGui::SmallButton(rerun_label.c_str())) {
                        force_rerun_pass(e.name);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Force re-run %s (discard disk cache)", e.name.data());
                }
                ImGui::SameLine();
            }
            ImGui::NewLine();  // wrap last row
        }
    }

    ImGui::Dummy(ImVec2(0, 6));

    // ── Clear All ───────────────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.10f, 0.10f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.60f, 0.15f, 0.15f, 1.0f));
    if (ImGui::Button("  \xe2\x9c\x95  Clear All  ")) {  // ✕
        clear_analysis();
    }
    ImGui::PopStyleColor(3);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Clear all analysis results and overlays");

    ImGui::PopStyleVar();  // ItemSpacing
    ImGui::End();
}

}  // namespace tenet
