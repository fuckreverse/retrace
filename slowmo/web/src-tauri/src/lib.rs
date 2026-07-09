use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use tauri::{
    menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder},
    Emitter, Manager,
};
use tauri_plugin_shell::{process::CommandChild, ShellExt};

// ── Data types ──────────────────────────────────────────────────────────────

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct RecentEntry {
    path: String,
    module_name: String,
    inst_count: u64,
    last_opened: i64,
}

#[derive(Clone, serde::Serialize)]
struct BackendPorts {
    ws_port: u16,
    mcp_port: u16,
    trace_path: String,
}

/// One line of `tenet` sidecar output, broadcast to the frontend so the
/// "Output (Log)" panel can show real backend logs instead of mock data.
///
/// `level` is a best-effort classification parsed from the line text (tenet's
/// own logger emits lines like `[+  0.123s  42.1MB] INFO  [mcp] message`,
/// see `tools/tenet/src/common/logger.h`); anything unrecognised falls back
/// to `"info"` for stdout and `"error"` for the `Error`/non-zero-exit cases.
#[derive(Clone, serde::Serialize)]
struct BackendLogLine {
    /// Canonicalized trace path this sidecar instance belongs to (matches
    /// `BackendPorts::trace_path`), so a multi-window frontend can filter.
    trace_path: String,
    level: String,
    message: String,
}

/// Strip ANSI SGR escape sequences (`\x1b[...m`) from a line of text.
///
/// tenet's logger (`common/logger.h`) always colorizes its stderr output via
/// `fmt::print(stderr, fmt::fg(fmt::color::xxx), ...)` — `{fmt}` does not do
/// its own `isatty()` check, so the escape codes are emitted unconditionally,
/// even when stderr is a pipe (as it is here: Tauri captures the sidecar's
/// stdout/stderr via `CommandEvent`, not a real terminal). Left unstripped,
/// these bytes show up as garbled `←[36m`-style text in the frontend's log
/// panel (which just renders the message as plain text) and also break the
/// prefix matching in `classify_log_line` below (the color code sits between
/// the timestamp block and the `INFO`/`ERROR`/... tag).
fn strip_ansi_codes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
            // Consume parameter bytes (0x30-0x3F) and intermediate bytes
            // (0x20-0x2F), then the final byte (0x40-0x7E, e.g. 'm').
            for ch in chars.by_ref() {
                if ch.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Classify a raw sidecar output line into a `LogLevel` string for the
/// frontend. tenet's logger prefixes lines with `ERROR`/`WARN `/`INFO `/
/// `DEBUG`/`TRACE` after the `[+<secs>s <mem>MB]` timestamp block; plain
/// `fmt::print` progress/info lines (no such prefix) are classified as info.
/// Expects `line` to already have ANSI escapes stripped (see
/// `strip_ansi_codes`), otherwise the color code sitting right before the
/// level tag would defeat the `starts_with` checks below.
fn classify_log_line(line: &str) -> &'static str {
    // Look at the text after the "] " timestamp block if present, otherwise
    // the whole line, so we don't accidentally match inside a message body.
    let tail = line.split_once("] ").map(|(_, t)| t).unwrap_or(line);
    let tail = tail.trim_start();
    if tail.starts_with("ERROR") || line.contains("Error:") || line.contains("error:") {
        "error"
    } else if tail.starts_with("WARN") || line.contains("Warning:") || line.contains("warning:") {
        "warn"
    } else if tail.starts_with("DEBUG") {
        "debug"
    } else if tail.starts_with("TRACE") {
        "trace"
    } else {
        "info"
    }
}

// ── Managed state ───────────────────────────────────────────────────────────

struct OpenTraces(Mutex<HashSet<String>>);

/// Handles to spawned `tenet` sidecar processes, keyed by canonicalized trace path.
///
/// The `tenet` C++ backend binary is bundled as a Tauri sidecar (see
/// `tauri.conf.json`'s `bundle.externalBin` + `src-tauri/scripts/prepare-sidecar.sh`),
/// so it ships inside the .app bundle (`Contents/MacOS/`) together with its
/// third-party dylibs (`Contents/Resources/lib/`, rewritten to load via
/// `@executable_path/../Resources/lib`). `app.shell().sidecar("tenet")` resolves
/// the correct path for both `tauri dev` and a bundled release build.
struct BackendProcesses(Mutex<HashMap<String, CommandChild>>);

// ── Helper: read recent.json ────────────────────────────────────────────────

fn read_recent_entries() -> Vec<RecentEntry> {
    let path = recent_json_path();
    let Ok(data) = std::fs::read_to_string(&path) else {
        return vec![];
    };
    serde_json::from_str(&data).unwrap_or_default()
}

fn recent_json_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tenet")
        .join("recent.json")
}

fn settings_json_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tenet")
        .join("settings.json")
}

// ── Tauri commands ──────────────────────────────────────────────────────────

/// Return the list of recently opened trace files.
#[tauri::command]
fn get_recent_files() -> Vec<RecentEntry> {
    read_recent_entries()
}

/// Save UI settings JSON to ~/.config/tenet/settings.json
#[tauri::command]
fn save_config(config: String) -> Result<(), String> {
    let path = settings_json_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, &config).map_err(|e| format!("Failed to save config: {e}"))
}

/// Load UI settings JSON from ~/.config/tenet/settings.json
#[tauri::command]
fn load_config() -> Result<String, String> {
    let path = settings_json_path();
    if !path.exists() {
        return Ok("{}".to_string());
    }
    std::fs::read_to_string(&path).map_err(|e| format!("Failed to load config: {e}"))
}

/// Check whether a given trace path is already open in this session.
#[tauri::command]
fn is_trace_open(state: tauri::State<'_, OpenTraces>, path: String) -> bool {
    state.0.lock().unwrap().contains(&path)
}

/// Open a trace: canonicalize the path, allocate ports, spawn the C++ backend,
/// and return the port pair so the frontend can connect via WebSocket / MCP.
#[tauri::command]
async fn open_trace(
    app: tauri::AppHandle,
    state: tauri::State<'_, OpenTraces>,
    path: String,
) -> Result<BackendPorts, String> {
    // Canonicalize so duplicate detection is reliable.
    let abs_path = std::fs::canonicalize(&path)
        .map_err(|e| format!("Invalid path: {e}"))?
        .to_string_lossy()
        .to_string();

    // Duplicate guard.
    {
        let open = state.0.lock().unwrap();
        if open.contains(&abs_path) {
            return Err(format!("Trace already open: {abs_path}"));
        }
    }

    // Allocate WS port (deterministic offset from instance count).
    // MCP uses the fixed hub port (10444) — all instances participate in
    // flock-based hub election so MCP clients only connect to one address.
    let ws_port = {
        let open = state.0.lock().unwrap();
        9090 + (open.len() as u16) * 10
    };
    let mcp_port: u16 = 10444; // fixed hub port

    // Mark as open *before* spawning so a second call for the same file will be
    // rejected even if the spawn is slow.
    state.0.lock().unwrap().insert(abs_path.clone());

    // Spawn the backend via the Tauri sidecar mechanism. `app.shell().sidecar("tenet")`
    // resolves to `src-tauri/binaries/tenet-<target-triple>` in both `tauri dev`
    // and a bundled release build (where it lives at `Contents/MacOS/tenet`),
    // so we no longer need to hand-roll path lookup via `find_tenet_binary`.
    //
    // Spawn the backend with --mcp-hub (hub/worker election) instead of
    // --mcp-http.  First instance wins flock and becomes hub on port 10444;
    // subsequent instances auto-connect as workers via TCP (no extra port).
    //
    // IMPORTANT: the trace path must NOT immediately follow `--mcp-hub` on
    // the command line. tenet's CLI parser greedily consumes the very next
    // non-flag token after `--mcp-hub` as an optional `host:port` override
    // (see cli_options.cpp), so `--mcp-hub <abs_path>` would swallow the
    // trace path as a bogus host:port, leave `trace_path` empty, and cause
    // tenet to print usage and exit(1) — which is what "backend didn't
    // start in time" actually was. Placing the trace path *before*
    // `--mcp-hub` avoids the ambiguity entirely.
    let sidecar = app
        .shell()
        .sidecar("tenet")
        .map_err(|e| format!("Failed to resolve tenet sidecar: {e}"))?;

    let (mut rx, child) = sidecar
        .args(["--ws-port", &ws_port.to_string(), &abs_path, "--mcp-hub"])
        .spawn()
        .map_err(|e| {
            // Roll back the open-traces set on failure.
            state.0.lock().unwrap().remove(&abs_path);
            format!("Failed to spawn tenet: {e}")
        })?;

    // Drain stdout/stderr on a background task so the sidecar never blocks on a
    // full pipe buffer; forward lines to the app log for debugging.
    //
    // If the sidecar exits on its own (e.g. tenet hit an argument-parsing
    // error, a port conflict with a stale hub instance, etc.), `spawn()`
    // above has *already* returned `Ok` — the frontend is holding a
    // BackendPorts it can never connect to. Without cleanup here, the entry
    // in `OpenTraces`/`BackendProcesses` would linger forever and the user
    // could never retry opening the same file (`open_trace` would keep
    // rejecting it as "already open"). Clean up on Terminated and notify the
    // frontend so it can reset its own state instead of waiting out a
    // connect timeout.
    let terminated_path = abs_path.clone();
    let terminated_app = app.clone();
    tauri::async_runtime::spawn(async move {
        use tauri_plugin_shell::process::CommandEvent;
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) | CommandEvent::Stderr(line) => {
                    let raw = String::from_utf8_lossy(&line);
                    let raw = raw.trim_end_matches(['\r', '\n']);
                    if raw.is_empty() {
                        continue;
                    }
                    // tenet colorizes its stderr output unconditionally (no
                    // isatty check — see `strip_ansi_codes` doc comment), so
                    // strip the escape codes before logging/classifying/
                    // forwarding, otherwise the frontend log panel renders
                    // garbled `←[36m`-style text instead of plain messages.
                    let text = strip_ansi_codes(raw);
                    let text = text.as_str();
                    log::info!(target: "tenet-backend", "{text}");
                    // Broadcast to the frontend regardless of build type (the
                    // `log` crate sink below is debug-only / best-effort), so
                    // the "Output (Log)" panel can show real backend output.
                    let _ = terminated_app.emit(
                        "backend-log",
                        BackendLogLine {
                            trace_path: terminated_path.clone(),
                            level: classify_log_line(text).to_string(),
                            message: text.to_string(),
                        },
                    );
                }
                CommandEvent::Error(err) => {
                    log::error!(target: "tenet-backend", "sidecar error: {err}");
                    let _ = terminated_app.emit(
                        "backend-log",
                        BackendLogLine {
                            trace_path: terminated_path.clone(),
                            level: "error".to_string(),
                            message: format!("sidecar error: {err}"),
                        },
                    );
                }
                CommandEvent::Terminated(payload) => {
                    log::info!(target: "tenet-backend", "exited: {payload:?}");
                    let exit_ok = payload.code == Some(0);
                    let _ = terminated_app.emit(
                        "backend-log",
                        BackendLogLine {
                            trace_path: terminated_path.clone(),
                            level: if exit_ok { "info".to_string() } else { "error".to_string() },
                            message: format!("[process exited] {payload:?}"),
                        },
                    );
                    {
                        let open_state = terminated_app.state::<OpenTraces>();
                        open_state.0.lock().unwrap().remove(&terminated_path);
                    }
                    {
                        let procs_state = terminated_app.state::<BackendProcesses>();
                        procs_state.0.lock().unwrap().remove(&terminated_path);
                    }
                    if !exit_ok {
                        let _ = terminated_app.emit("backend-crashed", &terminated_path);
                    }
                }
                _ => {}
            }
        }
    });

    // Stash the child handle for later cleanup.
    {
        let state_ref = app.state::<BackendProcesses>();
        let mut procs = state_ref.0.lock().unwrap();
        procs.insert(abs_path.clone(), child);
    }

    Ok(BackendPorts {
        ws_port,
        mcp_port,
        trace_path: abs_path,
    })
}

/// Close a trace: kill its backend process and remove it from the open set.
#[tauri::command]
fn close_trace(
    app: tauri::AppHandle,
    state: tauri::State<'_, OpenTraces>,
    path: String,
) {
    state.0.lock().unwrap().remove(&path);
    let state_ref = app.state::<BackendProcesses>();
    let mut procs = state_ref.0.lock().unwrap();
    if let Some(child) = procs.remove(&path) {
        let _ = child.kill();
    }
}

// ── Helper: kill every remaining backend when the app exits ─────────────────

fn kill_all_backends(app: &tauri::AppHandle) {
    let state_ref = app.state::<BackendProcesses>();
    let mut procs = state_ref.0.lock().unwrap();
    for (_path, child) in procs.drain() {
        let _ = child.kill();
    }
}

// ── Menu construction ───────────────────────────────────────────────────────

/// Build the macOS-style native menu bar.  Menu item clicks broadcast
/// `menu://<id>` events that the frontend's `useNativeMenu.ts` hook handles.
fn build_and_set_menu(app: &tauri::App) -> tauri::Result<()> {
    let handle = app.handle();

    // Shorthand for a greyed-out placeholder item.
    macro_rules! disabled {
        ($id:expr, $label:expr) => {
            &MenuItemBuilder::with_id($id, $label)
                .enabled(false)
                .build(handle)?
        };
    }

    // ── App menu ────────────────────────────────────────────────────────
    let app_menu = SubmenuBuilder::new(handle, "Tenet")
        .text("about", "About Tenet")
        .separator()
        .item(&PredefinedMenuItem::hide(handle, Some("Hide Tenet"))?)
        .item(&PredefinedMenuItem::hide_others(handle, Some("Hide Others"))?)
        .item(&PredefinedMenuItem::show_all(handle, Some("Show All"))?)
        .separator()
        .item(&PredefinedMenuItem::quit(handle, Some("Quit Tenet"))?)
        .build()?;

    // ── File menu ───────────────────────────────────────────────────────
    // "Open Trace…" is now enabled with Cmd+O accelerator.
    let open_item = MenuItemBuilder::with_id("file_open", "Open Trace…")
        .accelerator("CmdOrCtrl+O")
        .build(handle)?;

    // Populate "Open Recent" from recent.json.
    let recents = read_recent_entries();
    let mut recent_sub = SubmenuBuilder::new(handle, "Open Recent");
    if recents.is_empty() {
        recent_sub = recent_sub.item(disabled!("file_recent_empty", "(No Recent Files)"));
    } else {
        for entry in &recents {
            // Truncate long paths for the menu label.
            let display = if entry.module_name.is_empty() {
                truncate_path(&entry.path, 60)
            } else {
                format!("{} — {}", entry.module_name, truncate_path(&entry.path, 40))
            };
            // Use the full path as the menu-item id so the frontend can open it.
            let item = MenuItemBuilder::with_id(
                format!("file_recent:{}", entry.path),
                display,
            )
            .build(handle)?;
            recent_sub = recent_sub.item(&item);
        }
    }
    let file_recent = recent_sub.build()?;

    let file_menu = SubmenuBuilder::new(handle, "File")
        .item(&open_item)
        .item(&file_recent)
        .separator()
        .item(&PredefinedMenuItem::close_window(handle, Some("Close Window"))?)
        .build()?;

    // ── View ────────────────────────────────────────────────────────────
    let view_core = SubmenuBuilder::new(handle, "Core Panels")
        .text("view_memory", "Mem Access")
        .text("view_hexdump", "Hex Dump")
        .separator()
        .text("view_callstack", "Call Stack")
        .text("view_functions", "Functions")
        .text("view_strings", "Strings")
        .separator()
        .text("view_analysis", "Analysis")
        .build()?;
    let view_visual = SubmenuBuilder::new(handle, "Visualization")
        .text("view_cfg", "CFG View")
        .text("view_callgraph", "Call Graph")
        .text("view_regtimeline", "Register Timeline")
        .text("view_dataflow", "Dataflow Graph")
        .build()?;
    let view_results = SubmenuBuilder::new(handle, "Analysis Results")
        .text("view_patterns", "Patterns")
        .text("view_constants", "Constants")
        .text("view_loops", "Loops")
        .text("view_algorithms", "Algorithm Summary")
        .separator()
        .text("view_objc", "ObjC Messages")
        .text("view_objccrypto", "ObjC Crypto")
        .text("view_api", "API Intercepts")
        .separator()
        .text("view_memstrings", "Memory Strings")
        .build()?;
    let view_profiling = SubmenuBuilder::new(handle, "Profiling & Diff")
        .text("view_tracefold", "Trace Fold")
        .text("view_winstats", "Window Stats")
        .text("view_dataflow2", "Dataflow Graph")
        .text("view_regtimeline2", "Register Timeline")
        .text("view_tracediff", "Trace Diff")
        .separator()
        .text("view_dwarf", "Symbol Info (DWARF)")
        .build()?;
    let view_newwindow = SubmenuBuilder::new(handle, "Open in New Window")
        .text("popout_vm", "VM Workspace")
        .build()?;
    let view_menu = SubmenuBuilder::new(handle, "View")
        .item(&view_core)
        .item(&view_visual)
        .item(&view_results)
        .item(&view_profiling)
        .separator()
        .text("view_log", "Output (Log)")
        .text("view_cache", "Cache Manager")
        .separator()
        .item(&view_newwindow)
        .separator()
        .text("view_settings", "Settings…")
        .text("view_theme_toggle", "Toggle Theme")
        .separator()
        .item(&PredefinedMenuItem::fullscreen(handle, Some("Toggle Full Screen"))?)
        .build()?;

    // ── Navigate ────────────────────────────────────────────────────────
    let navigate_menu = SubmenuBuilder::new(handle, "Navigate")
        .item(disabled!("nav_goto", "Go to Instruction…"))
        .item(disabled!("nav_search", "Search…"))
        .separator()
        .text("nav_back", "Back")
        .text("nav_forward", "Forward")
        .separator()
        .text("nav_first", "First Instruction")
        .text("nav_last", "Last Instruction")
        .separator()
        .text("nav_bookmark", "Toggle Bookmark")
        .build()?;

    // ── Analysis ────────────────────────────────────────────────────────
    let an_dataflow = SubmenuBuilder::new(handle, "Data Flow")
        .text("an_taint_fwd", "Forward Taint…")
        .text("an_taint_back", "Backward Taint…")
        .separator()
        .text("an_regtimeline", "Register Timeline")
        .text("an_dataflow_graph", "Dataflow Graph")
        .build()?;
    let an_structure = SubmenuBuilder::new(handle, "Structure")
        .text("an_functions", "Function Analysis")
        .text("an_strings", "String Analysis")
        .separator()
        .text("an_callgraph", "Call Graph")
        .text("an_loops", "Loop Analysis")
        .text("an_cfg", "CFG Layout")
        .build()?;
    let an_crypto = SubmenuBuilder::new(handle, "Crypto & Pattern")
        .text("an_patterns", "Pattern Detection")
        .text("an_constants", "Constants")
        .text("an_algorithms", "Algorithm Summary")
        .text("an_objccrypto", "ObjC Crypto")
        .build()?;
    let an_objcapi = SubmenuBuilder::new(handle, "ObjC / API")
        .text("an_objc", "ObjC Messages")
        .text("an_api", "API Intercepts")
        .build()?;
    let an_profiling = SubmenuBuilder::new(handle, "Profiling")
        .text("an_tracefold", "Trace Fold")
        .text("an_winstats", "Window Stats")
        .text("an_tracediff", "Trace Diff")
        .text("an_memstrings", "Memory Strings")
        .build()?;
    let analysis_menu = SubmenuBuilder::new(handle, "Analysis")
        .item(&an_dataflow)
        .item(&an_structure)
        .item(&an_crypto)
        .item(&an_objcapi)
        .item(&an_profiling)
        .separator()
        .text("an_clear", "Clear All Analysis")
        .build()?;

    // ── Export ───────────────────────────────────────────────────────────
    let export_menu = SubmenuBuilder::new(handle, "Export")
        .text("export_cfg", "Export CFG… (DOT)")
        .text("export_callgraph", "Export Call Graph… (DOT)")
        .separator()
        .text("export_backtaint", "Export Backward Taint Graph… (DOT)")
        .text("export_dataflow", "Export Dataflow Graph… (DOT)")
        .build()?;

    // ── Tools ───────────────────────────────────────────────────────────
    let tools_menu = SubmenuBuilder::new(handle, "Tools")
        .text("tools_entropy", "Entropy…")
        .text("tools_snapshot", "Memory Snapshot…")
        .separator()
        .text("tools_memsearch", "Memory / Value Search…")
        .text("tools_yara", "YARA Scan…")
        .separator()
        .text("tools_memhistory", "Memory Write History…")
        .text("tools_dataflow_cursor", "Dataflow Graph from Cursor…")
        .build()?;

    let menu = MenuBuilder::new(handle)
        .items(&[
            &app_menu,
            &file_menu,
            &view_menu,
            &navigate_menu,
            &analysis_menu,
            &export_menu,
            &tools_menu,
        ])
        .build()?;

    app.set_menu(menu)?;

    // Custom menu-item clicks → broadcast `menu://<id>` to the frontend.
    // Predefined items (quit / hide / close / fullscreen) are handled by the
    // system and never reach this callback.
    //
    // For dynamic "file_recent:<path>" items, emit a single known event
    // `menu://file_recent` with the path as payload, so the frontend can
    // register one listener instead of needing to know all paths at startup.
    app.on_menu_event(move |app_handle, event| {
        let id = event.id().0.as_str();
        if let Some(path) = id.strip_prefix("file_recent:") {
            let _ = app_handle.emit("menu://file_recent", path);
        } else {
            let _ = app_handle.emit(&format!("menu://{id}"), ());
        }
    });

    Ok(())
}

/// Truncate a filesystem path to at most `max_len` characters, preserving the
/// tail (filename + parent directory) and prefixing with "…/" if shortened.
fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        return path.to_string();
    }
    // Keep the last `max_len - 2` characters and prepend "…/"
    let start = path.len() - (max_len - 2);
    format!("…/{}", &path[start..])
}

// ── Entrypoint ──────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(OpenTraces(Mutex::new(HashSet::new())))
        .manage(BackendProcesses(Mutex::new(HashMap::new())))
        .invoke_handler(tauri::generate_handler![
            get_recent_files,
            is_trace_open,
            open_trace,
            close_trace,
            save_config,
            load_config,
        ])
        .setup(|app| {
            // Registered unconditionally (not just in debug builds) so the
            // `tenet-backend` target lines (forwarded sidecar stdout/stderr,
            // see `open_trace` above) are still captured somewhere durable
            // in release/bundled builds — the frontend "Output (Log)" panel
            // consumes the `backend-log` event directly, but this on-disk
            // copy is the fallback for post-mortem debugging (e.g. the app
            // crashed before the panel could be opened).
            app.handle().plugin(
                tauri_plugin_log::Builder::default()
                    .level(log::LevelFilter::Info)
                    .targets([
                        tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Stdout),
                        tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir {
                            file_name: None,
                        }),
                    ])
                    .build(),
            )?;
            build_and_set_menu(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // When the *last* window is about to close, kill every backend
            // process so we don't leave orphans.
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let app = window.app_handle();
                // Only clean up if this is the last visible window.
                if app.webview_windows().len() <= 1 {
                    kill_all_backends(app);
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
