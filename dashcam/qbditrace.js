/*
 * qbditrace - Frida agent for the QBDI-based high-performance tracer.
 *
 * This script is intentionally thin: it only loads the native tracer library
 * (.dylib on iOS, .so on Android), resolves addresses, and diverts the target
 * function into the QBDI VM. Every per-instruction operation happens in native
 * code, so this JS has ZERO impact on tracing speed (it runs once at setup,
 * and once per traced call).
 *
 * IMPORTANT: This script MUST be loaded via the Python runner (qbditrace_runner.py).
 * Do NOT use `frida -l qbditrace.js` directly — the CONFIG is injected by the
 * Python loader via script.post() before execution begins.
 *
 * Tracing semantics:
 *   The tracer instruments the ENTIRE target module (via addInstrumentedModuleFromAddr).
 *   The --entry function is just the trigger: tracing starts when it is called and
 *   ends when it returns. All execution within the module during that window is
 *   recorded; calls to system libraries run natively and are logged as transfer events.
 *
 * Workflow (hook mode — default):
 *   1. Python loader spawns/attaches to the target, loads this script.
 *   2. Python sends CONFIG via script.post({ type: 'config', payload: {...} }).
 *   3. This script receives CONFIG, loads libqbditrace.dylib, resolves addresses.
 *      Optional CONFIG.memSnapshot.ranges captures absolute runtime memory ranges.
 *   4. Interceptor.replace(entryFunc) -> qbditrace_run_call(retOut, func, args)
 *   5. After the call returns, qbditrace_stop() flushes the trace to disk.
 *   6. Script sends status messages back to Python via send().
 *
 * Workflow (invoke mode — CONFIG.invoke=true):
 *   1-3. Same as hook mode.
 *   4. materializeArgs() converts typed argument descriptors into NativePointer
 *      values (int, str, bytes, buf, nullptr, nsstr, nsdata, nsnum).
 *   5. Directly calls qbditrace_run_call(retOut, func, argc, argv) — no hook.
 *   6. qbditrace_stop() + report buf outputs + send trace_done/all_done.
 */

'use strict';

// ===========================================================================
// Wait for CONFIG from Python loader
// ===========================================================================

var CONFIG = null;

function log(msg) {
  send({ type: 'log', level: 'info', text: '[qbditrace] ' + msg });
}

function logError(msg) {
  send({ type: 'log', level: 'error', text: '[qbditrace][ERROR] ' + msg });
}

function fail(msg) {
  logError(msg);
  send({ type: 'error', text: msg });
  throw new Error(msg);
}

function status(event, detail) {
  send({ type: 'status', event: event, detail: detail || {} });
}

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

function loadDylib(path) {
  const dlopen = new NativeFunction(
      Module.getGlobalExportByName('dlopen'), 'pointer', ['pointer', 'int']);
  const dlerror = new NativeFunction(
      Module.getGlobalExportByName('dlerror'), 'pointer', []);
  const pathStr = Memory.allocUtf8String(path);
  const handle = dlopen(pathStr, 2 /* RTLD_NOW */);
  if (handle.isNull()) {
    const err = dlerror();
    const msg = err.isNull() ? 'unknown error' : err.readUtf8String();
    fail('dlopen failed for ' + path + ': ' + msg);
  }
  const m = Process.findModuleByName(path.split('/').pop());
  if (!m) {
    fail('dlopen succeeded but module not found by name: ' + path);
  }
  log('loaded library: ' + path + ' @ ' + m.base + ' (via dlopen)');
  return m;
}

function resolveExports(dylibModule) {
  const names = [
    'qbditrace_configure',
    'qbditrace_run_call',
    'qbditrace_stop',
    'qbditrace_output_path',
    'qbditrace_stats_page',
  ];
  const ex = {};
  for (const n of names) {
    const p = dylibModule.findExportByName(n);
    if (p === null || p.isNull()) {
      fail('export not found: ' + n + ' (is the dylib the tracer build?)');
    }
    ex[n] = p;
  }
  /* Phase 2 (multi-thread): optional export — older dylibs simply lack it,
   * and installPthreadHooks() disables itself when absent. */
  const runThread = dylibModule.findExportByName('qbditrace_run_thread');
  if (runThread !== null && !runThread.isNull()) {
    ex.qbditrace_run_thread = runThread;
  }
  /* Crash diagnostics: optional export — dumps the last-executed-PC ring
   * (in-memory, survives the fault) to a file or stderr. Used by the invoke/
   * hook fault recovery paths when the entry function SIGSEGVs inside the VM
   * (Frida's exceptor sees the fault before our native handler can run). */
  const dumpPcRing = dylibModule.findExportByName('qbditrace_dump_pcring');
  if (dumpPcRing !== null && !dumpPcRing.isNull()) {
    ex.qbditrace_dump_pcring = dumpPcRing;
  }
  return ex;
}

/* Resolve the target module. On Android spawn scenarios the module may not be
 * loaded yet (lazy System.loadLibrary) — poll asynchronously every 2s for up
 * to `timeoutMs` (default 60s). Calls `onResolved(module)` on success.
 * Busy-waiting would deadlock: the JS thread must yield for the app to make
 * progress loading the module. */
function resolveTargetModuleAsync(timeoutMs, onResolved, onRetry) {
  const deadline = Date.now() + (timeoutMs || 60000);
  function attempt() {
    let m;
    if (CONFIG.moduleName) {
      m = Process.findModuleByName(CONFIG.moduleName);
    } else {
      m = Process.enumerateModules()[0];
    }
    if (m) {
      log('target module: ' + m.name + ' base=' + m.base + ' size=0x' +
          m.size.toString(16) + ' (' + m.size + ' bytes)');
      onResolved(m);
      return;
    }
    if (Date.now() >= deadline) {
      fail('module not found (waited ' + Math.round((timeoutMs || 60000) / 1000) +
           's): ' + CONFIG.moduleName);
      return;
    }
    if (onRetry) onRetry(Math.round((deadline - Date.now()) / 1000));
    setTimeout(attempt, 2000);
  }
  attempt();
}

function buildNativeFunctions(ex) {
  const fns = {
    configure: new NativeFunction(ex.qbditrace_configure, 'int', ['pointer']),
    runCall: new NativeFunction(ex.qbditrace_run_call, 'int',
        ['pointer', 'pointer', 'uint32', 'pointer']),
    stop: new NativeFunction(ex.qbditrace_stop, 'void', []),
    outputPath: new NativeFunction(ex.qbditrace_output_path, 'pointer', []),
    statsPage: new NativeFunction(ex.qbditrace_stats_page, 'pointer', []),
  };
  if (ex.qbditrace_run_thread) {
    fns.runThread = new NativeFunction(ex.qbditrace_run_thread, 'int',
        ['pointer', 'pointer', 'pointer']);
  }
  if (ex.qbditrace_dump_pcring) {
    fns.dumpPcRing = new NativeFunction(ex.qbditrace_dump_pcring, 'int',
        ['pointer']);
  }
  return fns;
}

function buildConfigStruct(opts) {
  /* Must match sizeof(qbditrace_config_t) — see QBDITrace.h for the canonical
   * layout.
   *
   * offset   0  struct_size          u32
   * offset   4  _reserved0           u32
   * offset   8  trace_start          u64
   * offset  16  trace_end            u64
   * offset  24  module_base          u64
   * offset  32  module_slide         u64
   * offset  40  module_name          ptr
   * offset  48  output_path          ptr
   * offset  56  record               u32
   * offset  60  anchor_interval      u32
   * offset  64  ring_bytes           u64
   * offset  72  objc_msgSend         u64
   * offset  80  objc_msgSendSuper    u64
   * offset  88  objc_msgSendSuper2   u64
   * offset  96  objc_msgSend_stret   u64
   * offset 104  extra_range_start    u64
   * offset 112  extra_range_end      u64
   * offset 120  disable_embed_code   u32
   * offset 124  enable_pc_delta      u32
   * offset 128  _reserved_old_value  u32  (deprecated, ignored)
   * offset 132  enable_fpr           u32
   * offset 136  disable_compress     u32
   * offset 140  disable_branch_hint  u32
   * offset 144  n_exclude_ranges     u32
   * offset 148  _pad_exclude         u32
   * offset 152  exclude_ranges[0..7] 8×{u64 start, u64 end} = 128 bytes
   * offset 280  enable_capi_intercept u32
   * offset 284  n_capi_funcs          u32
   * offset 288  capi_funcs[0..127]   128×{u64 addr, u16 api_id, u8 n_args, u8 str_args, u8 pad[4]}
   *                                  = 128×16 = 2048 bytes (C natural alignment: the struct's
   *                                  8-byte alignment pads each 12-byte entry up to 16)
   * offset 2336 enable_mem_snapshot  u32
   * offset 2340 n_snapshot_ranges    u32
   * offset 2344 snapshot_ranges[0..7] 8×{u64 start, u64 end} = 128 bytes
   *
   * Offset derivation: capi_funcs starts at 288 and occupies 128×16 = 2048
   * bytes, ending at 2336. The two u32 fields occupy 8 bytes, so the u64-aligned
   * range array starts naturally at 2344 with no extra padding.
   * Total: 2344 + 128 = 2472 bytes
   */
  const SIZE = 2472;
  const cfg = Memory.alloc(SIZE);
  for (let i = 0; i < SIZE; i += 8) cfg.add(i).writePointer(ptr(0));

  const moduleNameStr = opts.moduleName
      ? Memory.allocUtf8String(opts.moduleName) : NULL;
  const outputPathStr = opts.outputPath
      ? Memory.allocUtf8String(opts.outputPath) : NULL;
  cfg._keep = [moduleNameStr, outputPathStr];

  cfg.add(0).writeU32(SIZE);
  cfg.add(8).writePointer(opts.traceStart);
  cfg.add(16).writePointer(opts.traceEnd);
  cfg.add(24).writePointer(opts.moduleBase);
  cfg.add(32).writePointer(opts.moduleSlide);
  cfg.add(40).writePointer(moduleNameStr);
  cfg.add(48).writePointer(outputPathStr);
  cfg.add(56).writeU32(opts.record >>> 0);
  cfg.add(60).writeU32(opts.anchorInterval >>> 0);
  cfg.add(64).writePointer(ptr(opts.ringBytes));
  cfg.add(72).writePointer(opts.objcMsgSend || NULL);
  cfg.add(80).writePointer(opts.objcMsgSendSuper || NULL);
  cfg.add(88).writePointer(opts.objcMsgSendSuper2 || NULL);
  cfg.add(96).writePointer(opts.objcMsgSendStret || NULL);
  cfg.add(104).writePointer(opts.extraRangeStart || NULL);
  cfg.add(112).writePointer(opts.extraRangeEnd || NULL);
  cfg.add(120).writeU32(opts.embedCode === false ? 1 : 0);
  cfg.add(124).writeU32(opts.pcDelta    ? 1 : 0);
  cfg.add(128).writeU32(0); /* _reserved_old_value: deprecated, always 0 */
  cfg.add(132).writeU32(opts.fpr        ? 1 : 0);
  cfg.add(136).writeU32(opts.noCompress ? 1 : 0);
  cfg.add(140).writeU32(opts.noBranchHint ? 1 : 0);
  /* Exclude ranges array: up to 8 entries */
  const excludes = opts.excludeRanges || [];
  cfg.add(144).writeU32(excludes.length);
  /* offset 148 is _pad_exclude, already zeroed */
  for (let i = 0; i < excludes.length && i < 8; i++) {
    const base = 152 + i * 16;
    cfg.add(base).writePointer(excludes[i].start);
    cfg.add(base + 8).writePointer(excludes[i].end);
  }

  /* C API interception */
  const capiFuncs = opts.capiFuncs || [];
  cfg.add(280).writeU32(opts.enableCapiIntercept ? 1 : 0);
  cfg.add(284).writeU32(capiFuncs.length);
  /* Each capi_funcs entry is 16 bytes (12 bytes of fields + 4 bytes of
   * trailing alignment padding, matching the native struct's 8-byte alignment):
   *   u64 addr      (offset 0)
   *   u16 api_id    (offset 8)
   *   u8  n_args    (offset 10)
   *   u8  str_args  (offset 11)
   *   u8  _pad[4]   (offset 12, already zeroed)
   */
  for (let i = 0; i < capiFuncs.length && i < 128; i++) {
   const base = 288 + i * 16;
   cfg.add(base).writePointer(capiFuncs[i].addr || NULL);
   cfg.add(base + 8).writeU16(capiFuncs[i].apiId || 0);
   cfg.add(base + 10).writeU8(capiFuncs[i].nArgs || 0);
   cfg.add(base + 11).writeU8(capiFuncs[i].strArgs || 0);
  }

  /* Opt-in memory image snapshot. Ranges are absolute runtime addresses. */
  const snapshotRanges = opts.snapshotRanges || [];
  cfg.add(2336).writeU32(snapshotRanges.length > 0 ? 1 : 0);
  cfg.add(2340).writeU32(snapshotRanges.length);
  for (let i = 0; i < snapshotRanges.length && i < 8; i++) {
    const base = 2344 + i * 16;
    cfg.add(base).writePointer(snapshotRanges[i].start);
    cfg.add(base + 8).writePointer(snapshotRanges[i].end);
  }
  return cfg;
}

function isAndroid() {
  return Process.platform === 'linux';
}

const QBDITRACE_REC_MSGSEND = 1 << 4;
const OBJC_DISPATCHERS = [
  { key: 'objcMsgSend', configKey: 'objc_msgSend', symbol: 'objc_msgSend' },
  { key: 'objcMsgSendSuper', configKey: 'objc_msgSendSuper', symbol: 'objc_msgSendSuper' },
  { key: 'objcMsgSendSuper2', configKey: 'objc_msgSendSuper2', symbol: 'objc_msgSendSuper2' },
  { key: 'objcMsgSendStret', configKey: 'objc_msgSend_stret', symbol: 'objc_msgSend_stret' },
];

/* Pure policy helper. `lookup` is injected so precedence and disabled-platform
 * behavior can be tested without a Frida runtime. */
function planObjcDispatchers(config, platform, lookup) {
  const enabled = config.resolveObjc !== false &&
      ((config.record >>> 0) & QBDITRACE_REC_MSGSEND) !== 0;
  const result = { enabled: enabled, platform: platform, entries: [], missing: [] };

  for (const descriptor of OBJC_DISPATCHERS) {
    let address = null;
    let source = 'missing';
    const explicit = config[descriptor.key] !== undefined
        ? config[descriptor.key] : config[descriptor.configKey];

    if (enabled && platform !== 'linux') {
      if (explicit !== undefined && explicit !== null && explicit !== 0 && explicit !== '0' &&
          explicit !== '0x0') {
        address = lookup.explicit(explicit);
        if (address !== null) source = 'explicit';
      }
      if (address === null) {
        address = lookup.global(descriptor.symbol);
        if (address !== null) source = 'global';
      }
      if (address === null) {
        address = lookup.module(descriptor.symbol);
        if (address !== null) source = 'module';
      }
    }

    result.entries.push({
      key: descriptor.key,
      symbol: descriptor.symbol,
      address: address,
      source: source,
    });
    if (address === null) result.missing.push(descriptor.symbol);
  }
  return result;
}

function resolveObjcDispatchers() {
  let objcModule;

  function validPointer(value) {
    return value && !value.isNull() ? value : null;
  }

  const plan = planObjcDispatchers(CONFIG, Process.platform, {
    explicit(value) {
      try { return validPointer(ptr(value)); } catch (e) { return null; }
    },
    global(symbol) {
      try { return validPointer(Module.findGlobalExportByName(symbol)); }
      catch (e) { return null; }
    },
    module(symbol) {
      if (objcModule === undefined) {
        objcModule = Process.findModuleByName('libobjc.A.dylib');
      }
      if (!objcModule) return null;
      try { return validPointer(objcModule.findExportByName(symbol)); }
      catch (e) { return null; }
    },
  });

  const out = {
    objcMsgSend: NULL,
    objcMsgSendSuper: NULL,
    objcMsgSendSuper2: NULL,
    objcMsgSendStret: NULL,
  };

  if (!plan.enabled) {
    log('ObjC capture: disabled (record does not include MSGSEND or resolution was disabled)');
  } else if (isAndroid()) {
    /* Do not touch an ObjC bridge or runtime module on Android. */
    log('ObjC capture: unsupported on Android; dispatcher resolution skipped');
  } else {
    for (const entry of plan.entries) {
      if (entry.address !== null) out[entry.key] = entry.address;
    }
  }

  const addresses = plan.entries.map(function(entry) {
    return entry.symbol + '=' + (entry.address === null ? '0 (missing)' :
        entry.address + ' [' + entry.source + ']');
  }).join(', ');
  const selectorInlineCaptureAvailable = plan.enabled && !isAndroid() &&
      plan.entries.some(function(entry) { return entry.address !== null; });
  log('ObjC dispatchers: ' + addresses);
  log('ObjC coverage: direct symbol configured=' +
      (plan.entries[0].address !== null ? 'yes' : 'no') +
      '; selector inline capture available=' +
      (selectorInlineCaptureAvailable ? 'yes' : 'no') +
      '; objc_msgSend$selector stubs=' +
      (plan.enabled && !isAndroid() && plan.entries[0].address !== null
        ? 'resolve via transfer target (individual stubs are not configured)'
        : 'unsupported (objc_msgSend transfer target unavailable)'));
  if (plan.missing.length > 0) log('ObjC missing: ' + plan.missing.join(', '));

  out.diagnostic = {
    enabled: plan.enabled,
    platform: plan.platform,
    addresses: plan.entries.reduce(function(acc, entry) {
      acc[entry.symbol] = entry.address === null ? '0' : entry.address.toString();
      return acc;
    }, {}),
    missing: plan.missing,
    directSymbolConfigured: plan.entries[0].address !== null,
    selectorInlineCaptureAvailable: selectorInlineCaptureAvailable,
    selectorStubs: plan.enabled && !isAndroid() && plan.entries[0].address !== null
        ? 'transfer-target' : 'unsupported',
  };
  return out;
}

// ---------------------------------------------------------------------------
// C API function resolution
// ---------------------------------------------------------------------------

/* Standard platform functions (memcpy, strcmp, CC_SHA256, EVP_*, sqlite3_*, etc.)
 * are resolved by the native tracer's resolveCApiAddrsIntoConfig() at configure()
 * time via dlsym.  The JS side only handles two things that native cannot:
 *
 *   1. JNI vtable functions — not exported symbols; must be read from the
 *      JNINativeInterface_ function-pointer table at runtime.
 *   2. User-supplied custom addresses — passed in via CONFIG.capiJniFuncs
 *      from the Python runner (--capi-funcs).
 *
 * When capiFuncs is non-empty the native side appends them to its own table;
 * when capiFuncs is empty but enableCapiIntercept is true, the native side
 * resolves everything itself.
 */

/* ---------------------------------------------------------------------------
 * JNI vtable auto-resolution.
 *
 * JNI functions (FindClass, GetMethodID, CallObjectMethod, etc.) are NOT
 * exported symbols — they live in a virtual function pointer table pointed to
 * by JNIEnv->functions. The vtable layout is fixed by the JNI spec
 * (jni.h / JNINativeInterface_), so we can read function pointers directly.
 *
 * Strategy:
 *   1. Locate a JNIEnv pointer. On Android the JavaVM is available via
 *      `JNI_GetCreatedJavaVMs` (exported from libart.so or libjvm.so).
 *      Calling GetEnv() on the JavaVM gives us the JNIEnv for the current
 *      thread.
 *   2. Dereference env->functions (pointer at offset 0 of JNIEnv struct).
 *   3. Index into the vtable using the well-known slot offsets from jni.h.
 *
 * All offsets are for 64-bit AArch64 (8 bytes per pointer slot).
 *
 * ⚠ The slot numbers below follow the JNINativeInterface_ vtable layout as
 * FIXED BY THE JNI SPECIFICATION (0-based index; reserved0-3 occupy 0..3).
 * Every Call*Method family occupies THREE consecutive slots (Method,
 * MethodV, MethodA). Key reference points: GetVersion=4, GetMethodID=33,
 * CallVoidMethod=61, GetFieldID=94, GetStaticMethodID=113, GetStaticFieldID=144,
 * NewString=163, NewStringUTF=167, GetStringUTFChars=169, GetArrayLength=171,
 * GetByteArrayElements=184, RegisterNatives=215, GetJavaVM=219,
 * ExceptionCheck=228, GetObjectRefType=232.
 *
 * 112 high-value slots are intercepted (crypto-relevant string/array ops,
 * RegisterNatives binding-table exposure, direct byte buffers, all common
 * Call/Field families). api_ids are allocated in TraceFormat.h:
 * 280-301 (base), 302-359 (full vtable coverage), 700-731 (extended).
 */
var JNI_VTABLE_SLOTS = [
  // -- version / class / exceptions (4-18) --
  { slot:   4, apiId: 723, nArgs: 1, strArgs: 0x00, name: 'GetVersion' },
  { slot:   5, apiId: 300, nArgs: 4, strArgs: 0x02, name: 'DefineClass' },   // a1=name
  { slot:   6, apiId: 289, nArgs: 2, strArgs: 0x02, name: 'FindClass' },     // a1=name
  { slot:  10, apiId: 313, nArgs: 2, strArgs: 0x00, name: 'GetSuperclass' },
  { slot:  13, apiId: 321, nArgs: 2, strArgs: 0x00, name: 'Throw' },
  { slot:  14, apiId: 320, nArgs: 3, strArgs: 0x04, name: 'ThrowNew' },      // a2=msg
  { slot:  15, apiId: 319, nArgs: 1, strArgs: 0x00, name: 'ExceptionOccurred' },
  { slot:  17, apiId: 299, nArgs: 1, strArgs: 0x00, name: 'ExceptionClear' },
  // -- local/global refs (19-26) --
  { slot:  19, apiId: 721, nArgs: 2, strArgs: 0x00, name: 'PushLocalFrame' },
  { slot:  20, apiId: 722, nArgs: 2, strArgs: 0x00, name: 'PopLocalFrame' },
  { slot:  21, apiId: 718, nArgs: 2, strArgs: 0x00, name: 'NewGlobalRef' },
  { slot:  22, apiId: 719, nArgs: 2, strArgs: 0x00, name: 'DeleteGlobalRef' },
  { slot:  23, apiId: 720, nArgs: 2, strArgs: 0x00, name: 'DeleteLocalRef' },
  { slot:  24, apiId: 317, nArgs: 3, strArgs: 0x00, name: 'IsSameObject' },
  { slot:  25, apiId: 318, nArgs: 2, strArgs: 0x00, name: 'NewLocalRef' },
  // -- object construction (27-32) --
  { slot:  28, apiId: 716, nArgs: 3, strArgs: 0x00, name: 'NewObject' },
  { slot:  31, apiId: 312, nArgs: 2, strArgs: 0x00, name: 'GetObjectClass' },
  { slot:  32, apiId: 717, nArgs: 3, strArgs: 0x00, name: 'IsInstanceOf' },
  // -- instance method calls (33-63; each family = Method/V/A x3) --
  { slot:  33, apiId: 290, nArgs: 4, strArgs: 0x06, name: 'GetMethodID' },   // a2=name,a3=sig
  { slot:  34, apiId: 292, nArgs: 3, strArgs: 0x00, name: 'CallObjectMethod' },
  { slot:  37, apiId: 295, nArgs: 3, strArgs: 0x00, name: 'CallBooleanMethod' },
  { slot:  40, apiId: 336, nArgs: 3, strArgs: 0x00, name: 'CallByteMethod' },
  { slot:  43, apiId: 337, nArgs: 3, strArgs: 0x00, name: 'CallCharMethod' },
  { slot:  46, apiId: 338, nArgs: 3, strArgs: 0x00, name: 'CallShortMethod' },
  { slot:  49, apiId: 296, nArgs: 3, strArgs: 0x00, name: 'CallIntMethod' },
  { slot:  52, apiId: 297, nArgs: 3, strArgs: 0x00, name: 'CallLongMethod' },
  { slot:  55, apiId: 339, nArgs: 3, strArgs: 0x00, name: 'CallFloatMethod' },
  { slot:  58, apiId: 340, nArgs: 3, strArgs: 0x00, name: 'CallDoubleMethod' },
  { slot:  61, apiId: 294, nArgs: 3, strArgs: 0x00, name: 'CallVoidMethod' },
  // -- nonvirtual calls (64-93) --
  { slot:  64, apiId: 341, nArgs: 4, strArgs: 0x00, name: 'CallNonvirtualObjectMethod' },
  { slot:  79, apiId: 342, nArgs: 4, strArgs: 0x00, name: 'CallNonvirtualIntMethod' },
  { slot:  82, apiId: 343, nArgs: 4, strArgs: 0x00, name: 'CallNonvirtualLongMethod' },
  { slot:  91, apiId: 344, nArgs: 4, strArgs: 0x00, name: 'CallNonvirtualVoidMethod' },
  // -- instance fields (94-112) --
  { slot:  94, apiId: 704, nArgs: 4, strArgs: 0x06, name: 'GetFieldID' },    // a2=name,a3=sig
  { slot:  95, apiId: 702, nArgs: 3, strArgs: 0x00, name: 'GetObjectField' },
  { slot:  96, apiId: 323, nArgs: 3, strArgs: 0x00, name: 'GetBooleanField' },
  { slot:  97, apiId: 324, nArgs: 3, strArgs: 0x00, name: 'GetByteField' },
  { slot:  98, apiId: 325, nArgs: 3, strArgs: 0x00, name: 'GetCharField' },
  { slot:  99, apiId: 326, nArgs: 3, strArgs: 0x00, name: 'GetShortField' },
  { slot: 100, apiId: 700, nArgs: 3, strArgs: 0x00, name: 'GetIntField' },
  { slot: 101, apiId: 701, nArgs: 3, strArgs: 0x00, name: 'GetLongField' },
  { slot: 104, apiId: 703, nArgs: 4, strArgs: 0x00, name: 'SetObjectField' },
  { slot: 109, apiId: 327, nArgs: 4, strArgs: 0x00, name: 'SetIntField' },
  { slot: 110, apiId: 328, nArgs: 4, strArgs: 0x00, name: 'SetLongField' },
  // -- static methods (113-143) --
  { slot: 113, apiId: 291, nArgs: 4, strArgs: 0x06, name: 'GetStaticMethodID' }, // a2=name,a3=sig
  { slot: 114, apiId: 293, nArgs: 3, strArgs: 0x00, name: 'CallStaticObjectMethod' },
  { slot: 117, apiId: 715, nArgs: 3, strArgs: 0x00, name: 'CallStaticBooleanMethod' },
  { slot: 120, apiId: 346, nArgs: 3, strArgs: 0x00, name: 'CallStaticByteMethod' },
  { slot: 123, apiId: 347, nArgs: 3, strArgs: 0x00, name: 'CallStaticCharMethod' },
  { slot: 129, apiId: 714, nArgs: 3, strArgs: 0x00, name: 'CallStaticIntMethod' },
  { slot: 132, apiId: 345, nArgs: 3, strArgs: 0x00, name: 'CallStaticLongMethod' },
  { slot: 138, apiId: 348, nArgs: 3, strArgs: 0x00, name: 'CallStaticDoubleMethod' },
  { slot: 141, apiId: 731, nArgs: 3, strArgs: 0x00, name: 'CallStaticVoidMethod' },
  // -- static fields (144-162) --
  { slot: 144, apiId: 705, nArgs: 4, strArgs: 0x06, name: 'GetStaticFieldID' },
  { slot: 145, apiId: 329, nArgs: 3, strArgs: 0x00, name: 'GetStaticObjectField' },
  { slot: 146, apiId: 330, nArgs: 3, strArgs: 0x00, name: 'GetStaticBooleanField' },
  { slot: 150, apiId: 331, nArgs: 3, strArgs: 0x00, name: 'GetStaticIntField' },
  { slot: 151, apiId: 332, nArgs: 3, strArgs: 0x00, name: 'GetStaticLongField' },
  { slot: 154, apiId: 333, nArgs: 4, strArgs: 0x00, name: 'SetStaticObjectField' },
  { slot: 159, apiId: 334, nArgs: 4, strArgs: 0x00, name: 'SetStaticIntField' },
  { slot: 160, apiId: 335, nArgs: 4, strArgs: 0x00, name: 'SetStaticLongField' },
  // -- strings (163-170) --
  { slot: 163, apiId: 302, nArgs: 3, strArgs: 0x00, name: 'NewString' },
  { slot: 164, apiId: 303, nArgs: 2, strArgs: 0x00, name: 'GetStringLength' },
  { slot: 165, apiId: 304, nArgs: 3, strArgs: 0x00, name: 'GetStringChars' },
  { slot: 166, apiId: 305, nArgs: 3, strArgs: 0x00, name: 'ReleaseStringChars' },
  { slot: 167, apiId: 282, nArgs: 2, strArgs: 0x02, name: 'NewStringUTF' },  // a1=bytes
  { slot: 168, apiId: 283, nArgs: 2, strArgs: 0x00, name: 'GetStringUTFLength' },
  { slot: 169, apiId: 280, nArgs: 3, strArgs: 0x00, name: 'GetStringUTFChars' },
  { slot: 170, apiId: 281, nArgs: 3, strArgs: 0x00, name: 'ReleaseStringUTFChars' },
  // -- arrays (171-214) --
  { slot: 171, apiId: 707, nArgs: 2, strArgs: 0x00, name: 'GetArrayLength' },
  { slot: 172, apiId: 708, nArgs: 4, strArgs: 0x00, name: 'NewObjectArray' },
  { slot: 173, apiId: 709, nArgs: 3, strArgs: 0x00, name: 'GetObjectArrayElement' },
  { slot: 174, apiId: 710, nArgs: 4, strArgs: 0x00, name: 'SetObjectArrayElement' },
  { slot: 176, apiId: 288, nArgs: 2, strArgs: 0x00, name: 'NewByteArray' },
  { slot: 177, apiId: 349, nArgs: 2, strArgs: 0x00, name: 'NewCharArray' },
  { slot: 178, apiId: 350, nArgs: 2, strArgs: 0x00, name: 'NewShortArray' },
  { slot: 179, apiId: 711, nArgs: 2, strArgs: 0x00, name: 'NewIntArray' },
  { slot: 180, apiId: 351, nArgs: 2, strArgs: 0x00, name: 'NewLongArray' },
  { slot: 181, apiId: 352, nArgs: 2, strArgs: 0x00, name: 'NewFloatArray' },
  { slot: 182, apiId: 353, nArgs: 2, strArgs: 0x00, name: 'NewDoubleArray' },
  { slot: 184, apiId: 284, nArgs: 3, strArgs: 0x00, name: 'GetByteArrayElements' },
  { slot: 185, apiId: 354, nArgs: 3, strArgs: 0x00, name: 'GetCharArrayElements' },
  { slot: 186, apiId: 356, nArgs: 3, strArgs: 0x00, name: 'GetShortArrayElements' },
  { slot: 187, apiId: 712, nArgs: 3, strArgs: 0x00, name: 'GetIntArrayElements' },
  { slot: 188, apiId: 358, nArgs: 3, strArgs: 0x00, name: 'GetLongArrayElements' },
  { slot: 192, apiId: 285, nArgs: 4, strArgs: 0x00, name: 'ReleaseByteArrayElements' },
  { slot: 193, apiId: 355, nArgs: 4, strArgs: 0x00, name: 'ReleaseCharArrayElements' },
  { slot: 194, apiId: 357, nArgs: 4, strArgs: 0x00, name: 'ReleaseShortArrayElements' },
  { slot: 195, apiId: 713, nArgs: 4, strArgs: 0x00, name: 'ReleaseIntArrayElements' },
  { slot: 196, apiId: 359, nArgs: 4, strArgs: 0x00, name: 'ReleaseLongArrayElements' },
  { slot: 200, apiId: 286, nArgs: 5, strArgs: 0x00, name: 'GetByteArrayRegion' },
  { slot: 203, apiId: 727, nArgs: 5, strArgs: 0x00, name: 'GetIntArrayRegion' },
  { slot: 204, apiId: 729, nArgs: 5, strArgs: 0x00, name: 'GetLongArrayRegion' },
  { slot: 208, apiId: 287, nArgs: 5, strArgs: 0x00, name: 'SetByteArrayRegion' },
  { slot: 211, apiId: 728, nArgs: 5, strArgs: 0x00, name: 'SetIntArrayRegion' },
  { slot: 212, apiId: 730, nArgs: 5, strArgs: 0x00, name: 'SetLongArrayRegion' },
  // -- native registration / sync (215-219) --
  /* RegisterNatives exposes the JNINativeMethod binding table:
   * x2 = methods array pointer, x3 = nMethods count. */
  { slot: 215, apiId: 301, nArgs: 4, strArgs: 0x00, name: 'RegisterNatives' },
  { slot: 216, apiId: 322, nArgs: 2, strArgs: 0x00, name: 'UnregisterNatives' },
  { slot: 217, apiId: 724, nArgs: 2, strArgs: 0x00, name: 'MonitorEnter' },
  { slot: 218, apiId: 725, nArgs: 2, strArgs: 0x00, name: 'MonitorExit' },
  { slot: 219, apiId: 726, nArgs: 2, strArgs: 0x00, name: 'GetJavaVM' },
  // -- string regions / critical (220-225) --
  { slot: 220, apiId: 306, nArgs: 5, strArgs: 0x00, name: 'GetStringRegion' },
  { slot: 221, apiId: 706, nArgs: 5, strArgs: 0x00, name: 'GetStringUTFRegion' },
  { slot: 222, apiId: 307, nArgs: 3, strArgs: 0x00, name: 'GetPrimitiveArrayCritical' },
  { slot: 223, apiId: 308, nArgs: 4, strArgs: 0x00, name: 'ReleasePrimitiveArrayCritical' },
  // -- weak refs / exceptions / direct buffers (226-232) --
  { slot: 226, apiId: 315, nArgs: 2, strArgs: 0x00, name: 'NewWeakGlobalRef' },
  { slot: 227, apiId: 316, nArgs: 2, strArgs: 0x00, name: 'DeleteWeakGlobalRef' },
  { slot: 228, apiId: 298, nArgs: 1, strArgs: 0x00, name: 'ExceptionCheck' },
  { slot: 229, apiId: 309, nArgs: 3, strArgs: 0x00, name: 'NewDirectByteBuffer' },
  { slot: 230, apiId: 310, nArgs: 2, strArgs: 0x00, name: 'GetDirectBufferAddress' },
  { slot: 231, apiId: 311, nArgs: 2, strArgs: 0x00, name: 'GetDirectBufferCapacity' },
  { slot: 232, apiId: 314, nArgs: 2, strArgs: 0x00, name: 'GetObjectRefType' },
];

/* Attempt to obtain a JNIEnv pointer via JNI_GetCreatedJavaVMs (libart.so).
 * Returns a NativePointer to the JNINativeInterface_ vtable, or null. */
function resolveJniVtable() {
  if (!isAndroid()) return null;

  /* Step 1: find JNI_GetCreatedJavaVMs in libart.so (or libjvm.so). */
  var getVMsFn = null;
  var artLibs = ['libart.so', 'libjvm.so', 'libdvm.so'];
  for (var i = 0; i < artLibs.length; i++) {
    try {
      var p = Process.findModuleByName(artLibs[i]);
      if (p) {
        var ep = p.findExportByName('JNI_GetCreatedJavaVMs');
        if (ep && !ep.isNull()) { getVMsFn = ep; break; }
      }
    } catch (e) {}
  }
  if (!getVMsFn) {
    /* Fallback: global search */
    try { getVMsFn = Module.getGlobalExportByName('JNI_GetCreatedJavaVMs'); } catch (e) {}
  }
  if (!getVMsFn || getVMsFn.isNull()) {
    log('JNI vtable: JNI_GetCreatedJavaVMs not found — skipping vtable resolution');
    return null;
  }

  try {
    /* JNI_GetCreatedJavaVMs(JavaVM** vmBuf, jsize bufLen, jsize* nVMs) */
    var vmBuf = Memory.alloc(8);   /* one pointer */
    var nVMs  = Memory.alloc(4);
    var fn = new NativeFunction(getVMsFn, 'int', ['pointer', 'int', 'pointer']);
    var rc = fn(vmBuf, 1, nVMs);
    if (rc !== 0 || nVMs.readU32() === 0) {
      log('JNI vtable: JNI_GetCreatedJavaVMs returned rc=' + rc + ' nVMs=' + nVMs.readU32());
      return null;
    }
    var vm = vmBuf.readPointer();  /* JavaVM* */
    if (vm.isNull()) return null;

    /* Step 2: JavaVM->GetEnv(JavaVM*, void**, jint version) */
    /* JNIInvokeInterface_ layout (as array indices from the vtable pointer):
     *   [0..2] = reserved0..2, [3] = DestroyJavaVM,
     *   [4] = AttachCurrentThread, [5] = DetachCurrentThread,
     *   [6] = GetEnv, [7] = AttachCurrentThreadAsDaemon.
     * GetEnv is therefore at byte offset 6 * pointerSize. (An earlier version
     * used 3 here — that slot is DestroyJavaVM, which blocks waiting for all
     * attached threads to exit and never returns GetEnv's JNIEnv.) */
    var vmVtable = vm.readPointer();  /* JNIInvokeInterface_ * */
    var getEnvFnPtr = vmVtable.add(6 * Process.pointerSize).readPointer();
    if (getEnvFnPtr.isNull()) return null;

    var getEnvFn = new NativeFunction(getEnvFnPtr, 'int', ['pointer', 'pointer', 'int']);
    var envBuf = Memory.alloc(8);
    var JNI_VERSION_1_6 = 0x00010006;
    rc = getEnvFn(vm, envBuf, JNI_VERSION_1_6);
    if (rc === -2 /* JNI_EDETACHED: this thread (the Frida gum-js thread) is
                   * not attached to the VM yet. Attach it first — slot 4 is
                   * AttachCurrentThread(JavaVM*, JNIEnv**, JavaVMAttachArgs*),
                   * and NULL args selects the defaults. */ ) {
      var attachFnPtr = vmVtable.add(4 * Process.pointerSize).readPointer();
      var attachFn = new NativeFunction(attachFnPtr, 'int',
          ['pointer', 'pointer', 'pointer']);
      rc = attachFn(vm, envBuf, NULL);
      if (rc === 0) {
        log('JNI vtable: thread was detached — attached to VM, retrying GetEnv');
        rc = getEnvFn(vm, envBuf, JNI_VERSION_1_6);
      }
    }
    if (rc !== 0) {
      log('JNI vtable: GetEnv failed rc=' + rc);
      return null;
    }
    var env = envBuf.readPointer();   /* JNIEnv* */
    if (env.isNull()) return null;

    /* Step 3: vtable = *env (pointer to JNINativeInterface_) */
    var vtable = env.readPointer();
    if (vtable.isNull()) return null;

    log('JNI vtable resolved @ ' + vtable + ' (via JNIEnv @ ' + env + ')');
    return vtable;
  } catch (e) {
    log('JNI vtable: exception during resolution: ' + e.message);
    return null;
  }
}

/* Read function pointers from the JNI vtable for each slot in JNI_VTABLE_SLOTS.
 * Deduplicates by address (some vtable slots alias the same implementation). */
function resolveJniFunctions(vtable) {
  if (!vtable) return [];
  var result = [];
  var seen = {};  /* addr string => true, for dedup */
  var ptrSize = Process.pointerSize;

  for (var i = 0; i < JNI_VTABLE_SLOTS.length; i++) {
    var s = JNI_VTABLE_SLOTS[i];
    try {
      var fnPtr = vtable.add(s.slot * ptrSize).readPointer();
      if (fnPtr.isNull()) continue;
      var key = fnPtr.toString();
      if (seen[key]) continue;  /* skip duplicate implementations */
      seen[key] = true;
      result.push({
        addr: fnPtr,
        apiId: s.apiId,
        nArgs: s.nArgs,
        strArgs: s.strArgs,
      });
    } catch (e) {
      /* unreadable slot — skip */
    }
  }
  log('JNI vtable: resolved ' + result.length + ' unique function pointers');
  return result;
}

/* Collect the extra function addresses that native dlsym cannot reach:
 *   - JNI vtable pointers (Android only; these are not exported symbols)
 *   - User-supplied custom addresses from CONFIG.capiJniFuncs
 *
 * Standard platform functions (memcpy, strcmp, CC_SHA256, EVP_*, …) are
 * resolved by resolveCApiAddrsIntoConfig() inside the native tracer at
 * configure() time.  We pass an empty list here (or just the extras above)
 * and native handles the rest automatically when n_capi_funcs == 0.
 */
function resolveCApiFunctions() {
  var resolved = [];
  var seen = {};  /* addr string => true, dedup */

  function addEntry(addrPtr, apiId, nArgs, strArgs) {
    if (!addrPtr || addrPtr.isNull()) return;  /* skip NULL/invalid addresses */
    var key = addrPtr.toString();
    if (seen[key]) return;
    seen[key] = true;
    resolved.push({ addr: addrPtr, apiId: apiId, nArgs: nArgs, strArgs: strArgs });
  }

  /* 1. JNI vtable (Android only) */
  if (isAndroid()) {
    var jniVtable = resolveJniVtable();
    var jniFuncs = resolveJniFunctions(jniVtable);
    for (var j = 0; j < jniFuncs.length; j++) {
      var jf = jniFuncs[j];
      addEntry(jf.addr, jf.apiId, jf.nArgs, jf.strArgs);
    }
  }

  /* 2. User-supplied custom addresses (--capi-funcs from Python runner) */
  if (CONFIG.capiJniFuncs && CONFIG.capiJniFuncs.length > 0) {
    for (var i = 0; i < CONFIG.capiJniFuncs.length; i++) {
      var jf = CONFIG.capiJniFuncs[i];
      if (jf.addr) {
        addEntry(ptr(jf.addr), jf.apiId || 0, jf.nArgs || 0, jf.strArgs || 0);
      }
    }
  }

  log('C API interception: ' + resolved.length + ' extra addresses passed to native' +
      ' (standard functions resolved by native dlsym)' +
      (isAndroid() ? ' [Android]' : ' [iOS]'));
  return resolved;
}

// ---------------------------------------------------------------------------
// Pre-trace memory patches
// ---------------------------------------------------------------------------

/* Apply memory patches before tracing starts.
 * Each patch descriptor: { addr: "0x...", hex: "aabb...", is_offset: bool }
 *
 * When is_offset is true, addr is treated as an offset from moduleBase.
 * Original bytes are saved so they can be restored after tracing.
 *
 * Returns an array of { addr: NativePointer, original: ArrayBuffer, len: number }
 * for use by restorePatches(). */
function applyPatches(patches, moduleBase) {
  if (!patches || patches.length === 0) return [];

  var saved = [];
  for (var i = 0; i < patches.length; i++) {
    var p = patches[i];
    var target;
    if (p.is_offset) {
      target = moduleBase.add(ptr(p.addr));
    } else {
      target = ptr(p.addr);
    }

    var hexStr = p.hex;
    var len = hexStr.length / 2;
    var byteArr = [];
    for (var j = 0; j < hexStr.length; j += 2) {
      byteArr.push(parseInt(hexStr.substr(j, 2), 16));
    }

    // Save original bytes
    var original;
    try {
      original = target.readByteArray(len);
    } catch (e) {
      logError('patch[' + i + ']: failed to read original bytes at ' +
               target + ' (' + len + ' bytes): ' + e.message);
      continue;
    }

    // Make memory writable if needed, then write
    try {
      Memory.protect(target, len, 'rwx');
    } catch (e) {
      /* Some regions are already writable, or protection change is not needed.
       * On failure, still try the write — Frida may handle it. */
    }
    try {
      target.writeByteArray(byteArr);
    } catch (e) {
      logError('patch[' + i + ']: failed to write ' + len +
               ' bytes at ' + target + ': ' + e.message);
      continue;
    }

    saved.push({ addr: target, original: original, len: len });

    // Log: show hex preview (first 16 bytes)
    var preview = hexStr.length > 32 ? hexStr.substr(0, 32) + '...' : hexStr;
    var addrLabel = p.is_offset
        ? target + ' (+' + p.addr + ')'
        : target.toString();
    log('patch[' + i + ']: wrote ' + len + ' byte(s) at ' +
        addrLabel + ' <- ' + preview);
  }

  if (saved.length > 0) {
    log(saved.length + ' memory patch(es) applied (originals saved for restore)');
  }
  return saved;
}

/* Restore original bytes after tracing completes. */
function restorePatches(saved) {
  if (!saved || saved.length === 0) return;

  for (var i = 0; i < saved.length; i++) {
    var s = saved[i];
    try {
      Memory.protect(s.addr, s.len, 'rwx');
    } catch (e) { /* best effort */ }
    try {
      s.addr.writeByteArray(s.original);
    } catch (e) {
      logError('restore patch[' + i + ']: failed to restore ' + s.len +
               ' bytes at ' + s.addr + ': ' + e.message);
      continue;
    }
  }
  log(saved.length + ' memory patch(es) restored');
}

// ---------------------------------------------------------------------------
// Invoke mode: typed argument materialization
// ---------------------------------------------------------------------------

/* Materialize a list of typed argument descriptors (from Python's --args) into
 * an array of NativePointer values ready to write into the argv buffer.
 *
 * Each descriptor is { type: string, value: string|null }.
 * Allocated memory (strings, buffers) is kept alive via the returned _keep array.
 *
 * Supported types:
 *   int:N       — immediate integer/pointer value
 *   str:TEXT    — UTF-8 C string (Memory.allocUtf8String)
 *   bytes:HEX  — raw byte buffer from hex
 *   buf:SIZE   — zero-filled output buffer
 *   nullptr    — NULL pointer
 *   nsstr:TEXT  — ObjC NSString (iOS only)
 *   nsdata:HEX — ObjC NSData from hex (iOS only)
 *   nsnum:N    — ObjC NSNumber (iOS only)
 */
function materializeArgs(argDescs) {
  var pointers = [];
  var keep = [];  // prevent GC of allocated memory

  for (var i = 0; i < argDescs.length; i++) {
    var desc = argDescs[i];
    var t = desc.type;
    var v = desc.value;

    if (t === 'int') {
      pointers.push(ptr(v));

    } else if (t === 'nullptr') {
      pointers.push(NULL);

    } else if (t === 'str') {
      var s = Memory.allocUtf8String(v);
      keep.push(s);
      pointers.push(s);

    } else if (t === 'bytes') {
      // v is a hex string like "aabbccdd"
      var byteArr = [];
      for (var j = 0; j < v.length; j += 2) {
        byteArr.push(parseInt(v.substr(j, 2), 16));
      }
      var buf = Memory.alloc(byteArr.length);
      buf.writeByteArray(byteArr);
      keep.push(buf);
      pointers.push(buf);

    } else if (t === 'buf') {
      var size = parseInt(v, 10);
      var zbuf = Memory.alloc(size);
      // Memory.alloc returns zeroed memory in Frida
      keep.push(zbuf);
      pointers.push(zbuf);

    } else if (t === 'nsstr') {
      // ObjC NSString — requires ObjC runtime (iOS/macOS)
      if (isAndroid()) {
        fail('nsstr type is not supported on Android');
      }
      var nsObj = ObjC.classes.NSString.stringWithUTF8String_(
          Memory.allocUtf8String(v));
      keep.push(nsObj);
      pointers.push(nsObj.handle);

    } else if (t === 'nsdata') {
      // ObjC NSData from hex bytes
      if (isAndroid()) {
        fail('nsdata type is not supported on Android');
      }
      var dataBytes = [];
      for (var j = 0; j < v.length; j += 2) {
        dataBytes.push(parseInt(v.substr(j, 2), 16));
      }
      var dataBuf = Memory.alloc(dataBytes.length);
      dataBuf.writeByteArray(dataBytes);
      keep.push(dataBuf);
      var nsData = ObjC.classes.NSData.dataWithBytes_length_(
          dataBuf, dataBytes.length);
      keep.push(nsData);
      pointers.push(nsData.handle);

    } else if (t === 'nsnum') {
      // ObjC NSNumber from integer
      if (isAndroid()) {
        fail('nsnum type is not supported on Android');
      }
      var nsNum = ObjC.classes.NSNumber.numberWithLongLong_(
          parseInt(v, 10));
      keep.push(nsNum);
      pointers.push(nsNum.handle);

    } else {
      fail('unknown invoke arg type: ' + t);
    }

    log('invoke arg[' + i + '] = ' + t + ':' +
        (v !== null ? v : '(null)') + ' -> ' + pointers[pointers.length - 1]);
  }

  return { pointers: pointers, _keep: keep };
}

function buildIndexedOutputPath(template, index) {
  const suffix = '_' + String(index).padStart(3, '0');
  const dot = template.lastIndexOf('.');
  if (dot > 0 && dot > template.lastIndexOf('/')) {
    return template.slice(0, dot) + suffix + template.slice(dot);
  }
  return template + suffix;
}

// ---------------------------------------------------------------------------
// Java Entry Trigger (Android only)
//
// Uses the Frida Java bridge to hook a Java method (typically the JNI
// wrapper that calls into the target native library). When the method fires,
// the Java arguments are materialized into native pointers and the target
// native function is invoked through qbditrace_run_call — the trace captures
// the native execution with real Java-supplied inputs.
//
// NOTE: the original Java implementation is bypassed while tracing (the
// native function is called directly). Any Java-side logic before/after the
// native call does not run during the traced invocation.
// ---------------------------------------------------------------------------

/* Pure policy helper — maps a Frida Java argument type name to a conversion
 * strategy. Kept at top level so it can be unit-tested without a runtime. */
/* Some Frida Java-bridge versions report argument/return type names as JVM
 * signatures ('I', 'J', 'Ljava.lang.String;', '[B') instead of the spelled-out
 * form ('int', 'long', ...). Normalize both shapes to one canonical name so
 * the switches below work on either bridge. */
function normalizeJavaTypeName(t) {
  var sigMap = {
    'I': 'int', 'J': 'long', 'S': 'short', 'B': 'byte',
    'C': 'char', 'Z': 'boolean', 'F': 'float', 'D': 'double',
    'Ljava.lang.String;': 'java.lang.String', '[B': '[B',
  };
  return sigMap[t] || t;
}

function javaArgKind(typeName) {
  switch (normalizeJavaTypeName(typeName)) {
    case 'int':
    case 'long':
    case 'short':
    case 'byte':
    case 'char':
    case 'boolean':
      return 'primitive';
    case 'float':
    case 'double':
      return 'float';       // raw bits are passed; semantics may not match
    case 'java.lang.String':
      return 'utf8';        // allocate a C string via allocUtf8String
    case '[B':
      return 'bytearray';   // copy into a native buffer (unsupported for now)
    default:
      return 'object';      // pass the jobject handle as-is
  }
}

/* Pure policy helper — maps a Frida Java return type name to a conversion
 * strategy for the uint64 returned by qbditrace_run_call. */
function javaRetKind(typeName) {
  switch (normalizeJavaTypeName(typeName)) {
    case 'void':
      return 'void';
    case 'int':
    case 'short':
    case 'byte':
    case 'char':
    case 'boolean':
      return 'int32';
    case 'long':
      return 'int64';
    case 'float':
    case 'double':
      return 'float';       // unsupported: bits cannot be reinterpreted safely
    default:
      return 'object';      // unsupported: cannot rebuild a jobject from a raw pointer
  }
}

function installJavaEntryHook(opts) {
  const { fn, mod, baseOpts, funcStart, configureForTrace, makeOutputPath,
          maxTraces, startStatsPolling, stopStatsPolling } = opts;

  const spec = CONFIG.javaEntry;
  const lastDot = spec.lastIndexOf('.');
  if (lastDot <= 0 || lastDot === spec.length - 1) {
    fail('javaEntry must be "fully.qualified.Class.method", got: ' + spec);
  }
  const clsName = spec.slice(0, lastDot);
  const methName = spec.slice(lastDot + 1);

  Java.perform(function () {
    let javaTraceCount = 0;
    let javaInTrace = false;
    const retOut = Memory.alloc(8);

    let Klass;
    try {
      Klass = Java.use(clsName);
    } catch (e) {
      fail('Java.use("' + clsName + '") failed: ' + e.message);
      return;
    }

    const method = Klass[methName];
    if (!method || !method.overloads || method.overloads.length === 0) {
      fail('Java method not found: ' + spec);
      return;
    }
    const target = method.overloads[0];
    if (method.overloads.length > 1) {
      log('WARNING: ' + spec + ' has ' + method.overloads.length +
          ' overloads — hooking the first');
    }
    const retTypeName = target.returnType ? target.returnType.name : 'void';
    const argTypes = target.argumentTypes || [];

    log('[Java] hooking ' + spec + ' (' + argTypes.length +
        ' arg(s), returns ' + retTypeName + ') — native target ' + funcStart);

    function javaArgToPointer(v, typeName) {
      const kind = javaArgKind(typeName);
      if (kind === 'primitive') {
        /* Bridge-version robustness: some Java-bridge versions hand the
         * argument over as a wrapped object whose Number() coercion is NaN
         * (NaN >>> 0 === 0 — silently tracing with seed 0). Coerce through
         * toNumber() / intValue() / valueOf() before falling back. */
        let n = NaN;
        const tryNum = function (f) {
          try { const r = f(); return (typeof r === 'number') ? r : NaN; }
          catch (e) { return NaN; }
        };
        if (v !== null && v !== undefined) {
          if (typeof v === 'number') n = v;
          else if (typeof v.toNumber === 'function') n = tryNum(v.toNumber.bind(v));
          else if (typeof v.intValue === 'function') n = tryNum(v.intValue.bind(v));
          else if (typeof v.valueOf === 'function') n = tryNum(v.valueOf.bind(v));
          else n = tryNum(function () { return Number(v); });
        }
        if (typeof n !== 'number' || isNaN(n)) {
          log('WARNING: Java primitive arg could not be coerced (' +
              typeName + ') — passing 0');
          n = 0;
        }
        return ptr(n >>> 0);
      }
      if (kind === 'float') {
        log('WARNING: Java float/double arg ("' + typeName +
            '") passed as raw bits — semantics may not match');
        return ptr(0);
      }
      if (kind === 'utf8') {
        return Memory.allocUtf8String(String(v));
      }
      if (kind === 'bytearray') {
        log('WARNING: Java byte[] arg passed as jobject handle (no copy)');
        return (v && v.$h) ? v.$h : NULL;
      }
      return (v && v.$h) ? v.$h : NULL;
    }

    function javaRetFromPointer(ret, typeName) {
      const kind = javaRetKind(typeName);
      if (kind === 'void') return undefined;
      if (kind === 'int32') return ret.toUInt32();
      /* Java long: the bridge requires a value compatible with long — a JS
       * number when it fits exactly (|x| < 2^53), otherwise a decimal string
       * (a hex string is NOT accepted). NativePointer has no toNumber();
       * go via its string form. */
      if (kind === 'int64') {
        const s = ret.toString(10);
        const n = parseInt(s, 10);
        return Number.isSafeInteger(n) ? n : s;
      }
      if (kind === 'float') {
        log('WARNING: Java float/double return not supported — returning 0');
        return 0;
      }
      log('WARNING: Java object return (' + typeName +
          ') cannot be rebuilt from pointer ' + ret + ' — returning null');
      return null;
    }

    target.implementation = function () {
      if (javaInTrace) {
        log('WARNING: re-entrant Java call to ' + spec +
            ' during trace — calling original implementation');
        return this[methName].apply(this, arguments);
      }
      if (javaTraceCount >= maxTraces) {
        return this[methName].apply(this, arguments);
      }

      javaInTrace = true;
      javaTraceCount++;
      const thisTrace = javaTraceCount;

      log('[Java] -> ' + spec + ' (trace #' + thisTrace + ') with ' +
          argTypes.length + ' Java arg(s)');
      status('trace_start', { index: thisTrace, trigger: 'java' });

      const argPtrs = [];
      for (let i = 0; i < argTypes.length && i < 8; i++) {
        argPtrs.push(javaArgToPointer(arguments[i], argTypes[i].name));
      }
      if (argTypes.length > 8) {
        log('WARNING: ' + argTypes.length +
            ' Java args exceed the run_call limit (8) — tracing with the first 8');
      }
      const argc = argPtrs.length;
      const argv = argc > 0 ? Memory.alloc(8 * argc) : NULL;
      for (let i = 0; i < argc; i++) {
        argv.add(i * 8).writePointer(argPtrs[i]);
      }

      const cfg = configureForTrace(thisTrace);
      if (cfg === null) {
        logError('[Java] configure failed for trace #' + thisTrace +
                 ' — calling original implementation');
        javaInTrace = false;
        return this[methName].apply(this, arguments);
      }

      startStatsPolling();
      const r = fn.runCall(retOut, funcStart, argc, argv);
      if (r !== 0) {
        log('qbditrace_run_call returned error rc=' + r);
      }
      const ret = retOut.readPointer();
      fn.stop();
      stopStatsPolling();

      const outFile = fn.outputPath().readUtf8String();
      log('[Java] <- trace #' + thisTrace + ' done, native ret = ' + ret +
          '. output = ' + outFile);
      status('trace_done', { index: thisTrace, ret: ret.toString(), output: outFile });

      javaInTrace = false;

      if (javaTraceCount >= maxTraces) {
        log('all ' + javaTraceCount + ' trace(s) captured. Java hook stays installed but now passes through.');
        status('all_done', { total: javaTraceCount });
      }

      return javaRetFromPointer(ret, retTypeName);
    };

    status('java_hook_installed', {
      class: clsName,
      method: methName,
      nativeTarget: funcStart.toString(),
      argCount: argTypes.length,
      returnType: retTypeName,
      mode: CONFIG.traceMode,
      maxTraces: maxTraces === Infinity ? 'unlimited' : maxTraces,
    });
  });
}

// ---------------------------------------------------------------------------
// GCD Block Tracing
// ---------------------------------------------------------------------------

function installGCDHooks(opts) {
  const { fn, mod, baseOpts, makeGCDOutputPath } = opts;
  const moduleStart = mod.base;
  const moduleEnd = mod.base.add(mod.size);
  const filterByModule = CONFIG.gcdFilterByModule !== false;
  const maxCaptures = CONFIG.gcdMaxCaptures || 0;

  let gcdTraceCount = 0;
  let gcdInTrace = false;
  const gcdRetOut = Memory.alloc(8);
  const gcdArgv = Memory.alloc(8);

  function isInModule(addr) {
    return addr.compare(moduleStart) >= 0 && addr.compare(moduleEnd) < 0;
  }

  function traceBlockIfNeeded(block, dispatcherName) {
    if (gcdInTrace) return;
    if (block.isNull()) return;

    let invoke;
    try {
      invoke = block.add(16).readPointer();
    } catch (e) {
      return;
    }
    if (invoke.isNull()) return;

    if (filterByModule && !isInModule(invoke)) return;
    if (maxCaptures > 0 && gcdTraceCount >= maxCaptures) return;

    gcdInTrace = true;
    gcdTraceCount++;
    const idx = gcdTraceCount;

    log('[GCD] ' + dispatcherName + ': block invoke @ ' + invoke +
        ' (offset 0x' + invoke.sub(moduleStart).toString(16) +
        ') -> tracing as GCD capture #' + idx);

    const outPath = makeGCDOutputPath(idx);
    const cfgOpts = Object.assign({}, baseOpts, {
      outputPath: outPath,
      traceStart: moduleStart,
      traceEnd: moduleEnd,
    });
    const cfg = buildConfigStruct(cfgOpts);
    const rc = fn.configure(cfg);
    if (rc !== 0) {
      log('[GCD] WARNING: configure failed for GCD block #' + idx + ', rc=' + rc);
      gcdInTrace = false;
      return;
    }

    gcdArgv.writePointer(block);
    const r = fn.runCall(gcdRetOut, invoke, 1, gcdArgv);
    if (r !== 0) {
      log('[GCD] WARNING: run_call failed for GCD block #' + idx + ', rc=' + r);
    }
    fn.stop();

    log('[GCD] capture #' + idx + ' done. output = ' +
        fn.outputPath().readUtf8String());
    status('gcd_trace_done', { index: idx, path: outPath });

    gcdInTrace = false;
  }

  const dispatchers = [
    'dispatch_async',
    'dispatch_after',
    'dispatch_barrier_async',
  ];

  let hookedCount = 0;
  for (const name of dispatchers) {
    let addr = null;
    try {
      addr = Process.getModuleByName('libdispatch.dylib').findExportByName(name);
    } catch (e) { /* module not found or no export */ }
    if (!addr) {
      try {
        addr = Process.getModuleByName('libSystem.B.dylib').findExportByName(name);
      } catch (e) { /* fallback */ }
    }
    if (!addr) {
      try { addr = Module.getGlobalExportByName(name); } catch (e) { /* give up */ }
    }
    if (!addr || addr.isNull()) {
      log('[GCD] WARNING: could not resolve ' + name + ', skipping');
      continue;
    }

    const blockArgIndex = (name === 'dispatch_after') ? 2 : 1;

    Interceptor.attach(addr, {
      onEnter(args) {
        const block = args[blockArgIndex];
        traceBlockIfNeeded(block, name);
      }
    });
    hookedCount++;
    log('[GCD] hooked ' + name + ' @ ' + addr +
        ' (block arg index = ' + blockArgIndex + ')');
  }

  if (hookedCount === 0) {
    log('[GCD] WARNING: no GCD dispatchers could be hooked!');
  } else {
    log('[GCD] ' + hookedCount + ' dispatcher(s) hooked. ' +
        'Blocks within ' + mod.name + ' will be traced.' +
        (maxCaptures > 0 ? ' (max ' + maxCaptures + ' captures)' : ''));
  }
}

// ---------------------------------------------------------------------------
// Multi-thread tracing (Phase 2): pthread_create interception.
//
// When the traced code spawns worker threads whose start_routine lives in the
// target module, we swap the routine with a NativeCallback of the exact
// pthread ABI (void *(*)(void *)). The callback redirects the child thread
// into qbditrace_run_thread(), which runs the real routine inside a dedicated
// QBDI VM recording into the SAME trace file (interleaved chunks with
// THREAD markers — the Phase 1 reader contract).
//
// Unlike the GCD path, this does NOT reconfigure/stop per capture: the parent
// trace stays open, and qbditrace_stop() (called once by the loader after the
// main traced call) flushes all registered thread buffers.
// ---------------------------------------------------------------------------
function installPthreadHooks(opts) {
  const { fn, mod } = opts;
  const moduleStart = mod.base;
  const moduleEnd = mod.base.add(mod.size);
  const filterByModule = CONFIG.pthreadFilterByModule !== false;
  const maxCaptures = CONFIG.pthreadMaxCaptures || 0;

  if (!fn.runThread) {
    log('[pthread] qbditrace_run_thread not exported by this dylib — ' +
        'multi-thread tracing disabled (rebuild libqbditrace)');
    return;
  }

  let pthreadTraceCount = 0;
  // Per-child trampolines must stay alive for the child's whole lifetime.
  const keepAlive = [];

  function isInModule(addr) {
    return addr.compare(moduleStart) >= 0 && addr.compare(moduleEnd) < 0;
  }

  let createAddr = null;
  try { createAddr = Module.getGlobalExportByName('pthread_create'); } catch (e) {}
  if (!createAddr || createAddr.isNull()) {
    log('[pthread] pthread_create not found — multi-thread tracing disabled');
    return;
  }

  Interceptor.attach(createAddr, {
    onEnter(args) {
      const routine = args[2];
      if (routine.isNull()) return;
      if (filterByModule && !isInModule(routine)) return;
      if (maxCaptures > 0 && pthreadTraceCount >= maxCaptures) return;

      pthreadTraceCount++;
      const idx = pthreadTraceCount;
      const arg = args[3];

      // Exact pthread start_routine ABI: void *(*)(void *).
      // `routine` and `arg` are captured by value below; NativeCallback
      // receives the trampoline's own argument (pthreads may repackage it,
      // but by contract it is exactly the original arg pointer).
      const trampoline = new NativeCallback(function (realArg) {
        log('[pthread] child #' + idx + ' tracing routine @ ' + routine +
            ' (offset 0x' + routine.sub(moduleStart).toString(16) + ')');
        const retOut = Memory.alloc(8);
        // NativePointer → uint64: pass the raw pointer value without
        // truncation (toUInt32 would corrupt 64-bit arg pointers).
        const rc = fn.runThread(retOut, routine, realArg);
        if (rc !== 0) {
          log('[pthread] WARNING: run_thread failed for child #' + idx +
              ', rc=' + rc + ' — falling back to native execution');
          // Native fallback: call the real routine directly outside the VM.
          const direct = new NativeFunction(routine, 'pointer', ['pointer']);
          return direct(realArg);
        }
        return retOut.readPointer();
      }, 'pointer', ['pointer']);
      keepAlive.push(trampoline);

      args[2] = trampoline;
      log('[pthread] create #' + idx + ': routine ' + routine + ' swapped to ' +
          'trampoline');
      status('pthread_trace_start', { index: idx, routine: routine.toString() });
    }
  });

  log('[pthread] pthread_create hooked @ ' + createAddr + '. Threads whose ' +
      'start_routine is within ' + mod.name + ' will be traced.' +
      (maxCaptures > 0 ? ' (max ' + maxCaptures + ' children)' : ''));
}

// ---------------------------------------------------------------------------
// Main entry point — called after CONFIG is received from Python
// ---------------------------------------------------------------------------

function main() {
  try {
    mainImpl();
  } catch (e) {
    /* Top-level guard: catch any unhandled exception so Python always
     * receives a structured error message instead of a silent crash. */
    logError('fatal exception in main: ' + e.message + (e.stack ? '\n' + e.stack : ''));
    send({ type: 'error', text: 'qbditrace agent fatal: ' + e.message });
  }
}

function mainImpl() {
  status('initializing');

  const dylib = loadDylib(CONFIG.dylibPath);
  const ex = resolveExports(dylib);
  const fn = buildNativeFunctions(ex);

  // Module may not be loaded yet in Android spawn scenarios (lazy
  // System.loadLibrary) — resolve asynchronously and continue setup in the
  // callback. Busy-waiting here would deadlock the app.
  resolveTargetModuleAsync(CONFIG.moduleWaitMs, function (mod) {
  const modRef = mod;

  // --- Live stats polling ---
  // After configure(), obtain the stats page pointer once, then poll with
  // setInterval. Each poll reads the relaxed-atomic fields directly from
  // native memory (zero function-call overhead) and sends a 'stats' message
  // to Python for real-time display.
  var statsTimerId = null;
  var statsPtr = null; // set after first configure()

  function startStatsPolling() {
    if (statsTimerId !== null) return; // already polling
    if (statsPtr === null || statsPtr.isNull()) {
      statsPtr = fn.statsPage();
      if (statsPtr === null || statsPtr.isNull()) {
        log('WARNING: qbditrace_stats_page() returned NULL — stats disabled');
        return;
      }
    }
    var interval = (CONFIG.statsIntervalMs !== undefined) ? CONFIG.statsIntervalMs : 500;
    if (interval <= 0) return; // disabled by config
    var sp = statsPtr; // capture for closure
    statsTimerId = setInterval(function () {
      send({
        type: 'stats',
        insns:      sp.readU64().toString(),
        anchors:    sp.add(8).readU64().toString(),
        mem:        sp.add(16).readU64().toString(),
        events:     sp.add(24).readU64().toString(),
        svc:        sp.add(32).readU64().toString(),
        objc:       sp.add(40).readU64().toString(),
        code:       sp.add(48).readU64().toString(),
        capi:       sp.add(56).readU64().toString(),
        bytes:      sp.add(64).readU64().toString(),
        elapsedNs:  sp.add(72).readU64().toString(),
      });
    }, interval);
  }

  function stopStatsPolling() {
    if (statsTimerId !== null) {
      clearInterval(statsTimerId);
      statsTimerId = null;
    }
    // Send one final stats snapshot so the total is accurate
    if (statsPtr !== null && !statsPtr.isNull()) {
      // Call statsPage() once more to update elapsed_ns
      fn.statsPage();
      send({
        type: 'stats',
        final: true,
        insns:      statsPtr.readU64().toString(),
        anchors:    statsPtr.add(8).readU64().toString(),
        mem:        statsPtr.add(16).readU64().toString(),
        events:     statsPtr.add(24).readU64().toString(),
        svc:        statsPtr.add(32).readU64().toString(),
        objc:       statsPtr.add(40).readU64().toString(),
        code:       statsPtr.add(48).readU64().toString(),
        capi:       statsPtr.add(56).readU64().toString(),
        bytes:      statsPtr.add(64).readU64().toString(),
        elapsedNs:  statsPtr.add(72).readU64().toString(),
      });
    }
  }

  // --- Resolve the entry function ---
  const moduleBase = mod.base;
  let funcStart;
  if (CONFIG.funcName) {
    // Resolve by exported symbol name
    let resolved = null;
    try {
      if (CONFIG.moduleName) {
        resolved = Process.getModuleByName(CONFIG.moduleName).findExportByName(CONFIG.funcName);
      } else {
        resolved = Module.getGlobalExportByName(CONFIG.funcName);
      }
    } catch (e) {
      resolved = null;
    }
    if (resolved && !resolved.isNull()) {
      funcStart = resolved;
      log('resolved entry "' + CONFIG.funcName + '" @ ' + funcStart +
          ' (offset = 0x' + funcStart.sub(moduleBase).toString(16) + ')');
    } else if (CONFIG.funcOffset) {
      log('WARNING: entry "' + CONFIG.funcName +
          '" not found, falling back to offset 0x' + CONFIG.funcOffset.toString(16));
      funcStart = moduleBase.add(CONFIG.funcOffset);
    } else {
      fail('entry "' + CONFIG.funcName + '" not found and no offset fallback provided');
    }
  } else {
    funcStart = moduleBase.add(CONFIG.funcOffset);
    log('entry @ offset 0x' + CONFIG.funcOffset.toString(16) + ' -> ' + funcStart);
  }

  // --- Determine trace range ---
  // The tracer uses addInstrumentedModuleFromAddr for whole-module instrumentation.
  // traceStart/traceEnd in the config are used as fallback when module resolution
  // fails inside the native tracer. When rangeSize is 0 (default), we use the
  // full module size as the fallback range.
  var rangeSize = CONFIG.rangeSize;
  if (!rangeSize || rangeSize === 0) {
    rangeSize = mod.size;
    log('trace scope: entire module "' + mod.name + '" (0x' +
        mod.size.toString(16) + ' bytes, fallback range = full module)');
  } else {
    log('trace scope: entire module "' + mod.name + '" (fallback range-size = 0x' +
        rangeSize.toString(16) + ')');
  }

  // Fallback range: [funcStart, funcStart + rangeSize)
  // The native tracer will attempt addInstrumentedModuleFromAddr first; this
  // range is only used if that fails.
  const funcEnd = funcStart.add(rangeSize);

  const moduleSlide = moduleBase;

  log('entry = ' + funcStart + '  fallback end = ' + funcEnd);
  log('module base = ' + moduleBase + '  slide = ' + moduleSlide);
  if (CONFIG.excludeRanges && CONFIG.excludeRanges.length > 0) {
    CONFIG.excludeRanges.forEach(function(r, idx) {
      log('exclude[' + idx + '] = ' + moduleBase.add(r.start) +
          ' - ' + moduleBase.add(r.end) +
          ' (offset 0x' + r.start.toString(16) +
          ' - 0x' + r.end.toString(16) + ')');
    });
  }
  const snapshotConfig = CONFIG.memSnapshot || {};
  const snapshotRanges = (snapshotConfig.ranges || []).map(function(r, idx) {
    const start = ptr(r.start);
    const end = ptr(r.end);
    if (end.compare(start) <= 0) {
      fail('memSnapshot.ranges[' + idx + ']: end must be greater than start');
    }
    log('snapshot[' + idx + '] = ' + start + ' - ' + end + ' (absolute runtime range)');
    return { start: start, end: end };
  });
  if (snapshotRanges.length > 8) {
    fail('memSnapshot.ranges: maximum 8 ranges supported');
  }

  /* Always run the planner so disabled MSGSEND capture is diagnosed explicitly.
   * It performs no ObjC runtime/module access on Android or when disabled. */
  const objc = resolveObjcDispatchers();

  // --- Resolve C API function addresses ---
  const capiIntercept = CONFIG.enableCapiIntercept !== false;  // on by default
  const capiFuncs = capiIntercept ? resolveCApiFunctions() : [];

  // --- libart timing robustness (Android) ---
  // The JNI vtable can only be read once a JavaVM exists. On early attach
  // (spawn gating, JNI_OnLoad era) libart may not have created the VM yet,
  // and resolveCApiFunctions() silently misses every JNI function. Recover
  // by retrying in the background and refreshing the explicit capi table
  // right before each qbditrace_configure() call — by trace time the
  // runtime is guaranteed to be up.
  let jniPending = false;
  let mergeJniEntries = null;
  if (isAndroid() && capiIntercept) {
    const isJniId = function (id) {
      return (id >= 280 && id <= 359) || (id >= 700 && id <= 731);
    };
    jniPending = !capiFuncs.some(function (f) { return isJniId(f.apiId); });

    mergeJniEntries = function () {
      const vtable = resolveJniVtable();
      if (!vtable) return false;
      const jniFuncs = resolveJniFunctions(vtable);
      if (jniFuncs.length === 0) return false;
      const known = {};
      for (let i = 0; i < capiFuncs.length; i++) {
        known[capiFuncs[i].addr.toString()] = true;
      }
      let added = 0;
      for (let i = 0; i < jniFuncs.length && capiFuncs.length < 128; i++) {
        const key = jniFuncs[i].addr.toString();
        if (known[key]) continue;
        known[key] = true;
        capiFuncs.push(jniFuncs[i]);
        added++;
      }
      if (added > 0) {
        log('JNI vtable: +' + added + ' entries recovered (total capi funcs: ' +
            capiFuncs.length + ') — effective on next configure');
        baseOpts.capiFuncs = capiFuncs;
      }
      return true;
    };

    if (jniPending) {
      log('JNI vtable: not ready yet (libart/JavaVM pending) — retrying every 2s');
      let attempts = 0;
      const retryTimer = setInterval(function () {
        attempts++;
        if (mergeJniEntries()) {
          clearInterval(retryTimer);
          log('JNI vtable resolved after ' + attempts + ' retry attempt(s)');
          jniPending = false;
        } else if (attempts >= 30) {
          clearInterval(retryTimer);
          log('JNI vtable: giving up after ' + attempts +
              ' attempts — C API interception runs without JNI entries');
        }
      }, 2000);
    }
  }

  let maxTraces;
  const mode = CONFIG.traceMode;
  if (mode === 'once' || mode === 1) {
    maxTraces = 1;
  } else if (mode === 'multi') {
    maxTraces = Infinity;
    log('WARNING: trace-mode "multi" has no upper limit. Use Ctrl+C or a numeric limit to stop.');
  } else if (typeof mode === 'number' && mode > 0) {
    maxTraces = Math.floor(mode);
  } else {
    log('WARNING: unknown traceMode "' + mode + '", defaulting to "once"');
    maxTraces = 1;
  }
  const multiMode = maxTraces !== 1;

  const baseOpts = {
    traceStart: funcStart,
    traceEnd: funcEnd,
    moduleBase: moduleBase,
    moduleSlide: moduleSlide,
    moduleName: mod.path || mod.name,
    record: CONFIG.record,
    anchorInterval: CONFIG.anchorInterval,
    ringBytes: CONFIG.ringBytes,
    embedCode: CONFIG.embedCode,
    pcDelta: CONFIG.pcDelta,
    fpr: CONFIG.fpr,
    noCompress: CONFIG.noCompress,
    noBranchHint: CONFIG.noBranchHint,
    extraRangeStart: CONFIG.extraRangeStart ? ptr(CONFIG.extraRangeStart) : NULL,
    extraRangeEnd: CONFIG.extraRangeEnd ? ptr(CONFIG.extraRangeEnd) : NULL,
    excludeRanges: (CONFIG.excludeRanges || []).map(function(r) {
      return { start: moduleBase.add(r.start), end: moduleBase.add(r.end) };
    }),
    objcMsgSend: objc.objcMsgSend,
    objcMsgSendSuper: objc.objcMsgSendSuper,
    objcMsgSendSuper2: objc.objcMsgSendSuper2,
    objcMsgSendStret: objc.objcMsgSendStret,
    enableCapiIntercept: capiIntercept,  /* native resolves standard funcs when capiFuncs is empty */
    capiFuncs: capiFuncs,
    snapshotRanges: snapshotRanges,
  };

  function makeOutputPath(traceIndex) {
    if (multiMode) {
      return buildIndexedOutputPath(CONFIG.outputPath, traceIndex);
    }
    return CONFIG.outputPath;
  }

  function configureForTrace(traceIndex) {
    // Late JNI recovery: if libart was not up when the agent started, the
    // vtable is read now (hook mode implies the runtime is alive) so the
    // config below already carries the JNI interception table.
    if (jniPending && mergeJniEntries) {
      jniPending = !mergeJniEntries();
    }
    const outPath = makeOutputPath(traceIndex);
    const cfg = buildConfigStruct(Object.assign({}, baseOpts, { outputPath: outPath }));
    const rc = fn.configure(cfg);
    if (rc !== 0) {
      /* First trace: fatal — cannot proceed without a valid configuration.
       * Subsequent traces in multi mode: warn and keep the old config active
       * so previous traces are not lost. */
      if (traceIndex <= 1) {
        fail('qbditrace_configure failed (trace #' + traceIndex + '), rc=' + rc);
      } else {
        logError('qbditrace_configure failed for trace #' + traceIndex +
                 ', rc=' + rc + ' — skipping this trace');
        return null;
      }
    }
    log('configured trace #' + traceIndex +
        '. output = ' + fn.outputPath().readUtf8String());
    if (traceIndex === 1) {
      status('objc_configuration', objc.diagnostic);
    }
        return cfg;
  }

  // --- Optional: multi-thread tracing via pthread_create interception ---
  // Install before either trace trigger. In INVOKE mode the entry function runs
  // synchronously below, so installing this after the branch would miss every
  // pthread_create issued by that invocation.
  if (CONFIG.traceThreads) {
    installPthreadHooks({
      fn: fn,
      mod: modRef,
    });
  }

  // ==========================================================================
  // Branch: INVOKE mode vs HOOK mode
  // ==========================================================================
  if (CONFIG.invoke) {
    // --- INVOKE MODE: actively call the entry function with supplied args ---
    log('invoke mode: preparing to call ' + funcStart + ' with ' +
        CONFIG.invokeArgs.length + ' typed argument(s)');

    configureForTrace(1);

    // Apply pre-trace memory patches
    var savedPatches = applyPatches(CONFIG.patches, moduleBase);

    var matResult = materializeArgs(CONFIG.invokeArgs);
    var argPtrs = matResult.pointers;
    var invokeArgc = argPtrs.length;
    var invokeArgv = invokeArgc > 0 ? Memory.alloc(8 * invokeArgc) : NULL;
    for (var ia = 0; ia < invokeArgc; ia++) {
      invokeArgv.add(ia * 8).writePointer(argPtrs[ia]);
    }

    var invokeRetOut = Memory.alloc(8);

    status('invoke_start', {
      funcStart: funcStart.toString(),
      argc: invokeArgc,
    });

    log('-> invoking entry function @ ' + funcStart +
        ' with ' + invokeArgc + ' args...');

    startStatsPolling();
    var invokeRc = -1;
    var crashed = false;
    try {
      invokeRc = fn.runCall(invokeRetOut, funcStart, invokeArgc, invokeArgv);
    } catch (e) {
      /* Fault recovery: Frida's exceptor turns an in-VM SIGSEGV into this JS
       * exception before qbditrace's native fault handler can run. Dump the
       * still-intact in-memory PC ring for crash triage, then stop() so the
       * instructions recorded *before* the fault are flushed to the trace
       * file (otherwise it stays a bare 536-byte header). */
      crashed = true;
      log('!! entry function faulted: ' + e.message + ' — recovering crash context');
      if (fn.dumpPcRing) {
        try {
          var ringPath = CONFIG.outputPath + '.pcring';
          var nPc = fn.dumpPcRing(Memory.allocUtf8String(ringPath));
          log('pcring: ' + nPc + ' last PCs appended to ' + ringPath);
        } catch (e2) {
          log('pcring dump failed: ' + e2.message);
        }
      }
    }
    if (crashed) {
      log('qbditrace_run_call crashed (access violation)');
    } else if (invokeRc !== 0) {
      log('qbditrace_run_call returned error rc=' + invokeRc);
    }

    fn.stop();
    stopStatsPolling();

    if (crashed) {
      /* Partial trace is still on disk — surface the path, then bail out. */
      var crashOutFile = fn.outputPath().readUtf8String();
      log('<- invoke CRASHED. partial output = ' + crashOutFile +
          ' (instructions before the fault were flushed)');
      status('trace_done', { index: 1, crashed: true, output: crashOutFile });
      send({ type: 'error', text: 'entry function crashed: ' + 'access violation (partial trace + pcring saved)' });
      return;
    }
    var invokeRet = invokeRetOut.readPointer();

    // Restore patched memory
    restorePatches(savedPatches);

    var invokeOutFile = fn.outputPath().readUtf8String();
    log('<- invoke done, ret = ' + invokeRet + '. output = ' + invokeOutFile);

    // Report buf-type output arguments (dump first 64 bytes for quick inspection)
    for (var ib = 0; ib < CONFIG.invokeArgs.length; ib++) {
      if (CONFIG.invokeArgs[ib].type === 'buf') {
        var bufSize = parseInt(CONFIG.invokeArgs[ib].value, 10);
        var dumpLen = Math.min(bufSize, 64);
        var hexDump = '';
        try {
          var ba = argPtrs[ib].readByteArray(dumpLen);
          var u8 = new Uint8Array(ba);
          for (var hx = 0; hx < u8.length; hx++) {
            hexDump += ('0' + u8[hx].toString(16)).slice(-2);
          }
        } catch (e) {
          hexDump = '(read error: ' + e.message + ')';
        }
        log('output buf arg[' + ib + '] (' + bufSize + ' bytes, first ' +
            dumpLen + '): ' + hexDump);
      }
    }

    status('trace_done', {
      index: 1,
      ret: invokeRet.toString(),
      output: invokeOutFile,
    });
    status('all_done', { total: 1 });

  } else {
    // --- HOOK MODE: passive interception (existing behavior) ---
    let currentCfg = configureForTrace(1);
    let traceCount = 0;
    let inTrace = false;
    let hookActive = false;

    // Apply pre-trace memory patches (hook mode: applied once before first trace)
    var savedPatches = applyPatches(CONFIG.patches, moduleBase);

    const retOut = Memory.alloc(8);
    const argc = CONFIG.argCount >>> 0;
    const argv = argc > 0 ? Memory.alloc(8 * argc) : NULL;

    // We need a reference to the original function for re-entrant calls.
    const origFunc = new NativeFunction(funcStart, 'pointer',
        (function () { var t = []; for (var i = 0; i < argc; i++) t.push('pointer'); return t; })());

    function buildArgTypes(n) {
      const t = [];
      for (let i = 0; i < n; i++) t.push('pointer');
      return t;
    }

    function removeHook() {
      if (hookActive) {
        Interceptor.revert(funcStart);
        Interceptor.flush();
        hookActive = false;
      }
    }

    function installHook() {
      removeHook();  // safety: ensure no stale hook
      hookActive = true;

      Interceptor.replace(funcStart, new NativeCallback(function () {
        // --- Re-entrant guard ---
        if (inTrace) {
          log('WARNING: re-entrant call to entry during trace — calling original natively');
          var nativeArgs = [];
          for (var i = 0; i < argc; i++) {
            nativeArgs.push(this.context['x' + i]);
          }
          return origFunc.apply(null, nativeArgs);
        }

        inTrace = true;
        traceCount++;
        const thisTrace = traceCount;

        log('-> entering entry function (trace #' + thisTrace + ') with ' + argc + ' args');
        status('trace_start', { index: thisTrace });

        for (let i = 0; i < argc; i++) {
          argv.add(i * 8).writePointer(this.context['x' + i]);
        }

        removeHook();

        startStatsPolling();
        let r = -1;
        let crashed = false;
        try {
          r = fn.runCall(retOut, funcStart, argc, argv);
        } catch (e) {
          /* Same fault-recovery as the invoke path: dump the in-memory PC
           * ring, flush the pre-fault partial trace, and stop tracing. */
          crashed = true;
          log('!! entry function faulted (trace #' + thisTrace + '): ' +
              e.message + ' — recovering crash context');
          if (fn.dumpPcRing) {
            try {
              const ringPath = CONFIG.outputPath + '.pcring';
              const nPc = fn.dumpPcRing(Memory.allocUtf8String(ringPath));
              log('pcring: ' + nPc + ' last PCs appended to ' + ringPath);
            } catch (e2) {
              log('pcring dump failed: ' + e2.message);
            }
          }
        }
        if (crashed) {
          log('qbditrace_run_call crashed (access violation)');
        } else if (r !== 0) {
          log('qbditrace_run_call returned error rc=' + r);
        }

        fn.stop();
        stopStatsPolling();
        const outFile = fn.outputPath().readUtf8String();
        if (crashed) {
          log('<- trace #' + thisTrace + ' CRASHED. partial output = ' + outFile +
              ' (instructions before the fault were flushed)');
          status('trace_done', { index: thisTrace, crashed: true, output: outFile });
          inTrace = false;
          return;
        }
        const ret = retOut.readPointer();
        log('<- trace #' + thisTrace + ' done, ret = ' + ret + '. output = ' + outFile);
        status('trace_done', { index: thisTrace, ret: ret.toString(), output: outFile });

        inTrace = false;

        const wantMore = (traceCount < maxTraces);
        if (wantMore && CONFIG.rehook !== false) {
          const nextCfg = configureForTrace(traceCount + 1);
          if (nextCfg) {
            currentCfg = nextCfg;
            // Re-apply patches for next trace (in case previous restore changed them)
            restorePatches(savedPatches); // restore first
            savedPatches = applyPatches(CONFIG.patches, moduleBase);
            installHook();
            log('hook re-installed for trace #' + (traceCount + 1));
          } else {
            /* configure failed for next trace — stop gracefully */
            removeHook();
            restorePatches(savedPatches);
            log('configure failed for trace #' + (traceCount + 1) +
                ', stopping after ' + traceCount + ' trace(s).');
            status('all_done', { total: traceCount });
          }
        } else {
          removeHook();
          restorePatches(savedPatches);
          log('all ' + traceCount + ' trace(s) captured. Hook permanently removed.');
          status('all_done', { total: traceCount });
        }

        return ret;
      }, 'pointer', buildArgTypes(argc)));
    }

    if (CONFIG.javaEntry) {
      // --- Java-entry trigger (Android): hook a Java method that calls
      // into the native target; Java args are materialized natively. ---
      if (!isAndroid()) {
        fail('javaEntry mode is Android-only (use --android)');
      }
      installJavaEntryHook({
        fn: fn,
        mod: mod,
        baseOpts: baseOpts,
        funcStart: funcStart,
        configureForTrace: configureForTrace,
        makeOutputPath: makeOutputPath,
        maxTraces: maxTraces,
        startStatsPolling: startStatsPolling,
        stopStatsPolling: stopStatsPolling,
      });
      log('Java-entry mode: waiting for ' + CONFIG.javaEntry + ' to be called. ' +
          'Native target: ' + funcStart);
    } else {
      installHook();
      status('hook_installed', {
        funcStart: funcStart.toString(),
        moduleName: mod.name,
        moduleSize: '0x' + mod.size.toString(16),
        mode: CONFIG.traceMode,
        maxTraces: maxTraces === Infinity ? 'unlimited' : maxTraces,
      });

      if (multiMode) {
        log('hook installed on ' + funcStart + ' (mode=' + CONFIG.traceMode +
            ', max=' + maxTraces + '). Trigger the entry function to trace.');
      } else {
        log('hook installed on ' + funcStart +
            '. Trigger the entry function to trace.');
      }
    }

    // --- Optional: GCD block tracing (iOS/macOS only) ---
    if (CONFIG.traceGCD) {
      if (isAndroid()) {
        log('WARNING: GCD block tracing is not available on Android — skipping');
      } else {
        function makeGCDOutputPath(gcdIndex) {
          const suffix = '_gcd_' + String(gcdIndex).padStart(3, '0');
          const base = CONFIG.outputPath;
          const dot = base.lastIndexOf('.');
          if (dot > 0 && dot > base.lastIndexOf('/')) {
            return base.slice(0, dot) + suffix + base.slice(dot);
          }
          return base + suffix;
        }

        installGCDHooks({
          fn: fn,
          mod: mod,
          baseOpts: baseOpts,
          makeGCDOutputPath: makeGCDOutputPath,
        });
      }
    }

  }
  }, function (secondsLeft) {
    log('waiting for module "' + CONFIG.moduleName + '" to load... ' +
        secondsLeft + 's left');
  });
}

// ===========================================================================
// Message dispatcher — receives CONFIG from Python, then starts main()
// ===========================================================================

recv('config', function (message) {
  try {
    CONFIG = message.payload;
    log('config received from Python loader');
    main();
  } catch (e) {
    /* Catch any exception that escapes even the main() guard (e.g. during
     * CONFIG parsing itself), so Python always gets a structured error. */
    logError('fatal exception in recv handler: ' + e.message);
    send({ type: 'error', text: 'qbditrace agent fatal: ' + e.message });
  }
});

status('agent_loaded');
log('agent loaded, waiting for config from Python loader...');
