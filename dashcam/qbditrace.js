/*
 * qbditrace - Frida bootstrap for the QBDI-based high-performance tracer.
 *
 * This script is intentionally thin: it only loads the native tracer dylib,
 * resolves addresses, and diverts the target function into the QBDI VM. Every
 * per-instruction operation happens in native code, so this JS has ZERO impact
 * on tracing speed (it runs once at setup, and once per traced call).
 *
 * Usage (edit CONFIG below, then):
 *   frida -H 127.0.0.1:27042 -n "<AppName>" -l qbditrace.js
 *   # or spawn:
 *   frida -H 127.0.0.1:27042 -f <bundle.id> -l qbditrace.js --no-pause
 *
 * Workflow:
 *   1. Load libqbditrace.dylib into the target process.
 *   2. Resolve the target module base, compute the ASLR slide.
 *   3. qbditrace_configure(range = [funcStart, funcEnd), module info).
 *   4. Interceptor.replace(targetFunc) -> qbditrace_run_call(retOut, func, args)
 *      so that calling the function runs it under QBDI and traces it.
 *   5. After the call returns, qbditrace_stop() flushes the trace to disk.
 *
 * Multi-trace mode:
 *   Set traceMode: "multi" (or traceMode: N for exactly N captures) to record
 *   multiple invocations. Each capture is written to a separate file by
 *   appending a zero-padded index suffix before the extension:
 *     qbditrace.bin  → qbditrace_001.bin, qbditrace_002.bin, ...
 *   Between captures the tracer library is stopped and reconfigured with the
 *   new output path. The hook is kept live and re-arms itself automatically.
 */

'use strict';

// ===========================================================================
// CONFIG - edit these for your target
// ===========================================================================
const CONFIG = {
  // Absolute path of the tracer dylib on the device.
  dylibPath: '/var/jb/usr/lib/libqbditrace.dylib',

  // Module that contains the function to trace. For the main binary you can use
  // the executable name; for a framework use its filename.
  moduleName: null, // null => use the main executable module

  // ── Target function resolution ──────────────────────────────────────────
  // You can specify the target function in one of two ways:
  //
  //   1. funcOffset (traditional): static file offset within the module, i.e.
  //      the address in IDA minus the image base.
  //      Example: IDA shows func at 0x100A1B2C0, base 0x100000000 => 0xA1B2C0
  //
  //   2. funcName (auto-resolve): exported symbol name. The script will use
  //      Module.findExportByName to resolve it at runtime, computing the offset
  //      automatically. This is simpler for exported functions.
  //      Example: funcName: "_SecKeyRawSign"
  //
  // If both are set, funcName takes priority. If funcName resolution fails,
  // the script falls back to funcOffset.
  funcName: null,   // exported symbol name (e.g. "_CCCrypt") or null to use offset
  funcOffset: 0xEE91EC,  // sub_100EE91EC: Q-Field top-level coordinator

  // Length in bytes of the address range to trace (function size, or larger to
  // cover callees within the same module). Range = [start, start+rangeSize).
  rangeSize: 0x7124,  // sub_100EE91EC function size (28964 bytes)

  // Where to write the binary trace on the device.
  // In "multi" mode this is treated as a template: the three-digit index is
  // inserted before the last dot (e.g. "qbditrace.bin" → "qbditrace_001.bin").
  // If the path has no extension the suffix is appended directly.
  outputPath: '/var/mobile/Documents/qfield_trace.bin',

  // Record bitmask: 1=NZCV, 2=REGDIFF, 4=MEM, 8=SVC, 16=OBJC. 31 = all.
  record: 31,

  // Resolve the objc_msgSend family so call-site self/SEL get captured. Set to
  // false to skip objc resolution (e.g. non-ObjC targets).
  resolveObjc: true,

  // Emit a full register resync snapshot every N instructions (0 = library
  // default, 1024). Anchors are only resync checkpoints: register diffs store
  // absolute values, so smaller intervals only help partial/seek reads while
  // costing space. Leave 0 unless you need very fine-grained resync.
  anchorInterval: 0,

  // Per-thread ring buffer size in bytes (0 = default 64 MiB).
  ringBytes: 0,

  // Embed a deduplicated code table in the trace so the offline decoder can
  // disassemble without an external --image. On by default; set false only to
  // shave the (tiny, deduplicated) extra writes.
  embedCode: true,

  // How many integer args the traced function takes (forwarded to QBDI).
  // sub_100EE91EC takes 1 arg: NSMutableDictionary* dict (in x0)
  argCount: 1,

  // ── Multi-trace mode ────────────────────────────────────────────────────
  //
  // traceMode controls how many invocations of the target function are traced:
  //   "once"  - (default) trace only the first invocation, then revert the hook.
  //   "multi" - trace every invocation until the script is unloaded. Each call
  //             produces a separate numbered output file.
  //   N       - (positive integer) trace the first N invocations, then stop.
  //
  // Example: traceMode: 5  → capture five traces (_001.bin … _005.bin).
  traceMode: 'once',

  // Whether to re-install the Interceptor hook between traces ("multi"/N mode).
  // When true (the default) the trampoline is reinstalled after each capture so
  // the next call is also intercepted. When false the trampoline is permanently
  // removed after the first capture, making subsequent calls run natively.
  // Only relevant in "multi" / N mode.
  rehook: true,

  // ── GCD Block Tracing ─────────────────────────────────────────────────────
  //
  // When enabled, hooks dispatch_async / dispatch_after / dispatch_barrier_async
  // to intercept ObjC/C blocks dispatched via GCD. If the block's invoke pointer
  // falls within the traced module address range, the block is synchronously
  // executed under QBDI on the current thread (instead of asynchronously on a
  // GCD worker thread). Each captured block produces a separate trace file.
  //
  // This works because QBDI's VM is single-threaded and cannot follow execution
  // across thread boundaries. By extracting the block's invoke function pointer
  // (at block + 16 on arm64) and running it through qbditrace_run_call, we get
  // a full instruction-level trace of the GCD-dispatched work.
  //
  // LIMITATIONS:
  //   - Execution order/timing differs from native (block runs synchronously).
  //   - Blocks that depend on thread-local state of the worker may behave
  //     differently.
  //   - Only blocks whose invoke address is within [moduleBase, moduleBase +
  //     moduleSize) are captured; system/framework blocks are skipped.
  //
  // Set to true to enable. Default: false (off).
  traceGCD: false,

  // Filter: only trace GCD blocks whose invoke pointer is within the target
  // module. Set to false to trace ALL blocks (very noisy). Default: true.
  gcdFilterByModule: true,

  // Maximum number of GCD block traces to capture (0 = unlimited).
  // Useful to avoid flooding the filesystem when many blocks are dispatched.
  gcdMaxCaptures: 0,
};

// ===========================================================================
// Implementation
// ===========================================================================

function log(msg) {
  console.log('[qbditrace] ' + msg);
}

function fail(msg) {
  console.error('[qbditrace][ERROR] ' + msg);
  throw new Error(msg);
}

function loadDylib(path) {
  // Use dlopen directly instead of Module.load, because Module.load crashes
  // on some targets (null-pointer dereference inside Frida's module enumeration
  // after dlopen returns).  dlopen + Process.findModuleByName is equivalent.
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
  log('loaded dylib: ' + path + ' @ ' + m.base + ' (via dlopen)');
  return m;
}

function resolveExports(dylibModule) {
  const names = [
    'qbditrace_configure',
    'qbditrace_run_call',
    'qbditrace_stop',
    'qbditrace_output_path',
  ];
  const ex = {};
  for (const n of names) {
    const p = dylibModule.findExportByName(n);
    if (p === null || p.isNull()) {
      fail('export not found: ' + n + ' (is the dylib the tracer build?)');
    }
    ex[n] = p;
  }
  return ex;
}

function resolveTargetModule() {
  let m;
  if (CONFIG.moduleName) {
    m = Process.findModuleByName(CONFIG.moduleName);
    if (!m) {
      fail('module not found: ' + CONFIG.moduleName);
    }
  } else {
    // Main executable is the first enumerated module on Darwin.
    m = Process.enumerateModules()[0];
  }
  log('target module: ' + m.name + ' base=' + m.base + ' size=' + m.size);
  return m;
}

function buildNativeFunctions(ex) {
  return {
    configure: new NativeFunction(ex.qbditrace_configure, 'int', ['pointer']),
    runCall: new NativeFunction(ex.qbditrace_run_call, 'int',
        ['pointer', 'pointer', 'uint32', 'pointer']),
    stop: new NativeFunction(ex.qbditrace_stop, 'void', []),
    outputPath: new NativeFunction(ex.qbditrace_output_path, 'pointer', []),
  };
}

/*
 * Build the qbditrace_config_t struct in native memory matching the C layout:
 *
 *   uint64 trace_start
 *   uint64 trace_end
 *   uint64 module_base
 *   uint64 module_slide
 *   pointer module_name
 *   pointer output_path
 *   uint32 record
 *   uint32 anchor_interval
 *   uint64 ring_bytes
 *   uint64 objc_msgSend
 *   uint64 objc_msgSendSuper
 *   uint64 objc_msgSendSuper2
 *   uint64 objc_msgSend_stret
 *
 * On arm64 the struct is naturally aligned; pointers are 8 bytes. The two
 * uint32 fields (record, anchor_interval) pack into one 8-byte slot, then
 * ring_bytes and the four objc pointers follow 8-aligned.
 */
function buildConfigStruct(opts) {
  // Field offsets (bytes) for arm64 / LP64.
  // The struct starts with struct_size (u32) + _reserved0 (u32) = 8 bytes,
  // followed by the original fields shifted by 8:
  // 0:struct_size(u32) 4:_reserved0(u32) 8:start 16:end 24:base 32:slide
  // 40:name 48:out 56:record(u32) 60:anchor(u32) 64:ring_bytes
  // 72:objc_msgSend 80:objc_msgSendSuper 88:objc_msgSendSuper2
  // 96:objc_msgSend_stret 104:extra_range_start 112:extra_range_end
  // 120:disable_embed_code(u32) 124:enable_pc_delta(u32)
  // => total 128 bytes.
  const SIZE = 128;
  const cfg = Memory.alloc(SIZE);
  // Memory.alloc contents are undefined; zero the struct so any field we don't
  // explicitly set (incl. padding and the inverted-sense disable_embed_code)
  // defaults to 0 -> code embedding stays on.
  for (let i = 0; i < SIZE; i += 8) cfg.add(i).writePointer(ptr(0));

  const moduleNameStr = opts.moduleName
      ? Memory.allocUtf8String(opts.moduleName) : NULL;
  const outputPathStr = opts.outputPath
      ? Memory.allocUtf8String(opts.outputPath) : NULL;
  // Keep references alive on the struct object so GC doesn't free them.
  cfg._keep = [moduleNameStr, outputPathStr];

  // struct_size: ABI forward-compatibility field (must be set to sizeof).
  cfg.add(0).writeU32(SIZE);
  // _reserved0 stays 0 (already zeroed).
  cfg.add(8).writePointer(opts.traceStart);
  cfg.add(16).writePointer(opts.traceEnd);
  cfg.add(24).writePointer(opts.moduleBase);
  cfg.add(32).writePointer(opts.moduleSlide);
  cfg.add(40).writePointer(moduleNameStr);
  cfg.add(48).writePointer(outputPathStr);
  cfg.add(56).writeU32(opts.record >>> 0);
  cfg.add(60).writeU32(opts.anchorInterval >>> 0);
  cfg.add(64).writePointer(ptr(opts.ringBytes));
  // The objc fields are uint64 in C but we hold them as NativePointers; write
  // them as pointers (NULL when unresolved => 0, which the tracer ignores).
  cfg.add(72).writePointer(opts.objcMsgSend || NULL);
  cfg.add(80).writePointer(opts.objcMsgSendSuper || NULL);
  cfg.add(88).writePointer(opts.objcMsgSendSuper2 || NULL);
  cfg.add(96).writePointer(opts.objcMsgSendStret || NULL);
  // Optional second instrumented range (e.g. the module's __auth_stubs/__stubs
  // so objc_msgSend dispatch is observed with its real target). NULL => unused.
  cfg.add(104).writePointer(opts.extraRangeStart || NULL);
  cfg.add(112).writePointer(opts.extraRangeEnd || NULL);
  // Inverted sense: 0 keeps the default-on embedded code table. Pass
  // opts.embedCode === false to turn it off.
  cfg.add(120).writeU32(opts.embedCode === false ? 1 : 0);
  // enable_pc_delta stays 0 unless explicitly requested.
  return cfg;
}

/*
 * Resolve the objc_msgSend family runtime addresses from libobjc. Any that
 * cannot be found are returned as NULL (the tracer treats 0 as "not set").
 */
function resolveObjcDispatchers() {
  const out = {
    objcMsgSend: NULL,
    objcMsgSendSuper: NULL,
    objcMsgSendSuper2: NULL,
    objcMsgSendStret: NULL,
  };
  const map = {
    objcMsgSend: 'objc_msgSend',
    objcMsgSendSuper: 'objc_msgSendSuper',
    objcMsgSendSuper2: 'objc_msgSendSuper2',
    objcMsgSendStret: 'objc_msgSend_stret',
  };
  for (const key in map) {
    let p = null;
    try {
      p = Process.getModuleByName('libobjc.A.dylib').findExportByName(map[key]);
    } catch (e) {
      p = null;
    }
    if (!p) {
      try { p = Module.getGlobalExportByName(map[key]); } catch (e) { p = null; }
    }
    if (p && !p.isNull()) {
      out[key] = p;
      log('resolved ' + map[key] + ' @ ' + p);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Helper: build a numbered output path for multi-trace mode.
//
// Given "/var/mobile/Documents/qbditrace.bin" and index 3:
//   → "/var/mobile/Documents/qbditrace_003.bin"
// Given "/tmp/trace" (no extension) and index 42:
//   → "/tmp/trace_042"
// ---------------------------------------------------------------------------
function buildIndexedOutputPath(template, index) {
  const suffix = '_' + String(index).padStart(3, '0');
  const dot = template.lastIndexOf('.');
  if (dot > 0 && dot > template.lastIndexOf('/')) {
    return template.slice(0, dot) + suffix + template.slice(dot);
  }
  return template + suffix;
}

// ---------------------------------------------------------------------------
// GCD Block Tracing
//
// ObjC Block memory layout (arm64):
//   +0   isa pointer        (always _NSConcreteStackBlock or similar)
//   +8   flags (int32) + reserved (int32)
//   +16  invoke pointer     (void (*)(block_self, ...))   <-- this is what we want
//   +24  descriptor pointer
//   +32… captured variables
//
// dispatch_async(queue, block) submits the block to be invoked on a worker
// thread. We intercept the submission, read block+16 (the invoke function),
// and if it falls within our target module, immediately run it through QBDI
// on the calling thread.
// ---------------------------------------------------------------------------

function installGCDHooks(opts) {
  const { fn, mod, baseOpts, makeGCDOutputPath } = opts;
  const moduleStart = mod.base;
  const moduleEnd = mod.base.add(mod.size);
  const filterByModule = CONFIG.gcdFilterByModule !== false;
  const maxCaptures = CONFIG.gcdMaxCaptures || 0; // 0 = unlimited

  let gcdTraceCount = 0;
  let gcdInTrace = false;
  const gcdRetOut = Memory.alloc(8);
  const gcdArgv = Memory.alloc(8); // block invoke takes 1 arg: the block itself

  function isInModule(addr) {
    return addr.compare(moduleStart) >= 0 && addr.compare(moduleEnd) < 0;
  }

  function traceBlockIfNeeded(block, dispatcherName) {
    if (gcdInTrace) return; // avoid re-entrancy
    if (block.isNull()) return;

    // Read the invoke function pointer at offset +16.
    let invoke;
    try {
      invoke = block.add(16).readPointer();
    } catch (e) {
      return; // unreadable memory, skip silently
    }
    if (invoke.isNull()) return;

    // Filter: only trace if invoke is within the target module.
    if (filterByModule && !isInModule(invoke)) return;

    // Check capture limit.
    if (maxCaptures > 0 && gcdTraceCount >= maxCaptures) return;

    gcdInTrace = true;
    gcdTraceCount++;
    const idx = gcdTraceCount;

    log('[GCD] ' + dispatcherName + ': block invoke @ ' + invoke +
        ' (offset 0x' + invoke.sub(moduleStart).toString(16) +
        ') -> tracing as GCD capture #' + idx);

    // Configure a new trace file for this block.
    const outPath = makeGCDOutputPath(idx);
    const cfgOpts = Object.assign({}, baseOpts, {
      outputPath: outPath,
      // Widen the trace range to cover the block's invoke function.
      // Use the full module as the range so intra-module calls are followed.
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

    // Execute the block under QBDI: invoke(block)
    gcdArgv.writePointer(block);
    const r = fn.runCall(gcdRetOut, invoke, 1, gcdArgv);
    if (r !== 0) {
      log('[GCD] WARNING: run_call failed for GCD block #' + idx + ', rc=' + r);
    }
    fn.stop();

    log('[GCD] capture #' + idx + ' done. output = ' +
        fn.outputPath().readUtf8String());

    gcdInTrace = false;
  }

  // Hook the GCD dispatch family.
  const dispatchers = [
    'dispatch_async',
    'dispatch_after',  // dispatch_after(when, queue, block)
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

    // dispatch_async(queue, block):         block is arg[1]
    // dispatch_barrier_async(queue, block): block is arg[1]
    // dispatch_after(when, queue, block):   block is arg[2]
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

function main() {
  const dylib = loadDylib(CONFIG.dylibPath);
  const ex = resolveExports(dylib);
  const fn = buildNativeFunctions(ex);
  const mod = resolveTargetModule();

  // Compute runtime addresses from static offset or symbol name.
  const moduleBase = mod.base; // NativePointer
  let funcStart;
  if (CONFIG.funcName) {
    // Auto-resolve by exported symbol name.
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
      log('resolved funcName "' + CONFIG.funcName + '" @ ' + funcStart +
          ' (offset = 0x' + funcStart.sub(moduleBase).toString(16) + ')');
    } else {
      log('WARNING: funcName "' + CONFIG.funcName +
          '" not found, falling back to funcOffset');
      funcStart = moduleBase.add(CONFIG.funcOffset);
    }
  } else {
    funcStart = moduleBase.add(CONFIG.funcOffset);
  }
  const funcEnd = funcStart.add(CONFIG.rangeSize);

  // ASLR slide: difference between runtime base and the image's preferred base.
  // We approximate the preferred base as 0 here and treat module_slide ==
  // moduleBase, because the decoder normalizes via:
  //   static = runtime - module_slide
  // If your image's preferred base is non-zero (rare for PIE on iOS, which is
  // 0-based), set it explicitly. For PIE Mach-O the preferred base is 0, so
  // slide == moduleBase and static offsets map directly to funcOffset.
  const moduleSlide = moduleBase;

  log('func start = ' + funcStart + '  end = ' + funcEnd);
  log('module slide = ' + moduleSlide);

  const objc = CONFIG.resolveObjc ? resolveObjcDispatchers() : {
    objcMsgSend: NULL, objcMsgSendSuper: NULL,
    objcMsgSendSuper2: NULL, objcMsgSendStret: NULL,
  };

  // --- Determine trace limit from traceMode ---
  // maxTraces = 1        → "once"
  // maxTraces = Infinity → "multi"
  // maxTraces = N        → trace N times
  let maxTraces;
  const mode = CONFIG.traceMode;
  if (mode === 'once' || mode === 1) {
    maxTraces = 1;
  } else if (mode === 'multi') {
    maxTraces = Infinity;
  } else if (typeof mode === 'number' && mode > 0) {
    maxTraces = Math.floor(mode);
  } else {
    // Unknown mode: default to once.
    log('WARNING: unknown traceMode "' + mode + '", defaulting to "once"');
    maxTraces = 1;
  }
  const multiMode = maxTraces !== 1;

  // Shared info used across multiple captures.
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
    objcMsgSend: objc.objcMsgSend,
    objcMsgSendSuper: objc.objcMsgSendSuper,
    objcMsgSendSuper2: objc.objcMsgSendSuper2,
    objcMsgSendStret: objc.objcMsgSendStret,
  };

  // --- Configure and start the first trace ---
  // In multi mode the output path gets a numeric suffix; in once mode the
  // configured path is used verbatim for backward compatibility.
  function makeOutputPath(traceIndex) {
    if (multiMode) {
      return buildIndexedOutputPath(CONFIG.outputPath, traceIndex);
    }
    return CONFIG.outputPath;
  }

  function configureForTrace(traceIndex) {
    const outPath = makeOutputPath(traceIndex);
    const cfg = buildConfigStruct(Object.assign({}, baseOpts, { outputPath: outPath }));
    const rc = fn.configure(cfg);
    if (rc !== 0) {
      fail('qbditrace_configure failed (trace #' + traceIndex + '), rc=' + rc);
    }
    log('configured trace #' + traceIndex +
        '. output = ' + fn.outputPath().readUtf8String());
    return cfg; // keep alive
  }

  // Configure for the first trace now so the writer is ready before the hook fires.
  let currentCfg = configureForTrace(1);
  let traceCount = 0;
  let inTrace = false; // re-entrancy guard (shouldn't happen, but be safe)

  // Scratch buffers (allocated once, reused across captures).
  const retOut = Memory.alloc(8);
  const argc = CONFIG.argCount >>> 0;
  const argv = argc > 0 ? Memory.alloc(8 * argc) : NULL;

  // -------------------------------------------------------------------------
  // IMPORTANT: Interceptor.replace writes a trampoline over the first bytes of
  // funcStart. QBDI reads instructions straight from target memory, so if the
  // trampoline were still present QBDI would trace it instead of the real
  // prologue. Before calling QBDI we must revert the hook to restore the
  // genuine bytes. After QBDI returns we optionally re-arm the hook for the
  // next capture (multi mode only).
  // -------------------------------------------------------------------------

  function installHook() {
    Interceptor.replace(funcStart, new NativeCallback(function () {
      if (inTrace) {
        // Re-entrant call during tracing (should not happen in practice).
        // Call the real function natively by reverting and re-invoking.
        log('WARNING: re-entrant call during trace, running natively');
        Interceptor.revert(funcStart);
        Interceptor.flush();
        for (let i = 0; i < argc; i++) {
          argv.add(i * 8).writePointer(this.context['x' + i]);
        }
        const r = fn.runCall(retOut, funcStart, argc, argv);
        installHook(); // re-arm
        return retOut.readPointer();
      }

      // --- Capture this invocation ---
      inTrace = true;
      traceCount++;
      const thisTrace = traceCount;

      log('-> entering traced function (trace #' + thisTrace + ') with ' + argc + ' args');

      // Forward the original integer arguments (arm64 AAPCS: x0..x7).
      for (let i = 0; i < argc; i++) {
        argv.add(i * 8).writePointer(this.context['x' + i]);
      }

      // Remove our trampoline so funcStart holds the genuine instructions.
      Interceptor.revert(funcStart);
      Interceptor.flush();

      const r = fn.runCall(retOut, funcStart, argc, argv);
      if (r !== 0) {
        log('qbditrace_run_call returned error rc=' + r);
      }
      const ret = retOut.readPointer();

      // Flush this trace to disk.
      fn.stop();
      log('<- trace #' + thisTrace + ' done, ret = ' + ret +
          '. output = ' + fn.outputPath().readUtf8String());

      inTrace = false;

      // --- Decide whether to capture more ---
      const wantMore = (traceCount < maxTraces);
      if (wantMore && CONFIG.rehook !== false) {
        // Configure the next trace file and re-arm the hook.
        currentCfg = configureForTrace(traceCount + 1);
        installHook();
        log('hook re-installed for trace #' + (traceCount + 1) +
            '. Trigger the function again to capture.');
      } else if (!wantMore) {
        log('all ' + traceCount + ' trace(s) captured. Hook removed.');
        // Hook already reverted above; do not re-install.
      }
      // If wantMore but rehook===false, we simply leave the hook reverted.

      return ret;
    }, 'pointer', buildArgTypes(argc)));
  }

  installHook();

  if (multiMode) {
    log('hook installed on ' + funcStart + ' (mode=' + CONFIG.traceMode +
        ', max=' + maxTraces + '). Trigger the function to trace.');
  } else {
    log('hook installed on ' + funcStart + '. Trigger the function to trace.');
  }

  // --- Optional: GCD block tracing ---
  if (CONFIG.traceGCD) {
    // GCD trace files use a separate naming scheme: "..._gcd_001.bin"
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

function buildArgTypes(argc) {
  const t = [];
  for (let i = 0; i < argc; i++) {
    t.push('pointer');
  }
  return t;
}

main();
