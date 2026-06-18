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

  // Static (file) offset of the function start within the module, i.e. the
  // address you see in IDA minus the module's preferred base.
  // Example: IDA shows func at 0x100A1B2C0, image base 0x100000000 => 0xA1B2C0
  funcOffset: 0x0,

  // Length in bytes of the address range to trace (function size, or larger to
  // cover callees within the same module). Range = [start, start+rangeSize).
  rangeSize: 0x400,

  // Where to write the binary trace on the device.
  // In "multi" mode this is treated as a template: the three-digit index is
  // inserted before the last dot (e.g. "qbditrace.bin" → "qbditrace_001.bin").
  // If the path has no extension the suffix is appended directly.
  outputPath: '/var/mobile/Documents/qbditrace.bin',

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
  argCount: 0,

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
  // Frida's Module.load throws if it fails; that's what we want.
  const m = Module.load(path);
  log('loaded dylib: ' + path + ' @ ' + m.base);
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
        ['pointer', 'uint64', 'uint32', 'pointer']),
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
  // 0:start 8:end 16:base 24:slide 32:name 40:out 48:record 52:anchor
  // 56:ring_bytes 64:objc_msgSend 72:objc_msgSendSuper 80:objc_msgSendSuper2
  // 88:objc_msgSend_stret 96:extra_range_start 104:extra_range_end
  // 112:disable_embed_code (u32) -> struct padded to 8-byte multiple.
  // => total 120 bytes.
  const SIZE = 120;
  const cfg = Memory.alloc(SIZE);
  // Memory.alloc contents are undefined; zero the struct so any field we don't
  // explicitly set (incl. padding and the inverted-sense disable_embed_code)
  // defaults to 0 -> code embedding stays on.
  for (let i = 0; i < SIZE; i += 8) cfg.add(i).writeU64(0);

  const moduleNameStr = opts.moduleName
      ? Memory.allocUtf8String(opts.moduleName) : NULL;
  const outputPathStr = opts.outputPath
      ? Memory.allocUtf8String(opts.outputPath) : NULL;
  // Keep references alive on the struct object so GC doesn't free them.
  cfg._keep = [moduleNameStr, outputPathStr];

  cfg.add(0).writeU64(opts.traceStart);
  cfg.add(8).writeU64(opts.traceEnd);
  cfg.add(16).writeU64(opts.moduleBase);
  cfg.add(24).writeU64(opts.moduleSlide);
  cfg.add(32).writePointer(moduleNameStr);
  cfg.add(40).writePointer(outputPathStr);
  cfg.add(48).writeU32(opts.record >>> 0);
  cfg.add(52).writeU32(opts.anchorInterval >>> 0);
  cfg.add(56).writeU64(opts.ringBytes);
  // The objc fields are uint64 in C but we hold them as NativePointers; write
  // them as pointers (NULL when unresolved => 0, which the tracer ignores).
  cfg.add(64).writePointer(opts.objcMsgSend || NULL);
  cfg.add(72).writePointer(opts.objcMsgSendSuper || NULL);
  cfg.add(80).writePointer(opts.objcMsgSendSuper2 || NULL);
  cfg.add(88).writePointer(opts.objcMsgSendStret || NULL);
  // Optional second instrumented range (e.g. the module's __auth_stubs/__stubs
  // so objc_msgSend dispatch is observed with its real target). NULL => unused.
  cfg.add(96).writePointer(opts.extraRangeStart || NULL);
  cfg.add(104).writePointer(opts.extraRangeEnd || NULL);
  // Inverted sense: 0 keeps the default-on embedded code table. Pass
  // opts.embedCode === false to turn it off.
  cfg.add(112).writeU32(opts.embedCode === false ? 1 : 0);
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
      p = Module.findExportByName('libobjc.A.dylib', map[key]);
    } catch (e) {
      p = null;
    }
    if (!p) {
      try { p = Module.findExportByName(null, map[key]); } catch (e) { p = null; }
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

function main() {
  const dylib = loadDylib(CONFIG.dylibPath);
  const ex = resolveExports(dylib);
  const fn = buildNativeFunctions(ex);
  const mod = resolveTargetModule();

  // Compute runtime addresses from static offset.
  const moduleBase = mod.base; // NativePointer
  const funcStart = moduleBase.add(CONFIG.funcOffset);
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
        return retOut.readU64();
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
      const ret = retOut.readU64();

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
    }, 'uint64', buildArgTypes(argc)));
  }

  installHook();

  if (multiMode) {
    log('hook installed on ' + funcStart + ' (mode=' + CONFIG.traceMode +
        ', max=' + maxTraces + '). Trigger the function to trace.');
  } else {
    log('hook installed on ' + funcStart + '. Trigger the function to trace.');
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
