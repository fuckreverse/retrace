/*
 * qbditrace - Frida agent for the QBDI-based high-performance tracer.
 *
 * This script is intentionally thin: it only loads the native tracer dylib,
 * resolves addresses, and diverts the target function into the QBDI VM. Every
 * per-instruction operation happens in native code, so this JS has ZERO impact
 * on tracing speed (it runs once at setup, and once per traced call).
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
 * Workflow:
 *   1. Python loader spawns/attaches to the target, loads this script.
 *   2. Python sends CONFIG via script.post({ type: 'config', payload: {...} }).
 *   3. This script receives CONFIG, loads libqbditrace.dylib, resolves addresses.
 *   4. Interceptor.replace(entryFunc) -> qbditrace_run_call(retOut, func, args)
 *   5. After the call returns, qbditrace_stop() flushes the trace to disk.
 *   6. Script sends status messages back to Python via send().
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
    m = Process.enumerateModules()[0];
  }
  log('target module: ' + m.name + ' base=' + m.base + ' size=0x' +
      m.size.toString(16) + ' (' + m.size + ' bytes)');
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

function buildConfigStruct(opts) {
  const SIZE = 128;
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
  return cfg;
}

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
// Main entry point — called after CONFIG is received from Python
// ---------------------------------------------------------------------------

function main() {
  status('initializing');

  const dylib = loadDylib(CONFIG.dylibPath);
  const ex = resolveExports(dylib);
  const fn = buildNativeFunctions(ex);
  const mod = resolveTargetModule();

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

  const objc = CONFIG.resolveObjc ? resolveObjcDispatchers() : {
    objcMsgSend: NULL, objcMsgSendSuper: NULL,
    objcMsgSendSuper2: NULL, objcMsgSendStret: NULL,
  };

  let maxTraces;
  const mode = CONFIG.traceMode;
  if (mode === 'once' || mode === 1) {
    maxTraces = 1;
  } else if (mode === 'multi') {
    maxTraces = Infinity;
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
    objcMsgSend: objc.objcMsgSend,
    objcMsgSendSuper: objc.objcMsgSendSuper,
    objcMsgSendSuper2: objc.objcMsgSendSuper2,
    objcMsgSendStret: objc.objcMsgSendStret,
  };

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
    return cfg;
  }

  let currentCfg = configureForTrace(1);
  let traceCount = 0;
  let inTrace = false;

  const retOut = Memory.alloc(8);
  const argc = CONFIG.argCount >>> 0;
  const argv = argc > 0 ? Memory.alloc(8 * argc) : NULL;

  function buildArgTypes(n) {
    const t = [];
    for (let i = 0; i < n; i++) t.push('pointer');
    return t;
  }

  function installHook() {
    Interceptor.replace(funcStart, new NativeCallback(function () {
      if (inTrace) {
        log('WARNING: re-entrant call during trace, running natively');
        Interceptor.revert(funcStart);
        Interceptor.flush();
        for (let i = 0; i < argc; i++) {
          argv.add(i * 8).writePointer(this.context['x' + i]);
        }
        const r = fn.runCall(retOut, funcStart, argc, argv);
        installHook();
        return retOut.readPointer();
      }

      inTrace = true;
      traceCount++;
      const thisTrace = traceCount;

      log('-> entering entry function (trace #' + thisTrace + ') with ' + argc + ' args');
      status('trace_start', { index: thisTrace });

      for (let i = 0; i < argc; i++) {
        argv.add(i * 8).writePointer(this.context['x' + i]);
      }

      Interceptor.revert(funcStart);
      Interceptor.flush();

      const r = fn.runCall(retOut, funcStart, argc, argv);
      if (r !== 0) {
        log('qbditrace_run_call returned error rc=' + r);
      }
      const ret = retOut.readPointer();

      fn.stop();
      const outFile = fn.outputPath().readUtf8String();
      log('<- trace #' + thisTrace + ' done, ret = ' + ret + '. output = ' + outFile);
      status('trace_done', { index: thisTrace, ret: ret.toString(), output: outFile });

      inTrace = false;

      const wantMore = (traceCount < maxTraces);
      if (wantMore && CONFIG.rehook !== false) {
        currentCfg = configureForTrace(traceCount + 1);
        installHook();
        log('hook re-installed for trace #' + (traceCount + 1));
      } else if (!wantMore) {
        log('all ' + traceCount + ' trace(s) captured. Hook removed.');
        status('all_done', { total: traceCount });
      }

      return ret;
    }, 'pointer', buildArgTypes(argc)));
  }

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

  // --- Optional: GCD block tracing ---
  if (CONFIG.traceGCD) {
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

// ===========================================================================
// Message dispatcher — receives CONFIG from Python, then starts main()
// ===========================================================================

recv('config', function (message) {
  CONFIG = message.payload;
  log('config received from Python loader');
  main();
});

status('agent_loaded');
log('agent loaded, waiting for config from Python loader...');
