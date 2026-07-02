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
   * offset 288  capi_funcs[0..127]   128×{u64 addr, u8 api_id, u8 n_args, u8 str_args, u8 _reserved} = 128×16 = 2048 bytes
   *
   * Total: 280 + 4 + 4 + 2048 = 2336 bytes
   */
  const SIZE = 2336;
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
  /* Each capi_funcs entry is 16 bytes:
   *   u64 addr      (offset 0)
   *   u8  api_id    (offset 8)
   *   u8  n_args    (offset 9)
   *   u8  str_args  (offset 10)
   *   u8  _reserved (offset 11)
   *   u32 padding   (offset 12)
   */
  for (let i = 0; i < capiFuncs.length && i < 128; i++) {
    const base = 288 + i * 16;
    cfg.add(base).writePointer(capiFuncs[i].addr || NULL);
    cfg.add(base + 8).writeU8(capiFuncs[i].apiId || 0);
    cfg.add(base + 9).writeU8(capiFuncs[i].nArgs || 0);
    cfg.add(base + 10).writeU8(capiFuncs[i].strArgs || 0);
    cfg.add(base + 11).writeU8(0); /* _reserved */
  }
  return cfg;
}

function isAndroid() {
  return Process.platform === 'linux';
}

function resolveObjcDispatchers() {
  const out = {
    objcMsgSend: NULL,
    objcMsgSendSuper: NULL,
    objcMsgSendSuper2: NULL,
    objcMsgSendStret: NULL,
  };
  /* ObjC runtime is only available on iOS/macOS. On Android/Linux there is no
   * libobjc and no ObjC dispatchers to resolve — all pointers stay NULL, which
   * causes the native tracer to skip OBJC record emission automatically. */
  if (isAndroid()) {
    log('Android target — skipping ObjC dispatcher resolution');
    return out;
  }
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
 * The JNINativeInterface_ vtable layout (jni.h, AArch64 LP64):
 *   slot  0: reserved0
 *   slot  1: reserved1
 *   slot  2: reserved2
 *   slot  3: reserved3
 *   slot  4: GetVersion
 *   slot  5: DefineClass
 *   slot  6: FindClass
 *   slot  7: FromReflectedMethod
 *   slot  8: FromReflectedField
 *   slot  9: ToReflectedMethod
 *   slot 10: GetSuperclass
 *   slot 11: IsAssignableFrom
 *   slot 12: ToReflectedField
 *   slot 13: Throw
 *   slot 14: ThrowNew
 *   slot 15: ExceptionOccurred
 *   slot 16: ExceptionDescribe
 *   slot 17: ExceptionClear
 *   slot 18: FatalError
 *   slot 19: PushLocalFrame
 *   slot 20: PopLocalFrame
 *   slot 21: NewGlobalRef
 *   slot 22: DeleteGlobalRef
 *   slot 23: DeleteLocalRef
 *   slot 24: IsSameObject
 *   slot 25: NewLocalRef
 *   slot 26: EnsureLocalCapacity
 *   slot 27: AllocObject
 *   slot 28: NewObject
 *   slot 29: NewObjectV
 *   slot 30: NewObjectA
 *   slot 31: GetObjectClass
 *   slot 32: IsInstanceOf
 *   slot 33: GetMethodID
 *   slot 34: CallObjectMethod
 *   slot 36: CallObjectMethodA
 *   slot 37: CallBooleanMethod
 *   slot 40: CallBooleanMethodA
 *   slot 41: CallByteMethod
 *   slot 43: CallByteMethodA
 *   slot 44: CallCharMethod
 *   slot 47: CallIntMethod
 *   slot 50: CallLongMethod
 *   slot 53: CallFloatMethod
 *   slot 56: CallDoubleMethod
 *   slot 59: CallVoidMethod
 *   slot 62: CallVoidMethodA
 *   slot 63: CallNonvirtualObjectMethod
 *   slot 72: GetFieldID
 *   slot 73: GetObjectField
 *   slot 74: GetBooleanField
 *   slot 75: GetByteField
 *   slot 76: GetCharField
 *   slot 77: GetShortField
 *   slot 78: GetIntField
 *   slot 79: GetLongField
 *   slot 80: GetFloatField
 *   slot 81: GetDoubleField
 *   slot 82: SetObjectField
 *   slot 85: SetIntField
 *   slot 87: SetLongField
 *   slot 90: GetStaticMethodID
 *   slot 91: CallStaticObjectMethod
 *   slot 95: CallStaticBooleanMethod
 *   slot 99: CallStaticIntMethod
 *   slot 103: CallStaticLongMethod
 *   slot 107: CallStaticVoidMethod
 *   slot 110: GetStaticFieldID
 *   slot 111: GetStaticObjectField
 *   slot 119: SetStaticObjectField
 *   slot 124: NewString
 *   slot 125: GetStringLength
 *   slot 126: GetStringChars
 *   slot 127: ReleaseStringChars
 *   slot 128: NewStringUTF
 *   slot 129: GetStringUTFLength
 *   slot 130: GetStringUTFChars
 *   slot 131: ReleaseStringUTFChars
 *   slot 132: GetArrayLength
 *   slot 133: NewObjectArray
 *   slot 134: GetObjectArrayElement
 *   slot 135: SetObjectArrayElement
 *   slot 136: NewBooleanArray
 *   slot 137: NewByteArray
 *   slot 140: NewIntArray
 *   slot 152: GetByteArrayElements
 *   slot 156: GetIntArrayElements
 *   slot 162: ReleaseBooleanArrayElements
 *   slot 163: ReleaseByteArrayElements
 *   slot 167: ReleaseIntArrayElements
 *   slot 175: GetByteArrayRegion
 *   slot 179: GetIntArrayRegion
 *   slot 185: SetByteArrayRegion
 *   slot 189: SetIntArrayRegion
 *   slot 195: RegisterNatives
 *   slot 196: UnregisterNatives
 *   slot 197: MonitorEnter
 *   slot 198: MonitorExit
 *   slot 199: GetJavaVM
 *   slot 200: GetStringRegion
 *   slot 201: GetStringUTFRegion
 *   slot 204: NewWeakGlobalRef
 *   slot 205: DeleteWeakGlobalRef
 *   slot 206: ExceptionCheck
 *   slot 209: ExceptionClear (duplicate in some impls)
 *   slot 212: GetVersion (duplicate in some impls)
 */
var JNI_VTABLE_SLOTS = [
  { slot:   4, apiId: 723, nArgs: 1, strArgs: 0x00, name: 'GetVersion' },
  { slot:   5, apiId: 300, nArgs: 4, strArgs: 0x03, name: 'DefineClass' },  // a1=name, a2=loader
  { slot:   6, apiId: 289, nArgs: 2, strArgs: 0x02, name: 'FindClass' },    // a1=name
  { slot:  19, apiId: 721, nArgs: 2, strArgs: 0x00, name: 'PushLocalFrame' },
  { slot:  20, apiId: 722, nArgs: 2, strArgs: 0x00, name: 'PopLocalFrame' },
  { slot:  21, apiId: 718, nArgs: 2, strArgs: 0x00, name: 'NewGlobalRef' },
  { slot:  22, apiId: 719, nArgs: 2, strArgs: 0x00, name: 'DeleteGlobalRef' },
  { slot:  23, apiId: 720, nArgs: 2, strArgs: 0x00, name: 'DeleteLocalRef' },
  { slot:  28, apiId: 716, nArgs: 3, strArgs: 0x00, name: 'NewObject' },
  { slot:  32, apiId: 717, nArgs: 3, strArgs: 0x00, name: 'IsInstanceOf' },
  { slot:  33, apiId: 290, nArgs: 4, strArgs: 0x06, name: 'GetMethodID' },  // a2=name,a3=sig
  { slot:  34, apiId: 292, nArgs: 3, strArgs: 0x00, name: 'CallObjectMethod' },
  { slot:  37, apiId: 295, nArgs: 3, strArgs: 0x00, name: 'CallBooleanMethod' },
  { slot:  47, apiId: 296, nArgs: 3, strArgs: 0x00, name: 'CallIntMethod' },
  { slot:  50, apiId: 297, nArgs: 3, strArgs: 0x00, name: 'CallLongMethod' },
  { slot:  59, apiId: 294, nArgs: 3, strArgs: 0x00, name: 'CallVoidMethod' },
  { slot:  72, apiId: 704, nArgs: 4, strArgs: 0x06, name: 'GetFieldID' },   // a2=name,a3=sig
  { slot:  73, apiId: 702, nArgs: 3, strArgs: 0x00, name: 'GetObjectField' },
  { slot:  78, apiId: 700, nArgs: 3, strArgs: 0x00, name: 'GetIntField' },
  { slot:  79, apiId: 701, nArgs: 3, strArgs: 0x00, name: 'GetLongField' },
  { slot:  82, apiId: 703, nArgs: 4, strArgs: 0x00, name: 'SetObjectField' },
  { slot:  90, apiId: 291, nArgs: 4, strArgs: 0x06, name: 'GetStaticMethodID' }, // a2=name,a3=sig
  { slot:  91, apiId: 293, nArgs: 3, strArgs: 0x00, name: 'CallStaticObjectMethod' },
  { slot:  95, apiId: 715, nArgs: 3, strArgs: 0x00, name: 'CallStaticBooleanMethod' },
  { slot:  99, apiId: 714, nArgs: 3, strArgs: 0x00, name: 'CallStaticIntMethod' },
  { slot: 107, apiId: 294, nArgs: 3, strArgs: 0x00, name: 'CallStaticVoidMethod' },
  { slot: 110, apiId: 705, nArgs: 4, strArgs: 0x06, name: 'GetStaticFieldID' },
  { slot: 124, apiId: 282, nArgs: 2, strArgs: 0x00, name: 'NewStringUTF' },
  { slot: 128, apiId: 282, nArgs: 2, strArgs: 0x02, name: 'NewStringUTF' }, // a1=bytes
  { slot: 129, apiId: 283, nArgs: 2, strArgs: 0x00, name: 'GetStringUTFLength' },
  { slot: 130, apiId: 280, nArgs: 3, strArgs: 0x00, name: 'GetStringUTFChars' },
  { slot: 131, apiId: 281, nArgs: 3, strArgs: 0x00, name: 'ReleaseStringUTFChars' },
  { slot: 132, apiId: 707, nArgs: 2, strArgs: 0x00, name: 'GetArrayLength' },
  { slot: 133, apiId: 708, nArgs: 4, strArgs: 0x00, name: 'NewObjectArray' },
  { slot: 134, apiId: 709, nArgs: 3, strArgs: 0x00, name: 'GetObjectArrayElement' },
  { slot: 135, apiId: 710, nArgs: 4, strArgs: 0x00, name: 'SetObjectArrayElement' },
  { slot: 137, apiId: 288, nArgs: 2, strArgs: 0x00, name: 'NewByteArray' },
  { slot: 140, apiId: 711, nArgs: 2, strArgs: 0x00, name: 'NewIntArray' },
  { slot: 152, apiId: 284, nArgs: 3, strArgs: 0x00, name: 'GetByteArrayElements' },
  { slot: 156, apiId: 712, nArgs: 3, strArgs: 0x00, name: 'GetIntArrayElements' },
  { slot: 163, apiId: 285, nArgs: 4, strArgs: 0x00, name: 'ReleaseByteArrayElements' },
  { slot: 167, apiId: 713, nArgs: 4, strArgs: 0x00, name: 'ReleaseIntArrayElements' },
  { slot: 175, apiId: 286, nArgs: 5, strArgs: 0x00, name: 'GetByteArrayRegion' },
  { slot: 179, apiId: 712, nArgs: 5, strArgs: 0x00, name: 'GetIntArrayRegion' },
  { slot: 185, apiId: 287, nArgs: 5, strArgs: 0x00, name: 'SetByteArrayRegion' },
  { slot: 189, apiId: 713, nArgs: 5, strArgs: 0x00, name: 'SetIntArrayRegion' },
  { slot: 197, apiId: 724, nArgs: 2, strArgs: 0x00, name: 'MonitorEnter' },
  { slot: 198, apiId: 725, nArgs: 2, strArgs: 0x00, name: 'MonitorExit' },
  { slot: 199, apiId: 726, nArgs: 2, strArgs: 0x00, name: 'GetJavaVM' },
  { slot: 201, apiId: 706, nArgs: 5, strArgs: 0x00, name: 'GetStringUTFRegion' },
  { slot: 206, apiId: 298, nArgs: 1, strArgs: 0x00, name: 'ExceptionCheck' },
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
    /* JavaVM vtable layout: [0]=DestroyJavaVM,[1]=AttachCurrentThread,
     *                        [2]=DetachCurrentThread,[3]=GetEnv,
     *                        [4]=AttachCurrentThreadAsDaemon */
    var vmVtable = vm.readPointer();  /* JNIInvokeInterface_ * */
    var getEnvFnPtr = vmVtable.add(3 * Process.pointerSize).readPointer();
    if (getEnvFnPtr.isNull()) return null;

    var getEnvFn = new NativeFunction(getEnvFnPtr, 'int', ['pointer', 'pointer', 'int']);
    var envBuf = Memory.alloc(8);
    var JNI_VERSION_1_6 = 0x00010006;
    rc = getEnvFn(vm, envBuf, JNI_VERSION_1_6);
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
  if (CONFIG.excludeRanges && CONFIG.excludeRanges.length > 0) {
    CONFIG.excludeRanges.forEach(function(r, idx) {
      log('exclude[' + idx + '] = ' + moduleBase.add(r.start) +
          ' - ' + moduleBase.add(r.end) +
          ' (offset 0x' + r.start.toString(16) +
          ' - 0x' + r.end.toString(16) + ')');
    });
  }

  const objc = CONFIG.resolveObjc ? resolveObjcDispatchers() : {
    objcMsgSend: NULL, objcMsgSendSuper: NULL,
    objcMsgSendSuper2: NULL, objcMsgSendStret: NULL,
  };

  // --- Resolve C API function addresses ---
  const capiIntercept = CONFIG.enableCapiIntercept !== false;  // on by default
  const capiFuncs = capiIntercept ? resolveCApiFunctions() : [];

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
    return cfg;
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

    var invokeRc = fn.runCall(invokeRetOut, funcStart, invokeArgc, invokeArgv);
    if (invokeRc !== 0) {
      log('qbditrace_run_call returned error rc=' + invokeRc);
    }
    var invokeRet = invokeRetOut.readPointer();

    fn.stop();

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
