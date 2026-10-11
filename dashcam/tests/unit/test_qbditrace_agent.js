'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const agentPath = path.resolve(__dirname, '../../dashcam.js');
const context = vm.createContext({
  console,
  recv() {},
  send() {},
});
vm.runInContext(fs.readFileSync(agentPath, 'utf8'), context, { filename: agentPath });
const planObjcDispatchers = vm.runInContext('planObjcDispatchers', context);
const buildConfigStruct = vm.runInContext('buildConfigStruct', context);

function makeMemory() {
  return {
    alloc(size) {
      const bytes = Buffer.alloc(size);
      function pointer(offset = 0) {
        return {
          add(delta) { return pointer(offset + delta); },
          writePointer(value) {
            bytes.writeBigUInt64LE(BigInt(value && value.value || 0), offset);
          },
          writeU32(value) { bytes.writeUInt32LE(value >>> 0, offset); },
          writeU16(value) { bytes.writeUInt16LE(value >>> 0, offset); },
          writeU8(value) { bytes.writeUInt8(value >>> 0, offset); },
          get bytes() { return bytes; },
        };
      }
      return pointer();
    },
    allocUtf8String() { return { value: 0 }; },
  };
}

function lookup(overrides = {}) {
  return {
    explicit: overrides.explicit || (() => null),
    global: overrides.global || (() => null),
    module: overrides.module || (() => null),
  };
}

test('buildConfigStruct writes 16-bit C API ids without truncation', () => {
  context.Memory = makeMemory();
  context.NULL = { value: 0 };
  context.ptr = value => ({ value: Number(value) || 0 });

  const cfg = buildConfigStruct({
    ringBytes: 0,
    record: 0,
    anchorInterval: 0,
    capiFuncs: [
      { addr: { value: 0x1122334455667788n }, apiId: 723, nArgs: 3, strArgs: 5 },
      { addr: { value: 0x8877665544332211n }, apiId: 704, nArgs: 7, strArgs: 9 },
    ],
  });

  assert.equal(cfg.bytes.readBigUInt64LE(288), 0x1122334455667788n, 'entry 0 address');
  assert.equal(cfg.bytes.readUInt8(296), 0xd3, 'apiId low byte');
  assert.equal(cfg.bytes.readUInt8(297), 0x02, 'apiId high byte');
  assert.equal(cfg.bytes.readUInt8(298), 3, 'nArgs follows the uint16 apiId');
  assert.equal(cfg.bytes.readUInt8(299), 5, 'strArgs follows nArgs');
  assert.equal(cfg.bytes.readBigUInt64LE(304), 0x8877665544332211n,
      'entry 1 starts at the native 16-byte stride (12 bytes fields + 4 padding)');
  assert.equal(cfg.bytes.readUInt16LE(312), 704, 'entry 1 apiId uses its native offset');
  assert.equal(cfg.bytes.readUInt8(314), 7, 'entry 1 nArgs uses its native offset');
  assert.equal(cfg.bytes.readUInt8(315), 9, 'entry 1 strArgs uses its native offset');
  assert.equal(cfg.bytes.readUInt32LE(300), 0, 'entry 0 trailing padding stays zero');
  assert.equal(cfg.bytes.length, 2472, 'config size matches native sizeof(qbditrace_config_t)');
});

test('explicit ObjC address takes priority over automatic discovery', () => {
  let fallbackCalls = 0;
  const result = planObjcDispatchers(
      { record: 16, resolveObjc: true, objcMsgSend: '0x1111' },
      'darwin',
      lookup({
        explicit: value => value,
        global: () => { fallbackCalls++; return '0x2222'; },
        module: () => { fallbackCalls++; return '0x3333'; },
      }));

  assert.deepEqual(
      { address: result.entries[0].address, source: result.entries[0].source },
      { address: '0x1111', source: 'explicit' });
  assert.equal(fallbackCalls, 3, 'fallback is skipped only for the explicit dispatcher');
});

test('automatic discovery uses global export before module export fallback', () => {
  const result = planObjcDispatchers(
      { record: 16, resolveObjc: true },
      'darwin',
      lookup({
        global: symbol => symbol === 'objc_msgSend' ? 'global-send' : null,
        module: symbol => 'module-' + symbol,
      }));

  assert.equal(result.entries[0].address, 'global-send');
  assert.equal(result.entries[0].source, 'global');
  assert.equal(result.entries[1].address, 'module-objc_msgSendSuper');
  assert.equal(result.entries[1].source, 'module');
});

test('missing ObjC symbols remain zero-configurable and are reported', () => {
  const result = planObjcDispatchers(
      { record: 16, resolveObjc: true }, 'darwin', lookup());

  assert.equal(result.enabled, true);
  assert.equal(result.entries.every(entry => entry.address === null), true);
  assert.deepEqual(Array.from(result.missing), [
    'objc_msgSend',
    'objc_msgSendSuper',
    'objc_msgSendSuper2',
    'objc_msgSend_stret',
  ]);
});

test('record without MSGSEND disables resolution', () => {
  let lookupCalls = 0;
  const disabledLookup = lookup({
    explicit: () => { lookupCalls++; return 'explicit'; },
    global: () => { lookupCalls++; return 'global'; },
    module: () => { lookupCalls++; return 'module'; },
  });
  const result = planObjcDispatchers(
      { record: 15, resolveObjc: true, objcMsgSend: '0x1111' },
      'darwin', disabledLookup);

  assert.equal(result.enabled, false);
  assert.equal(lookupCalls, 0);
  assert.equal(result.entries.every(entry => entry.address === null), true);
});

test('Android skips all ObjC resolution even when MSGSEND is requested', () => {
  let lookupCalls = 0;
  const result = planObjcDispatchers(
      { record: 16, resolveObjc: true },
      'linux',
      lookup({ global: () => { lookupCalls++; return 'unexpected'; } }));

  assert.equal(result.enabled, true);
  assert.equal(lookupCalls, 0);
  assert.equal(result.entries.every(entry => entry.address === null), true);
});

// ─── Java entry trigger policy helpers ──────────────────────────────────────

const javaArgKind = vm.runInContext('javaArgKind', context);
const javaRetKind = vm.runInContext('javaRetKind', context);

test('javaArgKind maps primitive Java types to primitive conversion', () => {
  for (const t of ['int', 'long', 'short', 'byte', 'char', 'boolean']) {
    assert.equal(javaArgKind(t), 'primitive', t);
  }
});

test('javaArgKind maps float/double/String/byte[]/objects', () => {
  assert.equal(javaArgKind('float'), 'float');
  assert.equal(javaArgKind('double'), 'float');
  assert.equal(javaArgKind('java.lang.String'), 'utf8');
  assert.equal(javaArgKind('[B'), 'bytearray');
  assert.equal(javaArgKind('java.lang.Object'), 'object');
  assert.equal(javaArgKind('[Ljava.lang.String;'), 'object');
});

test('javaRetKind maps return types to conversion strategies', () => {
  assert.equal(javaRetKind('void'), 'void');
  assert.equal(javaRetKind('int'), 'int32');
  assert.equal(javaRetKind('boolean'), 'int32');
  assert.equal(javaRetKind('long'), 'int64');
  assert.equal(javaRetKind('double'), 'float');
  assert.equal(javaRetKind('java.lang.String'), 'object');
});

// ─── JNI vtable slot table integrity ────────────────────────────────────────

const jniSlots = vm.runInContext('JNI_VTABLE_SLOTS', context);

test('JNI vtable slots are unique and sorted', () => {
  // Array.from bridges the vm-realm array into this realm (deepEqual is
  // prototype-sensitive across realms).
  const slots = Array.from(jniSlots.map(e => e.slot));
  const sorted = [...slots].sort((a, b) => a - b);
  assert.deepEqual(slots, sorted, 'slot table must stay sorted');
  assert.equal(new Set(slots).size, slots.length, 'no duplicate slots');
  // The vtable ends at GetObjectRefType (slot 232) per the JNI spec.
  assert.ok(slots[slots.length - 1] <= 232, 'slot numbers must fit the vtable');
});

test('JNI vtable apiIds are unique and within the allocated id ranges', () => {
  const ids = Array.from(jniSlots.map(e => e.apiId));
  assert.equal(new Set(ids).size, ids.length,
      'every intercepted slot must map to a distinct C API id');
  for (const id of ids) {
    const inBase = id >= 280 && id <= 359;      // JNI base + full vtable coverage
    const inExt  = id >= 700 && id <= 731;      // JNI extended
    assert.ok(inBase || inExt, `apiId ${id} outside the JNI id ranges`);
  }
});

test('JNI vtable slots follow the JNI spec layout (anchor points)', () => {
  // Anchors from the JNINativeInterface_ layout fixed by the JNI spec —
  // guards against the historical slot-numbering drift bug.
  const bySlot = slot => jniSlots.find(e => e.slot === slot);
  const anchors = {
    4: 'GetVersion',        33: 'GetMethodID',        61: 'CallVoidMethod',
    94: 'GetFieldID',       113: 'GetStaticMethodID', 144: 'GetStaticFieldID',
    167: 'NewStringUTF',    169: 'GetStringUTFChars', 171: 'GetArrayLength',
    215: 'RegisterNatives', 219: 'GetJavaVM',         228: 'ExceptionCheck',
    232: 'GetObjectRefType',
  };
  for (const [slot, name] of Object.entries(anchors)) {
    const e = bySlot(+slot);
    assert.ok(e, `slot ${slot} must be intercepted`);
    assert.equal(e.name, name, `slot ${slot} must be ${name}`);
  }
});

test('RegisterNatives is intercepted at spec slot 215 with apiId 301', () => {
  const entry = jniSlots.find(e => e.slot === 215);
  assert.ok(entry, 'slot 215 (RegisterNatives) must be intercepted');
  assert.equal(entry.apiId, 301);
  assert.equal(entry.name, 'RegisterNatives');
});

test('NewStringUTF lives at spec slot 167 with a unique apiId 282', () => {
  const newStringUtf = jniSlots.filter(e => e.apiId === 282);
  assert.equal(newStringUtf.length, 1, 'exactly one entry maps to NewStringUTF');
  assert.equal(newStringUtf[0].slot, 167);
  assert.equal(newStringUtf[0].name, 'NewStringUTF');
});