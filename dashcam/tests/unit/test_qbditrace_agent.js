'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const agentPath = path.resolve(__dirname, '../../qbditrace.js');
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
  assert.equal(cfg.bytes.length, 2336, 'config size matches native sizeof(qbditrace_config_t)');
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
