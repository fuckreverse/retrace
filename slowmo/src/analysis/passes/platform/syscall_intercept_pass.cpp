#include "analysis/passes/platform/syscall_intercept_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"
#include "common/byte_codec.h"
#include "analysis/passes/platform/linux_syscalls.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstring>

namespace tenet {

using json = nlohmann::json;

// ─── SyscallInterceptResult serialization helpers ─────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x53494341 ("SICA")
//   u32  version = 4
//   u64  num_calls
//   for each InterceptedCall:
//     u64  inst_id
//     u64  call_site_pc
//     u64  callee_pc
//     u32  callee_name_len; u8[] callee_name
//     u8   category  (cast of ApiCategory)
//     u8   arg_count
//     u64[8]  raw_args
//     u32  summary_len; u8[] decoded_summary
//     u8   has_key_bytes; if 1: u32 key_len, u8[] key_bytes
//     u8   has_iv_bytes;  if 1: u32 iv_len, u8[] iv_bytes
//     u8   has_data_bytes;if 1: u32 data_len, u8[] data_bytes
//     u64  key_length
//     u64  data_length
//     u64  return_value
//     u8   has_return
//     u8   has_mach_msgh_id; if 1: u32 mach_msgh_id; u32 mach_msg_via_len; u8[] mach_msg_via
//     u8   has_objc_ctx; if 1: u32 objc_len, u8[] objc_ctx
//     u32  captured_string_count
//     for each CapturedString:
//       u8   arg_idx
//       u8   truncated
//       u8   binary
//       u32  value_len; u8[] value

namespace {

static constexpr uint32_t SICA_BLOB_MAGIC   = 0x53494341u;  // "SICA"
static constexpr uint32_t SICA_BLOB_VERSION = 4u;

const char* mig_routine_name(uint32_t msgh_id) {
    // XNU MIG definitions, verified against apple-oss-distributions/xnu main:
    // osfmk/mach/{mach_vm,task,thread_act,mach_port,vm_map,clock}.defs.
    // The host subsystem's public definitions moved out of osfmk/mach upstream;
    // retain only long-stable, high-confidence host message IDs here.
    struct MigRoutineEntry { uint32_t id; const char* name; };
    static constexpr MigRoutineEntry kMigRoutines[] = {
        // host.defs (base 200)
        {200, "host_info"}, {201, "host_kernel_version"},
        {202, "host_get_io_master"}, {203, "host_page_size"},
        {206, "host_processors"}, {209, "host_get_clock_service"},
        {210, "host_get_clock_control"}, {211, "host_request_notification"},
        {212, "host_statistics"}, {213, "host_statistics64"},
        // mach_port.defs (base 3200)
        {3200, "mach_port_names"}, {3201, "mach_port_type"},
        {3203, "mach_port_rename"}, {3204, "mach_port_allocate_name"},
        {3205, "mach_port_allocate"}, {3206, "mach_port_destroy"},
        {3207, "mach_port_deallocate"}, {3208, "mach_port_get_refs"},
        {3209, "mach_port_mod_refs"}, {3210, "mach_port_peek"},
        {3211, "mach_port_set_mscount"}, {3213, "mach_port_move_member"},
        {3214, "mach_port_request_notification"}, {3215, "mach_port_insert_right"},
        {3216, "mach_port_extract_right"}, {3217, "mach_port_set_seqno"},
        {3220, "mach_port_set_attributes"}, {3221, "mach_port_allocate_qos"},
        {3222, "mach_port_allocate_full"}, {3223, "task_set_port_space"},
        {3224, "mach_port_get_srights"}, {3226, "mach_port_dnrequest_info"},
        {3228, "mach_port_kernel_object"}, {3229, "mach_port_insert_member"},
        {3230, "mach_port_extract_member"}, {3232, "mach_port_set_context"},
        {3234, "mach_port_construct"}, {3235, "mach_port_destruct"},
        {3236, "mach_port_guard"}, {3237, "mach_port_unguard"},
        // task.defs (base 3400)
        {3400, "task_create"}, {3401, "task_terminate"}, {3402, "task_threads"},
        {3403, "mach_ports_register"}, {3404, "mach_ports_lookup"},
        {3405, "task_info"}, {3406, "task_set_info"}, {3407, "task_suspend"},
        {3408, "task_resume"}, {3409, "task_get_special_port"},
        {3410, "task_set_special_port"}, {3411, "thread_create"},
        {3412, "thread_create_running"}, {3413, "task_set_exception_ports"},
        {3414, "task_get_exception_ports"}, {3415, "task_swap_exception_ports"},
        {3418, "lock_set_create"}, {3419, "lock_set_destroy"},
        {3420, "semaphore_create"}, {3421, "semaphore_destroy"},
        {3422, "task_policy_set"}, {3423, "task_policy_get"},
        {3448, "task_get_state"}, {3449, "task_set_state"},
        {3450, "task_set_phys_footprint_limit"},
        // thread_act.defs (base 3600)
        {3600, "thread_terminate"}, {3601, "act_get_state"},
        {3602, "act_set_state"}, {3603, "thread_get_state"},
        {3604, "thread_set_state"}, {3605, "thread_suspend"},
        {3606, "thread_resume"}, {3607, "thread_abort"},
        {3608, "thread_abort_safely"}, {3609, "thread_depress_abort"},
        {3610, "thread_get_special_port"}, {3611, "thread_set_special_port"},
        {3612, "thread_info"}, {3613, "thread_set_exception_ports"},
        {3614, "thread_get_exception_ports"}, {3615, "thread_swap_exception_ports"},
        // vm_map.defs (base 3800)
        {3800, "vm_region"}, {3802, "vm_allocate"}, {3804, "vm_deallocate"},
        {3806, "vm_protect"}, {3807, "vm_inherit"}, {3808, "vm_read"},
        {3809, "vm_read_list"}, {3810, "vm_write"}, {3811, "vm_copy"},
        {3812, "vm_read_overwrite"}, {3813, "vm_msync"},
        {3814, "vm_behavior_set"}, {3815, "vm_map"},
        // mach_vm.defs (base 4800)
        {4800, "mach_vm_allocate"}, {4801, "mach_vm_deallocate"},
        {4802, "mach_vm_protect"}, {4803, "mach_vm_inherit"},
        {4804, "mach_vm_read"}, {4805, "mach_vm_read_list"},
        {4806, "mach_vm_write"}, {4807, "mach_vm_copy"},
        {4808, "mach_vm_read_overwrite"}, {4809, "mach_vm_msync"},
        {4810, "mach_vm_behavior_set"}, {4811, "mach_vm_map"},
        {4812, "mach_vm_machine_attribute"}, {4813, "mach_vm_remap"},
        {4814, "mach_vm_page_query"}, {4815, "mach_vm_region_recurse"},
        {4816, "mach_vm_region"},
        // clock.defs (base 1000)
        {1000, "clock_get_time"}, {1001, "clock_get_attributes"},
        {1002, "clock_alarm"},
    };
    for (const auto& entry : kMigRoutines) {
        if (entry.id == msgh_id) return entry.name;
    }
    return nullptr;
}

const char* mach_trap_name(int32_t trap_no) {
    // XNU bsd/kern/syscalls.master and osfmk/kern/syscall_sw.c. KernelRPC
    // prefixes are intentionally omitted to match the user-facing trap name.
    struct MachTrapEntry {
        int32_t number;
        const char* name;
    };
    static constexpr MachTrapEntry kMachTraps[] = {
        {-10, "mach_vm_allocate"}, {-11, "mach_vm_purgable_control"},
        {-12, "mach_vm_deallocate"}, {-13, "task_dyld_process_info_notify_get"},
        {-14, "mach_vm_protect"}, {-15, "mach_vm_map"}, {-16, "mach_port_allocate"},
        {-18, "mach_port_deallocate"}, {-19, "mach_port_mod_refs"},
        {-20, "mach_port_move_member"}, {-21, "mach_port_insert_right"},
        {-22, "mach_port_insert_member"}, {-23, "mach_port_extract_member"},
        {-24, "mach_port_construct"}, {-25, "mach_port_destruct"},
        {-26, "mach_reply_port"}, {-27, "thread_self_trap"},
        {-28, "task_self_trap"}, {-29, "host_self_trap"}, {-31, "mach_msg_trap"},
        {-32, "mach_msg_overwrite_trap"}, {-33, "semaphore_signal_trap"},
        {-34, "semaphore_signal_all_trap"}, {-35, "semaphore_signal_thread_trap"},
        {-36, "semaphore_wait_trap"}, {-37, "semaphore_wait_signal_trap"},
        {-38, "semaphore_timedwait_trap"}, {-39, "semaphore_timedwait_signal_trap"},
        {-40, "mach_port_get_attributes"}, {-41, "mach_port_guard"},
        {-42, "mach_port_unguard"}, {-43, "mach_generate_activity_id"},
        {-44, "task_name_for_pid"}, {-45, "task_for_pid"}, {-46, "pid_for_task"},
        {-47, "mach_msg2_trap"}, {-48, "macx_swapon"}, {-49, "macx_swapoff"},
        {-50, "thread_get_special_reply_port"}, {-51, "macx_triggers"},
        {-52, "macx_backing_store_suspend"}, {-53, "macx_backing_store_recovery"},
        {-58, "pfz_exit"}, {-59, "swtch_pri"}, {-60, "swtch"},
        {-61, "thread_switch"}, {-62, "clock_sleep_trap"},
        {-63, "mach_vm_reclaim_update_kernel_accounting"},
        {-70, "host_create_mach_voucher"}, {-72, "mach_voucher_extract_attr_recipe"},
        {-76, "mach_port_type"}, {-77, "mach_port_request_notification"},
        {-88, "exclaves_ctl"}, {-89, "mach_timebase_info_trap"},
        {-90, "mach_wait_until_trap"}, {-91, "mk_timer_create_trap"},
        {-92, "mk_timer_destroy_trap"}, {-93, "mk_timer_arm_trap"},
        {-94, "mk_timer_cancel_trap"}, {-95, "mk_timer_arm_leeway_trap"},
        {-96, "debug_control_port_for_pid"}, {-100, "iokit_user_client_trap"},
    };

    for (const auto& entry : kMachTraps) {
        if (entry.number == trap_no) return entry.name;
    }
    return nullptr;
}

std::string syscall_intercept_serialize(const SyscallInterceptResult& res) {
    ByteWriter w;

    w.u32(SICA_BLOB_MAGIC);
    w.u32(SICA_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.calls.size()));

    for (const auto& c : res.calls) {
        w.u64(c.inst_id);
        w.u64(c.call_site_pc);
        w.u64(c.callee_pc);
        w.str(c.callee_name);
        w.u8(static_cast<uint8_t>(c.category));
        w.u8(c.arg_count);
        for (uint64_t a : c.raw_args) w.u64(a);
        w.str(c.decoded_summary);
        w.opt_bytes(c.key_bytes);
        w.opt_bytes(c.iv_bytes);
        w.opt_bytes(c.data_bytes);
        w.u64(c.key_length);
        w.u64(c.data_length);
        w.u64(c.return_value);
        w.u64(c.return_x1);
        w.u32(c.return_nzcv);
        w.u8(c.has_return ? 1u : 0u);
        w.u8(c.errno_valid ? 1u : 0u);
        w.u32(static_cast<uint32_t>(c.errno_before));
        w.u32(static_cast<uint32_t>(c.errno_after));
        w.u8(c.raw_error.has_value() ? 1u : 0u);
        if (c.raw_error) w.u64(static_cast<uint64_t>(*c.raw_error));
        w.u8(c.svc_flags);
        w.u8(c.from_capicall_record ? 1u : 0u);
        w.u8(c.mach_msgh_id.has_value() ? 1u : 0u);
        if (c.mach_msgh_id) {
            w.u32(*c.mach_msgh_id);
            w.str(c.mach_msg_via.value_or(""));
        }
        w.opt_str(c.objc_context);
        w.u32(static_cast<uint32_t>(c.captured_strings.size()));
        for (const auto& captured : c.captured_strings) {
            w.u8(captured.arg_idx);
            w.u8(captured.truncated ? 1u : 0u);
            w.u8(captured.binary ? 1u : 0u);
            w.str(captured.value);
        }
    }

    return std::move(w).take();
}

bool syscall_intercept_deserialize(const std::string& blob, SyscallInterceptResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != SICA_BLOB_MAGIC)   return false;
    if (r.u32() != SICA_BLOB_VERSION) return false;

    uint64_t n = r.u64();
    out.calls.reserve(static_cast<size_t>(n));

    for (uint64_t i = 0; i < n; i++) {
        InterceptedCall c;
        c.inst_id      = r.u64();
        c.call_site_pc = r.u64();
        c.callee_pc    = r.u64();
        if (!r.str(c.callee_name)) return false;
        c.category  = static_cast<ApiCategory>(r.u8());
        c.arg_count = r.u8();
        for (uint64_t& a : c.raw_args) a = r.u64();
        if (!r.str(c.decoded_summary)) return false;
        if (!r.opt_bytes(c.key_bytes)) return false;
        if (!r.opt_bytes(c.iv_bytes)) return false;
        if (!r.opt_bytes(c.data_bytes)) return false;
        c.key_length   = r.u64();
        c.data_length  = r.u64();
        c.return_value = r.u64();
        c.return_x1    = r.u64();
        c.return_nzcv  = r.u32();
        c.has_return   = r.u8() != 0;
        c.errno_valid  = r.u8() != 0;
        c.errno_before = static_cast<int32_t>(r.u32());
        c.errno_after  = static_cast<int32_t>(r.u32());
        if (r.u8() != 0) c.raw_error = static_cast<int64_t>(r.u64());
        c.svc_flags = r.u8();
        c.from_capicall_record = r.u8() != 0;
        if (r.u8() != 0) {
            c.mach_msgh_id = r.u32();
            std::string via;
            if (!r.str(via)) return false;
            c.mach_msg_via = std::move(via);
        }
        if (!r.opt_str(c.objc_context)) return false;
        uint32_t captured_string_count = r.u32();
        c.captured_strings.reserve(captured_string_count);
        for (uint32_t j = 0; j < captured_string_count; ++j) {
            CapturedString captured;
            captured.arg_idx = r.u8();
            captured.truncated = r.u8() != 0;
            captured.binary = r.u8() != 0;
            if (!r.str(captured.value)) return false;
            c.captured_strings.push_back(std::move(captured));
        }

        size_t idx = out.calls.size();
        out.by_callee[c.callee_name].push_back(idx);
        out.by_category[c.category].push_back(idx);
        out.calls.push_back(std::move(c));
    }

    return r.ok();
}

}  // anonymous namespace (syscall_intercept serialization)

// ─── Known iOS API signature table ────────────────────────────────────────
//
// Argument indices are AArch64 ABI (x0=0, x1=1, ... x7=7).
//
// CCCrypt signature (from CommonCrypto/CommonCryptor.h):
//   CCCryptorStatus CCCrypt(
//       CCOperation op,         // x0 — 0=encrypt, 1=decrypt
//       CCAlgorithm alg,        // x1 — 0=AES, 1=DES, 2=3DES, ...
//       CCOptions options,      // x2 — mode flags (CBC=0, ECB=1, PKCS7=2)
//       const void *key,        // x3 — key pointer
//       size_t keyLength,       // x4 — key length
//       const void *iv,         // x5 — IV pointer (NULL for ECB/stream)
//       const void *dataIn,     // x6 — plaintext/ciphertext input pointer
//       size_t dataInLength,    // x7 — input length
//       ...                     // x8+ stack args (output buffer, output len, moved)
//   );
//
// CCHmac signature:
//   void CCHmac(
//       CCHmacAlgorithm algorithm, // x0
//       const void *key,           // x1
//       size_t keyLength,          // x2
//       const void *data,          // x3
//       size_t dataLength,         // x4
//       void *macOut               // x5
//   );
//
// CCKeyDerivationPBKDF:
//   int CCKeyDerivationPBKDF(
//       CCPBKDFAlgorithm algorithm,  // x0
//       const char *password,        // x1
//       size_t passwordLen,          // x2
//       const uint8_t *salt,         // x3
//       size_t saltLen,              // x4
//       CCPseudoRandomAlgorithm prf, // x5
//       uint rounds,                 // x6
//       uint8_t *derivedKey,         // x7
//       ...
//   );
//
// SecKeyCreateSignature (Security.framework):
//   CFDataRef SecKeyCreateSignature(
//       SecKeyRef key,          // x0 — SecKey object
//       SecKeyAlgorithm alg,    // x1 — CFStringRef naming the algorithm
//       CFDataRef dataToSign,   // x2 — data to sign
//       CFErrorRef *error       // x3
//   );
//
// SecItemCopyMatching:
//   OSStatus SecItemCopyMatching(
//       CFDictionaryRef query, // x0
//       CFTypeRef *result      // x1
//   );

const std::vector<ApiSignature>& SyscallInterceptCollector::known_apis() {
    static const std::vector<ApiSignature> apis = {
        // ── CommonCrypto ──────────────────────────────────────────────────
        {
            .name          = "CCCrypt",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 8,
            .key_ptr_arg   = 3,    // x3 = key pointer
            .key_len_arg   = 4,    // x4 = key length
            .iv_ptr_arg    = 5,    // x5 = IV pointer
            .iv_len_arg    = UINT8_MAX, // no separate iv_len in x0-x7 (it's implied by algorithm)
            .data_ptr_arg  = 6,    // x6 = input data pointer
            .data_len_arg  = 7,    // x7 = input data length
            .operation_arg = 0,    // x0 = CCOperation (0=enc, 1=dec)
            .algorithm_arg = 1,    // x1 = CCAlgorithm
            .mode_arg      = 2,    // x2 = CCOptions (mode flags)
        },
        {
            .name          = "CCCryptorCreate",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 7,
            .key_ptr_arg   = 3,
            .key_len_arg   = 4,
            .iv_ptr_arg    = 5,
            .operation_arg = 0,
            .algorithm_arg = 1,
            .mode_arg      = 2,
        },
        {
            .name          = "CCCryptorCreateWithMode",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 8,
            .key_ptr_arg   = 4,
            .key_len_arg   = 5,
            .iv_ptr_arg    = 6,
            .operation_arg = 0,
            .algorithm_arg = 1,
            .mode_arg      = 2,
        },
        {
            .name          = "CCCryptorUpdate",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 7,
            // x0 is an opaque CCCryptorRef; x1/x2 are the input buffer/length.
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
        },
        {
            .name          = "CCCryptorFinal",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 4,
            // x0 is an opaque CCCryptorRef and must never be dereferenced.
        },
        {
            .name          = "CCCryptorRelease",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 1,
        },
        {
            .name          = "CCHmac",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 6,
            .key_ptr_arg   = 1,
            .key_len_arg   = 2,
            .data_ptr_arg  = 3,
            .data_len_arg  = 4,
            .algorithm_arg = 0,
        },
        {
            .name          = "CCHmacInit",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 4,
            .key_ptr_arg   = 2,
            .key_len_arg   = 3,
            .algorithm_arg = 1,
        },
        // One-shot digests all use (data, len, out). CC_DIGEST (id 136) is
        // shared by CC_SHA1/MD5/224/256, so retain the tracer-resolved name.
        {
            .name          = "CC_SHA256",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 3,
            .data_ptr_arg  = 0,
            .data_len_arg  = 1,
        },
        {
            .name          = "CC_SHA224",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 3,
            .data_ptr_arg  = 0,
            .data_len_arg  = 1,
        },
        {
            .name          = "CC_SHA384",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 3,
            .data_ptr_arg  = 0,
            .data_len_arg  = 1,
        },
        {
            .name          = "CC_SHA512",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 3,
            .data_ptr_arg  = 0,
            .data_len_arg  = 1,
        },
        {
            .name          = "CC_SHA256_Init",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 1,
        },
        {
            .name          = "CC_SHA256_Update",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 3,
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
        },
        {
            .name          = "CC_SHA256_Final",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 2,
        },
        {
            .name          = "CCKeyDerivationPBKDF",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 8,
            .key_ptr_arg   = 1,  // password ptr
            .key_len_arg   = 2,  // password len
            .data_ptr_arg  = 3,  // salt ptr
            .data_len_arg  = 4,  // salt len
            .algorithm_arg = 0,
        },
        // ── Security.framework ────────────────────────────────────────────
        {
            .name          = "SecKeyCreateSignature",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 4,
            // x0 is an opaque SecKeyRef and x2 is an opaque CFDataRef.
            // Neither is a raw byte buffer.
        },
        {
            .name          = "SecKeyRawSign",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 5,
            // x0 is an opaque SecKeyRef; only x2/x3 are raw bytes.
            .data_ptr_arg  = 2,   // x2 = data to sign
            .data_len_arg  = 3,
        },
        {
            .name          = "SecKeyRawVerify",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 6,
            // x0 is an opaque SecKeyRef.
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
        {
            .name          = "SecKeyEncrypt",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 5,
            // x0 is an opaque SecKeyRef.
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
        {
            .name          = "SecKeyDecrypt",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 5,
            // x0 is an opaque SecKeyRef.
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
        {
            .name          = "SecItemCopyMatching",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 2,
        },
        {
            .name          = "SecItemAdd",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 2,
        },
        {
            .name          = "SecKeyCreateWithData",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 3,
            .key_ptr_arg   = 0,  // x0 = CFDataRef (key bytes)
        },
        // ── Compression / zlib ────────────────────────────────────────────
        {
            .name          = "compress2",
            .category      = ApiCategory::Compression,
            .arg_count     = 5,
            .data_ptr_arg  = 2,  // source
            .data_len_arg  = 3,
        },
        {
            .name          = "uncompress",
            .category      = ApiCategory::Compression,
            .arg_count     = 4,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
    };
    return apis;
}

// ─── Android / Linux (BoringSSL / OpenSSL) API signature table ────────────
//
// BoringSSL is the default TLS/crypto library on Android (used by
// conscrypt, OkHttp, Chromium, ...).  Function signatures follow
// the OpenSSL EVP interface — same argument positions on AArch64.

const std::vector<ApiSignature>& SyscallInterceptCollector::known_android_apis() {
    static const std::vector<ApiSignature> apis = {
        // ── BoringSSL / OpenSSL EVP symmetric cipher ──────────────────────
        {
            .name          = "EVP_EncryptInit_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
            .key_ptr_arg   = 3,    // x3 = key pointer
            .iv_ptr_arg    = 4,    // x4 = IV pointer
        },
        {
            .name          = "EVP_DecryptInit_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
            .key_ptr_arg   = 3,
            .iv_ptr_arg    = 4,
        },
        {
            .name          = "EVP_CipherInit_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 6,
            .key_ptr_arg   = 3,
            .iv_ptr_arg    = 4,
            .operation_arg = 5,    // x5 = enc (1) or dec (0)
        },
        {
            .name          = "EVP_EncryptUpdate",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
            .data_ptr_arg  = 3,    // x3 = input data
            .data_len_arg  = 4,    // x4 = input length
        },
        {
            .name          = "EVP_DecryptUpdate",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
            .data_ptr_arg  = 3,
            .data_len_arg  = 4,
        },
        {
            .name          = "EVP_EncryptFinal_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        {
            .name          = "EVP_DecryptFinal_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        // ── BoringSSL / OpenSSL HMAC ──────────────────────────────────────
        {
            .name          = "HMAC",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 7,
            .key_ptr_arg   = 1,    // x1 = key
            .key_len_arg   = 2,    // x2 = key_len
            .data_ptr_arg  = 3,    // x3 = data
            .data_len_arg  = 4,    // x4 = data_len
        },
        {
            .name          = "HMAC_Init_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 4,
            .key_ptr_arg   = 1,
            .key_len_arg   = 2,
        },
        {
            .name          = "HMAC_Update",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
        },
        // ── BoringSSL / OpenSSL Digest ────────────────────────────────────
        {
            .name          = "EVP_DigestInit_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        {
            .name          = "EVP_DigestUpdate",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
        },
        {
            .name          = "EVP_DigestFinal_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        // ── BoringSSL / OpenSSL RSA / EC signing ──────────────────────────
        {
            .name          = "EVP_DigestSignInit",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
        },
        {
            .name          = "EVP_DigestSignFinal",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        {
            .name          = "EVP_DigestVerifyInit",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
        },
        {
            .name          = "EVP_DigestVerifyFinal",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
        },
        // ── BoringSSL / OpenSSL AES low-level ─────────────────────────────
        {
            .name          = "AES_set_encrypt_key",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .key_ptr_arg   = 0,    // x0 = userKey
            .key_len_arg   = 1,    // x1 = bits (128/192/256)
        },
        {
            .name          = "AES_set_decrypt_key",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .key_ptr_arg   = 0,
            .key_len_arg   = 1,
        },
        {
            .name          = "AES_cbc_encrypt",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 6,
            .iv_ptr_arg    = 4,    // x4 = ivec
            .data_ptr_arg  = 0,    // x0 = in
            .data_len_arg  = 2,    // x2 = length
            .operation_arg = 5,    // x5 = enc
        },
        // ── BoringSSL / OpenSSL KDF ───────────────────────────────────────
        {
            .name          = "PKCS5_PBKDF2_HMAC",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 8,
            .key_ptr_arg   = 0,    // x0 = password
            .key_len_arg   = 1,    // x1 = pass_len
            .data_ptr_arg  = 3,    // x3 = salt
            .data_len_arg  = 4,    // x4 = salt_len
        },
        {
            .name          = "PKCS5_PBKDF2_HMAC_SHA1",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 7,
            .key_ptr_arg   = 0,
            .key_len_arg   = 1,
            .data_ptr_arg  = 2,    // x2 = salt
            .data_len_arg  = 3,    // x3 = salt_len
        },
        // ── Compression (shared with iOS) ─────────────────────────────────
        {
            .name          = "compress2",
            .category      = ApiCategory::Compression,
            .arg_count     = 5,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
        {
            .name          = "uncompress",
            .category      = ApiCategory::Compression,
            .arg_count     = 4,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
    };
    return apis;
}

// ─── SyscallInterceptCollector ────────────────────────────────────────────

SyscallInterceptCollector::SyscallInterceptCollector(
    const SyscallInterceptConfig& config,
    const CodeTable& code_table,
    MemoryModel& memory,
    const ObjcResult* objc,
    uint32_t target_os)
    : config_(config)
    , code_table_(code_table)
    , memory_(memory)
    , objc_result_(objc)
    , target_os_(target_os)
{
    // Select the API signature table based on target platform.
    // Darwin → CommonCrypto/Security.framework table.
    // Android/Linux → BoringSSL/OpenSSL table.
    // Unknown → load both tables (best-effort match).
    auto load_table = [&](const std::vector<ApiSignature>& table) {
        for (const auto& sig : table) {
            api_by_name_[sig.name] = &sig;
        }
    };

    bool is_darwin_target = (target_os == 1);   // TargetOS::iOS
    bool is_linux_target  = (target_os == 2 || target_os == 3);  // Android or Linux

    if (is_darwin_target) {
        load_table(known_apis());
    } else if (is_linux_target) {
        load_table(known_android_apis());
    } else {
        // Unknown platform — load both tables for best coverage.
        load_table(known_apis());
        load_table(known_android_apis());
    }

    // Add user-specified extra names (matched as prefix, no decode).
    for (const auto& extra : config_.extra_api_names) {
        if (api_by_name_.find(extra) == api_by_name_.end()) {
            api_by_name_[extra] = nullptr;  // nullptr = no signature
        }
    }
}

bool SyscallInterceptCollector::begin(uint64_t /*start_inst_id*/,
                                       uint64_t /*end_inst_id*/) {
    // Reset state for a fresh scan.
    std::memset(cur_regs_, 0, sizeof(cur_regs_));
    regs_valid_ = false;
    cur_inst_id_ = 0;
    last_objc_inst_id_ = 0;
    last_objc_context_.clear();
    result_ = {};
    pending_returns_.clear();
    capicall_seen_.clear();
    return true;
}

void SyscallInterceptCollector::on_inst(uint64_t /*inst_id*/, const InstView& inst) {
    // Apply reg_diffs to maintain x0-x7 state.
    for (uint8_t r = 0; r < inst.reg_diff_count; ++r) {
        auto diff = inst.reg_diff(r);
        if (diff.index < MAX_ARG_REGS) {
            cur_regs_[diff.index] = diff.value;
            regs_valid_ = true;
        }
    }
    cur_inst_id_++;
}

void SyscallInterceptCollector::on_objc(uint64_t /*inst_id*/, const ObjcView& objc) {
    // Track ObjC context for annotation.
    last_objc_inst_id_ = cur_inst_id_;

    std::string cls_name(objc.cls ? objc.cls : "");
    // Try to resolve selector from symbol table.
    std::string sel_name;
    if (objc.sel != 0) {
        auto s = code_table_.image_read_cstring(objc.sel, 128);
        if (s) sel_name = *s;
    }
    if (sel_name.empty()) {
        // Fallback: use previously resolved selector from ObjcResult.
        if (objc_result_) {
            for (auto rit = objc_result_->messages.rbegin();
                 rit != objc_result_->messages.rend(); ++rit) {
                if (rit->inst_id <= cur_inst_id_) {
                    sel_name = rit->selector_name;
                    if (cls_name.empty()) cls_name = rit->class_name;
                    break;
                }
            }
        }
    }
    if (!cls_name.empty() && !sel_name.empty()) {
        last_objc_context_ = '[' + cls_name + ' ' + sel_name + ']';
    } else if (!cls_name.empty()) {
        last_objc_context_ = '[' + cls_name + " ?]";
    } else if (!sel_name.empty()) {
        last_objc_context_ = "[? " + sel_name + ']';
    }
}

void SyscallInterceptCollector::on_event(const EventView& ev) {
    // The authoritative CAPICALL record is emitted immediately before its
    // XFER_CALL event. Suppress only that fallback event at the same site.
    if (capicall_seen_.find(ev.site) != capicall_seen_.end()) return;

    // XFER_CALL events: callee PC is outside the traced module.
    // event type: XFER_CALL = EventKind value (check TraceFormat.h)
    // qbditrace defines: QBDITRACE_EV_SEQ_ENTRY=0, XFER_CALL=2, XFER_RETURN=3
    // We accept both types 2 (XFER_CALL) and 0 to catch cross-module calls.
    if (ev.event != 2 && ev.event != 0) return;

    uint64_t callee_pc = ev.addr;
    if (callee_pc == 0) return;

    // ── Resolve callee name ────────────────────────────────────────
    std::string callee_name;

    if (!code_table_.opcode_at(callee_pc).has_value()) {
        // The callee is NOT in the traced module — it's a cross-library call.
        auto sym = code_table_.image_read_cstring(callee_pc, 64);
        if (sym) callee_name = *sym;
    }

    // ── Match against known APIs ──────────────────────────────────
    const ApiSignature* sig = nullptr;
    if (!callee_name.empty()) {
        auto ait = api_by_name_.find(callee_name);
        if (ait != api_by_name_.end()) {
            sig = ait->second;
        } else {
            // Prefix match for user-specified extra names.
            for (const auto& [name, s] : api_by_name_) {
                if (callee_name.rfind(name, 0) == 0) {
                    sig = s;
                    callee_name = name;
                    break;
                }
            }
        }
    }

    // If we have a signature match OR user requested all unresolved.
    if (sig == nullptr && !config_.intercept_unresolved) return;
    if (sig == nullptr && callee_name.empty()) return;

    if (!regs_valid_) return;

    // ── Build the intercepted call record ─────────────────────────
    InterceptedCall call;
    call.inst_id       = cur_inst_id_;
    call.call_site_pc  = ev.site;
    call.callee_pc     = callee_pc;
    call.callee_name   = callee_name.empty() ?
                             fmt::format("sub_{:x}", callee_pc) : callee_name;
    call.category      = sig ? sig->category : ApiCategory::Custom;
    std::memcpy(call.raw_args.data(), cur_regs_, sizeof(uint64_t) * MAX_ARG_REGS);
    call.arg_count     = sig ? sig->arg_count : MAX_ARG_REGS;

    // Attach ObjC context if recent.
    if (!last_objc_context_.empty() &&
        cur_inst_id_ - last_objc_inst_id_ < 100000) {
        call.objc_context = last_objc_context_;
    }

    // Decode arguments for known APIs.
    if (sig) {
        decode_known_api(call, *sig);
    } else {
        call.decoded_summary = call.callee_name +
            fmt::format(": x0=0x{:x} x1=0x{:x} x2=0x{:x} x3=0x{:x}",
                        cur_regs_[0], cur_regs_[1], cur_regs_[2], cur_regs_[3]);
    }

    // ── Index and store ───────────────────────────────────────────
    size_t hit_idx = result_.calls.size();
    result_.by_callee[call.callee_name].push_back(hit_idx);
    result_.by_category[call.category].push_back(hit_idx);
    result_.calls.push_back(std::move(call));
}

// ─── CapiCall ID → name / signature lookup ────────────────────────────────
//
// Maps qbditrace_capi_id_t (uint8_t, but stored as uint8_t in the record) to
// a human-readable name and optionally the matching ApiSignature from the
// known-API tables.  We use a flat switch for O(1) lookup; the compiler will
// typically turn this into a jump table.

const SyscallInterceptCollector::CapiEntry&
SyscallInterceptCollector::capi_entry(uint16_t api_id) {
    using namespace qbditrace;

    // Each entry is { name, nullptr } — we set sig pointers lazily from the
    // known_apis() / known_android_apis() tables in the constructor, but for
    // the simple name lookup we just need the name string here.
    static const CapiEntry kEntries[] = {
        // 0
        { nullptr,                           nullptr },  // UNKNOWN
        // 1–8  Memory
        { "memcpy",                          nullptr },
        { "memmove",                         nullptr },
        { "memset",                          nullptr },
        { "memcmp",                          nullptr },
        { "memchr",                          nullptr },
        { "bcopy",                           nullptr },
        { "bzero",                           nullptr },
        { "memmem",                          nullptr },
        // 9–19 reserved
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr },
        // 20–48 Strings
        { "strlen",          nullptr },  // 20
        { "strnlen",         nullptr },  // 21
        { "strcmp",          nullptr },  // 22
        { "strncmp",         nullptr },  // 23
        { "strcasecmp",      nullptr },  // 24
        { "strncasecmp",     nullptr },  // 25
        { "strcpy",          nullptr },  // 26
        { "strncpy",         nullptr },  // 27
        { "strlcpy",         nullptr },  // 28
        { "strcat",          nullptr },  // 29
        { "strncat",         nullptr },  // 30
        { "strlcat",         nullptr },  // 31
        { "strdup",          nullptr },  // 32
        { "strndup",         nullptr },  // 33
        { "strchr",          nullptr },  // 34
        { "strrchr",         nullptr },  // 35
        { "strstr",          nullptr },  // 36
        { "strtok",          nullptr },  // 37
        { "strtok_r",        nullptr },  // 38
        { "sprintf",         nullptr },  // 39
        { "snprintf",        nullptr },  // 40
        { "sscanf",          nullptr },  // 41
        { "atoi",            nullptr },  // 42
        { "atol",            nullptr },  // 43
        { "atoll",           nullptr },  // 44
        { "strtol",          nullptr },  // 45
        { "strtoll",         nullptr },  // 46
        { "strtoul",         nullptr },  // 47
        { "strtoull",        nullptr },  // 48
        // 49–59 reserved (11 entries)
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr },
        // 60–65 Heap alloc
        { "malloc",          nullptr },  // 60
        { "calloc",          nullptr },  // 61
        { "realloc",         nullptr },  // 62
        { "free",            nullptr },  // 63
        { "posix_memalign",  nullptr },  // 64
        { "valloc",          nullptr },  // 65
        // 66–79 reserved (14 entries)
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr },
        // 80–91 I/O
        { "fopen",           nullptr },  // 80
        { "fclose",          nullptr },  // 81
        { "fread",           nullptr },  // 82
        { "fwrite",          nullptr },  // 83
        { "fgets",           nullptr },  // 84
        { "fputs",           nullptr },  // 85
        { "read",            nullptr },  // 86
        { "write",           nullptr },  // 87
        { "pread",           nullptr },  // 88
        { "pwrite",          nullptr },  // 89
        { "open",            nullptr },  // 90
        { "close",           nullptr },  // 91
        // 92–99 reserved (8 entries)
        { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr },
        // 100–102 Crypto libc
        { "arc4random",         nullptr },  // 100
        { "arc4random_buf",     nullptr },  // 101
        { "getrandom",          nullptr },  // 102
        // 103–129 reserved (27 entries)
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr },
        // 130–142 iOS platform APIs
        { "CFStringCreateWithCString",      nullptr },  // 130
        { "CFStringCreateWithBytes",        nullptr },  // 131
        { "CFDataCreate",                   nullptr },  // 132
        { "CFDataGetBytePtr",               nullptr },  // 133
        { "CCCrypt",                        nullptr },  // 134
        { "CCHmac",                         nullptr },  // 135
        { "CC_SHA256",                      nullptr },  // 136
        { "CCKeyDerivationPBKDF",           nullptr },  // 137
        { "SecItemCopyMatching",            nullptr },  // 138
        { "SecKeyCreateWithData",           nullptr },  // 139
        { "SecTransformExecute",            nullptr },  // 140
        { "CFURLCreateWithBytes",           nullptr },  // 141
        { "NSURLSession_dataTask",          nullptr },  // 142
    };

    // kEntries covers indices 0..142 (143 entries).
    static constexpr uint16_t kTableSize = 143;

    if (api_id < kTableSize) {
        return kEntries[api_id];
    }

    // For IDs not in the compact table, use a secondary switch for the extended
    // ranges (200+, 280+, 360+, 380+, 400+, 420+, 450+, 470+, 600+, 700+).
    // We return static locals to avoid allocations.

    static const CapiEntry kFallback = { nullptr, nullptr };

    // Extended table via switch.
    switch (static_cast<uint16_t>(api_id)) {
        // 200–207 Android
        case 200: { static CapiEntry e{"strlcpy",               nullptr}; return e; }
        case 201: { static CapiEntry e{"__android_log_print",   nullptr}; return e; }
        case 202: { static CapiEntry e{"__android_log_write",   nullptr}; return e; }
        case 203: { static CapiEntry e{"SharedPreferences_getString", nullptr}; return e; }
        case 204: { static CapiEntry e{"SharedPreferences_putString", nullptr}; return e; }
        case 205: { static CapiEntry e{"IBinder_transact",      nullptr}; return e; }
        case 206: { static CapiEntry e{"dlopen",                nullptr}; return e; }
        case 207: { static CapiEntry e{"dlsym",                 nullptr}; return e; }
        // 280–301 JNI base (301 = RegisterNatives)
        case 280: { static CapiEntry e{"GetStringUTFChars",     nullptr}; return e; }
        case 281: { static CapiEntry e{"ReleaseStringUTFChars", nullptr}; return e; }
        case 282: { static CapiEntry e{"NewStringUTF",          nullptr}; return e; }
        case 283: { static CapiEntry e{"GetStringUTFLength",    nullptr}; return e; }
        case 284: { static CapiEntry e{"GetByteArrayElements",  nullptr}; return e; }
        case 285: { static CapiEntry e{"ReleaseByteArrayElements", nullptr}; return e; }
        case 286: { static CapiEntry e{"GetByteArrayRegion",    nullptr}; return e; }
        case 287: { static CapiEntry e{"SetByteArrayRegion",    nullptr}; return e; }
        case 288: { static CapiEntry e{"NewByteArray",          nullptr}; return e; }
        case 289: { static CapiEntry e{"FindClass",             nullptr}; return e; }
        case 290: { static CapiEntry e{"GetMethodID",           nullptr}; return e; }
        case 291: { static CapiEntry e{"GetStaticMethodID",     nullptr}; return e; }
        case 292: { static CapiEntry e{"CallObjectMethod",      nullptr}; return e; }
        case 293: { static CapiEntry e{"CallStaticObjectMethod",nullptr}; return e; }
        case 294: { static CapiEntry e{"CallVoidMethod",        nullptr}; return e; }
        case 295: { static CapiEntry e{"CallBooleanMethod",     nullptr}; return e; }
        case 296: { static CapiEntry e{"CallIntMethod",         nullptr}; return e; }
        case 297: { static CapiEntry e{"CallLongMethod",        nullptr}; return e; }
        case 298: { static CapiEntry e{"ExceptionCheck",        nullptr}; return e; }
        case 299: { static CapiEntry e{"ExceptionClear",        nullptr}; return e; }
        case 300: { static CapiEntry e{"DefineClass",           nullptr}; return e; }
        case 301: { static CapiEntry e{"RegisterNatives",       nullptr}; return e; }
        // 302–359 JNI extended (full vtable coverage, see TraceFormat.h)
        case 302: { static CapiEntry e{"NewString",                 nullptr}; return e; }
        case 303: { static CapiEntry e{"GetStringLength",           nullptr}; return e; }
        case 304: { static CapiEntry e{"GetStringChars",            nullptr}; return e; }
        case 305: { static CapiEntry e{"ReleaseStringChars",        nullptr}; return e; }
        case 306: { static CapiEntry e{"GetStringRegion",           nullptr}; return e; }
        case 307: { static CapiEntry e{"GetPrimitiveArrayCritical", nullptr}; return e; }
        case 308: { static CapiEntry e{"ReleasePrimitiveArrayCritical", nullptr}; return e; }
        case 309: { static CapiEntry e{"NewDirectByteBuffer",       nullptr}; return e; }
        case 310: { static CapiEntry e{"GetDirectBufferAddress",    nullptr}; return e; }
        case 311: { static CapiEntry e{"GetDirectBufferCapacity",   nullptr}; return e; }
        case 312: { static CapiEntry e{"GetObjectClass",            nullptr}; return e; }
        case 313: { static CapiEntry e{"GetSuperclass",             nullptr}; return e; }
        case 314: { static CapiEntry e{"GetObjectRefType",          nullptr}; return e; }
        case 315: { static CapiEntry e{"NewWeakGlobalRef",          nullptr}; return e; }
        case 316: { static CapiEntry e{"DeleteWeakGlobalRef",       nullptr}; return e; }
        case 317: { static CapiEntry e{"IsSameObject",              nullptr}; return e; }
        case 318: { static CapiEntry e{"NewLocalRef",               nullptr}; return e; }
        case 319: { static CapiEntry e{"ExceptionOccurred",         nullptr}; return e; }
        case 320: { static CapiEntry e{"ThrowNew",                  nullptr}; return e; }
        case 321: { static CapiEntry e{"Throw",                     nullptr}; return e; }
        case 322: { static CapiEntry e{"UnregisterNatives",         nullptr}; return e; }
        case 323: { static CapiEntry e{"GetBooleanField",           nullptr}; return e; }
        case 324: { static CapiEntry e{"GetByteField",              nullptr}; return e; }
        case 325: { static CapiEntry e{"GetCharField",              nullptr}; return e; }
        case 326: { static CapiEntry e{"GetShortField",             nullptr}; return e; }
        case 327: { static CapiEntry e{"SetIntField",               nullptr}; return e; }
        case 328: { static CapiEntry e{"SetLongField",              nullptr}; return e; }
        case 329: { static CapiEntry e{"GetStaticObjectField",      nullptr}; return e; }
        case 330: { static CapiEntry e{"GetStaticBooleanField",     nullptr}; return e; }
        case 331: { static CapiEntry e{"GetStaticIntField",         nullptr}; return e; }
        case 332: { static CapiEntry e{"GetStaticLongField",        nullptr}; return e; }
        case 333: { static CapiEntry e{"SetStaticObjectField",      nullptr}; return e; }
        case 334: { static CapiEntry e{"SetStaticIntField",         nullptr}; return e; }
        case 335: { static CapiEntry e{"SetStaticLongField",        nullptr}; return e; }
        case 336: { static CapiEntry e{"CallByteMethod",            nullptr}; return e; }
        case 337: { static CapiEntry e{"CallCharMethod",            nullptr}; return e; }
        case 338: { static CapiEntry e{"CallShortMethod",           nullptr}; return e; }
        case 339: { static CapiEntry e{"CallFloatMethod",           nullptr}; return e; }
        case 340: { static CapiEntry e{"CallDoubleMethod",          nullptr}; return e; }
        case 341: { static CapiEntry e{"CallNonvirtualObjectMethod",nullptr}; return e; }
        case 342: { static CapiEntry e{"CallNonvirtualIntMethod",   nullptr}; return e; }
        case 343: { static CapiEntry e{"CallNonvirtualLongMethod",  nullptr}; return e; }
        case 344: { static CapiEntry e{"CallNonvirtualVoidMethod",  nullptr}; return e; }
        case 345: { static CapiEntry e{"CallStaticLongMethod",      nullptr}; return e; }
        case 346: { static CapiEntry e{"CallStaticByteMethod",      nullptr}; return e; }
        case 347: { static CapiEntry e{"CallStaticCharMethod",      nullptr}; return e; }
        case 348: { static CapiEntry e{"CallStaticDoubleMethod",    nullptr}; return e; }
        case 349: { static CapiEntry e{"NewCharArray",              nullptr}; return e; }
        case 350: { static CapiEntry e{"NewShortArray",             nullptr}; return e; }
        case 351: { static CapiEntry e{"NewLongArray",              nullptr}; return e; }
        case 352: { static CapiEntry e{"NewFloatArray",             nullptr}; return e; }
        case 353: { static CapiEntry e{"NewDoubleArray",            nullptr}; return e; }
        case 354: { static CapiEntry e{"GetCharArrayElements",      nullptr}; return e; }
        case 355: { static CapiEntry e{"ReleaseCharArrayElements",  nullptr}; return e; }
        case 356: { static CapiEntry e{"GetShortArrayElements",     nullptr}; return e; }
        case 357: { static CapiEntry e{"ReleaseShortArrayElements", nullptr}; return e; }
        case 358: { static CapiEntry e{"GetLongArrayElements",      nullptr}; return e; }
        case 359: { static CapiEntry e{"ReleaseLongArrayElements",  nullptr}; return e; }
        // 360–363 pthread
        case 360: { static CapiEntry e{"pthread_create",        nullptr}; return e; }
        case 361: { static CapiEntry e{"pthread_join",          nullptr}; return e; }
        case 362: { static CapiEntry e{"pthread_mutex_lock",    nullptr}; return e; }
        case 363: { static CapiEntry e{"pthread_mutex_unlock",  nullptr}; return e; }
        // 380–385 Network
        case 380: { static CapiEntry e{"socket",                nullptr}; return e; }
        case 381: { static CapiEntry e{"connect",               nullptr}; return e; }
        case 382: { static CapiEntry e{"send",                  nullptr}; return e; }
        case 383: { static CapiEntry e{"recv",                  nullptr}; return e; }
        case 384: { static CapiEntry e{"sendto",                nullptr}; return e; }
        case 385: { static CapiEntry e{"recvfrom",              nullptr}; return e; }
        // 400–401 Encoding
        case 400: { static CapiEntry e{"base64_encode",         nullptr}; return e; }
        case 401: { static CapiEntry e{"base64_decode",         nullptr}; return e; }
        // 420–429 AntiDebug
        case 420: { static CapiEntry e{"ptrace",                nullptr}; return e; }
        case 421: { static CapiEntry e{"sysctl",                nullptr}; return e; }
        case 422: { static CapiEntry e{"prctl",                 nullptr}; return e; }
        case 423: { static CapiEntry e{"getenv",                nullptr}; return e; }
        case 424: { static CapiEntry e{"access",                nullptr}; return e; }
        case 425: { static CapiEntry e{"stat",                  nullptr}; return e; }
        case 426: { static CapiEntry e{"kill",                  nullptr}; return e; }
        case 427: { static CapiEntry e{"getpid",                nullptr}; return e; }
        case 428: { static CapiEntry e{"sysctlbyname",          nullptr}; return e; }
        case 429: { static CapiEntry e{"isatty",                nullptr}; return e; }
        // 450–460 FS / mmap
        case 450: { static CapiEntry e{"rename",                nullptr}; return e; }
        case 451: { static CapiEntry e{"unlink",                nullptr}; return e; }
        case 452: { static CapiEntry e{"mkdir",                 nullptr}; return e; }
        case 453: { static CapiEntry e{"rmdir",                 nullptr}; return e; }
        case 454: { static CapiEntry e{"openat",                nullptr}; return e; }
        case 455: { static CapiEntry e{"pread64",               nullptr}; return e; }
        case 456: { static CapiEntry e{"pwrite64",              nullptr}; return e; }
        case 457: { static CapiEntry e{"lseek",                 nullptr}; return e; }
        case 458: { static CapiEntry e{"mmap",                  nullptr}; return e; }
        case 459: { static CapiEntry e{"munmap",                nullptr}; return e; }
        case 460: { static CapiEntry e{"mprotect",              nullptr}; return e; }
        // 470–526 iOS extended
        case 470: { static CapiEntry e{"CC_SHA224",             nullptr}; return e; }
        case 471: { static CapiEntry e{"CC_SHA384",             nullptr}; return e; }
        case 472: { static CapiEntry e{"CC_SHA512",             nullptr}; return e; }
        case 473: { static CapiEntry e{"CC_SHA256_Init",        nullptr}; return e; }
        case 474: { static CapiEntry e{"CC_SHA256_Update",      nullptr}; return e; }
        case 475: { static CapiEntry e{"CC_SHA256_Final",       nullptr}; return e; }
        case 476: { static CapiEntry e{"CCHmacInit",            nullptr}; return e; }
        case 477: { static CapiEntry e{"CCHmacUpdate",          nullptr}; return e; }
        case 478: { static CapiEntry e{"CCHmacFinal",           nullptr}; return e; }
        case 479: { static CapiEntry e{"CCCryptorCreate",       nullptr}; return e; }
        case 480: { static CapiEntry e{"CCCryptorUpdate",       nullptr}; return e; }
        case 481: { static CapiEntry e{"CCCryptorFinal",        nullptr}; return e; }
        case 482: { static CapiEntry e{"CCCryptorRelease",      nullptr}; return e; }
        case 483: { static CapiEntry e{"CCRandomGenerateBytes", nullptr}; return e; }
        case 484: { static CapiEntry e{"CFStringGetCString",    nullptr}; return e; }
        case 485: { static CapiEntry e{"CFStringGetCStringPtr", nullptr}; return e; }
        case 486: { static CapiEntry e{"CFStringCompare",       nullptr}; return e; }
        case 487: { static CapiEntry e{"CFStringHasPrefix",     nullptr}; return e; }
        case 488: { static CapiEntry e{"CFStringHasSuffix",     nullptr}; return e; }
        case 489: { static CapiEntry e{"CFDataGetBytePtr",      nullptr}; return e; }
        case 490: { static CapiEntry e{"CFDataGetLength",       nullptr}; return e; }
        case 491: { static CapiEntry e{"CFDictionaryGetValue",  nullptr}; return e; }
        case 492: { static CapiEntry e{"CFDictionaryCreate",    nullptr}; return e; }
        case 493: { static CapiEntry e{"CFArrayCreate",         nullptr}; return e; }
        case 494: { static CapiEntry e{"CFArrayGetValueAtIndex",nullptr}; return e; }
        case 495: { static CapiEntry e{"CFNumberCreate",        nullptr}; return e; }
        case 496: { static CapiEntry e{"CFNumberGetValue",      nullptr}; return e; }
        case 497: { static CapiEntry e{"CFPropertyListCreateWithData", nullptr}; return e; }
        case 498: { static CapiEntry e{"CFPropertyListCreateXMLData",  nullptr}; return e; }
        case 499: { static CapiEntry e{"CFRelease",             nullptr}; return e; }
        case 500: { static CapiEntry e{"CFRetain",              nullptr}; return e; }
        case 501: { static CapiEntry e{"SecRandomCopyBytes",    nullptr}; return e; }
        case 502: { static CapiEntry e{"SecKeyCopyExternalRepresentation", nullptr}; return e; }
        case 503: { static CapiEntry e{"SecKeyCreateFromData",  nullptr}; return e; }
        case 504: { static CapiEntry e{"SecKeyEncrypt",         nullptr}; return e; }
        case 505: { static CapiEntry e{"SecKeyDecrypt",         nullptr}; return e; }
        case 506: { static CapiEntry e{"SecCertificateCreateWithData", nullptr}; return e; }
        case 507: { static CapiEntry e{"SecIdentityCopyCertificate", nullptr}; return e; }
        case 508: { static CapiEntry e{"SecTrustEvaluate",      nullptr}; return e; }
        case 509: { static CapiEntry e{"SecItemAdd",            nullptr}; return e; }
        case 510: { static CapiEntry e{"SecItemUpdate",         nullptr}; return e; }
        case 511: { static CapiEntry e{"SecItemDelete",         nullptr}; return e; }
        case 512: { static CapiEntry e{"CFURLGetString",        nullptr}; return e; }
        case 513: { static CapiEntry e{"CFHTTPMessageCreateRequest",  nullptr}; return e; }
        case 514: { static CapiEntry e{"CFHTTPMessageSetHeaderFieldValue", nullptr}; return e; }
        case 515: { static CapiEntry e{"CFHTTPMessageSetBody",  nullptr}; return e; }
        case 516: { static CapiEntry e{"dispatch_async",        nullptr}; return e; }
        case 517: { static CapiEntry e{"dispatch_sync",         nullptr}; return e; }
        case 518: { static CapiEntry e{"dispatch_after",        nullptr}; return e; }
        case 519: { static CapiEntry e{"dispatch_once",         nullptr}; return e; }
        case 520: { static CapiEntry e{"NSString_UTF8String",   nullptr}; return e; }
        case 521: { static CapiEntry e{"NSString_dataUsingEncoding", nullptr}; return e; }
        case 522: { static CapiEntry e{"NSData_bytes",          nullptr}; return e; }
        case 523: { static CapiEntry e{"b64_encode",            nullptr}; return e; }
        case 524: { static CapiEntry e{"b64_decode",            nullptr}; return e; }
        case 525: { static CapiEntry e{"iconv_open",            nullptr}; return e; }
        case 526: { static CapiEntry e{"iconv",                 nullptr}; return e; }
        // 600–644 Android extended
        case 600: { static CapiEntry e{"EVP_EncryptInit_ex",    nullptr}; return e; }
        case 601: { static CapiEntry e{"EVP_EncryptUpdate",     nullptr}; return e; }
        case 602: { static CapiEntry e{"EVP_EncryptFinal_ex",   nullptr}; return e; }
        case 603: { static CapiEntry e{"EVP_DecryptInit_ex",    nullptr}; return e; }
        case 604: { static CapiEntry e{"EVP_DecryptUpdate",     nullptr}; return e; }
        case 605: { static CapiEntry e{"EVP_DecryptFinal_ex",   nullptr}; return e; }
        case 606: { static CapiEntry e{"EVP_DigestInit_ex",     nullptr}; return e; }
        case 607: { static CapiEntry e{"EVP_DigestUpdate",      nullptr}; return e; }
        case 608: { static CapiEntry e{"EVP_DigestFinal_ex",    nullptr}; return e; }
        case 609: { static CapiEntry e{"HMAC_CTX_new",          nullptr}; return e; }
        case 610: { static CapiEntry e{"HMAC_Init_ex",          nullptr}; return e; }
        case 611: { static CapiEntry e{"HMAC_Update",           nullptr}; return e; }
        case 612: { static CapiEntry e{"HMAC_Final",            nullptr}; return e; }
        case 613: { static CapiEntry e{"SHA256_Init",           nullptr}; return e; }
        case 614: { static CapiEntry e{"SHA256_Update",         nullptr}; return e; }
        case 615: { static CapiEntry e{"SHA256_Final",          nullptr}; return e; }
        case 616: { static CapiEntry e{"AES_set_encrypt_key",   nullptr}; return e; }
        case 617: { static CapiEntry e{"AES_set_decrypt_key",   nullptr}; return e; }
        case 618: { static CapiEntry e{"AES_cbc_encrypt",       nullptr}; return e; }
        case 619: { static CapiEntry e{"RSA_sign",              nullptr}; return e; }
        case 620: { static CapiEntry e{"RSA_verify",            nullptr}; return e; }
        case 621: { static CapiEntry e{"RAND_bytes",            nullptr}; return e; }
        case 622: { static CapiEntry e{"RAND_priv_bytes",       nullptr}; return e; }
        case 623: { static CapiEntry e{"EVP_md5",               nullptr}; return e; }
        case 624: { static CapiEntry e{"EVP_sha1",              nullptr}; return e; }
        case 625: { static CapiEntry e{"EVP_sha256",            nullptr}; return e; }
        case 626: { static CapiEntry e{"BIO_new_mem_buf",       nullptr}; return e; }
        case 627: { static CapiEntry e{"PEM_read_bio_RSAPublicKey", nullptr}; return e; }
        case 628: { static CapiEntry e{"Base64_encode",         nullptr}; return e; }
        case 629: { static CapiEntry e{"Base64_decode",         nullptr}; return e; }
        case 630: { static CapiEntry e{"sqlite3_open",          nullptr}; return e; }
        case 631: { static CapiEntry e{"sqlite3_prepare_v2",    nullptr}; return e; }
        case 632: { static CapiEntry e{"sqlite3_step",          nullptr}; return e; }
        case 633: { static CapiEntry e{"sqlite3_column_text",   nullptr}; return e; }
        case 634: { static CapiEntry e{"sqlite3_close",         nullptr}; return e; }
        case 635: { static CapiEntry e{"sqlite3_exec",          nullptr}; return e; }
        case 636: { static CapiEntry e{"Keymaster_importKey",   nullptr}; return e; }
        case 637: { static CapiEntry e{"Keymaster_exportKey",   nullptr}; return e; }
        case 638: { static CapiEntry e{"Keymaster_finish",      nullptr}; return e; }
        case 639: { static CapiEntry e{"art_InvokeVirtual",     nullptr}; return e; }
        case 640: { static CapiEntry e{"art_Thread_Current",    nullptr}; return e; }
        case 641: { static CapiEntry e{"getaddrinfo",           nullptr}; return e; }
        case 642: { static CapiEntry e{"getnameinfo",           nullptr}; return e; }
        case 643: { static CapiEntry e{"inet_aton",             nullptr}; return e; }
        case 644: { static CapiEntry e{"inet_ntop",             nullptr}; return e; }
        // 700–726 JNI extended
        case 700: { static CapiEntry e{"GetIntField",           nullptr}; return e; }
        case 701: { static CapiEntry e{"GetLongField",          nullptr}; return e; }
        case 702: { static CapiEntry e{"GetObjectField",        nullptr}; return e; }
        case 703: { static CapiEntry e{"SetObjectField",        nullptr}; return e; }
        case 704: { static CapiEntry e{"GetFieldID",            nullptr}; return e; }
        case 705: { static CapiEntry e{"GetStaticFieldID",      nullptr}; return e; }
        case 706: { static CapiEntry e{"GetStringUTFRegion",    nullptr}; return e; }
        case 707: { static CapiEntry e{"GetArrayLength",        nullptr}; return e; }
        case 708: { static CapiEntry e{"NewObjectArray",        nullptr}; return e; }
        case 709: { static CapiEntry e{"GetObjectArrayElement", nullptr}; return e; }
        case 710: { static CapiEntry e{"SetObjectArrayElement", nullptr}; return e; }
        case 711: { static CapiEntry e{"NewIntArray",           nullptr}; return e; }
        case 712: { static CapiEntry e{"GetIntArrayElements",   nullptr}; return e; }
        case 713: { static CapiEntry e{"ReleaseIntArrayElements",nullptr}; return e; }
        case 714: { static CapiEntry e{"CallStaticIntMethod",   nullptr}; return e; }
        case 715: { static CapiEntry e{"CallStaticBooleanMethod",nullptr}; return e; }
        case 716: { static CapiEntry e{"NewObject",             nullptr}; return e; }
        case 717: { static CapiEntry e{"IsInstanceOf",          nullptr}; return e; }
        case 718: { static CapiEntry e{"NewGlobalRef",          nullptr}; return e; }
        case 719: { static CapiEntry e{"DeleteGlobalRef",       nullptr}; return e; }
        case 720: { static CapiEntry e{"DeleteLocalRef",        nullptr}; return e; }
        case 721: { static CapiEntry e{"PushLocalFrame",        nullptr}; return e; }
        case 722: { static CapiEntry e{"PopLocalFrame",         nullptr}; return e; }
        case 723: { static CapiEntry e{"GetVersion",            nullptr}; return e; }
        case 724: { static CapiEntry e{"MonitorEnter",          nullptr}; return e; }
        case 725: { static CapiEntry e{"MonitorExit",           nullptr}; return e; }
        case 726: { static CapiEntry e{"GetJavaVM",             nullptr}; return e; }
        // 727–731 JNI extended (array regions + CallStaticVoidMethod)
        case 727: { static CapiEntry e{"GetIntArrayRegion",     nullptr}; return e; }
        case 728: { static CapiEntry e{"SetIntArrayRegion",     nullptr}; return e; }
        case 729: { static CapiEntry e{"GetLongArrayRegion",    nullptr}; return e; }
        case 730: { static CapiEntry e{"SetLongArrayRegion",    nullptr}; return e; }
        case 731: { static CapiEntry e{"CallStaticVoidMethod",  nullptr}; return e; }
        default: break;
    }
    return kFallback;
}

std::string SyscallInterceptCollector::syscall_name(uint64_t raw_syscall_no) const {
    uint64_t syscall_no = raw_syscall_no;
    if (target_os_ == qbditrace::QBDITRACE_OS_IOS) {
        const auto signed_syscall_no = static_cast<int64_t>(raw_syscall_no);
        if (signed_syscall_no < 0) {
            const auto trap_no = static_cast<int32_t>(signed_syscall_no);
            if (const char* name = mach_trap_name(trap_no)) return name;
            return fmt::format("mach_trap_{}", signed_syscall_no);
        }

        // Darwin BSD selectors carry the syscall class in the high byte
        // (for example 0x02000004 is BSD write). Mach traps are signed and
        // must have returned above before this normalization.
        syscall_no &= 0x00ffffffULL;
        switch (syscall_no) {
        case 3: return "read";
        case 4: return "write";
        case 5: return "open";
        case 6: return "close";
        case 20: return "getpid";
        case 26: return "ptrace";
        case 29: return "recv";
        case 74: return "mprotect";
        case 97: return "socket";
        case 98: return "connect";
        case 133: return "send";
        case 197: return "mmap";
        case 463: return "openat";
        case 500: return "getentropy";
        default: break;
        }
    } else if (target_os_ == qbditrace::QBDITRACE_OS_ANDROID || target_os_ == qbditrace::QBDITRACE_OS_LINUX) {
        // Full arm64 asm-generic table (generated from the kernel's
        // asm-generic/unistd.h; see platform/linux_syscalls.h).
        if (const char* name = linux_syscall_name(syscall_no)) {
            return name;
        }
    }
    return fmt::format("syscall_{}", raw_syscall_no);
}

void SyscallInterceptCollector::on_svc(uint64_t inst_id, const SvcView& svc) {
    InterceptedCall call;
    call.inst_id      = inst_id;
    call.call_site_pc = svc.pc;
    call.callee_pc    = 0;
    call.callee_name  = syscall_name(svc.syscall_no);
    // Anti-debug syscalls (ptrace / process_vm_readv / kill(SIGTRAP) ...) get
    // their own category so pattern reports can surface them immediately;
    // everything else stays ApiCategory::Syscall.
    call.category     = ((target_os_ == qbditrace::QBDITRACE_OS_ANDROID ||
                          target_os_ == qbditrace::QBDITRACE_OS_LINUX) &&
                         linux_syscall_is_anti_debug(svc.syscall_no))
                            ? ApiCategory::AntiDebug
                            : ApiCategory::Syscall;
    call.svc_flags    = svc.flags;
    call.arg_count    = 6;
    for (uint8_t i = 0; i < 6; ++i) call.raw_args[i] = svc.args[i];
    call.decoded_summary = fmt::format(
        "{}(x0=0x{:x}, x1=0x{:x}, x2=0x{:x}, x3=0x{:x}) [raw={}]",
        call.callee_name, svc.args[0], svc.args[1], svc.args[2], svc.args[3],
        static_cast<int64_t>(svc.syscall_no));
    decode_mach_message(call, svc.syscall_no);

    const size_t idx = result_.calls.size();
    finalize_call(std::move(call));
    pending_returns_.push_back(
        {qbditrace::QBDITRACE_REC_SVC, svc.syscall_no, svc.pc, idx});
}

void SyscallInterceptCollector::decode_mach_message(InterceptedCall& call,
                                                     uint64_t raw_syscall_no) {
    if (target_os_ != qbditrace::QBDITRACE_OS_IOS) return;
    const int64_t signed_syscall_no = static_cast<int64_t>(raw_syscall_no);
    if (signed_syscall_no != -31 && signed_syscall_no != -32 && signed_syscall_no != -47) return;

    // x1 is mach_msg option only for mach_msg_trap. A pure receive buffer does
    // not contain an outbound MIG request, so never interpret it as one.
    constexpr uint64_t kMachSendMsg = 0x1;
    const std::string trap_name = call.callee_name;
    uint32_t msgh_id = 0;

    if (signed_syscall_no == -47) {
        // XNU libsyscall/mach/mach_msg.c: mach_msg2_internal() forwards
        // (data, option64, bits_and_send_size, remote_and_local_port,
        // voucher_and_id, ...) directly to mach_msg2_trap(). Therefore the
        // mach_msg2 ABI carries option64 in x1 and msgh_id in x4[31:0], not
        // in a mach_msg_header_t addressed by x0.
        if ((call.raw_args[1] & kMachSendMsg) == 0) return;
        msgh_id = static_cast<uint32_t>(call.raw_args[4]);
    } else {
        if (signed_syscall_no == -31 && (call.raw_args[1] & kMachSendMsg) == 0) return;

        const auto header = read_memory_at(call.raw_args[0], 24, call.inst_id);
        if (header.size() < 24) {
            call.decoded_summary += " (msgh unreadable)";
            return;
        }

        msgh_id = static_cast<uint32_t>(header[20]) |
            (static_cast<uint32_t>(header[21]) << 8) |
            (static_cast<uint32_t>(header[22]) << 16) |
            (static_cast<uint32_t>(header[23]) << 24);
    }
    if (const char* routine = mig_routine_name(msgh_id)) {
        call.mach_msgh_id = msgh_id;
        call.mach_msg_via = trap_name;
        call.callee_name = routine;
        call.decoded_summary = fmt::format(
            "{} via {}(msgh_id=0x{:x})(x0=0x{:x}, x1=0x{:x}, x2=0x{:x}, x3=0x{:x}) [raw={}]",
            routine, trap_name, msgh_id, call.raw_args[0], call.raw_args[1],
            call.raw_args[2], call.raw_args[3], signed_syscall_no);
    } else {
        call.decoded_summary += fmt::format(" (msgh_id=0x{:x})", msgh_id);
    }
}

void SyscallInterceptCollector::on_retval(uint64_t /*inst_id*/, const RetvalView& retval) {
    auto match = pending_returns_.rend();
    for (auto it = pending_returns_.rbegin(); it != pending_returns_.rend(); ++it) {
        if (it->source_kind == retval.source_kind &&
            it->site == retval.site && it->source_id == retval.source_id) {
            match = it;
            break;
        }
    }
    if (match == pending_returns_.rend()) return;

    const size_t call_index = match->call_index;
    pending_returns_.erase(std::next(match).base());
    if (call_index >= result_.calls.size()) return;

    auto& call = result_.calls[call_index];
    call.has_return = true;
    call.return_value = retval.x0;
    call.return_x1 = retval.x1;
    call.return_nzcv = retval.nzcv;
    call.errno_valid = (retval.flags & QBDITRACE_RET_FL_ERRNO_VALID) != 0;
    if (call.errno_valid) {
        call.errno_before = retval.errno_before;
        call.errno_after = retval.errno_after;
    }

    if (call.category == ApiCategory::Syscall) {
        const auto signed_x0 = static_cast<int64_t>(retval.x0);
        const bool linux_error = target_os_ != qbditrace::QBDITRACE_OS_IOS &&
            signed_x0 < 0 && signed_x0 >= -4095;
        const bool darwin_error = target_os_ == qbditrace::QBDITRACE_OS_IOS &&
            (retval.nzcv & (1u << 29)) != 0;
        if (linux_error) call.raw_error = signed_x0;
        else if (darwin_error) call.raw_error = static_cast<int64_t>(retval.x0);
    }
    refresh_summary_with_return(call);
}

void SyscallInterceptCollector::on_capicall(uint64_t inst_id, const CapiCallView& capi) {
    // Look up the API name from the static entry table.
    const CapiEntry& entry = capi_entry(capi.api_id);
    const char* api_name = entry.name ? entry.name : nullptr;

    // REC_CAPICALL records represent distinct invocations even when they call
    // the same target. Keep only a marker for suppressing heuristic Event
    // fallback; never deduplicate authoritative records by callee address.
    capicall_seen_[capi.pc] = inst_id;

    InterceptedCall call;
    call.inst_id           = inst_id;
    call.call_site_pc      = capi.pc;
    call.callee_pc         = capi.target;
    call.from_capicall_record = true;

    // Determine name: from table first, else synthetic.
    if (api_name) {
        call.callee_name = api_name;
    } else {
        call.callee_name = fmt::format("sub_{:x}", capi.target);
    }

    // Determine category from signature table.
    call.category = ApiCategory::Custom;
    if (entry.sig) {
        call.category = entry.sig->category;
    } else if (api_name) {
        // Try to match against our known API tables.
        auto ait = api_by_name_.find(call.callee_name);
        if (ait != api_by_name_.end() && ait->second) {
            call.category = ait->second->category;
        } else if (capi.api_id >= 600 && capi.api_id <= 629) {
            call.category = ApiCategory::BoringSSL;
        } else if ((capi.api_id >= 280 && capi.api_id <= 359) ||
                   (capi.api_id >= 700 && capi.api_id <= 731)) {
            call.category = ApiCategory::JNI;
        }
    }

    // Copy raw args from CapiCallView.
    call.arg_count = std::min<uint8_t>(capi.arg_count, static_cast<uint8_t>(call.raw_args.size()));
    for (uint8_t i = 0; i < call.arg_count; ++i) {
        call.raw_args[i] = capi.args[i];
    }

    // Copy captured inline strings from the record.
    for (uint8_t si = 0; si < capi.str_count; ++si) {
        auto sv = capi.str_at(si);
        CapturedString cs;
        cs.arg_idx   = sv.arg_idx;
        cs.truncated = sv.is_truncated();
        cs.binary    = sv.is_binary();
        if (sv.data && sv.str_len > 0) {
            cs.value.assign(sv.data, sv.str_len);
        }
        call.captured_strings.push_back(std::move(cs));
    }

    // Attach ObjC context if recent.
    if (!last_objc_context_.empty() &&
        cur_inst_id_ - last_objc_inst_id_ < 100000) {
        call.objc_context = last_objc_context_;
    }

    // Decode known signatures even when the CAPI record has inline captures:
    // decode_known_api() uses those captures as the preferred byte source.
    if (entry.sig) {
        decode_known_api(call, *entry.sig);
    } else {
        auto ait = api_by_name_.find(call.callee_name);
        if (ait != api_by_name_.end() && ait->second) {
            decode_known_api(call, *ait->second);
        } else if (!call.captured_strings.empty()) {
            std::string summary = call.callee_name + ": ";
            for (const auto& cs : call.captured_strings) {
                summary += fmt::format("x{}=\"{}\"{}  ",
                    cs.arg_idx,
                    cs.value.substr(0, std::min<size_t>(cs.value.size(), 64)),
                    cs.truncated ? "…" : "");
            }
            call.decoded_summary = std::move(summary);
        } else {
            call.decoded_summary = call.callee_name +
                fmt::format(": x0=0x{:x} x1=0x{:x} x2=0x{:x} x3=0x{:x}",
                    call.raw_args[0], call.raw_args[1],
                    call.raw_args[2], call.raw_args[3]);
        }
    }

    const size_t idx = result_.calls.size();
    const uint64_t source_id = capi.api_id;
    const uint64_t site = capi.pc;
    finalize_call(std::move(call));
    pending_returns_.push_back(
        {qbditrace::QBDITRACE_REC_CAPICALL, source_id, site, idx});
}

void SyscallInterceptCollector::finalize_call(InterceptedCall call) {
    const size_t idx = result_.calls.size();
    result_.by_callee[call.callee_name].push_back(idx);
    result_.by_category[call.category].push_back(idx);
    result_.calls.push_back(std::move(call));
}

void SyscallInterceptCollector::refresh_summary_with_return(InterceptedCall& call) const {
    if (!call.has_return) return;
    call.decoded_summary += fmt::format(" => x0=0x{:x}, x1=0x{:x}, nzcv=0x{:x}",
                                       call.return_value, call.return_x1,
                                       call.return_nzcv);
    if (call.raw_error) {
        call.decoded_summary += fmt::format(" error={}", *call.raw_error);
    }
    if (call.errno_valid) {
        call.decoded_summary += fmt::format(" errno={}->{}",
                                           call.errno_before, call.errno_after);
    }
}

void SyscallInterceptCollector::end() {
    // Nothing to finalize — results are already accumulated.
}

// ─── Memory reading helper ────────────────────────────────────────────────

std::vector<uint8_t> SyscallInterceptCollector::read_memory_at(
    uint64_t addr, uint32_t max_bytes, uint64_t at_inst_id)
{
    if (addr == 0 || max_bytes == 0) return {};

    // Single read_region call replaces the previous N-chunk read() loop.
    // read_region internally uses the PageWriteIndex batch path, so this is
    // both fewer RocksDB seeks and better cache locality.
    auto region = memory_.read_region(addr, max_bytes, at_inst_id);

    std::vector<uint8_t> result;
    result.reserve(max_bytes);

    for (size_t i = 0; i < region.data.size(); ++i) {
        if (!region.known[i]) {
            // Stop if the very first byte is unknown; otherwise pad with 0.
            if (result.empty()) break;
            result.push_back(0);
        } else {
            result.push_back(region.data[i]);
        }
    }

    return result;
}

// ─── Decode a known API call ──────────────────────────────────────────────

void SyscallInterceptCollector::decode_known_api(InterceptedCall& call,
                                                  const ApiSignature& sig)
{
    const auto* regs = call.raw_args.data();
    const uint32_t capture = config_.capture_bytes;

    // Inline CAPI captures are produced at the call boundary, so they remain
    // available even when the trace never touches the source memory page.
    // Preserve their bytes verbatim (including BINARY/TRUNCATED captures) and
    // prefer them over reconstructed memory for signature-designated buffers.
    auto captured_arg = [&](uint8_t arg_idx) -> std::optional<std::vector<uint8_t>> {
        for (const auto& captured : call.captured_strings) {
            if (captured.arg_idx == arg_idx) {
                return std::vector<uint8_t>(captured.value.begin(), captured.value.end());
            }
        }
        return std::nullopt;
    };

    // Helper lambda for reading a pointer arg and returning bytes.
    auto read_ptr_arg = [&](uint8_t ptr_idx, uint8_t len_idx,
                             uint64_t default_len) -> std::vector<uint8_t> {
        if (ptr_idx >= 8) return {};
        uint64_t ptr = regs[ptr_idx];
        if (ptr == 0) return {};
        uint64_t len = default_len;
        if (len_idx < 8 && regs[len_idx] > 0 && regs[len_idx] < (1ULL << 20)) {
            len = regs[len_idx];
        }
        uint32_t cap = static_cast<uint32_t>(std::min<uint64_t>(len, capture));
        return read_memory_at(ptr, cap, call.inst_id);
    };

    // Extract key material.
    if (sig.key_ptr_arg < 8) {
        if (auto captured = captured_arg(sig.key_ptr_arg)) {
            call.key_length = (sig.key_len_arg < 8) ? regs[sig.key_len_arg] : captured->size();
            call.key_bytes = std::move(*captured);
        } else if (auto kb = read_ptr_arg(sig.key_ptr_arg, sig.key_len_arg, 32); !kb.empty()) {
            call.key_length = (sig.key_len_arg < 8) ? regs[sig.key_len_arg] : kb.size();
            call.key_bytes = std::move(kb);
        }
    }

    // Extract IV.
    if (sig.iv_ptr_arg < 8) {
        if (auto captured = captured_arg(sig.iv_ptr_arg)) {
            call.iv_bytes = std::move(*captured);
        } else if (auto iv = read_ptr_arg(sig.iv_ptr_arg, sig.iv_len_arg, 16); !iv.empty()) {
            call.iv_bytes = std::move(iv);
        }
    }

    // Extract input data (first `capture` bytes).
    if (sig.data_ptr_arg < 8) {
        if (auto captured = captured_arg(sig.data_ptr_arg)) {
            call.data_length = (sig.data_len_arg < 8) ? regs[sig.data_len_arg] : captured->size();
            call.data_bytes = std::move(*captured);
        } else if (auto db = read_ptr_arg(sig.data_ptr_arg, sig.data_len_arg, 64); !db.empty()) {
            call.data_length = (sig.data_len_arg < 8) ? regs[sig.data_len_arg] : db.size();
            call.data_bytes = std::move(db);
        }
    }

    // Build human-readable decoded_summary.
    // CAPI IDs can be shared by a family (for example CC_DIGEST). The call
    // name is resolved at the writer and must remain the user-facing name.
    std::string summary = call.callee_name.empty() ? sig.name : call.callee_name;
    summary += ": ";
    bool has_semantic_content = false;

    if (sig.operation_arg < 8) {
        uint32_t op = static_cast<uint32_t>(regs[sig.operation_arg]);
        summary += cc_operation_name(op);
        summary += " ";
        has_semantic_content = true;
    }
    if (sig.algorithm_arg < 8) {
        uint32_t alg = static_cast<uint32_t>(regs[sig.algorithm_arg]);
        // Distinguish CCAlgorithm vs CCHmacAlgorithm vs CCPBKDFAlgorithm
        // by function name prefix.
        if (sig.name.rfind("CCHmac", 0) == 0) {
            summary += cc_hmac_alg_name(alg);
        } else {
            summary += cc_algorithm_name(alg);
        }
        summary += " ";
        has_semantic_content = true;
    }
    if (sig.mode_arg < 8) {
        uint32_t mode = static_cast<uint32_t>(regs[sig.mode_arg]);
        summary += cc_mode_name(mode);
        summary += " ";
        has_semantic_content = true;
    }
    if (call.key_bytes.has_value()) {
        summary += fmt::format("key[{}]=", call.key_length);
        for (size_t i = 0; i < std::min<size_t>(call.key_bytes->size(), 8); ++i) {
            summary += fmt::format("{:02x}", (*call.key_bytes)[i]);
        }
        if (call.key_bytes->size() > 8) summary += "...";
        summary += " ";
        has_semantic_content = true;
    }
    if (call.iv_bytes.has_value()) {
        summary += fmt::format("iv[{}]=", call.iv_bytes->size());
        for (size_t i = 0; i < std::min<size_t>(call.iv_bytes->size(), 8); ++i) {
            summary += fmt::format("{:02x}", (*call.iv_bytes)[i]);
        }
        if (call.iv_bytes->size() > 8) summary += "...";
        summary += " ";
        has_semantic_content = true;
    }
    if (call.data_bytes.has_value()) {
        summary += fmt::format("data[{}]=", call.data_length);
        for (size_t i = 0; i < std::min<size_t>(call.data_bytes->size(), 8); ++i) {
            summary += fmt::format("{:02x}", (*call.data_bytes)[i]);
        }
        if (call.data_bytes->size() > 8) summary += "...";
        has_semantic_content = true;
    }
    if (!has_semantic_content) {
        for (uint8_t i = 0; i < std::min<uint8_t>(call.arg_count, 8); ++i) {
            summary += fmt::format("x{}=0x{:x}{}", i, regs[i],
                                   i + 1 < std::min<uint8_t>(call.arg_count, 8) ? " " : "");
        }
    }

    call.decoded_summary = std::move(summary);
}

// ─── SyscallInterceptPass::declare_scan ──────────────────────────────────

void SyscallInterceptPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& code_table = ctx.code_table();
    auto& memory = ctx.memory();
    auto& reader = ctx.reader();

    // Optional: get ObjC messages for context annotation.
    // try_require only checks the cache — it does NOT trigger execution.
    const ObjcResult* objc = ctx.try_require<ObjcResult>("objc");

    collector_ = std::make_unique<SyscallInterceptCollector>(
        config_, code_table, memory, objc,
        static_cast<uint32_t>(reader.header().target_os));
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}

// ─── SyscallInterceptPass::run ────────────────────────────────────────────

std::optional<PassResult> SyscallInterceptPass::try_load_cached(PassContext& ctx) {
    const bool is_default_cfg =
        config_.extra_api_names.empty() && !config_.intercept_unresolved &&
        config_.capture_bytes == 64;
    if (!is_default_cfg || !ctx.range().is_full_trace()) return std::nullopt;

    std::string blob;
    if (!ctx.index().load_pass_blob("syscall_intercept", blob)) return std::nullopt;

    SyscallInterceptResult cached;
    if (!syscall_intercept_deserialize(blob, cached)) return std::nullopt;

    collector_.reset();
    ctx.progress(1.0f, fmt::format(
        "syscall_intercept: {} calls ({} unique callees) (from cache)",
        cached.calls.size(), cached.by_callee.size()));
    return PassResult::success(std::move(cached));
}

PassResult SyscallInterceptPass::run(PassContext& ctx) {
    const bool is_default_cfg =
        config_.extra_api_names.empty() && !config_.intercept_unresolved &&
        config_.capture_bytes == 64;

    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    ctx.progress(0.01f, "syscall_intercept: extracting results...");

    auto result = collector_->take_result();

    // ── Persist result for future sessions ───────────────────────────────
    if (is_default_cfg && ctx.range().is_full_trace()) {
        std::string blob = syscall_intercept_serialize(result);
        if (!blob.empty()) {
            ctx.index().save_pass_blob("syscall_intercept", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format(
        "syscall_intercept: {} API calls intercepted ({} unique callees)",
        result.calls.size(), result.by_callee.size()));

    return PassResult::success(std::move(result));
}

// ─── SyscallInterceptResult helpers ──────────────────────────────────────

std::vector<const InterceptedCall*>
SyscallInterceptResult::find_calls(const std::string& name_pattern) const {
    std::vector<const InterceptedCall*> found;
    for (const auto& c : calls) {
        if (c.callee_name.find(name_pattern) != std::string::npos) {
            found.push_back(&c);
        }
    }
    return found;
}

static const char* api_category_str(ApiCategory cat) {
    switch (cat) {
        case ApiCategory::CommonCrypto:      return "CommonCrypto";
        case ApiCategory::SecurityFramework: return "Security.framework";
        case ApiCategory::CryptoKit:         return "CryptoKit";
        case ApiCategory::CocoaFoundation:   return "Foundation";
        case ApiCategory::LibSystem:         return "libSystem";
        case ApiCategory::BoringSSL:         return "BoringSSL";
        case ApiCategory::AndroidKeystore:   return "AndroidKeystore";
        case ApiCategory::JNI:               return "JNI";
        case ApiCategory::MemoryOps:         return "MemoryOps";
        case ApiCategory::StringOps:         return "StringOps";
        case ApiCategory::HeapAlloc:         return "HeapAlloc";
        case ApiCategory::FileIO:            return "FileIO";
        case ApiCategory::Network:           return "Network";
        case ApiCategory::AntiDebug:         return "AntiDebug";
        case ApiCategory::Threading:         return "Threading";
        case ApiCategory::Encoding:          return "Encoding";
        case ApiCategory::Compression:       return "Compression";
        case ApiCategory::SQLite:            return "SQLite";
        case ApiCategory::DynLink:           return "DynLink";
        case ApiCategory::ObjCRuntime:       return "ObjCRuntime";
        case ApiCategory::MemoryMap:         return "MemoryMap";
        case ApiCategory::Syscall:           return "Syscall";
        case ApiCategory::Custom:            return "Custom";
    }
    return "Unknown";
}

std::string SyscallInterceptResult::to_json() const {
    json output;
    output["total"]   = calls.size();
    output["callees"] = by_callee.size();

    // Summary table: callee → call count
    json callee_summary = json::object();
    for (const auto& [name, idxs] : by_callee) {
        callee_summary[name] = idxs.size();
    }
    output["callee_counts"] = std::move(callee_summary);

    json calls_arr = json::array();
    for (const auto& c : calls) {
        json cj;
        cj["inst_id"]     = c.inst_id;
        cj["call_site"]   = fmt::format("0x{:X}", c.call_site_pc);
        cj["callee"]      = c.callee_name;
        cj["callee_pc"]   = fmt::format("0x{:X}", c.callee_pc);
        cj["category"]    = api_category_str(c.category);
        cj["summary"]     = c.decoded_summary;
        cj["svc_flags"]   = c.svc_flags;
        if (c.mach_msgh_id) {
            cj["mach_msgh_id"] = *c.mach_msgh_id;
            cj["mach_msg_via"] = c.mach_msg_via.value_or("");
        }
        cj["has_return"]  = c.has_return;
        if (c.has_return) {
            cj["return_x0"] = fmt::format("0x{:X}", c.return_value);
            cj["return_x1"] = fmt::format("0x{:X}", c.return_x1);
            cj["return_nzcv"] = c.return_nzcv;
            cj["errno_valid"] = c.errno_valid;
            if (c.errno_valid) {
                cj["errno_before"] = c.errno_before;
                cj["errno_after"] = c.errno_after;
            }
            if (c.raw_error) cj["raw_error"] = *c.raw_error;
        }

        if (c.objc_context.has_value()) {
            cj["objc_context"] = *c.objc_context;
        }

        // Raw args
        json args_arr = json::array();
        for (uint8_t i = 0; i < std::min<uint8_t>(c.arg_count, 8); ++i) {
            args_arr.push_back(fmt::format("0x{:X}", c.raw_args[i]));
        }
        cj["args_x0_x7"] = std::move(args_arr);

        // Key material
        if (c.key_bytes.has_value()) {
            cj["key_length"] = c.key_length;
            std::string hex;
            for (uint8_t b : *c.key_bytes) hex += fmt::format("{:02x}", b);
            cj["key_hex"] = hex;
        }
        if (c.iv_bytes.has_value()) {
            std::string hex;
            for (uint8_t b : *c.iv_bytes) hex += fmt::format("{:02x}", b);
            cj["iv_hex"] = hex;
        }
        if (c.data_bytes.has_value()) {
            cj["data_length"] = c.data_length;
            std::string hex;
            for (uint8_t b : *c.data_bytes) hex += fmt::format("{:02x}", b);
            cj["data_hex_first64"] = hex;
        }

        calls_arr.push_back(std::move(cj));
    }
    output["calls"] = std::move(calls_arr);

    return output.dump(2);
}

// ─── ApiArg::to_string ───────────────────────────────────────────────────

std::string ApiArg::to_string() const {
    if (as_string.has_value()) return *as_string;
    if (as_bytes.has_value()) {
        std::string hex;
        for (uint8_t b : *as_bytes) hex += fmt::format("{:02x}", b);
        return hex;
    }
    return fmt::format("0x{:x}", raw_value);
}

}  // namespace tenet
