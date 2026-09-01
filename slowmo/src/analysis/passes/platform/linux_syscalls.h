// linux_syscalls.h — Linux/Android arm64 (asm-generic) syscall name table.
//
// GENERATED from the Android NDK's asm-generic/unistd.h (aarch64, 64-bit)
// via `clang -dM -E` — the numbers are the kernel ABI truth, not hand-curated.
// Regenerate with:
//   $CC -dM -E -include asm-generic/unistd.h -x c /dev/null \
//       | grep -oE "#define __NR_[a-zA-Z0-9_]+ [0-9]+" | sort -k2 -n
// Shared by the SyscallInterceptPass and the trace_dump frontend so the two
// never drift apart.
//
// Anti-debug relevance: Android targets commonly probe ptrace /
// process_vm_readv / kill(SIGTRAP) / perf_event_open; the syscall_intercept
// pass marks those as ApiCategory::AntiDebug via linux_syscall_is_anti_debug().

#ifndef TENET_LINUX_SYSCALLS_H_
#define TENET_LINUX_SYSCALLS_H_

#include <cstdint>

namespace tenet {

/// Name of an arm64 Linux/Android syscall, or nullptr when unknown.
const char* linux_syscall_name(uint64_t syscall_no);

/// True when the syscall is commonly abused for anti-debugging /
/// integrity checking (ptrace self-attach, process_vm_readv probing,
/// signal-based breakpoint checks, perf_event_open watchdogs...).
bool linux_syscall_is_anti_debug(uint64_t syscall_no);

} // namespace tenet

#endif // TENET_LINUX_SYSCALLS_H_
