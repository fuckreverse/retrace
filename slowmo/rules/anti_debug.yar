/*
 * Tenet YARA rules — Anti-debug and anti-tamper detection
 *
 * Scans the syscall stream buffer: each entry is 16 bytes:
 *   [8-byte inst_id LE][2-byte syscall_no LE][6-byte zero padding]
 *
 * iOS/macOS (Darwin XNU) syscall numbers used here.
 */

// ═══════════════════════════════════════════════════════════════════════════
// Classic anti-debug syscalls
// ═══════════════════════════════════════════════════════════════════════════

rule Ptrace_AntiDebug
{
    meta:
        description = "ptrace() syscall — PT_DENY_ATTACH anti-debug"
        category = "anti_debug"
        confidence = "high"

    strings:
        // syscall number 26 = 0x001a
        $ptrace = { 1a 00 }

    condition:
        $ptrace
}

rule Sysctl_AntiDebug
{
    meta:
        description = "sysctl() — may check P_TRACED flag (kern.proc.pid)"
        category = "anti_debug"
        confidence = "medium"

    strings:
        // syscall number 202 = 0x00ca
        $sysctl = { ca 00 }

    condition:
        $sysctl
}

rule Getppid_AntiDebug
{
    meta:
        description = "getppid() — checks if parent is debugger (launchd vs lldb)"
        category = "anti_debug"
        confidence = "low"

    strings:
        // syscall number 39 = 0x0027
        $getppid = { 27 00 }

    condition:
        $getppid
}

rule Isatty_AntiDebug
{
    meta:
        description = "isatty()/ioctl() — terminal detection anti-debug"
        category = "anti_debug"
        confidence = "low"

    strings:
        // ioctl = syscall number 54 = 0x0036
        $ioctl = { 36 00 }

    condition:
        $ioctl
}

// ═══════════════════════════════════════════════════════════════════════════
// Mach port / task-based anti-debug
// ═══════════════════════════════════════════════════════════════════════════

rule Exception_Ports_AntiDebug
{
    meta:
        description = "task_get_exception_ports Mach trap — debugger port check"
        category = "anti_debug"
        confidence = "high"

    strings:
        // Mach trap -27 → unsigned in SVC imm is architecture-specific
        // On ARM64 Darwin, mach traps go through SVC 0x80 with negative numbers
        // We detect via the task_get_exception_ports pattern in the trace
        // Mach trap numbers are passed in X16 as negative:
        //   task_get_exception_ports = -27 → 0xFFFFFFE5 → LE { e5 ff }
        $trap_neg = { e5 ff }

    condition:
        $trap_neg
}

// ═══════════════════════════════════════════════════════════════════════════
// Anti-tamper / code integrity
// ═══════════════════════════════════════════════════════════════════════════

rule Csops_IntegrityCheck
{
    meta:
        description = "csops() — code signing / integrity check (CS_OPS)"
        category = "anti_tamper"
        confidence = "medium"

    strings:
        // syscall number 0x14e = 334
        $csops = { 4e 01 }

    condition:
        $csops
}

rule Csops_Audittoken
{
    meta:
        description = "csops_audittoken() — code signing check with audit token"
        category = "anti_tamper"
        confidence = "medium"

    strings:
        // syscall number 0x14f = 335
        $csops_at = { 4f 01 }

    condition:
        $csops_at
}

rule Fcntl_F_GETPATH
{
    meta:
        description = "fcntl() — may be used to verify executable path integrity"
        category = "anti_tamper"
        confidence = "low"

    strings:
        // syscall number 92 = 0x005c
        $fcntl = { 5c 00 }

    condition:
        $fcntl
}

rule Access_Check
{
    meta:
        description = "access()/stat() — checks for jailbreak files or debugger presence"
        category = "anti_tamper"
        confidence = "low"

    strings:
        // access = syscall 33 = 0x0021
        $access = { 21 00 }
        // stat64 = syscall 338 = 0x0152
        $stat64 = { 52 01 }

    condition:
        any of them
}

// ═══════════════════════════════════════════════════════════════════════════
// Jailbreak detection syscalls
// ═══════════════════════════════════════════════════════════════════════════

rule Fork_Detection
{
    meta:
        description = "fork() — sandbox escape / jailbreak detection (fork fails in sandbox)"
        category = "anti_tamper"
        confidence = "medium"

    strings:
        // fork = syscall 2 = 0x0002
        $fork = { 02 00 }

    condition:
        $fork
}

rule Dlopen_Check
{
    meta:
        description = "open() on dynamic library paths — potential dylib injection detection"
        category = "anti_tamper"
        confidence = "low"

    strings:
        // open = syscall 5 = 0x0005
        $open = { 05 00 }

    condition:
        $open
}

// ═══════════════════════════════════════════════════════════════════════════
// Timing-based anti-debug
// ═══════════════════════════════════════════════════════════════════════════

rule Gettimeofday_Timing
{
    meta:
        description = "gettimeofday() — timing-based anti-debug check"
        category = "anti_debug"
        confidence = "low"

    strings:
        // gettimeofday = syscall 116 = 0x0074
        $gtod = { 74 00 }

    condition:
        $gtod
}
