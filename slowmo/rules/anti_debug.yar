/*
 * Tenet YARA rules — Anti-debug and anti-tamper detection
 * Scans the syscall stream buffer: each entry is 16 bytes:
 *   [8-byte inst_id LE][2-byte syscall_no LE][6-byte zero padding]
 */

rule Ptrace_AntiDebug
{
    meta:
        description = "ptrace syscall detected (potential anti-debug)"
        category = "anti_debug"
        confidence = "high"

    strings:
        // syscall number 26 = 0x001a in the 2-byte LE field
        $ptrace = { 1a 00 }

    condition:
        $ptrace
}

rule Sysctl_AntiDebug
{
    meta:
        description = "sysctl() — may check P_TRACED flag"
        category = "anti_debug"
        confidence = "medium"

    strings:
        // syscall number 202 = 0x00ca
        $sysctl = { ca 00 }

    condition:
        $sysctl
}

rule Csops_IntegrityCheck
{
    meta:
        description = "csops() code signing integrity check"
        category = "anti_tamper"
        confidence = "medium"

    strings:
        // syscall number 169 = 0x00a9  (CS_OPS)
        $csops = { 4e 01 }

    condition:
        $csops
}
