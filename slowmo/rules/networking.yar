/*
 * Tenet YARA rules — Networking and communication patterns
 *
 * Detects syscalls and constants related to network communication.
 * Primarily scans the syscall buffer.
 */

// ═══════════════════════════════════════════════════════════════════════════
// Socket syscalls
// ═══════════════════════════════════════════════════════════════════════════

rule Socket_Create
{
    meta:
        description = "socket() syscall — network socket creation"
        category = "networking"
        confidence = "medium"

    strings:
        // socket = syscall 97 = 0x0061
        $socket = { 61 00 }

    condition:
        $socket
}

rule Connect_Call
{
    meta:
        description = "connect() syscall — outbound network connection"
        category = "networking"
        confidence = "medium"

    strings:
        // connect = syscall 98 = 0x0062
        $connect = { 62 00 }

    condition:
        $connect
}

rule Sendto_Recvfrom
{
    meta:
        description = "sendto()/recvfrom() — UDP-style data transfer"
        category = "networking"
        confidence = "medium"

    strings:
        // sendto = syscall 133 = 0x0085
        $sendto = { 85 00 }
        // recvfrom = syscall 29 = 0x001d
        $recvfrom = { 1d 00 }

    condition:
        any of them
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS resolution
// ═══════════════════════════════════════════════════════════════════════════

rule DNS_Port
{
    meta:
        description = "DNS port number 53 (0x35) in register values"
        category = "networking"
        confidence = "low"

    strings:
        // port 53 as 16-bit BE in a network struct: 0x0035
        $dns_port_be = { 00 35 }

    condition:
        $dns_port_be
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS / SSL
// ═══════════════════════════════════════════════════════════════════════════

rule TLS_ClientHello
{
    meta:
        description = "TLS ClientHello record type 0x16 + version 0x0301 (TLS 1.0)"
        category = "networking"
        confidence = "medium"

    strings:
        // Content type 0x16 (Handshake), Version 0x0301
        $ch = { 16 03 01 }
        // TLS 1.2 version
        $ch12 = { 16 03 03 }

    condition:
        any of them
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP
// ═══════════════════════════════════════════════════════════════════════════

rule HTTP_Request_Verbs
{
    meta:
        description = "HTTP request method strings in register/memory values"
        category = "networking"
        confidence = "low"

    strings:
        $get  = "GET "
        $post = "POST "
        $put  = "PUT "

    condition:
        any of them
}
