/*
 * Tenet YARA rules — Encoding / hashing utility detection
 *
 * Detects Base64, Base32, hex encoding tables, and common utility constants
 * in register-value and code buffers.
 */

// ═══════════════════════════════════════════════════════════════════════════
// Base64
// ═══════════════════════════════════════════════════════════════════════════

rule Base64_Standard_Table
{
    meta:
        description = "Standard Base64 alphabet (first 32 chars: A-Za-f)"
        category = "encoding"
        confidence = "high"

    strings:
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        $table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"

    condition:
        $table
}

rule Base64_URL_Safe_Table
{
    meta:
        description = "URL-safe Base64 alphabet: uses - and _ instead of + and /"
        category = "encoding"
        confidence = "high"

    strings:
        // Standard has '+/' at positions 62,63; URL-safe has '-_'
        // We look for the tail with '-_' instead of '+/'
        // "wxyz0123456789-_"
        $url_safe_tail = "0123456789-_"

    condition:
        $url_safe_tail
}

rule Base64_Custom_Table
{
    meta:
        description = "Potential custom Base64 alphabet (62 consecutive printable + 2 special)"
        category = "encoding"
        confidence = "low"

    strings:
        // The uppercase part is always present in any Base64 variant
        $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        $lower = "abcdefghijklmnopqrstuvwxyz"
        $digits = "0123456789"

    condition:
        all of them
}

// ═══════════════════════════════════════════════════════════════════════════
// Base32
// ═══════════════════════════════════════════════════════════════════════════

rule Base32_Standard_Table
{
    meta:
        description = "Standard Base32 alphabet (RFC 4648)"
        category = "encoding"
        confidence = "high"

    strings:
        $table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    condition:
        $table
}

rule Base32_Hex_Table
{
    meta:
        description = "Base32hex alphabet (RFC 4648 extended hex)"
        category = "encoding"
        confidence = "high"

    strings:
        $table = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

    condition:
        $table
}

// ═══════════════════════════════════════════════════════════════════════════
// Hex encoding
// ═══════════════════════════════════════════════════════════════════════════

rule Hex_Lowercase_Table
{
    meta:
        description = "Lowercase hex encoding table"
        category = "encoding"
        confidence = "medium"

    strings:
        $hex = "0123456789abcdef"

    condition:
        $hex
}

rule Hex_Uppercase_Table
{
    meta:
        description = "Uppercase hex encoding table"
        category = "encoding"
        confidence = "medium"

    strings:
        $hex = "0123456789ABCDEF"

    condition:
        $hex
}
