/*
 * Tenet YARA rules — Obfuscation pattern detection
 *
 * Detects common code obfuscation patterns in register-value and code buffers:
 *   - MBA (Mixed Boolean-Arithmetic) expression residues
 *   - CFF (Control Flow Flattening) dispatcher constants
 *   - Opaque predicate patterns
 *   - String encryption / decryption patterns
 */

// ═══════════════════════════════════════════════════════════════════════════
// MBA (Mixed Boolean-Arithmetic) indicators
// ═══════════════════════════════════════════════════════════════════════════

rule MBA_Magic_XOR_AND
{
    meta:
        description = "MBA obfuscation: common transform constant 0x5555555555555555"
        category = "obfuscation"
        confidence = "medium"

    strings:
        // 0x5555555555555555 LE — classic MBA mask for (a ^ b) rewrite
        $mask_55 = { 55 55 55 55 55 55 55 55 }
        // 0xAAAAAAAAAAAAAAAA LE — complement mask
        $mask_aa = { aa aa aa aa aa aa aa aa }

    condition:
        any of them
}

rule MBA_Magic_33
{
    meta:
        description = "MBA obfuscation: bit-counting constant 0x3333333333333333"
        category = "obfuscation"
        confidence = "low"

    strings:
        // popcount MBA: 0x3333333333333333
        $mask_33 = { 33 33 33 33 33 33 33 33 }
        // popcount MBA: 0x0F0F0F0F0F0F0F0F
        $mask_0f = { 0f 0f 0f 0f 0f 0f 0f 0f }

    condition:
        all of them
}

// ═══════════════════════════════════════════════════════════════════════════
// CFF (Control Flow Flattening) dispatcher
// ═══════════════════════════════════════════════════════════════════════════

rule CFF_Dispatcher_Pattern
{
    meta:
        description = "CFF flattening: state variable update with multiply-add pattern"
        category = "obfuscation"
        confidence = "low"

    strings:
        // OLLVM uses state_var = state_var * A + B pattern
        // Common multiplier values seen in OLLVM/Hikari CFF
        // 0x7FFFFFFF (max signed 32-bit) used as modulus
        $mod_max = { ff ff ff 7f }

    condition:
        $mod_max
}

// ═══════════════════════════════════════════════════════════════════════════
// String encryption constants
// ═══════════════════════════════════════════════════════════════════════════

rule XOR_Key_Repeating
{
    meta:
        description = "Repeating XOR key pattern (4-byte key repeated)"
        category = "obfuscation"
        confidence = "low"

    strings:
        // Detect any 4-byte pattern repeated 4 times consecutively
        // This is a heuristic — common in string decryption routines
        // We look for known common XOR keys used in iOS malware/protection
        $dead = { de ad be ef de ad be ef }
        $cafe = { ca fe ba be ca fe ba be }

    condition:
        any of them
}
