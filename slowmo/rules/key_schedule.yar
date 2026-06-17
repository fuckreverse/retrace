/*
 * Tenet YARA rules — Key schedule and key expansion patterns
 *
 * Detects constants associated with key derivation functions (KDF),
 * key expansion algorithms, and password hashing.
 * Scans reg_value and code buffers.
 */

// ═══════════════════════════════════════════════════════════════════════════
// PBKDF2 / HKDF indicators
// ═══════════════════════════════════════════════════════════════════════════

rule HKDF_Ipad_Opad_Block
{
    meta:
        description = "HMAC-based key derivation: ipad/opad blocks in key expansion"
        category = "key_schedule"
        confidence = "medium"

    strings:
        // HMAC ipad block (16 consecutive 0x36 bytes)
        $ipad_block = { 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 }
        // HMAC opad block (16 consecutive 0x5c bytes)
        $opad_block = { 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c }

    condition:
        all of them
}

// ═══════════════════════════════════════════════════════════════════════════
// Blowfish
// ═══════════════════════════════════════════════════════════════════════════

rule Blowfish_Pbox
{
    meta:
        description = "Blowfish P-array initial values (P1-P3, LE)"
        category = "key_schedule"
        confidence = "high"

    strings:
        // P1 = 0x243F6A88 (digits of pi, LE)
        $p1 = { 88 6a 3f 24 }
        // P2 = 0x85A308D3 (LE)
        $p2 = { d3 08 a3 85 }
        // P3 = 0x13198A2E (LE)
        $p3 = { 2e 8a 19 13 }

    condition:
        2 of them
}

// ═══════════════════════════════════════════════════════════════════════════
// Twofish
// ═══════════════════════════════════════════════════════════════════════════

rule Twofish_MDS_Matrix
{
    meta:
        description = "Twofish MDS matrix constants (first row polynomial evaluation)"
        category = "key_schedule"
        confidence = "medium"

    strings:
        // MDS[0] row entries: 0x01, 0xEF, 0x5B, 0x5B
        $mds_row0 = { 01 ef 5b 5b }

    condition:
        $mds_row0
}

// ═══════════════════════════════════════════════════════════════════════════
// Camellia
// ═══════════════════════════════════════════════════════════════════════════

rule Camellia_Sigma
{
    meta:
        description = "Camellia cipher sigma constants (first two, LE)"
        category = "key_schedule"
        confidence = "high"

    strings:
        // Sigma1 = 0xA09E667F3BCC908B (LE)
        $sigma1 = { 8b 90 cc 3b 7f 66 9e a0 }
        // Sigma2 = 0xB67AE8584CAA73B2 (LE)
        $sigma2 = { b2 73 aa 4c 58 e8 7a b6 }

    condition:
        any of them
}

// ═══════════════════════════════════════════════════════════════════════════
// Whirlpool
// ═══════════════════════════════════════════════════════════════════════════

rule Whirlpool_SBox
{
    meta:
        description = "Whirlpool S-Box (first 8 bytes)"
        category = "key_schedule"
        confidence = "medium"

    strings:
        $sbox = { 18 23 c6 e8 87 b8 01 4f }

    condition:
        $sbox
}

// ═══════════════════════════════════════════════════════════════════════════
// SEED (Korean standard cipher)
// ═══════════════════════════════════════════════════════════════════════════

rule SEED_KC
{
    meta:
        description = "SEED key schedule constants KC[0] and KC[1]"
        category = "key_schedule"
        confidence = "high"

    strings:
        // KC[0] = 0x9E3779B9 (LE, same as TEA delta)
        $kc0 = { b9 79 37 9e }
        // KC[1] = 0x3C6EF372 (LE, 2*KC[0] mod 2^32)
        $kc1 = { 72 f3 6e 3c }

    condition:
        all of them
}
