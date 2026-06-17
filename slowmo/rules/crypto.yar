/*
 * Tenet YARA rules — Cryptographic pattern detection
 * Scans over register-value / code / syscall buffers for crypto constants.
 *
 * Buffer layouts (set by PatternPass):
 *   reg_value: concatenated 8-byte LE register diff values
 *   code:      raw 4-byte opcode words (LE) from code table
 *   syscall:   16-byte entries [inst_id(8) | syscall_no(2) | pad(6)]
 */

// ═══════════════════════════════════════════════════════════════════════════
// SHA family
// ═══════════════════════════════════════════════════════════════════════════

rule SHA256_Constants
{
    meta:
        description = "SHA-256 initial hash values (H0-H3)"
        category = "crypto"
        confidence = "high"

    strings:
        $h0 = { 67 e6 09 6a }
        $h1 = { 85 ae 67 bb }
        $h2 = { 72 f3 6e 3c }
        $h3 = { 3a f5 4f a5 }

    condition:
        2 of them
}

rule SHA256_Round_Constants
{
    meta:
        description = "SHA-256 round constants K[0..3] (first four)"
        category = "crypto"
        confidence = "high"

    strings:
        // K[0]=0x428a2f98, K[1]=0x71374491, K[2]=0xb5c0fbcf, K[3]=0xe9b5dba5 (LE)
        $k0 = { 98 2f 8a 42 }
        $k1 = { 91 44 37 71 }
        $k2 = { cf fb c0 b5 }
        $k3 = { a5 db b5 e9 }

    condition:
        3 of them
}

rule SHA1_Constants
{
    meta:
        description = "SHA-1 initial hash values H0-H4"
        category = "crypto"
        confidence = "high"

    strings:
        // H0=0x67452301, H1=0xEFCDAB89, H2=0x98BADCFE, H3=0x10325476, H4=0xC3D2E1F0 (LE)
        $h0 = { 01 23 45 67 }
        $h1 = { 89 ab cd ef }
        $h2 = { fe dc ba 98 }
        $h3 = { 76 54 32 10 }
        $h4 = { f0 e1 d2 c3 }

    condition:
        3 of them
}

rule SHA512_Constants
{
    meta:
        description = "SHA-512 initial hash values (first two, 64-bit)"
        category = "crypto"
        confidence = "high"

    strings:
        // H0=0x6a09e667f3bcc908 (LE bytes)
        $h0 = { 08 c9 bc f3 67 e6 09 6a }
        // H1=0xbb67ae8584caa73b
        $h1 = { 3b a7 ca 84 85 ae 67 bb }

    condition:
        all of them
}

// ═══════════════════════════════════════════════════════════════════════════
// MD family
// ═══════════════════════════════════════════════════════════════════════════

rule MD5_Constants
{
    meta:
        description = "MD5 initialization constants"
        category = "crypto"
        confidence = "high"

    strings:
        $a = { 78 a4 6a d7 }
        $b = { 56 b7 c7 e8 }
        $c = { db 70 20 24 }

    condition:
        2 of them
}

// ═══════════════════════════════════════════════════════════════════════════
// AES
// ═══════════════════════════════════════════════════════════════════════════

rule AES_SBox_Table
{
    meta:
        description = "AES S-Box lookup table (first 16 bytes)"
        category = "crypto"
        confidence = "high"

    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }

    condition:
        $sbox
}

rule AES_Inv_SBox_Table
{
    meta:
        description = "AES inverse S-Box lookup table (first 16 bytes)"
        category = "crypto"
        confidence = "high"

    strings:
        $inv_sbox = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }

    condition:
        $inv_sbox
}

rule AES_Rcon
{
    meta:
        description = "AES key expansion round constants (Rcon 1-10)"
        category = "crypto"
        confidence = "high"

    strings:
        // Rcon[1..10] = 0x01,02,04,08,10,20,40,80,1b,36
        $rcon = { 01 02 04 08 10 20 40 80 1b 36 }

    condition:
        $rcon
}

// ═══════════════════════════════════════════════════════════════════════════
// SM3 / SM4 (Chinese national standards — very common in mobile RE)
// ═══════════════════════════════════════════════════════════════════════════

rule SM3_IV
{
    meta:
        description = "SM3 hash initial values (IV[0..3] LE)"
        category = "crypto"
        confidence = "high"

    strings:
        // IV: 7380166f 4914b2b9 172442d7 da8a0600 (each as 4-byte LE)
        $iv0 = { 6f 16 80 73 }
        $iv1 = { b9 b2 14 49 }
        $iv2 = { d7 42 24 17 }
        $iv3 = { 00 06 8a da }

    condition:
        3 of them
}

rule SM3_IV_Remaining
{
    meta:
        description = "SM3 hash initial values (IV[4..7] LE)"
        category = "crypto"
        confidence = "high"

    strings:
        // IV: a96f30bc 163138aa e38dee4d b0fb0e4e (each as 4-byte LE)
        $iv4 = { bc 30 6f a9 }
        $iv5 = { aa 38 31 16 }
        $iv6 = { 4d ee 8d e3 }
        $iv7 = { 4e 0e fb b0 }

    condition:
        3 of them
}

rule SM4_FK
{
    meta:
        description = "SM4 system parameter FK[0..3]"
        category = "crypto"
        confidence = "high"

    strings:
        // FK = a3b1bac6, 56aa3350, 677d9197, b27022dc (LE)
        $fk0 = { c6 ba b1 a3 }
        $fk1 = { 50 33 aa 56 }
        $fk2 = { 97 91 7d 67 }
        $fk3 = { dc 22 70 b2 }

    condition:
        3 of them
}

rule SM4_SBox
{
    meta:
        description = "SM4 S-Box (first 16 bytes)"
        category = "crypto"
        confidence = "high"

    strings:
        $sbox = { d6 90 e9 fe cc e1 3d b7 16 b6 14 c2 28 fb 2c 05 }

    condition:
        $sbox
}

rule SM4_CK
{
    meta:
        description = "SM4 constant key CK[0..3]"
        category = "crypto"
        confidence = "medium"

    strings:
        // CK[0]=0x00070e15, CK[1]=0x1c232a31, CK[2]=0x383f464d, CK[3]=0x545b6269 (LE)
        $ck0 = { 15 0e 07 00 }
        $ck1 = { 31 2a 23 1c }
        $ck2 = { 4d 46 3f 38 }
        $ck3 = { 69 62 5b 54 }

    condition:
        3 of them
}

// ═══════════════════════════════════════════════════════════════════════════
// ChaCha20 / Salsa20
// ═══════════════════════════════════════════════════════════════════════════

rule ChaCha20_Sigma
{
    meta:
        description = "ChaCha20 sigma constants ('expand 32-byte k')"
        category = "crypto"
        confidence = "high"

    strings:
        $sigma0 = { 65 78 70 61 }
        $sigma1 = { 6e 64 20 33 }
        $sigma2 = { 32 2d 62 79 }
        $sigma3 = { 74 65 20 6b }

    condition:
        3 of them
}

rule Salsa20_Tau
{
    meta:
        description = "Salsa20 tau constants ('expand 16-byte k')"
        category = "crypto"
        confidence = "high"

    strings:
        $tau0 = { 65 78 70 61 }
        $tau1 = { 6e 64 20 31 }
        $tau2 = { 36 2d 62 79 }
        $tau3 = { 74 65 20 6b }

    condition:
        all of them
}

// ═══════════════════════════════════════════════════════════════════════════
// RC4
// ═══════════════════════════════════════════════════════════════════════════

rule RC4_SBox_Init
{
    meta:
        description = "RC4 key schedule S-box initialization (0x00-0x1f)"
        category = "crypto"
        confidence = "medium"

    strings:
        $init = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f }

    condition:
        $init
}

// ═══════════════════════════════════════════════════════════════════════════
// HMAC
// ═══════════════════════════════════════════════════════════════════════════

rule HMAC_Ipad_Opad
{
    meta:
        description = "HMAC ipad/opad XOR masks (0x36/0x5c repeated)"
        category = "crypto"
        confidence = "medium"

    strings:
        // ipad: 8 consecutive 0x36 bytes
        $ipad = { 36 36 36 36 36 36 36 36 }
        // opad: 8 consecutive 0x5c bytes
        $opad = { 5c 5c 5c 5c 5c 5c 5c 5c }

    condition:
        all of them
}

// ═══════════════════════════════════════════════════════════════════════════
// Poly1305 / BLAKE2
// ═══════════════════════════════════════════════════════════════════════════

rule BLAKE2b_IV
{
    meta:
        description = "BLAKE2b initialization vector (first two 64-bit words LE)"
        category = "crypto"
        confidence = "high"

    strings:
        // IV[0] = 0x6a09e667f3bcc908 (same as SHA-512 H0, but context matters)
        $iv0 = { 08 c9 bc f3 67 e6 09 6a }
        // IV[1] = 0xbb67ae8584caa73b
        $iv1 = { 3b a7 ca 84 85 ae 67 bb }
        // IV[2] = 0x3c6ef372fe94f82b
        $iv2 = { 2b f8 94 fe 72 f3 6e 3c }
        // IV[3] = 0xa54ff53a5f1d36f1
        $iv3 = { f1 36 1d 5f 3a f5 4f a5 }

    condition:
        3 of them
}

rule BLAKE2s_IV
{
    meta:
        description = "BLAKE2s initialization vector (first four 32-bit words LE)"
        category = "crypto"
        confidence = "high"

    strings:
        // Same as SHA-256 H values but in a BLAKE2s context
        $iv0 = { 67 e6 09 6a }
        $iv1 = { 85 ae 67 bb }
        $iv2 = { 72 f3 6e 3c }
        $iv3 = { 3a f5 4f a5 }
        $iv4 = { 51 0e 52 7f }
        $iv5 = { 9b 05 68 8c }

    condition:
        4 of them
}

// ═══════════════════════════════════════════════════════════════════════════
// DES / 3DES
// ═══════════════════════════════════════════════════════════════════════════

rule DES_Initial_Permutation
{
    meta:
        description = "DES initial permutation table (first 16 values)"
        category = "crypto"
        confidence = "medium"

    strings:
        // IP: 58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4
        $ip = { 3a 32 2a 22 1a 12 0a 02 3c 34 2c 24 1c 14 0c 04 }

    condition:
        $ip
}

// ═══════════════════════════════════════════════════════════════════════════
// Elliptic Curve constants
// ═══════════════════════════════════════════════════════════════════════════

rule Curve25519_Constant
{
    meta:
        description = "Curve25519 constant 121665 = 0x1DB41 (LE 64-bit)"
        category = "crypto"
        confidence = "medium"

    strings:
        $c = { 41 db 01 00 00 00 00 00 }

    condition:
        $c
}

rule P256_Prime
{
    meta:
        description = "NIST P-256 prime modulus p (last 8 bytes LE)"
        category = "crypto"
        confidence = "medium"

    strings:
        // p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        // last 8 bytes LE: FF FF FF FF FF FF FF FF
        // more distinctive: first 8 bytes LE of p
        $p_start = { ff ff ff ff 00 00 00 00 }
        $p_mid   = { 01 00 00 00 ff ff ff ff }

    condition:
        all of them
}

// ═══════════════════════════════════════════════════════════════════════════
// CRC32
// ═══════════════════════════════════════════════════════════════════════════

rule CRC32_Polynomial
{
    meta:
        description = "CRC32 standard polynomial 0xEDB88320 (LE)"
        category = "crypto"
        confidence = "medium"

    strings:
        $poly = { 20 83 b8 ed }

    condition:
        $poly
}

rule CRC32_Table_Head
{
    meta:
        description = "CRC32 lookup table entries T[1] and T[2]"
        category = "crypto"
        confidence = "high"

    strings:
        // T[1] = 0x77073096 (LE), T[2] = 0xEE0E612C (LE)
        $t1 = { 96 30 07 77 }
        $t2 = { 2c 61 0e ee }

    condition:
        all of them
}

// ═══════════════════════════════════════════════════════════════════════════
// TEA / XTEA / XXTEA
// ═══════════════════════════════════════════════════════════════════════════

rule TEA_Delta
{
    meta:
        description = "TEA/XTEA delta constant 0x9E3779B9 (golden ratio)"
        category = "crypto"
        confidence = "medium"

    strings:
        $delta_le = { b9 79 37 9e }

    condition:
        $delta_le
}
