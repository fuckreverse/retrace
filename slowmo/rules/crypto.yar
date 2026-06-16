/*
 * Tenet YARA rules — Cryptographic pattern detection
 * Scans over memory/code buffers for crypto constants and instruction patterns.
 */

rule SHA256_Constants
{
    meta:
        description = "SHA-256 initial hash values"
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

rule ChaCha20_Sigma
{
    meta:
        description = "ChaCha20 sigma constants (expand 32-byte k)"
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
