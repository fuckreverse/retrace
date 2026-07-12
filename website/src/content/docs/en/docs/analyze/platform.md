---
title: ObjC, syscalls and platform API
sidebar:
  order: 6
---

Platform-specific passes translate low-level events into high-level API semantics. They answer "which system or framework call occurred, with what arguments, and which high-level method triggered it?"

## Objective-C messages

`objc` parses `objc_msgSend`, `objc_msgSendSuper`, `objc_msgSendSuper2` and `objc_msgSend_stret` records, extracting class, selector, arguments and return value. It works only on Darwin targets; Android and Linux traces are skipped automatically.

```bash
./tenet trace.bin --objc --objc-class NSString
```

Filter by class name to focus a search. Use `objc_crypto` to correlate messages with detected crypto operations.

```bash
./tenet trace.bin --objc --pattern --objc-crypto
```

## ObjC × Crypto

`objc_crypto` (Darwin-only) combines pattern hits with ObjC call stacks to show which high-level method triggered each crypto operation.

## System and C API intercepts

`syscall_intercept` captures crypto and system API calls with parameter data. It works across all platforms with automatic API-table selection:

| Platform | Source priority |
|---|---|
| Darwin (iOS) | `REC_CAPICALL` records → `REC_SVC` → `XFER_CALL` heuristic |
| Android | `REC_CAPICALL` → `XFER_CALL` heuristic |
| Linux | `REC_SVC` → `XFER_CALL` heuristic |
| Unknown | Heuristic from module name |

Intercepted APIs include:

- **CommonCrypto:** CCCrypt, CCDigest, CCHmac, CCKeyDerivationPBKDF, CCCryptorCreateWithMode
- **Security.framework:** SecKeyCreateDecrypted, SecKeyGeneratePair, SecAccessControlCreateWithFlags
- **CryptoKit:** CryptoKit AES/ChaChaPoly/GCM/P256/P384 operations
- **BoringSSL / OpenSSL:** EVP_EncryptUpdate, EVP_DigestInit, SSL_write, RSA_sign, etc.
- **JNI:** RegisterNatives, FindClass, CallVoidMethod, GetMethodID, etc.
- **System calls:** mmap, mprotect, write, open, ioctl, etc. (where SVC records exist)

```bash
./tenet trace.bin --syscall-intercept --syscall-intercept-bytes 128
```

`--syscall-intercept-bytes` controls captured bytes per pointer argument (default 64).

## Data source quality

The quality and completeness of platform-API results depend on what QBDITrace was configured to record:

- **REC_CAPICALL** records (from `enable_capi_intercept`) are the most precise and complete.
- **REC_SVC** records provide syscall-level data where available.
- **XFER_CALL** heuristic can identify some calls without dedicated records but may miss or misattribute.
- Traces without any of these records produce no platform-API results.

## Platform limitations

| Platform | ObjC | API intercepts |
|---|---|---|
| iOS / Darwin | Full | CommonCrypto, Security, CryptoKit, BoringSSL |
| Android | Skipped | BoringSSL, JNI |
| Linux | Skipped | OpenSSL, syscalls |
| Unknown | Heuristic | Heuristic from module name |

For `target_os = Unknown`, Tenet attempts heuristic detection based on module names and available record types.
