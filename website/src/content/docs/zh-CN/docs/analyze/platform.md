---
title: ObjC、系统调用与平台 API
sidebar:
  order: 6
---

平台相关 Pass 把底层事件翻译为高层 API 语义。它们回答"发生了什么系统或框架调用、参数是什么、哪个高层方法触发了它"。

## Objective-C 消息

`objc` 解析 `objc_msgSend`、`objc_msgSendSuper`、`objc_msgSendSuper2` 和 `objc_msgSend_stret` 记录，提取类名、selector、参数和返回值。仅 Darwin 目标可用；Android/Linux Trace 自动跳过。

```bash
./tenet trace.bin --objc --objc-class NSString
```

按类名过滤聚焦搜索。配合 `objc_crypto` 将消息与密码学操作关联：

```bash
./tenet trace.bin --objc --pattern --objc-crypto
```

## ObjC × Crypto

`objc_crypto`（仅 Darwin）将模式命中与 ObjC 调用栈组合，展示哪个高层方法触发了每个密码学操作。

## 系统调用与 C API 拦截

`syscall_intercept` 捕获密码学和系统 API 调用及参数数据。它跨平台自动选择 API 表：

| 平台 | 数据源优先级 |
|---|---|
| Darwin (iOS) | `REC_CAPICALL` → `REC_SVC` → `XFER_CALL` 启发式 |
| Android | `REC_CAPICALL` → `XFER_CALL` 启发式 |
| Linux | `REC_SVC` → `XFER_CALL` 启发式 |
| Unknown | 基于模块名的启发式 |

拦截的 API 包括：

- **CommonCrypto：** CCCrypt、CCDigest、CCHmac、CCKeyDerivationPBKDF、CCCryptorCreateWithMode
- **Security.framework：** SecKeyCreateDecrypted、SecKeyGeneratePair、SecAccessControlCreateWithFlags
- **CryptoKit：** CryptoKit AES/ChaChaPoly/GCM/P256/P384 操作
- **BoringSSL / OpenSSL：** EVP_EncryptUpdate、EVP_DigestInit、SSL_write、RSA_sign 等
- **JNI：** RegisterNatives、FindClass、CallVoidMethod、GetMethodID 等
- **系统调用：** mmap、mprotect、write、open、ioctl 等（需有 SVC 记录）

```bash
./tenet trace.bin --syscall-intercept --syscall-intercept-bytes 128
```

`--syscall-intercept-bytes` 控制每个指针参数捕获字节数（默认 64）。

## 数据源质量

平台 API 结果的质量和完整性取决于 QBDITrace 录制配置：

- **REC_CAPICALL** 记录（`enable_capi_intercept` 开启）最精确完整。
- **REC_SVC** 记录提供系统调用级数据。
- **XFER_CALL** 启发式可在无专用记录时识别部分调用，但可能遗漏或误归。
- 缺少以上所有记录的 Trace 不产生平台 API 结果。

## 平台限制

| 平台 | ObjC | API 拦截 |
|---|---|---|
| iOS / Darwin | 完整 | CommonCrypto、Security、CryptoKit、BoringSSL |
| Android | 跳过 | BoringSSL、JNI |
| Linux | 跳过 | OpenSSL、系统调用 |
| Unknown | 启发式 | 基于模块名的启发式 |

`target_os = Unknown` 时，Tenet 根据模块名和可用记录类型尝试启发式检测。
