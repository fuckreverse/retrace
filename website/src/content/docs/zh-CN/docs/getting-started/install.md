---
title: 安装 Tenet
sidebar:
  order: 2
---

**目标：** 在 Apple Silicon Mac 上安装 Tenet Tauri 桌面应用。  
**前置条件：** 预览包要求 macOS 14 或更高版本。

## 平台状态

Tenet 后端（CLI、TUI、RPC 和 MCP）已支持 Windows、Linux 和 macOS（x86_64/arm64）。当前网站可下载的桌面安装包仍只有 macOS Apple Silicon 预览版 DMG；Windows、Linux 和 macOS Intel 的独立安装包正在制作中。

## 下载并校验

1. 从[下载页](/zh-CN/download/)获取当前 DMG。
2. 验证 SHA-256：

```bash
shasum -a 256 Tenet-0.1.0-preview.1-arm64.dmg
```

3. 将完整的 64 字符结果与下载页对比。
4. 打开 DMG，将 `Tenet.app` 移入 `/Applications`（“应用程序”）。

## 首次启动与 Gatekeeper

:::caution[使用 ad-hoc 签名的预览版]
当前预览包采用 **ad-hoc 签名**，且**未经 Apple 公证**。该签名可以保护应用包完整性，但不能证明软件来自已登记的 Apple 开发者，因此 Gatekeeper 可能阻止它在其他 Mac 上首次启动。
:::

请先尝试从 Finder 打开 Tenet。如果 macOS 阻止运行，可右键点击 `Tenet.app`、选择“打开”，然后再次确认“打开”。在支持的 macOS 版本中，也可以前往“系统设置 → 隐私与安全性 → 仍要打开”。

如果图形界面选项不可用，请对已经移入 `/Applications` 的应用副本移除下载隔离属性，然后启动：

```bash
xattr -dr com.apple.quarantine /Applications/Tenet.app
open /Applications/Tenet.app
```

`xattr` 命令只会修改这份 Tenet 安装的隔离状态，不会在系统范围内关闭 Gatekeeper。请勿执行 `sudo spctl --master-disable`；没有必要为了运行一个应用而降低所有应用的系统保护。

如果命令提示 `/Applications/Tenet.app` 不存在，请确认已先将应用从 DMG 复制出来。只对 DMG 本身移除隔离属性，不会更新此前已经复制到其他位置的应用。

## 本地验证应用包

首次启动前，可以检查并验证 ad-hoc 签名：

```bash
codesign -dv --verbose=4 /Applications/Tenet.app
codesign --verify --deep --strict --verbose=2 /Applications/Tenet.app
```

使用 ad-hoc 签名且未经公证的预览版，仍可能无法通过 `spctl --assess` 等显式 Gatekeeper 评估；这不等同于应用包完整性校验失败。

当前安装包仅包含 ARM64 二进制文件，只能在 Apple Silicon Mac 上运行。移除隔离属性不能让它在 Intel Mac 或低于最低版本要求的 macOS 上运行。

未来正式版本计划采用 Developer ID 签名并完成 Apple 公证，从而不再需要上述手动首次启动步骤。

捕获端还需要 Python 3.9+、Frida Python 绑定，以及目标设备上版本完全匹配的 Frida 服务。
