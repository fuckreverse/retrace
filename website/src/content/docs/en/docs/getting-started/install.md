---
title: Install Tenet
sidebar:
  order: 2
---

**Goal:** install the Tenet Tauri desktop application on an Apple Silicon Mac.  
**Prerequisite:** macOS 14 or newer for the preview package.

## Platform status

The Tenet backend (CLI, TUI, RPC, and MCP) supports Windows, Linux, and macOS (x86_64/arm64). The only desktop package currently available from this website is the macOS Apple Silicon preview DMG; standalone packages for Windows, Linux, and macOS Intel are in progress.

## Download and verify

1. Download the current DMG from the [download page](/en/download/).
2. Verify its SHA-256 value:

```bash
shasum -a 256 Tenet-0.1.0-preview.1-arm64.dmg
```

3. Compare the complete 64-character value with the download page.
4. Open the DMG and move `Tenet.app` into `/Applications`.

## First launch and Gatekeeper

:::caution[Ad-hoc signed preview]
The current preview package has an **ad-hoc signature** and is **not notarized by Apple**. The signature protects bundle integrity but does not identify a registered Apple developer. Gatekeeper may therefore block the first launch on another Mac.
:::

Try opening Tenet from Finder first. If macOS blocks it, you can right-click `Tenet.app`, choose **Open**, and confirm **Open** again. On supported macOS versions, you may also use **System Settings → Privacy & Security → Open Anyway**.

If the graphical options are unavailable, remove the download quarantine attribute from the copy already placed in `/Applications`, then launch it:

```bash
xattr -dr com.apple.quarantine /Applications/Tenet.app
open /Applications/Tenet.app
```

The `xattr` command changes only the quarantine state of this Tenet installation. It does not disable Gatekeeper system-wide. Do not run `sudo spctl --master-disable`; weakening protection for every application is unnecessary.

If the command reports that `/Applications/Tenet.app` does not exist, confirm that you copied the app out of the DMG before running it. Removing quarantine from the DMG itself does not update an app that was already copied elsewhere.

## Verify the bundle locally

You can inspect and verify the ad-hoc signature before launching:

```bash
codesign -dv --verbose=4 /Applications/Tenet.app
codesign --verify --deep --strict --verbose=2 /Applications/Tenet.app
```

An ad-hoc, non-notarized preview may still be rejected by an explicit Gatekeeper assessment such as `spctl --assess`; that does not mean its bundle integrity check failed.

The current package contains ARM64 binaries and runs on Apple Silicon Macs. Removing quarantine cannot make it run on an Intel Mac or on a macOS release older than the stated minimum.

Future production releases are intended to use Developer ID signing and Apple notarization so this manual first-launch step is no longer required.

For capture you also need Python 3.9 or newer, Frida Python bindings, and a matching Frida service on the target device.
