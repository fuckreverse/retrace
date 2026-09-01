#!/bin/bash
# build_apk.sh — 构建 hellotrace 测试 APK (无 gradle, 纯 SDK 工具链)
# 产物: $HERE/out/hellotrace.apk + $HERE/out/libdemo_jni.so
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
mkdir -p "$HERE/out"
SDK=/tmp/android-sdk-cmdline
BT=$SDK/build-tools/34.0.0
PLATFORM=$SDK/platforms/android-33/android.jar
NDK=/opt/homebrew/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK
CC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang

[[ -f "$PLATFORM" ]] || { echo "ERROR: android.jar missing at $PLATFORM"; exit 1; }

# ── 1. javac ──────────────────────────────────────────────────────────────
cd "$HERE"
rm -rf obj && mkdir -p obj
# MainActivity.java is flat in this directory; javac derives the package dir
# structure in obj/ from its `package` declaration.
javac -source 8 -target 8 -bootclasspath "$PLATFORM" -d obj \
    MainActivity.java 2>&1 | grep -v "^警告\|^warning" || true
[[ -f obj/com/example/hellotrace/MainActivity.class ]] || { echo "javac failed"; exit 1; }

# ── 2. d8 → classes.dex ───────────────────────────────────────────────────
"$BT/d8" --release --lib "$PLATFORM" --output "$HERE" \
    $(find obj -name '*.class') 2>/dev/null
[[ -f "$HERE/classes.dex" ]] || { echo "d8 failed"; exit 1; }

# ── 3. native libdemo_jni.so ──────────────────────────────────────────────
$CC -std=c11 -O2 -shared -fPIC -nostdlib++ \
    demo_jni.c -o $HERE/out/libdemo_jni.so \
    -llog
echo "libdemo_jni.so symbols:"
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-nm -D \
    $HERE/out/libdemo_jni.so | grep -E "demo_jni_entry|Java_|JNI_OnLoad"

# ── 4. aapt2 link (manifest-only apk) ────────────────────────────────────
cat > AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.hellotrace">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="28"/>
    <application android:label="HelloTrace">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
EOF
"$BT/aapt2" link -I "$PLATFORM" --manifest AndroidManifest.xml \
    -o "$HERE/hellotrace-unsigned.apk"

# ── 5. 注入 classes.dex + native lib ─────────────────────────────────────
# .so 必须打进 APK (lib/arm64-v8a/): untrusted_app 域不能 dlopen
# /data/local/tmp (shell_data_file) — SELinux 拒绝.
cd "$HERE" && zip -q -j hellotrace-unsigned.apk classes.dex
mkdir -p lib/arm64-v8a
cp $HERE/out/libdemo_jni.so lib/arm64-v8a/
zip -q hellotrace-unsigned.apk lib/arm64-v8a/libdemo_jni.so

# ── 6. 签名 (debug key) ───────────────────────────────────────────────────
KS=$HERE/out/debug.keystore
[[ -f "$KS" ]] || keytool -genkeypair -keystore "$KS" -storepass android \
    -keypass android -alias androiddebugkey -dname "CN=Android Debug,O=Android,C=US" \
    -keyalg RSA -keysize 2048 -validity 10000 2>/dev/null
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android \
    --out "$HERE/hellotrace.apk" "$HERE/hellotrace-unsigned.apk"
"$BT/apksigner" verify "$HERE/hellotrace.apk" && echo "APK verified OK"

echo "==> $HERE/hellotrace.apk"
