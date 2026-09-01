package com.example.hellotrace;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    static {
        // Native lib is bundled in the APK (lib/arm64-v8a/): the
        // untrusted_app SELinux domain cannot dlopen /data/local/tmp.
        System.loadLibrary("demo_jni");
    }

    public static native long nativeWork(int seed);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        long r = nativeWork(0x1234);
        Log.i("hellotrace", "nativeWork -> 0x" + Long.toHexString(r));
        // The agent installs the Java hook asynchronously after spawn-resume;
        // tick once per second so at least one call lands after the hook.
        for (int i = 0; i < 60; i++) {
            try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
            r = nativeWork(0x1234 + i);
            Log.i("hellotrace", "tick " + i + " -> 0x" + Long.toHexString(r));
        }
    }
}
