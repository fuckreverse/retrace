/*
 * demo_jni.c — JNI native library for the hellotrace test APK.
 *
 * Exports:
 *   Java_com_example_hellotrace_MainActivity_nativeWork — JNI bridge; calls
 *       demo_jni_entry with the Java int seed.
 *   demo_jni_entry(uint64_t seed) — the function qbditrace traces
 *       (--entry demo_jni_entry). Deliberately exercises, inside the
 *       instrumented range:
 *         1. JavaVM InvokeInterface vtable call (GetEnv, index 3)
 *         2. JNIEnv JNINativeInterface vtable call (GetVersion, slot 4)
 *            → both match the agent-registered JNI vtable CAPI table
 *         3. stack array fill/sum (mem W/R records)
 *         4. inline svc getpid (x8=172, svc #0)
 */
#include <jni.h>
#include <stdint.h>

static JavaVM *g_vm = NULL;

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    return JNI_VERSION_1_6;
}

__attribute__((visibility("default")))
__attribute__((noinline))
uint64_t demo_jni_entry(uint64_t seed) {
    uint64_t acc = seed;

    /* 1. vm->GetEnv — JNIInvokeInterface vtable index 6
     *    (reserved0..2, DestroyJavaVM[3], AttachCurrentThread[4],
     *     DetachCurrentThread[5], GetEnv[6], AttachCurrentThreadAsDaemon[7]).
     *     NB: index 3 is DestroyJavaVM — calling it deadlocks the main thread
     *     (it waits for all attached threads to exit). */
    JNIEnv *env = NULL;
    if (g_vm) {
        void **invokeVt = *(void ***)g_vm;
        jint (*getEnv)(JavaVM *, void **, jint) =
            (jint (*)(JavaVM *, void **, jint))invokeVt[6];
        if (getEnv && getEnv(g_vm, (void **)&env, JNI_VERSION_1_6) == 0 && env) {
            /* 2. env->GetVersion — JNINativeInterface vtable slot 4
             *    (JNI_GetVersion, the first non-reserved slot). */
            void **envVt = *(void ***)env;
            jint (*getVersion)(JNIEnv *) = (jint (*)(JNIEnv *))envVt[4];
            if (getVersion) acc ^= ((uint64_t)(uint32_t)getVersion(env)) << 8;
        }
    }

    /* 3. memory write + read (stack array) */
    uint64_t buf[8];
    for (int i = 0; i < 8; i++) buf[i] = seed + (uint64_t)i;
    uint64_t s = 0;
    for (int i = 0; i < 8; i++) s += buf[i];

    /* 4. inline svc getpid (Linux aarch64: x8=172, svc #0) */
    register uint64_t x8 __asm__("x8") = 172;
    register uint64_t x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "cc", "memory");

    return acc ^ s ^ (x0 << 4);
}

JNIEXPORT jlong JNICALL
Java_com_example_hellotrace_MainActivity_nativeWork(JNIEnv *env, jobject thiz,
                                                    jint seed) {
    (void)env;
    (void)thiz;
    return (jlong)demo_jni_entry((uint64_t)seed);
}
