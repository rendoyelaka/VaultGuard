/*
 * np_loader.c — DEX decrypt JNI engine
 *
 * Class name and method name are injected at build time by build_module.py
 * via np_loader_class.h — this avoids the hardcoded Java_pkg_class_method
 * that would break when package name changes per build.
 *
 * RegisterNatives in JNI_OnLoad resolves the correct class regardless of
 * per-build package name.
 *
 * Security hardening applied:
 *   Fix 1 — NP_CLASS stored as 4 XOR-encoded split chunks (np_loader_class.h).
 *            Decoded at runtime into a stack buffer. No signable class string
 *            in .rodata or .data sections.
 *   Fix 3 — __android_log_print entirely removed in release builds.
 *            LOG() macro expands to nothing when NDEBUG is defined (release).
 *            liblog is NOT linked in release — import table stays clean.
 */

#include <jni.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Build-time generated header — written by build_module.py before CMake runs.
   Defines NP_C0..NP_C3, NP_DECODE_CLASS(), NP_XOR_KEY, NP_METHOD.
*/
#include "np_loader_class.h"

/*
 * Fix 3 — Logging macro.
 *
 * Release builds: NDEBUG is set by the Android Gradle plugin for assembleRelease.
 * LOG() expands to nothing → no __android_log_print call, no liblog import.
 *
 * Debug builds: include <android/log.h> and emit real logcat output.
 * CMakeLists.txt links liblog only when NOT CMAKE_BUILD_TYPE=Release.
 */
#ifndef NDEBUG
#  include <android/log.h>
#  define NP_TAG "np"
#  define LOG(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, NP_TAG, fmt, ##__VA_ARGS__)
#else
#  define LOG(fmt, ...) ((void)0)
#endif

/* Derive 16-byte XOR key from ANDROID_ID using simple hash stretch.
   No OpenSSL dependency — pure stdlib. */
static void derive_key(JNIEnv *env, jobject ctx, uint8_t key[16]) {
    jclass cls = (*env)->GetObjectClass(env, ctx);
    jmethodID cr = (*env)->GetMethodID(env, cls, "getContentResolver",
                                        "()Landroid/content/ContentResolver;");
    if (!cr) { memset(key, 0x5A, 16); return; }
    jobject resolver = (*env)->CallObjectMethod(env, ctx, cr);
    jclass settings = (*env)->FindClass(env, "android/provider/Settings$Secure");
    if (!settings) { memset(key, 0x5A, 16); return; }
    jmethodID gs = (*env)->GetStaticMethodID(env, settings, "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    if (!gs) { memset(key, 0x5A, 16); return; }
    jstring key_name = (*env)->NewStringUTF(env, "android_id");
    jstring aid = (jstring)(*env)->CallStaticObjectMethod(env, settings, gs,
                                                           resolver, key_name);
    (*env)->DeleteLocalRef(env, key_name);
    if (!aid) { memset(key, 0x5A, 16); return; }
    const char *aid_c = (*env)->GetStringUTFChars(env, aid, 0);
    if (!aid_c) { memset(key, 0x5A, 16); return; }

    /* djb2-style stretch into 4 uint32 slots */
    uint32_t h[4] = {0x12345678u, 0x9abcdef0u, 0xfedcba98u, 0x87654321u};
    for (int i = 0; aid_c[i]; i++) {
        h[i % 4] = h[i % 4] * 31u + (uint8_t)aid_c[i];
    }
    memcpy(key, h, 16);
    (*env)->ReleaseStringUTFChars(env, aid, aid_c);
    (*env)->DeleteLocalRef(env, aid);
}

/*
 * Native implementation of xd(Context ctx, String assetName) -> byte[]
 *
 * Reads encrypted blob from res/raw/img_XXXX.png asset:
 *   [16 bytes fake PNG header] [encrypted DEX]
 *
 * Decryption: rotating XOR — key[i%16] XOR ((i>>8)&0xFF)
 * where key is derived from ANDROID_ID (same as build-time encrypt in build_module.py).
 *
 * Returns decrypted DEX bytes as jbyteArray.
 * Caller passes result directly to InMemoryDexClassLoader via JNI — never touches Java.
 */
static jbyteArray np_xd(JNIEnv *env, jobject thiz,
                         jobject ctx, jstring j_asset_name) {
    (void)thiz;

    /* Get AssetManager from Context */
    jclass actx_cls = (*env)->GetObjectClass(env, ctx);
    jmethodID gam = (*env)->GetMethodID(env, actx_cls, "getAssets",
                                         "()Landroid/content/res/AssetManager;");
    if (!gam) return NULL;
    jobject jam = (*env)->CallObjectMethod(env, ctx, gam);
    if (!jam) return NULL;
    AAssetManager *am = AAssetManager_fromJava(env, jam);
    if (!am) return NULL;

    /* Open asset by name passed from smali (XOR-decoded at smali level) */
    const char *asset_name = (*env)->GetStringUTFChars(env, j_asset_name, 0);
    if (!asset_name) return NULL;
    AAsset *asset = AAssetManager_open(am, asset_name, AASSET_MODE_BUFFER);
    (*env)->ReleaseStringUTFChars(env, j_asset_name, asset_name);
    if (!asset) return NULL;

    off_t size = AAsset_getLength(asset);
    if (size < 16 + 8) { AAsset_close(asset); return NULL; }

    uint8_t *buf = (uint8_t *)malloc((size_t)size);
    if (!buf) { AAsset_close(asset); return NULL; }
    AAsset_read(asset, buf, (size_t)size);
    AAsset_close(asset);

    /* Strip 16-byte fake PNG header */
    uint8_t *dex     = buf + 16;
    off_t    dex_len = size - 16;

    /* Derive key from ANDROID_ID */
    uint8_t key[16];
    derive_key(env, ctx, key);

    /* Decrypt: rotating XOR — same algorithm as Python build-time encrypt */
    for (off_t i = 0; i < dex_len; i++) {
        dex[i] ^= key[i % 16] ^ (uint8_t)(i >> 8);
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)dex_len);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)dex_len, (jbyte *)dex);
    }

    /* Wipe sensitive data before free */
    memset(key, 0, 16);
    memset(buf, 0, (size_t)size);
    free(buf);
    return result;
}

/*
 * JNI_OnLoad — register native methods via RegisterNatives.
 *
 * Fix 1: NP_CLASS is decoded at runtime from XOR-encoded split chunks.
 *        Stack buffer np_class_buf never persists beyond this function.
 *        No class path string in .rodata.
 *
 * Signature: (Landroid/content/Context;Ljava/lang/String;)[B
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    /* Fix 1: decode class path from XOR chunks into stack buffer at runtime */
    char np_class_buf[NP_CLASS_LEN];
    NP_DECODE_CLASS(np_class_buf);

    jclass cls = (*env)->FindClass(env, np_class_buf);

    /* Wipe stack buffer immediately after FindClass — minimize exposure window */
    memset(np_class_buf, 0, NP_CLASS_LEN);

    if (!cls) {
        /* Fix 3: LOG() is a no-op in release builds — no __android_log_print call */
        LOG("FindClass failed");
        return JNI_ERR;
    }

    static const JNINativeMethod methods[] = {
        {
            NP_METHOD,
            "(Landroid/content/Context;Ljava/lang/String;)[B",
            (void *)np_xd
        }
    };

    if ((*env)->RegisterNatives(env, cls, methods, 1) != JNI_OK) {
        LOG("RegisterNatives failed");
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
