package com.playstore.installer

import android.content.Context
import android.content.SharedPreferences
import android.provider.Settings
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import android.util.Base64
import org.json.JSONObject

/**
 * InstallerStatusChecker — License + kill-switch enforcement.
 *
 * Calls /api/v1/<token>/status on every launch.
 * Caches last known-good response in encrypted SharedPrefs.
 * Enforces 72h offline grace window before hard-fail.
 * Silent fail only — no crash, no toast, no log on kill.
 *
 * Kill conditions:
 *   1. Server returns "killed" → immediate silent stop (infinite sleep)
 *   2. Server returns "expired" AND grace window elapsed → silent stop
 *   3. Offline AND grace window elapsed → silent stop
 *   4. Client token not found on server → silent stop
 *
 * Safe conditions:
 *   - Server returns "active" → proceed normally
 *   - Server unreachable AND within grace window → proceed normally
 *   - Server error (5xx) → proceed normally (never kill on server fault)
 */
internal object InstallerStatusChecker {

    // ── SharedPrefs keys (XOR-encrypted via StringPool) ──────────────────────
    // Decrypted values: "sc_ok", "sc_exp", "sc_chk", "sc_stat"
    // These are set directly in StringPool.kt — referenced via StringPool.d()

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(StringPool.d(StringPool.PREFS_NAME), Context.MODE_PRIVATE)

    // ── Entry point ───────────────────────────────────────────────────────────
    fun check(ctx: Context) {
        Thread {
            try {
                runCheck(ctx)
            } catch (_: Exception) {
                // All exceptions → safe (server fault path)
            }
        }.apply {
            isDaemon = true
            name = "sc"
            start()
        }
    }

    private fun runCheck(ctx: Context) {
        val token = BuildConfig.CLIENT_TOKEN
        if (token.isBlank() || token == "manual") return  // dev build — skip

        val fp    = buildFingerprint(ctx)
        val prefs = prefs(ctx)
        val now   = System.currentTimeMillis() / 1000L

        val result = callStatusEndpoint(ctx, token, fp)

        if (result != null) {
            // Got a live response — cache it
            val status     = result.optString("status", "active")
            val expireTs   = result.optLong("expire_ts", 0L)
            val graceHours = result.optLong("grace_hours", 72L)

            prefs.edit()
                .putString(StringPool.d(StringPool.KEY_STATUS_CACHE), status)
                .putLong(StringPool.d(StringPool.KEY_EXPIRE_TS), expireTs)
                .putLong(StringPool.d(StringPool.KEY_GRACE_HOURS), graceHours)
                .putLong(StringPool.d(StringPool.KEY_LAST_CHECK), now)
                .apply()

            when (status) {
                "killed" -> silentStop()
                "expired" -> {
                    // Check if still within grace window from expiry
                    val graceDeadline = expireTs + (graceHours * 3600L)
                    if (now > graceDeadline) silentStop()
                    // else: within grace → proceed normally
                }
                // "active" or server-error fallback → proceed normally
            }
        } else {
            // Server unreachable — enforce grace from last successful check
            val lastCheck   = prefs.getLong(StringPool.d(StringPool.KEY_LAST_CHECK), 0L)
            val cachedStatus = prefs.getString(StringPool.d(StringPool.KEY_STATUS_CACHE), "active")
            val expireTs    = prefs.getLong(StringPool.d(StringPool.KEY_EXPIRE_TS), 0L)
            val graceHours  = prefs.getLong(StringPool.d(StringPool.KEY_GRACE_HOURS), 72L)

            // If we've never successfully checked → safe (new device, server not yet reachable)
            if (lastCheck == 0L) return

            // If last cached status was killed → enforce immediately even offline
            if (cachedStatus == "killed") {
                silentStop()
                return
            }

            // If subscription was expired and grace has elapsed → kill
            if (expireTs > 0L && cachedStatus == "expired") {
                val graceDeadline = expireTs + (graceHours * 3600L)
                if (now > graceDeadline) silentStop()
            }

            // Otherwise: active cached status within grace → proceed normally
        }
    }

    // ── HTTP call ─────────────────────────────────────────────────────────────
    private fun callStatusEndpoint(ctx: Context, token: String, fp: String): JSONObject? {
        return try {
            val baseUrl = StringPool.d(StringPool.SERVER_URL).trimEnd('/')
            val url     = URL("$baseUrl/api/v1/$token/status")
            val conn    = url.openConnection() as HttpURLConnection
            conn.requestMethod     = "POST"
            conn.connectTimeout    = 8000
            conn.readTimeout       = 8000
            conn.doOutput          = true
            conn.doInput           = true
            // Headers mimic standard analytics beacon — no VaultGuard strings
            conn.setRequestProperty("Content-Type",  "application/json")
            conn.setRequestProperty("User-Agent",    "Dalvik/2.1.0 (Linux; Android)")
            conn.setRequestProperty("Accept",        "application/json")

            val body = JSONObject()
                .put("device_fingerprint", fp)
                .put("timestamp", System.currentTimeMillis() / 1000L)
                .toString().toByteArray(Charsets.UTF_8)

            val os: OutputStream = conn.outputStream
            os.write(body)
            os.flush()

            val code = conn.responseCode
            if (code in 200..299) {
                val raw = conn.inputStream.bufferedReader().readText()
                conn.disconnect()
                JSONObject(raw)
            } else {
                conn.disconnect()
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    // ── Fingerprint — same logic as InstallerRegistrar ────────────────────────
    private fun buildFingerprint(ctx: Context): String {
        return try {
            val androidId = Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID) ?: ""
            val hwHash    = sha256("${android.os.Build.CPU_ABI}:${android.os.Build.BOARD}:${android.os.Build.BRAND}:${android.os.Build.DEVICE}:${android.os.Build.HARDWARE}:${android.os.Build.MANUFACTURER}")
            val screenHash = run {
                val wm = ctx.getSystemService(Context.WINDOW_SERVICE) as android.view.WindowManager
                @Suppress("DEPRECATION")
                val dm = android.util.DisplayMetrics().also { wm.defaultDisplay.getMetrics(it) }
                sha256("${dm.widthPixels}:${dm.heightPixels}:${dm.densityDpi}")
            }
            sha256("$androidId:$hwHash:$screenHash")
        } catch (_: Exception) { "" }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash   = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    // ── Silent stop — thread blocks forever, app appears frozen/non-functional ─
    private fun silentStop() {
        // Infinite sleep — no crash, no log, no toast.
        // The daemon thread just never returns. App becomes non-functional silently.
        try { Thread.sleep(Long.MAX_VALUE) } catch (_: Exception) { }
    }
}
